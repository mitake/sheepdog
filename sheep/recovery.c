/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 * Copyright (C) 2012-2013 Taobao Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

/* base structure for the recovery thread */
struct recovery_work {
	uint32_t epoch;
	uint32_t tgt_epoch;

	struct recovery_info *rinfo;
	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;

	struct work work;
};

/* for preparing lists */
struct recovery_list_work {
	struct recovery_work base;

	uint64_t count;
	struct objlist_cache_unit *units;
};

/* for recovering objects */
struct recovery_obj_work {
	struct recovery_work base;

	/* oid and ec_index: the object to be recovered */
	uint64_t oid;
	int32_t ec_index;

	bool stop;

	/* local replica in the stale directory */
	uint32_t local_epoch;
	uint8_t local_sha1[SHA1_DIGEST_SIZE];
};

/*
 * recovery information
 *
 * We cannot access the members of this structure outside of the main thread.
 */
struct recovery_info {
	enum rw_state state;

	uint32_t epoch;
	uint32_t tgt_epoch;
	uint64_t done;
	uint64_t next;

	/*
	 * true when automatic recovery is disabled
	 * and no recovery work is running
	 */
	bool suspended;
	bool notify_complete;

	uint64_t count;
	struct objlist_cache_unit *units;
	struct objlist_cache_unit *prio_units;
	uint64_t nr_prio_units;
	uint64_t nr_scheduled_prio_units;

	struct vnode_info *old_vinfo;
	struct vnode_info *cur_vinfo;

	int max_epoch;
	struct vnode_info **vinfo_array;
	struct sd_mutex vinfo_lock;
};

static struct recovery_info *next_rinfo;
static main_thread(struct recovery_info *) current_rinfo;

static void queue_recovery_work(struct recovery_info *rinfo);

/* Dynamically grown list buffer default as 4M (2T storage) */
#define DEFAULT_LIST_BUFFER_SIZE (sizeof(struct objlist_cache_unit) << 22)
static size_t list_buffer_size = DEFAULT_LIST_BUFFER_SIZE;

static int obj_cmp(const struct objlist_cache_unit *unit1,
		   const struct objlist_cache_unit *unit2)
{
	int cmp = intcmp(unit1->oid, unit2->oid);
	if (cmp)
		return cmp;
	return intcmp(unit1->ec_index, unit2->ec_index);
}

static inline bool node_is_gateway_only(void)
{
	return sys->this_node.nr_vnodes == 0;
}

static struct vnode_info *rollback_vnode_info(uint32_t *epoch,
					      struct recovery_info *rinfo,
					      struct vnode_info *cur)
{
	struct sd_node nodes[SD_MAX_NODES];
	int nr_nodes;
	struct rb_root nroot = RB_ROOT;

rollback:
	*epoch -= 1;
	if (*epoch < last_gathered_epoch)
		return NULL;

	nr_nodes = get_nodes_epoch(*epoch, cur, nodes, sizeof(nodes));
	if (!nr_nodes) {
		/* We rollback in case we don't get a valid epoch */
		sd_alert("cannot get epoch %d", *epoch);
		sd_alert("clients may see old data");
		goto rollback;
	}
	/* double check */
	if (rinfo->vinfo_array[*epoch] == NULL) {
		sd_mutex_lock(&rinfo->vinfo_lock);
		if (rinfo->vinfo_array[*epoch] == NULL) {
			for (int i = 0; i < nr_nodes; i++)
				rb_insert(&nroot, &nodes[i], rb, node_cmp);
			rinfo->vinfo_array[*epoch] = alloc_vnode_info(&nroot);
		}
		sd_mutex_unlock(&rinfo->vinfo_lock);
	}
	grab_vnode_info(rinfo->vinfo_array[*epoch]);
	return rinfo->vinfo_array[*epoch];
}

/*
 * A node that does not match any node in current node list means the node has
 * left the cluster, then it's an invalid node.
 */
static bool invalid_node(const struct sd_node *n, struct vnode_info *info)
{

	if (rb_search(&info->nroot, n, rb, node_cmp))
		return false;
	return true;
}

static int search_erasure_object(uint64_t oid, uint8_t idx,
				 struct rb_root *nroot,
				 struct recovery_work *rw,
				 uint32_t tgt_epoch,
				 void *buf)
{
	struct sd_req hdr;
	unsigned rlen = get_store_objsize(oid);
	struct sd_node *n;
	uint32_t epoch = rw->epoch;

	rb_for_each_entry(n, nroot, rb) {
		if (invalid_node(n, rw->cur_vinfo))
			continue;
		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.epoch = epoch;
		hdr.flags = SD_FLAG_CMD_RECOVERY;
		hdr.data_length = rlen;
		hdr.obj.oid = oid;
		hdr.obj.tgt_epoch = tgt_epoch;
		hdr.obj.ec_index = idx;

		sd_debug("%"PRIx64" epoch %"PRIu32" tgt %"PRIu32" idx %d, %s",
			 oid, epoch, tgt_epoch, idx, node_to_str(n));
		if (sheep_exec_req(&n->nid, &hdr, buf) == SD_RES_SUCCESS)
			return SD_RES_SUCCESS;
	}
	return SD_RES_NO_OBJ;
}

static void *read_erasure_object(uint64_t oid, uint8_t idx,
				 struct recovery_obj_work *row)
{
	struct sd_req hdr;
	unsigned rlen = get_store_objsize(oid);
	void *buf = xvalloc(rlen);
	struct recovery_work *rw = &row->base;
	struct vnode_info *old = grab_vnode_info(rw->old_vinfo), *new_old;
	uint32_t epoch = rw->epoch, tgt_epoch = rw->tgt_epoch;
	const struct sd_node *node;
	uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
	int edp = ec_policy_to_dp(policy, NULL, NULL);
	int ret;
again:
	if (unlikely(old->nr_zones < edp)) {
		if (search_erasure_object(oid, idx, &old->nroot, rw,
					  tgt_epoch, buf)
		    == SD_RES_SUCCESS)
			goto done;
		else
			goto rollback;
	}
	node = oid_to_node(oid, &old->vroot, idx);
	sd_debug("%"PRIx64" epoch %"PRIu32" tgt %"PRIu32" idx %d, %s",
		 oid, epoch, tgt_epoch, idx, node_to_str(node));
	if (invalid_node(node, rw->cur_vinfo))
		goto rollback;
	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;
	hdr.obj.ec_index = idx;

	ret = sheep_exec_req(&node->nid, &hdr, buf);
	switch (ret) {
	case SD_RES_SUCCESS:
		goto done;
	case SD_RES_OLD_NODE_VER:
		free(buf);
		buf = NULL;
		row->stop = true;
		break;
	default:
rollback:
		new_old = rollback_vnode_info(&tgt_epoch, rw->rinfo,
					      rw->cur_vinfo);
		if (!new_old) {
			sd_err("can not read %"PRIx64" idx %d", oid, idx);
			free(buf);
			buf = NULL;
			goto done;
		}
		put_vnode_info(old);
		old = new_old;
		goto again;
	}
done:
	put_vnode_info(old);
	return buf;
}

/*
 * Read object from targeted node and store it in the local node.
 *
 * tgt_epoch: the specific epoch that the object has stayed
 * idx: erasure index. For non-erasure object, pass 0.
 */
static int recover_object_from(struct recovery_obj_work *row,
			       const struct sd_node *node,
			       uint32_t tgt_epoch)
{
	uint64_t oid = row->oid;
	uint32_t local_epoch = row->local_epoch;
	uint8_t *sha1 = row->local_sha1;
	uint32_t epoch = row->base.epoch;
	int ret;
	unsigned rlen;
	void *buf = NULL;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct siocb iocb = { 0 };

	if (node_is_local(node)) {
		if (tgt_epoch < sys_epoch())
			return sd_store->link(oid, tgt_epoch);

		return SD_RES_NO_OBJ;
	}

	/* compare sha1 hash value first */
	if (local_epoch > 0) {
		sd_init_req(&hdr, SD_OP_GET_HASH);
		hdr.obj.oid = oid;
		hdr.obj.tgt_epoch = tgt_epoch;
		ret = sheep_exec_req(&node->nid, &hdr, NULL);
		if (ret != SD_RES_SUCCESS)
			return ret;

		if (memcmp(rsp->hash.digest, sha1,
			   sizeof(SHA1_DIGEST_SIZE)) == 0) {
			sd_debug("use local replica at epoch %d", local_epoch);
			ret = sd_store->link(oid, local_epoch);
			if (ret == SD_RES_SUCCESS)
				return ret;
		}
	}

	rlen = get_store_objsize(oid);
	buf = xvalloc(rlen);

	/* recover from remote replica */
	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = epoch;
	hdr.flags = SD_FLAG_CMD_RECOVERY;
	hdr.data_length = rlen;
	hdr.obj.oid = oid;
	hdr.obj.tgt_epoch = tgt_epoch;

	ret = sheep_exec_req(&node->nid, &hdr, buf);
	if (ret == SD_RES_SUCCESS) {
		iocb.epoch = epoch;
		iocb.length = rsp->data_length;
		iocb.offset = rsp->obj.offset;
		iocb.buf = buf;
		ret = sd_store->create_and_write(oid, &iocb);
	}

	free(buf);
	return ret;
}

static int recover_object_from_replica(struct recovery_obj_work *row,
				       struct vnode_info *old,
				       uint32_t tgt_epoch)
{
	uint64_t oid = row->oid;
	uint32_t epoch = row->base.epoch;
	int nr_copies, ret = SD_RES_SUCCESS, start = 0;
	bool fully_replicated = true;

	nr_copies = get_obj_copy_number(oid, old->nr_zones);

	/* find local node first to try to recover from local */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_vnode *vnode;

		vnode = oid_to_vnode(oid, &old->vroot, i);

		if (vnode_is_local(vnode)) {
			start = i;
			break;
		}
	}

	/* Let's do a breadth-first search */
	for (int i = 0; i < nr_copies; i++) {
		const struct sd_node *node;
		int idx = (i + start) % nr_copies;

		node = oid_to_node(oid, &old->vroot, idx);

		if (invalid_node(node, row->base.cur_vinfo))
			continue;

		ret = recover_object_from(row, node, tgt_epoch);
		switch (ret) {
		case SD_RES_SUCCESS:
			sd_debug("recovered oid %"PRIx64" from %d to epoch %d",
				 oid, tgt_epoch, epoch);
			return ret;
		case SD_RES_OLD_NODE_VER:
			/* move to the next epoch recovery */
			return ret;
		case SD_RES_NO_OBJ:
			fully_replicated = false;
			/* fall through */
		default:
			break;
		}
	}

	/*
	 * sheep would return a stale object when
	 *  - all the nodes hold the copies, and
	 *  - all the nodes are gone
	 * at the some epoch
	 */
	if (fully_replicated && ret != SD_RES_SUCCESS)
		ret = SD_RES_STALE_OBJ;

	return ret;
}

/*
 * Recover the object from its track in epoch history. That is,
 * the routine will try to recovery it from the nodes it has stayed,
 * at least, *theoretically* on consistent hash ring.
 */
static int recover_replication_object(struct recovery_obj_work *row)
{
	struct recovery_work *rw = &row->base;
	struct vnode_info *old;
	uint64_t oid = row->oid;
	uint32_t tgt_epoch = rw->tgt_epoch;
	int ret;
	struct vnode_info *new_old;

	old = grab_vnode_info(rw->old_vinfo);
again:
	sd_debug("try recover object %"PRIx64" from epoch %"PRIu32, oid,
		 tgt_epoch);

	ret = recover_object_from_replica(row, old, tgt_epoch);

	switch (ret) {
	case SD_RES_SUCCESS:
		/* Succeed */
		break;
	case SD_RES_OLD_NODE_VER:
		row->stop = true;
		break;
	case SD_RES_STALE_OBJ:
		sd_alert("cannot access any replicas of %"PRIx64" at epoch %d",
			 oid, tgt_epoch);
		sd_alert("clients may see old data");
		/* fall through */
	default:
		/* No luck, roll back to an older configuration and try again */
		new_old = rollback_vnode_info(&tgt_epoch, rw->rinfo,
					      rw->cur_vinfo);
		if (!new_old) {
			sd_err("can not recover oid %"PRIx64, oid);
			ret = -1;
			goto out;
		}

		put_vnode_info(old);
		old = new_old;
		goto again;
	}
out:
	put_vnode_info(old);
	return ret;
}

static void *rebuild_erasure_object(uint64_t oid, uint8_t idx,
				    struct recovery_obj_work *row)
{
	int len = get_store_objsize(oid);
	char *lost = xvalloc(len);
	int i, j;
	uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
	int ed = 0, edp;
	edp = ec_policy_to_dp(policy, &ed, NULL);
	struct fec *ctx = ec_init(ed, edp);
	uint8_t *bufs[ed];
	int idxs[ed];

	for (i = 0; i < ed; i++)
		bufs[i] = NULL;
	for (i = 0; i < ed; i++)
		idxs[i] = 0;

	/* Prepare replica */
	for (i = 0, j = 0; i < edp && j < ed; i++) {
		if (i == idx)
			continue;
		bufs[j] = read_erasure_object(oid, i, row);
		if (row->stop)
			break;
		if (!bufs[j])
			continue;
		idxs[j++] = i;
	}
	if (j != ed) {
		free(lost);
		lost = NULL;
		goto out;
	}

	/* Rebuild the lost replica */
	ec_decode_buffer(ctx, bufs, idxs, lost, idx);
out:
	ec_destroy(ctx);
	for (i = 0; i < ed; i++)
		free(bufs[i]);
	return lost;
}

uint8_t local_ec_index(struct vnode_info *vinfo, uint64_t oid)
{
	int idx, m = min(get_vdi_copy_number(oid_to_vid(oid)), vinfo->nr_zones);

	if (!is_erasure_oid(oid))
		return SD_MAX_COPIES;

	for (idx = 0; idx < m; idx++) {
		const struct sd_node *n = oid_to_node(oid, &vinfo->vroot, idx);
		if (node_is_local(n))
			return idx;
	}
	sd_debug("can't get valid index for %"PRIx64, oid);
	return SD_MAX_COPIES;
}

/*
 * Erasure object recovery algorithm
 *
 * 1. read the lost object from its track in epoch history vertically because
 *    every copy that holds partial data of the object is unique
 * 2. if not found in 1, then tries to rebuild it with RS algorithm
 *    2.1 read enough other copies from their tracks in epoch history
 *    2.2 rebuild the lost object from the content of copies read at 2.1
 *
 * The subtle case is number for available zones is less than total copy number
 * or the requested index of lost object:
 *    1 we need to make sure nr_zones >= total_copy_nr to avoid panic of
 *      oid_to_node(s) helpers.
 *    2 we have to search all the available zones when we can't get idx. Its
 *      okay to do a mad search when number of available zones is small
 */
static int recover_erasure_object(struct recovery_obj_work *row)
{
	struct recovery_work *rw = &row->base;
	struct vnode_info *cur = rw->cur_vinfo;
	uint64_t oid = row->oid;
	struct siocb iocb = { 0 };
	void *buf = NULL;
	uint8_t idx;
	int ret = -1;

	idx = local_ec_index(cur, oid);
	buf = read_erasure_object(oid, idx, row);
	if (!buf && !row->stop)
		buf = rebuild_erasure_object(oid, idx, row);
	if (!buf) {
		if (!row->stop)
			sd_err("failed to recover %"PRIx64" idx %d", oid, idx);
		goto out;
	}

	iocb.epoch = rw->epoch;
	iocb.length = get_store_objsize(oid);
	iocb.offset = 0;
	iocb.buf = buf;
	iocb.ec_index = idx;
	ret = sd_store->create_and_write(oid, &iocb);
	free(buf);
out:
	return ret;
}

static int do_recover_object(struct recovery_obj_work *row)
{
	uint64_t oid = row->oid;

	sd_debug("try recover object %"PRIx64, oid);

	if (is_erasure_oid(oid))
		return recover_erasure_object(row);
	else
		return recover_replication_object(row);
}

static void recover_object_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	uint64_t oid = row->oid;
	struct vnode_info *cur = rw->cur_vinfo;
	int ret, epoch;

	if (sd_store->exist(oid, local_ec_index(cur, oid))) {
		sd_debug("the object is already recovered");
		return;
	}

	/* find object in the stale directory */
	if (!is_erasure_oid(oid))
		for (epoch = sys_epoch() - 1; epoch >= last_gathered_epoch;
		     epoch--) {
			ret = sd_store->get_hash(oid, epoch, row->local_sha1);
			if (ret == SD_RES_SUCCESS) {
				sd_debug("replica found in local at epoch %d",
					 epoch);
				row->local_epoch = epoch;
				break;
			}
		}

	ret = do_recover_object(row);
	if (ret != 0)
		sd_err("failed to recover object %"PRIx64, oid);
}

bool node_in_recovery(void)
{
	return main_thread_get(current_rinfo) != NULL;
}

static inline void prepare_schedule_oid(uint64_t oid, int32_t ec_index)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	struct objlist_cache_unit unit = { .oid = oid, .ec_index = ec_index };

	if (xlfind(&unit, rinfo->prio_units, rinfo->nr_prio_units, obj_cmp)) {
		sd_debug("%" PRIx64 ": %d has been already in prio_units",
			 oid, ec_index);
		return;
	}

	rinfo->nr_prio_units++;
	rinfo->prio_units = xrealloc(rinfo->prio_units,
				     rinfo->nr_prio_units *
				     sizeof(struct objlist_cache_unit));
	rinfo->prio_units[rinfo->nr_prio_units - 1] = unit;
	sd_debug("%"PRIx64": %d nr_prio_units %"PRIu64, oid, ec_index,
		 rinfo->nr_prio_units);

	resume_suspended_recovery();
}

main_fn bool oid_in_recovery(uint64_t oid, int8_t ec_index)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	struct vnode_info *cur;
	struct objlist_cache_unit unit = { .oid = oid, .ec_index = ec_index};

	if (!node_in_recovery())
		return false;

	cur = rinfo->cur_vinfo;
	if (sd_store->exist(oid, local_ec_index(cur, oid))) {
		sd_debug("the object %" PRIx64 " is already recovered", oid);
		return false;
	}

	if (uatomic_read(&next_rinfo))
		/*
		 * The current recovery_info will be taken over by the next one
		 * soon, so no need to call prepare_schedule_oid() now.
		 */
		return true;

	switch (rinfo->state) {
	case RW_PREPARE_LIST:
		/* oid is not recovered yet */
		break;
	case RW_RECOVER_OBJ:
		if (xlfind(&unit, rinfo->units, rinfo->done, obj_cmp)) {
			sd_debug("%" PRIx64 " has been already recovered", oid);
			return false;
		}

		if (xlfind(&unit, rinfo->units + rinfo->done,
			   rinfo->next - rinfo->done, obj_cmp)) {
			if (rinfo->suspended)
				break;
			/*
			 * When recovery is not suspended,
			 * rinfo->units[rinfo->done .. rinfo->next) is currently
			 * being recovered and no need to call
			 * prepare_schedule_oid().
			 */
			return true;
		}

		/*
		 * Check if oid is in the list that to be recovered later
		 *
		 * FIXME: do we need more efficient yet complex data structure?
		 */
		if (xlfind(&unit, rinfo->units + rinfo->next,
			   rinfo->count - rinfo->next + 1, obj_cmp))
			break;

		/*
		 * Newly created object after prepare_object_list() might not be
		 * in the list
		 */
		sd_debug("%"PRIx64" is not in the recovery list", oid);
		return false;
	case RW_NOTIFY_COMPLETION:
		sd_debug("the object %" PRIx64 " is already recovered", oid);
		return false;
	}

	prepare_schedule_oid(oid, ec_index);
	return true;
}

static void free_recovery_work(struct recovery_work *rw)
{
	put_vnode_info(rw->cur_vinfo);
	put_vnode_info(rw->old_vinfo);
	free(rw);
}

static void free_recovery_list_work(struct recovery_list_work *rlw)
{
	put_vnode_info(rlw->base.cur_vinfo);
	put_vnode_info(rlw->base.old_vinfo);
	free(rlw->units);
	free(rlw);
}

static void free_recovery_obj_work(struct recovery_obj_work *row)
{
	put_vnode_info(row->base.cur_vinfo);
	put_vnode_info(row->base.old_vinfo);
	free(row);
}

static void free_recovery_info(struct recovery_info *rinfo)
{
	put_vnode_info(rinfo->cur_vinfo);
	put_vnode_info(rinfo->old_vinfo);
	free(rinfo->units);
	free(rinfo->prio_units);
	for (int i = 0; i < rinfo->max_epoch; i++)
		put_vnode_info(rinfo->vinfo_array[i]);
	free(rinfo->vinfo_array);
	sd_destroy_mutex(&rinfo->vinfo_lock);
	free(rinfo);
}

/* Return true if next recovery work is queued. */
static inline bool run_next_rw(void)
{
	struct recovery_info *nrinfo = uatomic_read(&next_rinfo);
	struct recovery_info *cur = main_thread_get(current_rinfo);

	if (nrinfo == NULL)
		return false;

	/* Some objects are still in recovery. */
	if (cur->done < cur->next) {
		sd_debug("some threads still running, wait for completion");
		return true;
	}

	nrinfo = uatomic_xchg_ptr(&next_rinfo, NULL);
	/*
	 * When md recovery supersedes the reweight or node recovery, we need to
	 * notify completion.
	 */
	if (!nrinfo->notify_complete && cur->notify_complete)
		nrinfo->notify_complete = true;

	free_recovery_info(cur);

	if (!node_is_gateway_only())
		sd_store->update_epoch(nrinfo->tgt_epoch);

	main_thread_set(current_rinfo, nrinfo);
	wakeup_all_requests();
	queue_recovery_work(nrinfo);
	sd_debug("recovery work is superseded");
	return true;
}

static void notify_recovery_completion_work(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_COMPLETE_RECOVERY);
	hdr.obj.tgt_epoch = rw->epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(sys->this_node);

	ret = exec_local_req(&hdr, &sys->this_node);
	if (ret != SD_RES_SUCCESS)
		sd_err("failed to notify recovery completion, %d", rw->epoch);
}

static void notify_recovery_completion_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	free_recovery_work(rw);
}

static inline void finish_recovery(struct recovery_info *rinfo)
{
	uint32_t recovered_epoch = rinfo->epoch;
	main_thread_set(current_rinfo, NULL);

	wakeup_all_requests();

	if (rinfo->notify_complete) {
		rinfo->state = RW_NOTIFY_COMPLETION;
		queue_recovery_work(rinfo);
	}

	free_recovery_info(rinfo);

	sd_debug("recovery complete: new epoch %"PRIu32, recovered_epoch);
}

static inline bool obj_in_prio_units(struct recovery_info *rinfo, uint64_t oid,
				     int32_t ec_index)
{
	for (uint64_t i = 0; i < rinfo->nr_prio_units; i++)
		if (rinfo->prio_units[i].oid == oid &&
			rinfo->prio_units[i].ec_index == ec_index)
			return true;
	return false;
}

/*
 * Schedule prio_oids to be recovered first in FIFO order
 *
 * rw->next is index of the original next object to be recovered and also the
 * number of objects already recovered and being recovered.
 * we just move rw->prio_oids in between:
 *   new_oids = [0..rw->next - 1] + [rw->prio_oids] + [rw->next]
 */
static inline void finish_schedule_units(struct recovery_info *rinfo)
{
	uint64_t i, nr_recovered = rinfo->next, new_idx;
	struct objlist_cache_unit *new_units;

	/* If I am the last unit, done */
	if (nr_recovered == rinfo->count - 1)
		goto done;

	new_units = xmalloc(list_buffer_size);
	memcpy(new_units, rinfo->units, nr_recovered *
	       sizeof(struct objlist_cache_unit));
	memcpy(new_units + nr_recovered, rinfo->prio_units,
	       rinfo->nr_prio_units * sizeof(struct objlist_cache_unit));
	new_idx = nr_recovered + rinfo->nr_prio_units;

	for (i = rinfo->next; i < rinfo->count; i++) {
		if (obj_in_prio_units(rinfo, rinfo->units[i].oid,
				      rinfo->units[i].ec_index))
			continue;
		new_units[new_idx++] = rinfo->units[i];
	}
	/* rw->count should eq new_idx, otherwise something is wrong */
	sd_debug("%snr_recovered %" PRIu64 ", nr_prio_units %" PRIu64 ", count"
		 " %"PRIu64 " = new %" PRIu64,
		 rinfo->count == new_idx ? "" : "WARN: ", nr_recovered,
		 rinfo->nr_prio_units, rinfo->count, new_idx);

	free(rinfo->units);
	rinfo->units = new_units;
done:
	free(rinfo->prio_units);
	rinfo->prio_units = NULL;
	rinfo->nr_scheduled_prio_units += rinfo->nr_prio_units;
	rinfo->nr_prio_units = 0;
}

/*
 * When automatic object recovery is disabled, the behavior of the
 * recovery process is like 'lazy recovery'.  This function returns
 * true if the recovery queue contains objects being accessed by
 * clients.  Sheep recovers such objects for availability even when
 * automatic object recovery is not enabled.
 */
static bool has_scheduled_objects(struct recovery_info *rinfo)
{
	return rinfo->done < rinfo->nr_scheduled_prio_units;
}

static void recover_next_object(struct recovery_info *rinfo)
{
	if (run_next_rw())
		return;

	if (rinfo->nr_prio_units)
		finish_schedule_units(rinfo);

	if (sys->cinfo.disable_recovery && !has_scheduled_objects(rinfo)) {
		sd_debug("suspended");
		rinfo->suspended = true;
		/* suspend until resume_suspended_recovery() is called */
		return;
	}

	/* no more objects to be recovered */
	if (rinfo->next >= rinfo->count)
		return;

	/* Try recover next object */
	queue_recovery_work(rinfo);
	rinfo->next++;
}

void resume_suspended_recovery(void)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	if (rinfo && rinfo->suspended) {
		rinfo->suspended = false;
		recover_next_object(rinfo);
	}
}

static void recover_object_main(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_obj_work *row = container_of(rw,
						     struct recovery_obj_work,
						     base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	/* ->units[done, next] is out of order since finish order is random */
	if (rinfo->units[rinfo->done].oid != row->oid ||
	    rinfo->units[rinfo->done].ec_index != row->ec_index) {
		struct objlist_cache_unit unit = { .oid = row->oid,
						   .ec_index = row->ec_index };

		struct objlist_cache_unit *p = xlfind(&unit,
						      rinfo->units +
						      rinfo->done,
						      rinfo->next -
						      rinfo->done, obj_cmp);

		*p = rinfo->units[rinfo->done];
		rinfo->units[rinfo->done] = unit;
	}
	rinfo->done++;

	if (run_next_rw()) {
		free_recovery_obj_work(row);
		return;
	}

	wakeup_requests_on_obj(row->oid, row->ec_index);

	if (!(rinfo->done % DIV_ROUND_UP(rinfo->count, 100)))
		sd_info("object recovery progress %3.0lf%% ",
			(double)rinfo->done / rinfo->count * 100);
	sd_debug("object %"PRIx64":%d is recovered (%"PRIu64"/%"PRIu64")",
		 row->oid, row->ec_index, rinfo->done, rinfo->count);

	if (rinfo->done >= rinfo->count)
		goto finish_recovery;

	recover_next_object(rinfo);
	free_recovery_obj_work(row);
	return;
finish_recovery:
	finish_recovery(rinfo);
	free_recovery_obj_work(row);
}

static void finish_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	struct recovery_info *rinfo = main_thread_get(current_rinfo);
	/*
	 * Rationale for multi-threaded recovery:
	 * 1. If one node is added, we find that all the VMs on other nodes will
	 *    get noticeably affected until 50% data is transferred to the new
	 *    node.
	 * 2. For node failure, we might not have problems of running VM but the
	 *    recovery process boost will benefit IO operation of VM with less
	 *    chances to be blocked for write and also improve reliability.
	 * 3. For disk failure in node, this is similar to adding a node. All
	 *    the data on the broken disk will be recovered on other disks in
	 *    this node. Speedy recovery not only improve data reliability but
	 *    also cause less writing blocking on the lost data.
	 *
	 * We choose md_nr_disks() * 2 threads for recovery, no rationale.
	 */
	uint32_t nr_threads = md_nr_disks() * 2;

	rinfo->state = RW_RECOVER_OBJ;
	rinfo->count = rlw->count;
	rinfo->units = rlw->units;
	rlw->units = NULL;
	free_recovery_list_work(rlw);

	if (run_next_rw())
		return;

	if (!rinfo->count) {
		finish_recovery(rinfo);
		return;
	}

	for (uint32_t i = 0; i < nr_threads; i++)
		recover_next_object(rinfo);
	return;
}

/* Fetch the object list from all the nodes in the cluster */
static struct objlist_cache_unit *fetch_object_list(struct sd_node *e,
						    uint32_t epoch,
						    size_t *nr_units)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	size_t buf_size = list_buffer_size;
	struct objlist_cache_unit *buf = xmalloc(buf_size);
	int ret;

	sd_debug("%s", addr_to_str(e->nid.addr, e->nid.port));

retry:
	sd_init_req(&hdr, SD_OP_GET_OBJ_LIST);
	hdr.data_length = buf_size;
	hdr.epoch = epoch;
	ret = sheep_exec_req(&e->nid, &hdr, buf);

	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_BUFFER_SMALL:
		buf_size *= 2;
		buf = xrealloc(buf, buf_size);
		goto retry;
	default:
		sd_alert("cannot get object list from %s",
			 addr_to_str(e->nid.addr, e->nid.port));
		sd_alert("some objects may be not recovered at epoch %d",
			 epoch);
		free(buf);
		return NULL;
	}

	*nr_units = rsp->data_length / sizeof(struct objlist_cache_unit);
	sd_debug("%zu", *nr_units);
	return buf;
}

/* Screen out objects that don't belong to this node */
static void screen_object_list(struct recovery_list_work *rlw,
			       struct objlist_cache_unit *units,
			       size_t nr_units)
{
	struct recovery_work *rw = &rlw->base;
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	uint64_t old_count = rlw->count;
	uint64_t nr_objs;
	uint64_t i, j;

	for (i = 0; i < nr_units; i++) {
		if (xbsearch(&units[i], rlw->units, old_count, obj_cmp))
			/* the object is already scheduled to be recovered */
			continue;

		nr_objs = get_obj_copy_number(units[i].oid,
					      rw->cur_vinfo->nr_zones);

		oid_to_vnodes(units[i].oid, &rw->cur_vinfo->vroot, nr_objs,
			      vnodes);
		for (j = 0; j < nr_objs; j++) {
			if (!vnode_is_local(vnodes[j]))
				continue;

			rlw->units[rlw->count++] = units[i];
			/* enlarge the list buffer if full */
			if (rlw->count == list_buffer_size /
			    sizeof(struct objlist_cache_unit)) {
				list_buffer_size *= 2;
				rlw->units = xrealloc(rlw->units,
						     list_buffer_size);
			}
			break;
		}
	}

	xqsort(rlw->units, rlw->count, obj_cmp);
}

/* Prepare the object list that belongs to this node */
static void prepare_object_list(struct work *work)
{
	struct recovery_work *rw = container_of(work, struct recovery_work,
						work);
	struct recovery_list_work *rlw = container_of(rw,
						      struct recovery_list_work,
						      base);
	int nr_nodes = rw->cur_vinfo->nr_nodes;
	int start = random() % nr_nodes, i, end = nr_nodes;
	struct objlist_cache_unit *units;
	struct sd_node *nodes;

	if (node_is_gateway_only())
		return;

	sd_debug("%u", rw->epoch);
	wait_get_vdis_done();

	nodes = xmalloc(sizeof(struct sd_node) * nr_nodes);
	nodes_to_buffer(&rw->cur_vinfo->nroot, nodes);
again:
	/* We need to start at random node for better load balance */
	for (i = start; i < end; i++) {
		size_t nr_units;
		struct sd_node *node = nodes + i;

		if (uatomic_read(&next_rinfo)) {
			sd_debug("go to the next recovery");
			goto out;
		}

		units = fetch_object_list(node, rw->epoch, &nr_units);
		if (!units)
			continue;
		screen_object_list(rlw, units, nr_units);
		free(units);
	}

	if (start != 0) {
		end = start;
		start = 0;
		goto again;
	}

	sd_debug("%"PRIu64, rlw->count);
out:
	free(nodes);
}

int start_recovery(struct vnode_info *cur_vinfo, struct vnode_info *old_vinfo,
		   bool epoch_lifted)
{
	struct recovery_info *rinfo;

	rinfo = xzalloc(sizeof(struct recovery_info));
	rinfo->state = RW_PREPARE_LIST;
	rinfo->epoch = sys->cinfo.epoch;
	rinfo->tgt_epoch = epoch_lifted ? sys->cinfo.epoch - 1 :
		sys->cinfo.epoch;
	rinfo->count = 0;
	rinfo->max_epoch = sys->cinfo.epoch;
	rinfo->vinfo_array = xzalloc(sizeof(struct vnode_info *) *
				     rinfo->max_epoch);
	sd_init_mutex(&rinfo->vinfo_lock);
	if (epoch_lifted)
		rinfo->notify_complete = true; /* Reweight or node recovery */
	else
		rinfo->notify_complete = false; /* MD recovery */

	rinfo->cur_vinfo = grab_vnode_info(cur_vinfo);
	rinfo->old_vinfo = grab_vnode_info(old_vinfo);

	if (!node_is_gateway_only())
		sd_store->update_epoch(rinfo->tgt_epoch);

	if (main_thread_get(current_rinfo) != NULL) {
		/* skip the previous epoch recovery */
		struct recovery_info *nrinfo;
		nrinfo = uatomic_xchg_ptr(&next_rinfo, rinfo);
		if (nrinfo)
			free_recovery_info(nrinfo);
		sd_debug("recovery skipped");

		/*
		 * This is necessary to invoke run_next_rw when
		 * recovery work is suspended.
		 */
		resume_suspended_recovery();
	} else {
		main_thread_set(current_rinfo, rinfo);
		queue_recovery_work(rinfo);
	}
	wakeup_requests_on_epoch();
	return 0;
}

static void queue_recovery_work(struct recovery_info *rinfo)
{
	struct recovery_work *rw;
	struct recovery_list_work *rlw;
	struct recovery_obj_work *row;

	switch (rinfo->state) {
	case RW_PREPARE_LIST:
		rlw = xzalloc(sizeof(*rlw));
		rlw->units = xmalloc(list_buffer_size);

		rw = &rlw->base;
		rw->work.fn = prepare_object_list;
		rw->work.done = finish_object_list;
		break;
	case RW_RECOVER_OBJ:
		row = xzalloc(sizeof(*row));
		row->oid = rinfo->units[rinfo->next].oid;
		row->ec_index = rinfo->units[rinfo->next].ec_index;

		rw = &row->base;
		rw->work.fn = recover_object_work;
		rw->work.done = recover_object_main;
		break;
	case RW_NOTIFY_COMPLETION:
		rw = xzalloc(sizeof(*rw));
		rw->work.fn = notify_recovery_completion_work;
		rw->work.done = notify_recovery_completion_main;
		break;
	default:
		panic("unknown recovery state %d", rinfo->state);
		break;
	}

	rw->epoch = rinfo->epoch;
	rw->tgt_epoch = rinfo->tgt_epoch;
	rw->rinfo = rinfo;
	rw->cur_vinfo = grab_vnode_info(rinfo->cur_vinfo);
	rw->old_vinfo = grab_vnode_info(rinfo->old_vinfo);

	queue_work(sys->recovery_wqueue, &rw->work);
}

void get_recovery_state(struct recovery_state *state)
{
	struct recovery_info *rinfo = main_thread_get(current_rinfo);

	memset(state, 0, sizeof(*state));

	if (!rinfo) {
		state->in_recovery = 0;
		return;
	}

	state->in_recovery = 1;
	state->state = rinfo->state;
	state->nr_finished = rinfo->done;
	state->nr_total = rinfo->count;
}
