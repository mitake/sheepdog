/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/file.h>
#include <dirent.h>
#include <urcu/uatomic.h>
#include <sys/eventfd.h>

#include "sheep_priv.h"
#include "util.h"
#include "strbuf.h"
#include "rbtree.h"

/*
 * Object Cache ID
 *
 *  0 - 19 (20 bits): data object space
 *  20 - 27 (8 bits): object flag space
 *  28 - 31 (4 bits): object type indentifier space
 */
#define CACHE_VDI_SHIFT       31 /* if the entry is identified as VDI object */
#define CACHE_CREATE_SHIFT    27 /* If the entry should be created at backend */

#define CACHE_VDI_BIT         (UINT32_C(1) << CACHE_VDI_SHIFT)
#define CACHE_CREATE_BIT      (UINT32_C(1) << CACHE_CREATE_SHIFT)

#define CACHE_INDEX_MASK      (CACHE_CREATE_BIT)

#define CACHE_BLOCK_SIZE      ((UINT64_C(1) << 10) * 64) /* 64 KB */

#define CACHE_OBJECT_SIZE (SD_DATA_OBJ_SIZE / 1024 / 1024) /* M */

struct global_cache {
	uint32_t capacity; /* The real capacity of object cache of this node */
	uatomic_bool in_reclaim; /* If the relcaimer is working */
};

struct object_cache_entry {
	uint32_t idx; /* Index of this entry */
	int refcnt; /* Reference count of this entry */
	uint64_t bmap; /* Each bit represents one dirty block in object */
	struct object_cache *oc; /* Object cache this entry belongs to */
	struct rb_node node; /* For lru tree of object cache */
	struct list_head dirty_list; /* For dirty list of object cache */
	struct list_head lru_list; /* For lru list of object cache */

	pthread_rwlock_t lock; /* Entry lock */
};

struct object_cache {
	uint32_t vid; /* The VID of this VDI */
	uint32_t push_count; /* How many push threads queued in push phase. */
	struct hlist_node hash; /* VDI is linked to the global hash lists */
	struct rb_root lru_tree; /* For faster object search */
	struct list_head lru_head; /* Per VDI LRU list for reclaimer */
	struct list_head dirty_head; /* Dirty objects linked to this list */
	int push_efd; /* Used to synchronize between pusher and push threads */

	pthread_rwlock_t lock; /* Cache lock */
};

static struct global_cache gcache;
static char object_cache_dir[PATH_MAX];
static int def_open_flags = O_RDWR;

#define HASH_BITS	5
#define HASH_SIZE	(1 << HASH_BITS)

static pthread_rwlock_t hashtable_lock[HASH_SIZE] = {
	[0 ... HASH_SIZE - 1] = PTHREAD_RWLOCK_INITIALIZER
};

static struct hlist_head cache_hashtable[HASH_SIZE];

static inline bool entry_is_dirty(const struct object_cache_entry *entry)
{
	return !!entry->bmap;
}

static inline int hash(uint64_t vid)
{
	return hash_64(vid, HASH_BITS);
}

/* We should always use this helper to get entry idx */
static inline uint32_t entry_idx(const struct object_cache_entry *entry)
{
	return entry->idx & ~CACHE_INDEX_MASK;
}

static inline uint32_t object_cache_oid_to_idx(uint64_t oid)
{
	uint32_t idx = data_oid_to_idx(oid);
	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;
	return idx;
}

static inline bool idx_has_vdi_bit(uint32_t idx)
{
	return !!(idx & CACHE_VDI_BIT);
}

static uint64_t calc_object_bmap(size_t len, off_t offset)
{
	int start, end, nr;
	unsigned long bmap = 0;

	start = offset / CACHE_BLOCK_SIZE;
	end = DIV_ROUND_UP(len + offset, CACHE_BLOCK_SIZE);
	nr = end - start;

	while (nr--)
		set_bit(start + nr, &bmap);

	return (uint64_t)bmap;
}

static inline void get_cache_entry(struct object_cache_entry *entry)
{
	uatomic_inc(&entry->refcnt);
}

static inline void put_cache_entry(struct object_cache_entry *entry)
{
	uatomic_dec(&entry->refcnt);
}

static inline bool entry_in_use(struct object_cache_entry *entry)
{
	return uatomic_read(&entry->refcnt) > 0;
}

/*
 * Mutual exclusive protection strategy:
 *
 * reader and writer:          no need to project since it is okay to read
 *                             unacked stale data.
 * reader, writer and pusher:    cache lock and entry lock and refcnt.
 * reader, writer and reclaimer: cache lock and entry refcnt.
 * pusher and reclaimer:       cache lock and entry refcnt.
 *
 * entry->bmap is projected by mostly entry lock, sometimes cache lock.
 * dirty list is projected by cache lock.
 */
static inline void read_lock_cache(struct object_cache *oc)
{
	pthread_rwlock_rdlock(&oc->lock);
}

static inline void write_lock_cache(struct object_cache *oc)
{
	pthread_rwlock_wrlock(&oc->lock);
}

static inline void unlock_cache(struct object_cache *oc)
{
	pthread_rwlock_unlock(&oc->lock);
}

static inline void read_lock_entry(struct object_cache_entry *entry)
{
	pthread_rwlock_rdlock(&entry->lock);
}

static inline void write_lock_entry(struct object_cache_entry *entry)
{
	pthread_rwlock_wrlock(&entry->lock);
}

static inline void unlock_entry(struct object_cache_entry *entry)
{
	pthread_rwlock_unlock(&entry->lock);
}

static struct object_cache_entry *
lru_tree_insert(struct rb_root *root, struct object_cache_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct object_cache_entry *entry;
	uint32_t idx = entry_idx(new);

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct object_cache_entry, node);

		if (idx < entry_idx(entry))
			p = &(*p)->rb_left;
		else if (idx > entry_idx(entry))
			p = &(*p)->rb_right;
		else {
			/* already has this entry */
			return entry;
		}
	}
	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return NULL; /* insert successfully */
}

static struct object_cache_entry *lru_tree_search(struct rb_root *root,
						  uint32_t idx)
{
	struct rb_node *n = root->rb_node;
	struct object_cache_entry *t;

	while (n) {
		t = rb_entry(n, struct object_cache_entry, node);

		if (idx < entry_idx(t))
			n = n->rb_left;
		else if (idx > entry_idx(t))
			n = n->rb_right;
		else
			return t; /* found it */
	}

	return NULL;
}

static inline void
free_cache_entry(struct object_cache_entry *entry)
{
	struct object_cache *oc = entry->oc;

	rb_erase(&entry->node, &oc->lru_tree);
	list_del_init(&entry->lru_list);
	if (!list_empty(&entry->dirty_list))
		list_del_init(&entry->dirty_list);
	pthread_rwlock_destroy(&entry->lock);
	free(entry);
}

static uint64_t idx_to_oid(uint32_t vid, uint32_t idx)
{
	if (idx_has_vdi_bit(idx))
		return vid_to_vdi_oid(vid);
	else
		return vid_to_data_oid(vid, idx);
}

static int remove_cache_object(struct object_cache *oc, uint32_t idx)
{
	int ret = SD_RES_SUCCESS;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%06"PRIx32"/%08"PRIx32,
		 object_cache_dir, oc->vid, idx);
	sd_dprintf("%"PRIx64"\n", idx_to_oid(oc->vid, idx));
	if (unlink(path) < 0) {
		sd_eprintf("failed to remove cached object %m\n");
		if (errno == ENOENT)
			return SD_RES_SUCCESS;
		ret = SD_RES_EIO;
		goto out;
	}
out:
	return ret;
}

static int read_cache_object_noupdate(uint32_t vid, uint32_t idx, void *buf,
				      size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	char p[PATH_MAX];

	snprintf(p, sizeof(p), "%s/%06"PRIx32"/%08"PRIx32, object_cache_dir,
		 vid, idx);

	if (sys->object_cache_directio && !idx_has_vdi_bit(idx))
		flags |= O_DIRECT;

	fd = open(p, flags, def_fmode);
	if (fd < 0) {
		sd_eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	size = xpread(fd, buf, count, offset);

	if (size != count) {
		sd_eprintf("size %zu, count:%zu, offset %jd %m\n",
			   size, count, (intmax_t)offset);
		ret = SD_RES_EIO;
		goto out_close;
	}

out_close:
	close(fd);
out:
	return ret;
}

static int write_cache_object_noupdate(uint32_t vid, uint32_t idx, void *buf,
				       size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	char p[PATH_MAX];

	snprintf(p, sizeof(p), "%s/%06"PRIx32"/%08"PRIx32, object_cache_dir,
		 vid, idx);
	if (sys->object_cache_directio && !idx_has_vdi_bit(idx))
		flags |= O_DIRECT;

	fd = open(p, flags, def_fmode);
	if (fd < 0) {
		sd_eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	size = xpwrite(fd, buf, count, offset);

	if (size != count) {
		sd_eprintf("size %zu, count:%zu, offset %jd %m\n",
			   size, count, (intmax_t)offset);
		ret = SD_RES_EIO;
		goto out_close;
	}

out_close:
	close(fd);
out:
	return ret;
}

static int read_cache_object(struct object_cache_entry *entry, void *buf,
			     size_t count, off_t offset)
{
	uint32_t vid = entry->oc->vid, idx = entry_idx(entry);
	struct object_cache *oc = entry->oc;
	int ret;

	ret = read_cache_object_noupdate(vid, idx, buf, count, offset);

	if (ret == SD_RES_SUCCESS) {
		write_lock_cache(oc);
		list_move_tail(&entry->lru_list, &oc->lru_head);
		unlock_cache(oc);
	}
	return ret;
}

static int write_cache_object(struct object_cache_entry *entry, void *buf,
			      size_t count, off_t offset, bool create,
			      bool writeback)
{
	uint32_t vid = entry->oc->vid, idx = entry_idx(entry);
	uint64_t oid = idx_to_oid(vid, idx);
	struct object_cache *oc = entry->oc;
	struct sd_req hdr;
	int ret;

	write_lock_entry(entry);

	ret = write_cache_object_noupdate(vid, idx, buf, count, offset);
	if (ret != SD_RES_SUCCESS) {
		unlock_entry(entry);
		return ret;
	}
	write_lock_cache(oc);
	if (writeback) {
		entry->bmap |= calc_object_bmap(count, offset);
		if (list_empty(&entry->dirty_list))
			list_add_tail(&entry->dirty_list, &oc->dirty_head);
	}
	list_move_tail(&entry->lru_list, &oc->lru_head);
	unlock_cache(oc);

	unlock_entry(entry);

	if (writeback)
		goto out;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags =  SD_FLAG_CMD_WRITE;
	hdr.data_length = count;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS) {
		sd_eprintf("failed to write object %" PRIx64 ", %x\n",
			   oid, ret);
		return ret;
	}
out:
	return ret;
}

static int push_cache_object(uint32_t vid, uint32_t idx, uint64_t bmap,
			     bool create)
{
	struct sd_req hdr;
	void *buf;
	off_t offset;
	unsigned data_length;
	int ret = SD_RES_NO_MEM;
	uint64_t oid = idx_to_oid(vid, idx);
	int first_bit, last_bit;

	sd_dprintf("%"PRIx64", create %d\n", oid, create);

	if (!bmap) {
		sd_dprintf("WARN: nothing to flush\n");
		return SD_RES_SUCCESS;
	}

	first_bit = ffsll(bmap) - 1;
	last_bit = fls64(bmap) - 1;

	sd_dprintf("bmap:0x%"PRIx64", first_bit:%d, last_bit:%d\n",
		   bmap, first_bit, last_bit);
	offset = first_bit * CACHE_BLOCK_SIZE;
	data_length = (last_bit - first_bit + 1) * CACHE_BLOCK_SIZE;

	/*
	 * CACHE_BLOCK_SIZE may not be divisible by SD_INODE_SIZE,
	 * so (offset + data_length) could larger than SD_INODE_SIZE
	 */
	if (is_vdi_obj(oid) && (offset + data_length) > SD_INODE_SIZE)
		data_length = SD_INODE_SIZE - offset;

	buf = xvalloc(data_length);
	ret = read_cache_object_noupdate(vid, idx, buf, data_length, offset);
	if (ret != SD_RES_SUCCESS)
		goto out;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = data_length;
	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS)
		sd_eprintf("failed to push object %x\n", ret);
out:
	free(buf);
	return ret;
}

/*
 * The reclaim algorithm is similar to Linux kernel's page cache:
 *  - only tries to reclaim 'clean' object, which doesn't has any dirty updates,
 *    in a LRU list.
 *  - skip the object when it is in R/W operation.
 *  - skip the dirty object if it is not in push(writeback) phase.
 *  - wait on the dirty object if it is in push phase.
 */

/*
 * 90% is targeted for a large cache quota such as 200G, then we have 20G
 * buffer which is large enough to prevent cache overrun.
 */
#define HIGH_WATERMARK (sys->object_cache_size * 9 / 10)
static void do_reclaim_object(struct object_cache *oc)
{
	struct object_cache_entry *entry, *t;
	uint64_t oid;
	uint32_t cap;

	write_lock_cache(oc);
	list_for_each_entry_safe(entry, t, &oc->lru_head, lru_list) {
		oid = idx_to_oid(oc->vid, entry_idx(entry));
		if (entry_in_use(entry)) {
			sd_dprintf("%"PRIx64" is in use, skip...\n", oid);
			continue;
		}
		if (entry_is_dirty(entry)) {
			sd_dprintf("%"PRIx64" is dirty, skip...\n", oid);
			continue;
		}
		if (remove_cache_object(oc, entry_idx(entry)) != SD_RES_SUCCESS)
			continue;
		free_cache_entry(entry);
		cap = uatomic_sub_return(&gcache.capacity, CACHE_OBJECT_SIZE);
		sd_dprintf("%"PRIx64" reclaimed. capacity:%"PRId32"\n",
			   oid, cap);
		if (cap <= HIGH_WATERMARK)
			break;
	}
	unlock_cache(oc);
}

struct reclaim_work {
	struct work work;
	int delay;
};

static void do_reclaim(struct work *work)
{
	struct reclaim_work *rw = container_of(work, struct reclaim_work, work);
	struct object_cache *cache;
	struct hlist_node *node;
	int i, j;

	if (rw->delay)
		sleep(rw->delay);
	/* We choose a random victim to avoid reclaim the same one every time */
	j = random();
	for (i = 0; i < HASH_SIZE; i++) {
		int idx = (i + j) % HASH_SIZE;
		struct hlist_head *head = cache_hashtable + idx;

		pthread_rwlock_rdlock(&hashtable_lock[idx]);
		hlist_for_each_entry(cache, node, head, hash) {
			uint32_t cap;

			do_reclaim_object(cache);
			cap = uatomic_read(&gcache.capacity);
			if (cap <= HIGH_WATERMARK) {
				pthread_rwlock_unlock(&hashtable_lock[idx]);
				sd_dprintf("complete, capacity %"PRIu32"\n",
					   cap);
				return;
			}
		}
		pthread_rwlock_unlock(&hashtable_lock[idx]);
	}
	sd_dprintf("finished\n");
}

static void reclaim_done(struct work *work)
{
	struct reclaim_work *rw = container_of(work, struct reclaim_work, work);
	uatomic_set_false(&gcache.in_reclaim);
	free(rw);
}

static int create_dir_for(uint32_t vid)
{
	int ret = 0;
	char p[PATH_MAX];

	snprintf(p, sizeof(p), "%s/%06"PRIx32, object_cache_dir, vid);
	if (mkdir(p, def_dmode) < 0)
		if (errno != EEXIST) {
			sd_eprintf("%s, %m\n", p);
			ret = -1;
			goto err;
		}
err:
	return ret;
}

static struct object_cache *find_object_cache(uint32_t vid, bool create)
{
	int h = hash(vid);
	struct hlist_head *head = cache_hashtable + h;
	struct object_cache *cache = NULL;
	struct hlist_node *node;

	if (create)
		pthread_rwlock_wrlock(&hashtable_lock[h]);
	else
		pthread_rwlock_rdlock(&hashtable_lock[h]);

	if (hlist_empty(head))
		goto not_found;

	hlist_for_each_entry(cache, node, head, hash) {
		if (cache->vid == vid)
			goto out;
	}
not_found:
	if (create) {
		cache = xzalloc(sizeof(*cache));
		cache->vid = vid;
		cache->lru_tree = RB_ROOT;
		create_dir_for(vid);
		cache->push_efd = eventfd(0, 0);

		INIT_LIST_HEAD(&cache->dirty_head);
		INIT_LIST_HEAD(&cache->lru_head);

		pthread_rwlock_init(&cache->lock, NULL);
		hlist_add_head(&cache->hash, head);
	} else {
		cache = NULL;
	}
out:
	pthread_rwlock_unlock(&hashtable_lock[h]);
	return cache;
}

void object_cache_try_to_reclaim(int delay)
{
	struct reclaim_work *rw;

	if (!sys->object_cache_size)
		return;

	if (uatomic_read(&gcache.capacity) < HIGH_WATERMARK)
		return;

	if (!uatomic_set_true(&gcache.in_reclaim))
		/* the cache is already in reclaim, */
		return;

	rw = xzalloc(sizeof(struct reclaim_work));
	rw->delay = delay;
	rw->work.fn = do_reclaim;
	rw->work.done = reclaim_done;
	queue_work(sys->oc_reclaim_wqueue, &rw->work);
}

static inline struct object_cache_entry *
alloc_cache_entry(struct object_cache *oc, uint32_t idx)
{
	struct object_cache_entry *entry;

	entry = xzalloc(sizeof(*entry));
	entry->oc = oc;
	entry->idx = idx;
	pthread_rwlock_init(&entry->lock, NULL);
	INIT_LIST_HEAD(&entry->dirty_list);
	INIT_LIST_HEAD(&entry->lru_list);

	return entry;
}

static void add_to_lru_cache(struct object_cache *oc, uint32_t idx, bool create)
{
	struct object_cache_entry *entry = alloc_cache_entry(oc, idx);

	sd_dprintf("oid %"PRIx64" added\n", idx_to_oid(oc->vid, idx));

	write_lock_cache(oc);
	if (lru_tree_insert(&oc->lru_tree, entry))
		panic("the object already exist\n");
	uatomic_add(&gcache.capacity, CACHE_OBJECT_SIZE);
	list_add_tail(&entry->lru_list, &oc->lru_head);
	if (create) {
		/* Cache lock assure it is not raced with pusher */
		entry->bmap = UINT64_MAX;
		entry->idx |= CACHE_CREATE_BIT;
		list_add_tail(&entry->dirty_list, &oc->dirty_head);
	}
	unlock_cache(oc);
}

static inline int lookup_path(char *path)
{
	int ret = SD_RES_SUCCESS;

	if (access(path, R_OK | W_OK) < 0) {
		if (errno != ENOENT) {
			sd_dprintf("%m\n");
			ret = SD_RES_EIO;
		} else {
			ret = SD_RES_NO_CACHE;
		}
	}
	return ret;
}

static int object_cache_lookup(struct object_cache *oc, uint32_t idx,
			       bool create, bool writeback)
{
	int fd, ret, flags = def_open_flags;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%06"PRIx32"/%08"PRIx32,
		 object_cache_dir, oc->vid, idx);
	if (!create)
		return lookup_path(path);

	flags |= O_CREAT | O_TRUNC;
	fd = open(path, flags, def_fmode);
	if (fd < 0) {
		sd_dprintf("%s, %m\n", path);
		ret = SD_RES_EIO;
		goto out;
	}
	ret = prealloc(fd, get_objsize(idx_to_oid(oc->vid, idx)));
	if (ret < 0) {
		ret = SD_RES_EIO;
		goto out_close;
	}
	add_to_lru_cache(oc, idx, writeback);
	object_cache_try_to_reclaim(0);
out_close:
	close(fd);
out:
	return ret;
}

static int create_cache_object(struct object_cache *oc, uint32_t idx,
			       void *buffer, size_t buf_size, off_t offset,
			       size_t obj_size)
{
	int flags = def_open_flags | O_CREAT | O_EXCL, fd;
	int ret = SD_RES_OID_EXIST;
	char path[PATH_MAX], tmp_path[PATH_MAX];

	snprintf(tmp_path, sizeof(tmp_path), "%s/%06"PRIx32"/%08"PRIx32".tmp",
		object_cache_dir, oc->vid, idx);
	fd = open(tmp_path, flags, def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			sd_dprintf("%08"PRIx32" already created\n", idx);
			goto out;
		}
		sd_dprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	/* We need to extend it if the buffer is trimmed */
	if (offset != 0 || buf_size != obj_size) {
		ret = prealloc(fd, obj_size);
		if (ret < 0) {
			ret = SD_RES_EIO;
			sd_eprintf("%m\n");
			goto out_close;
		}
	}

	ret = xpwrite(fd, buffer, buf_size, offset);
	if (ret != buf_size) {
		ret = SD_RES_EIO;
		sd_eprintf("failed, vid %"PRIx32", idx %"PRIx32"\n",
			   oc->vid, idx);
		goto out_close;
	}
	/* This is intended to take care of partial write due to crash */
	snprintf(path, sizeof(path), "%s/%06"PRIx32"/%08"PRIx32,
		 object_cache_dir, oc->vid, idx);
	ret = link(tmp_path, path);
	if (ret < 0) {
		if (errno == EEXIST) {
			ret = SD_RES_OID_EXIST;
			goto out_close;
		}
		sd_dprintf("failed to link %s to %s: %m\n", tmp_path, path);
		ret = err_to_sderr(idx_to_oid(oc->vid, idx), errno);
		goto out_close;
	}
	ret = SD_RES_SUCCESS;
	sd_dprintf("%08"PRIx32" size %zu\n", idx, obj_size);
out_close:
	close(fd);
	unlink(tmp_path);
out:
	return ret;
}

/* Fetch the object, cache it in the clean state */
static int object_cache_pull(struct object_cache *oc, uint32_t idx)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret = SD_RES_NO_MEM;
	uint64_t oid = idx_to_oid(oc->vid, idx);
	uint32_t data_length = get_objsize(oid);
	void *buf;

	buf = xvalloc(data_length);
	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = data_length;
	hdr.obj.oid = oid;
	hdr.obj.offset = 0;
	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS)
		goto err;

	sd_dprintf("oid %"PRIx64" pulled successfully\n", oid);
	ret = create_cache_object(oc, idx, buf, rsp->data_length,
				  rsp->obj.offset, data_length);
	/*
	 * We try to delay reclaim objects to avoid object ping-pong
	 * because the pulled object is clean and likely to be reclaimed
	 * in a cache over high watermark. We can't simply pass without
	 * waking up reclaimer because the cache is easy to be filled
	 * full with a read storm.
	 */
	switch (ret) {
	case SD_RES_SUCCESS:
		add_to_lru_cache(oc, idx, false);
		object_cache_try_to_reclaim(1);
		break;
	case SD_RES_OID_EXIST:
		ret = SD_RES_SUCCESS;
		break;
	default:
		break;
	}
err:
	free(buf);
	return ret;
}

struct push_work {
	struct work work;
	struct object_cache_entry *entry;
};

static void do_push_object(struct work *work)
{
	struct push_work *pw = container_of(work, struct push_work, work);
	struct object_cache_entry *entry = pw->entry;
	struct object_cache *oc = entry->oc;
	uint64_t oid = idx_to_oid(oc->vid, entry_idx(entry));

	sd_dprintf("%"PRIx64"\n", oid);

	read_lock_entry(entry);
	if (push_cache_object(oc->vid, entry_idx(entry), entry->bmap,
			      !!(entry->idx & CACHE_CREATE_BIT))
	    != SD_RES_SUCCESS)
		panic("push failed but should never fail\n");
	if (uatomic_sub_return(&oc->push_count, 1) == 0)
		eventfd_write(oc->push_efd, 1);
	entry->idx &= ~CACHE_CREATE_BIT;
	entry->bmap = 0;
	unlock_entry(entry);

	sd_dprintf("%"PRIx64" done\n", oid);
	put_cache_entry(entry);
}

static void push_object_done(struct work *work)
{
	struct push_work *pw = container_of(work, struct push_work, work);
	free(pw);
}

/*
 * Push back all the dirty objects before the FLUSH request to sheep replicated
 * storage synchronously.
 *
 * 1. Don't grab cache lock tight so we can serve RW requests while pushing.
 *    It is okay for allow subsequent RW after FLUSH because we only need to
 *    garantee the dirty objects before FLUSH to be pushed.
 * 2. Use threaded AIO to boost push performance, such as fsync(2) from VM.
 */
static int object_cache_push(struct object_cache *oc)
{
	struct object_cache_entry *entry, *t;
	eventfd_t value;

	write_lock_cache(oc);
	if (list_empty(&oc->dirty_head)) {
		unlock_cache(oc);
		return SD_RES_SUCCESS;
	}
	list_for_each_entry_safe(entry, t, &oc->dirty_head, dirty_list) {
		struct push_work *pw;

		get_cache_entry(entry);
		uatomic_inc(&oc->push_count);
		pw = xzalloc(sizeof(struct push_work));
		pw->work.fn = do_push_object;
		pw->work.done = push_object_done;
		pw->entry = entry;
		queue_work(sys->oc_push_wqueue, &pw->work);
		list_del_init(&entry->dirty_list);
	}
	unlock_cache(oc);
reread:
	if (eventfd_read(oc->push_efd, &value) < 0) {
		sd_eprintf("eventfd read failed, %m\n");
		goto reread;
	}
	sd_dprintf("%"PRIx32" completed\n", oc->vid);
	return SD_RES_SUCCESS;
}

bool object_is_cached(uint64_t oid)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, false);
	if (!cache)
		return false;

	return (object_cache_lookup(cache, idx, 0, false) == SD_RES_SUCCESS);
}

void object_cache_delete(uint32_t vid)
{
	struct object_cache *cache;
	int h = hash(vid);
	struct object_cache_entry *entry, *t;
	char path[PATH_MAX];

	cache = find_object_cache(vid, false);
	if (!cache)
		return;

	/* Firstly we free memeory */
	pthread_rwlock_wrlock(&hashtable_lock[h]);
	hlist_del(&cache->hash);
	pthread_rwlock_unlock(&hashtable_lock[h]);

	write_lock_cache(cache);
	list_for_each_entry_safe(entry, t, &cache->lru_head, lru_list) {
		free_cache_entry(entry);
		uatomic_sub(&gcache.capacity, CACHE_OBJECT_SIZE);
	}
	unlock_cache(cache);
	pthread_rwlock_destroy(&cache->lock);
	close(cache->push_efd);
	free(cache);

	/* Then we free disk */
	snprintf(path, sizeof(path), "%s/%06"PRIx32, object_cache_dir, vid);
	rmdir_r(path);
}

static struct object_cache_entry *
get_cache_entry_from(struct object_cache *cache, uint32_t idx)
{
	struct object_cache_entry *entry;

	read_lock_cache(cache);
	entry = lru_tree_search(&cache->lru_tree, idx);
	if (!entry) {
		/* The cache entry may be reclaimed, so try again. */
		unlock_cache(cache);
		return NULL;
	}
	get_cache_entry(entry);
	unlock_cache(cache);
	return entry;
}

static int object_cache_flush_and_delete(struct object_cache *oc)
{
	DIR *dir;
	struct dirent *d;
	uint32_t vid = oc->vid;
	uint32_t idx;
	uint64_t all = UINT64_MAX;
	int ret = 0;
	char p[PATH_MAX];

	sd_dprintf("%"PRIx32"\n", vid);
	snprintf(p, sizeof(p), "%s/%06"PRIx32, object_cache_dir, vid);
	dir = opendir(p);
	if (!dir) {
		sd_dprintf("%m\n");
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		if (strcmp(d->d_name + 8, ".tmp") == 0) {
			sd_dprintf("try to del %s\n", d->d_name);
			if (unlinkat(dirfd(dir), d->d_name, 0) < 0)
				sd_eprintf("%m\n");
			continue;
		}

		idx = strtoul(d->d_name, NULL, 16);
		if (idx == ULLONG_MAX)
			continue;
		if (push_cache_object(vid, idx, all, true) !=
		    SD_RES_SUCCESS) {
			sd_dprintf("failed to push %"PRIx64"\n",
				   idx_to_oid(vid, idx));
			ret = -1;
			goto out_close_dir;
		}
	}

	object_cache_delete(vid);
out_close_dir:
	closedir(dir);
out:
	return ret;
}

bool bypass_object_cache(const struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	if (req->rq.flags & SD_FLAG_CMD_DIRECT) {
		uint32_t vid = oid_to_vid(oid);
		struct object_cache *cache;

		cache = find_object_cache(vid, false);
		if (!cache)
			return true;
		if (req->rq.flags & SD_FLAG_CMD_WRITE) {
			object_cache_flush_and_delete(cache);
			return true;
		} else  {
			/* For read requet, we can read cache if any */
			uint32_t idx = object_cache_oid_to_idx(oid);

			if (object_cache_lookup(cache, idx, false, false) == 0)
				return false;
			else
				return true;
		}
	}

	/*
	 * For vmstate && vdi_attr object, we don't do caching
	 */
	if (is_vmstate_obj(oid) || is_vdi_attr_obj(oid) ||
	    req->rq.flags & SD_FLAG_CMD_COW)
		return true;
	return false;
}

int object_cache_handle_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	uint64_t oid = req->rq.obj.oid;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret;
	bool create = false;

	sd_dprintf("%08"PRIx32", len %"PRIu32", off %"PRIu64"\n", idx,
		   hdr->data_length, hdr->obj.offset);

	cache = find_object_cache(vid, true);

	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		create = true;
retry:
	ret = object_cache_lookup(cache, idx, create,
				  hdr->flags & SD_FLAG_CMD_CACHE);
	switch (ret) {
	case SD_RES_NO_CACHE:
		ret = object_cache_pull(cache, idx);
		if (ret != SD_RES_SUCCESS)
			return ret;
		break;
	case SD_RES_EIO:
		return ret;
	}

	entry = get_cache_entry_from(cache, idx);
	if (!entry) {
		sd_dprintf("retry oid %"PRIx64"\n", oid);
		/*
		 * For the case that object exists but isn't added to object
		 * list yet, we call pthread_yield() to expect other thread can
		 * add object to list ASAP.
		 */
		pthread_yield();
		goto retry;
	}

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		ret = write_cache_object(entry, req->data, hdr->data_length,
					 hdr->obj.offset, create,
					 hdr->flags & SD_FLAG_CMD_CACHE);
		if (ret != SD_RES_SUCCESS)
			goto err;
	} else {
		ret = read_cache_object(entry, req->data, hdr->data_length,
					hdr->obj.offset);
		if (ret != SD_RES_SUCCESS)
			goto err;
		req->rp.data_length = hdr->data_length;
	}
err:
	put_cache_entry(entry);
	return ret;
}

int object_cache_write(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, uint16_t flags, bool create)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret;

	sd_dprintf("%" PRIx64 "\n", oid);
	cache = find_object_cache(vid, false);
	entry = get_cache_entry_from(cache, idx);
	if (!entry) {
		sd_dprintf("%" PRIx64 " doesn't exist\n", oid);
		return SD_RES_NO_CACHE;
	}

	ret = write_cache_object(entry, data, datalen, offset, create, false);
	put_cache_entry(entry);
	return ret;
}

int object_cache_read(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret;

	sd_dprintf("%" PRIx64 "\n", oid);
	cache = find_object_cache(vid, false);
	entry = get_cache_entry_from(cache, idx);
	if (!entry) {
		sd_dprintf("%" PRIx64 " doesn't exist\n", oid);
		return SD_RES_NO_CACHE;
	}

	ret = read_cache_object(entry, data, datalen, offset);
	put_cache_entry(entry);
	return ret;
}

int object_cache_flush_vdi(uint32_t vid)
{
	struct object_cache *cache;

	cache = find_object_cache(vid, false);
	if (!cache) {
		sd_dprintf("%"PRIx32" not found\n", vid);
		return SD_RES_SUCCESS;
	}

	return object_cache_push(cache);
}

int object_cache_flush_and_del(const struct request *req)
{
	uint32_t vid = oid_to_vid(req->rq.obj.oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, false);

	if (cache && object_cache_flush_and_delete(cache) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int load_cache_object(struct object_cache *cache)
{
	DIR *dir;
	struct dirent *d;
	uint32_t idx;
	char path[PATH_MAX];
	int ret = 0;

	snprintf(path, sizeof(path), "%s/%06"PRIx32, object_cache_dir,
		 cache->vid);
	dir = opendir(path);
	if (!dir) {
		sd_dprintf("%m\n");
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;

		if (strcmp(d->d_name + 8, ".tmp") == 0) {
			sd_dprintf("try to del %s\n", d->d_name);
			if (unlinkat(dirfd(dir), d->d_name, 0) < 0)
				sd_eprintf("%m\n");
			continue;
		}

		idx = strtoul(d->d_name, NULL, 16);
		if (idx == ULLONG_MAX)
			continue;

		/*
		 * We don't know VM's cache type after restarting, so we assume
		 * that it is writeback and mark all the objects diry to avoid
		 * false reclaim. Donot try to reclaim at loading phase becaue
		 * cluster isn't fully working.
		 */
		add_to_lru_cache(cache, idx, true);
		sd_dprintf("%"PRIx64"\n", idx_to_oid(cache->vid, idx));
	}

	closedir(dir);
out:
	return ret;
}

static int load_cache(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t vid;
	char path[PATH_MAX];
	int ret = 0;

	snprintf(path, sizeof(path), "%s", object_cache_dir);
	dir = opendir(path);
	if (!dir) {
		sd_dprintf("%m\n");
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		vid = strtoul(d->d_name, NULL, 16);
		if (vid == ULLONG_MAX)
			continue;

		load_cache_object(find_object_cache(vid, true));
	}

	closedir(dir);
out:
	return ret;
}

int object_cache_init(const char *p)
{
	int ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	if (mkdir(buf.buf, def_dmode) < 0) {
		if (errno != EEXIST) {
			sd_eprintf("%s %m\n", buf.buf);
			ret = -1;
			goto err;
		}
	}
	strbuf_addstr(&buf, "/cache");
	if (mkdir(buf.buf, def_dmode) < 0) {
		if (errno != EEXIST) {
			sd_eprintf("%s %m\n", buf.buf);
			ret = -1;
			goto err;
		}
	}
	strbuf_copyout(&buf, object_cache_dir, sizeof(object_cache_dir));

	uatomic_set(&gcache.capacity, 0);
	uatomic_set_false(&gcache.in_reclaim);

	ret = load_cache();
err:
	strbuf_release(&buf);
	return ret;
}

void object_cache_format(void)
{
	struct object_cache *cache;
	struct hlist_node *node, *t;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		struct hlist_head *head = cache_hashtable + i;
		hlist_for_each_entry_safe(cache, node, t, head, hash) {
			object_cache_delete(cache->vid);
		}
	}
	uatomic_set(&gcache.capacity, 0);
}
