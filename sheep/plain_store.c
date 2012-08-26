/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#include "sheep_priv.h"

static char stale_dir[PATH_MAX];

static int get_open_flags(uint64_t oid, bool create)
{
	int flags = O_DSYNC | O_RDWR;

	if (is_data_obj(oid))
		flags |= O_DIRECT;

	if (create)
		flags |= O_CREAT | O_TRUNC;

	return flags;
}

static int get_obj_path(uint64_t oid, char *path)
{
	return sprintf(path, "%s%016" PRIx64, obj_path, oid);
}

static int get_tmp_obj_path(uint64_t oid, char *path)
{
	return sprintf(path, "%s%016"PRIx64".tmp", obj_path, oid);
}

static int get_stale_obj_path(uint64_t oid, uint32_t epoch, char *path)
{
	return sprintf(path, "%s/%016"PRIx64".%d", stale_dir, oid, epoch);
}

int for_each_object_in_wd(int (*func)(uint64_t oid, void *arg), void *arg)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;
	int ret = SD_RES_SUCCESS;
	char path[PATH_MAX];

	dir = opendir(obj_path);
	if (!dir)
		return SD_RES_EIO;

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;

		/* remove object if it is temporary one */
		if (strlen(d->d_name) == 20 &&
		    strcmp(d->d_name + 16, ".tmp") == 0) {
			get_tmp_obj_path(oid, path);
			dprintf("remove tmp object %s\n", path);
			unlink(path);
			continue;
		}

		ret = func(oid, arg);
		if (ret != SD_RES_SUCCESS)
			break;
	}
	closedir(dir);
	return ret;
}

int default_exist(uint64_t oid)
{
	char path[PATH_MAX];

	get_obj_path(oid, path);
	if (access(path, R_OK | W_OK) < 0) {
		if (errno != ENOENT)
			eprintf("%m\n");
		return 0;
	}

	return 1;
}

static int err_to_sderr(uint64_t oid, int err)
{
	struct stat s;

	if (err != ENOENT) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	if (stat(obj_path, &s) < 0) {
		eprintf("corrupted\n");
		return SD_RES_EIO;
	}

	dprintf("object %016" PRIx64 " not found locally\n", oid);
	return SD_RES_NO_OBJ;
}

int default_write(uint64_t oid, struct siocb *iocb, int create)
{
	int flags = get_open_flags(oid, create), fd, ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	ssize_t size;

	if (iocb->epoch < sys_epoch()) {
		dprintf("%"PRIu32" sys %"PRIu32"\n", iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}

	get_obj_path(oid, path);
	fd = open(path, flags, def_fmode);
	if (fd < 0)
		return err_to_sderr(oid, errno);

	if (create && !(iocb->flags & SD_FLAG_CMD_COW)) {
		ret = prealloc(fd, get_objsize(oid));
		if (ret != SD_RES_SUCCESS)
			goto out;
	}
	size = xpwrite(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}
out:
	close(fd);
	return ret;
}

int default_cleanup(void)
{
	rmdir_r(stale_dir);
	if (mkdir(stale_dir, 0755) < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

static int init_vdi_copy_number(uint64_t oid)
{
	char path[PATH_MAX];
	int fd, flags = get_open_flags(oid, false), ret;
	struct sheepdog_inode inode;

	snprintf(path, sizeof(path), "%s%016" PRIx64, obj_path, oid);

	fd = open(path, flags);
	if (fd < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	ret = xpread(fd, (void *)&inode, SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_INODE_HEADER_SIZE) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	add_vdi_copy_number(oid_to_vid(oid), inode.nr_copies);

	return SD_RES_SUCCESS;
}

static int init_objlist_and_vdi_bitmap(uint64_t oid, void *arg)
{
	int ret;
	objlist_cache_insert(oid);

	if (is_vdi_obj(oid)) {
		vprintf(SDOG_DEBUG, "found the VDI object %" PRIx64 "\n", oid);
		set_bit(oid_to_vid(oid), sys->vdi_inuse);
		ret = init_vdi_copy_number(oid);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return SD_RES_SUCCESS;
}

int default_init(char *p)
{
	dprintf("use plain store driver\n");

	/* create a stale directory */
	snprintf(stale_dir, sizeof(stale_dir), "%s/.stale", p);
	if (mkdir(stale_dir, 0755) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			return SD_RES_EIO;
		}
	}

	return for_each_object_in_wd(init_objlist_and_vdi_bitmap, NULL);
}

static int default_read_from_path(uint64_t oid, char *path,
				       struct siocb *iocb)
{
	int flags = get_open_flags(oid, false), fd, ret = SD_RES_SUCCESS;
	ssize_t size;

	fd = open(path, flags);

	if (fd < 0)
		return err_to_sderr(oid, errno);

	size = xpread(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		ret = SD_RES_EIO;
		goto out;
	}
out:
	close(fd);

	return ret;
}

int default_read(uint64_t oid, struct siocb *iocb)
{
	int ret;
	char path[PATH_MAX];
	uint32_t epoch = sys_epoch();

	get_obj_path(oid, path);
	ret = default_read_from_path(oid, path, iocb);

	/* If the request is againt the older epoch, try to read from
	 * the stale directory */
	while (ret == SD_RES_NO_OBJ && iocb->epoch < epoch) {
		epoch--;
		get_stale_obj_path(oid, epoch, path);
		ret = default_read_from_path(oid, path, iocb);
	}

	return ret;
}

int default_atomic_put(uint64_t oid, struct siocb *iocb)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	int flags = get_open_flags(oid, true);
	int ret = SD_RES_EIO, fd;
	uint32_t len = iocb->length;

	get_obj_path(oid, path);
	get_tmp_obj_path(oid, tmp_path);

	fd = open(tmp_path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s: %m\n", tmp_path);
		return SD_RES_EIO;
	}

	ret = xwrite(fd, iocb->buf, len);
	if (ret != len) {
		eprintf("failed to write object. %m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	ret = rename(tmp_path, path);
	if (ret < 0) {
		eprintf("failed to rename %s to %s: %m\n", tmp_path, path);
		ret = SD_RES_EIO;
		goto out;
	}
	dprintf("%"PRIx64"\n", oid);
	ret = SD_RES_SUCCESS;
out:
	close(fd);
	return ret;
}

int default_link(uint64_t oid, struct siocb *iocb, uint32_t tgt_epoch)
{
	char path[PATH_MAX], stale_path[PATH_MAX];

	dprintf("try link %"PRIx64" from snapshot with epoch %d\n", oid,
		tgt_epoch);

	get_obj_path(oid, path);
	get_stale_obj_path(oid, tgt_epoch, stale_path);

	if (rename(stale_path, path) < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

static bool oid_stale(uint64_t oid)
{
	int i, nr_copies;
	struct vnode_info *vinfo;
	struct sd_vnode *v;
	bool ret = true;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];

	vinfo = get_vnode_info();
	nr_copies = get_obj_copy_number(oid, vinfo->nr_zones);
	if (!nr_copies) {
		ret = false;
		goto out;
	}

	oid_to_vnodes(vinfo->vnodes, vinfo->nr_vnodes, oid,
		      nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = false;
			break;
		}
	}
out:
	put_vnode_info(vinfo);
	return ret;
}

static int move_object_to_stale_dir(uint64_t oid, void *arg)
{
	char path[PATH_MAX], stale_path[PATH_MAX];
	uint32_t tgt_epoch = *(int *)arg;

	get_obj_path(oid, path);
	get_stale_obj_path(oid, tgt_epoch, stale_path);

	if (rename(path, stale_path) < 0) {
		eprintf("%s:%m\n", path);
		return SD_RES_EIO;
	}

	dprintf("moved object %"PRIx64"\n", oid);
	return SD_RES_SUCCESS;
}

static int check_stale_objects(uint64_t oid, void *arg)
{
	if (oid_stale(oid))
		return move_object_to_stale_dir(oid, arg);

	return SD_RES_SUCCESS;
}

int default_end_recover(uint32_t old_epoch, struct vnode_info *old_vnode_info)
{
	if (old_epoch == 0)
		return SD_RES_SUCCESS;

	return for_each_object_in_wd(check_stale_objects, &old_epoch);
}

int default_format(char *name)
{
	unsigned ret;

	dprintf("try get a clean store\n");
	ret = rmdir_r(obj_path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", obj_path, strerror(-ret));
		return SD_RES_EIO;
	}
	if (mkdir(obj_path, def_dmode) < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	if (set_cluster_store(name) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

int default_remove_object(uint64_t oid)
{
	char path[PATH_MAX];

	get_obj_path(oid, path);

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return SD_RES_NO_OBJ;

		eprintf("%m\n");
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int default_purge_obj(void)
{
	uint32_t tgt_epoch = get_latest_epoch();

	return for_each_object_in_wd(move_object_to_stale_dir, &tgt_epoch);
}

struct store_driver plain_store = {
	.name = "plain",
	.init = default_init,
	.exist = default_exist,
	.write = default_write,
	.read = default_read,
	.link = default_link,
	.atomic_put = default_atomic_put,
	.end_recover = default_end_recover,
	.cleanup = default_cleanup,
	.format = default_format,
	.remove_object = default_remove_object,
	.purge_obj = default_purge_obj,
};

add_store_driver(plain_store);
