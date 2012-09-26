/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "collie.h"
#include "treeview.h"

static struct sd_option vdi_options[] = {
	{'P', "prealloc", 0, "preallocate all the data objects"},
	{'i', "index", 1, "specify the index of data objects"},
	{'s', "snapshot", 1, "specify a snapshot id or tag name"},
	{'x', "exclusive", 0, "write in an exclusive mode"},
	{'d', "delete", 0, "delete a key"},
	{'w', "writeback", 0, "use writeback mode"},
	{'c', "copies", 1, "specify the data redundancy (number of copies)"},
	{'F', "from", 1, "create a differential backup from the snapshot"},
	{ 0, NULL, 0, NULL },
};

struct vdi_cmd_data {
	unsigned int index;
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	int exclusive;
	int delete;
	int prealloc;
	int nr_copies;
	bool writeback;
	int from_snapshot_id;
	char from_snapshot_tag[SD_MAX_VDI_TAG_LEN];
} vdi_cmd_data = { ~0, };

struct get_vdi_info {
	char *name;
	char *tag;
	uint32_t vid;
	uint32_t snapid;
};

static int parse_option_size(const char *value, uint64_t *ret)
{
	char *postfix;
	double sizef;

	sizef = strtod(value, &postfix);
	switch (*postfix) {
	case 'T':
		sizef *= 1024;
	case 'G':
		sizef *= 1024;
	case 'M':
		sizef *= 1024;
	case 'K':
	case 'k':
		sizef *= 1024;
	case 'b':
	case '\0':
		*ret = (uint64_t) sizef;
		break;
	default:
		fprintf(stderr, "Invalid size '%s'\n", value);
		fprintf(stderr, "You may use k, M, G or T suffixes for "
			"kilobytes, megabytes, gigabytes and terabytes.\n");
		return -1;
	}

	return 0;
}

static void print_vdi_list(uint32_t vid, char *name, char *tag, uint32_t snapid,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	int idx, is_clone = 0;
	uint64_t my_objs, cow_objs;
	char vdi_size_str[16], my_objs_str[16], cow_objs_str[16];
	time_t ti;
	struct tm tm;
	char dbuf[128];
	struct get_vdi_info *info = data;

	if (info && strcmp(name, info->name) != 0)
		return;

	ti = i->create_time >> 32;
	if (raw_output) {
		snprintf(dbuf, sizeof(dbuf), "%" PRIu64, (uint64_t) ti);
	} else {
		localtime_r(&ti, &tm);
		strftime(dbuf, sizeof(dbuf),
			 "%Y-%m-%d %H:%M", &tm);
	}

	my_objs = 0;
	cow_objs = 0;
	for (idx = 0; idx < MAX_DATA_OBJS; idx++) {
		if (!i->data_vdi_id[idx])
			continue;
		if (is_data_obj_writeable(i, idx))
			my_objs++;
		else
			cow_objs++;
	}

	size_to_str(i->vdi_size, vdi_size_str, sizeof(vdi_size_str));
	size_to_str(my_objs * SD_DATA_OBJ_SIZE, my_objs_str, sizeof(my_objs_str));
	size_to_str(cow_objs * SD_DATA_OBJ_SIZE, cow_objs_str, sizeof(cow_objs_str));

	if (i->snap_id == 1 && i->parent_vdi_id != 0)
		is_clone = 1;

	if (raw_output) {
		printf("%c ", is_current(i) ? (is_clone ? 'c' : '=') : 's');
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %s %s %" PRIx32 " %d %s\n", snapid,
				vdi_size_str, my_objs_str, cow_objs_str, dbuf, vid,
				i->nr_copies, i->tag);
	} else {
		printf("%c %-8s %5d %7s %7s %7s %s  %7" PRIx32 " %5d %13s\n",
				is_current(i) ? (is_clone ? 'c' : ' ') : 's',
				name, snapid, vdi_size_str, my_objs_str, cow_objs_str,
				dbuf, vid, i->nr_copies, i->tag);
	}
}

static void print_vdi_tree(uint32_t vid, char *name, char * tag, uint32_t snapid,
			   uint32_t flags, struct sheepdog_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char buf[128];

	if (is_current(i))
		strcpy(buf, "(you are here)");
	else {
		ti = i->create_time >> 32;
		localtime_r(&ti, &tm);

		strftime(buf, sizeof(buf),
			 "[%Y-%m-%d %H:%M]", &tm);
	}

	add_vdi_tree(name, buf, vid, i->parent_vdi_id, highlight && is_current(i));
}

static void print_vdi_graph(uint32_t vid, char *name, char * tag, uint32_t snapid,
			    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char dbuf[128], tbuf[128], size_str[128];

	ti = i->create_time >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);
	size_to_str(i->vdi_size, size_str, sizeof(size_str));

	printf("  \"%x\" -> \"%x\";\n", i->parent_vdi_id, vid);
	printf("  \"%x\" [\n"
	       "    group = \"%s\",\n"
	       "    label = \"",
	       vid, name);
	printf("Name: %10s\\n"
	       "Tag:  %10x\\n"
	       "Size: %10s\\n"
	       "Date: %10s\\n"
	       "Time: %10s",
	       name, snapid, size_str, dbuf, tbuf);

	if (is_current(i))
		printf("\",\n    color=\"red\"\n  ];\n\n");
	else
		printf("\"\n  ];\n\n");

}

static void get_oid(uint32_t vid, char *name, char *tag, uint32_t snapid,
		    uint32_t flags, struct sheepdog_inode *i, void *data)
{
	struct get_vdi_info *info = data;

	if (info->name) {
		if (info->tag && info->tag[0]) {
			if (!strcmp(name, info->name) && !strcmp(tag, info->tag))
				info->vid = vid;
		} else if (info->snapid) {
			if (!strcmp(name, info->name) && snapid == info->snapid)
				info->vid = vid;
		} else {
			if (!strcmp(name, info->name))
				info->vid = vid;
		}
	}
}

typedef int (*obj_parser_func_t)(char *sheep, uint64_t oid,
				  struct sd_rsp *rsp, char *buf, void *data);

static int do_print_obj(char *sheep, uint64_t oid, struct sd_rsp *rsp,
			 char *buf, void *data)
{
	switch (rsp->result) {
	case SD_RES_SUCCESS:
		printf("%s has the object (should be %d copies)\n",
		       sheep, rsp->obj.copies);
		break;
	case SD_RES_NO_OBJ:
		printf("%s doesn't have the object\n", sheep);
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		fprintf(stderr, "The node list has changed: please try again\n");
		break;
	default:
		fprintf(stderr, "%s: hit an unexpected error (%d)\n",
		       sheep, rsp->result);
		break;
	}

	return 0;
}

struct get_data_oid_info {
	int success;
	uint64_t data_oid;
	unsigned idx;
};

static int get_data_oid(char *sheep, uint64_t oid, struct sd_rsp *rsp,
			 char *buf, void *data)
{
	struct get_data_oid_info *info = data;
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		if (info->success)
			break;
		info->success = 1;
		if (inode->data_vdi_id[info->idx]) {
			info->data_oid = vid_to_data_oid(inode->data_vdi_id[info->idx], info->idx);
			return 1;
		}
		break;
	case SD_RES_NO_OBJ:
		break;
	case SD_RES_OLD_NODE_VER:
	case SD_RES_NEW_NODE_VER:
		fprintf(stderr, "The node list has changed: please try again\n");
		break;
	default:
		fprintf(stderr, "%s: hit an unexpected error (%d)\n",
		       sheep, rsp->result);
		break;
	}

	return 0;
}

static void parse_objs(uint64_t oid, obj_parser_func_t func, void *data, unsigned size)
{
	char name[128];
	int i, fd, ret, cb_ret;
	char *buf;

	buf = zalloc(size);
	if (!buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		return;
	}

	for (i = 0; i < sd_nodes_nr; i++) {
		unsigned wlen = 0, rlen = size;
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		addr_to_str(name, sizeof(name), sd_nodes[i].nid.addr, 0);

		fd = connect_to(name, sd_nodes[i].nid.port);
		if (fd < 0)
			break;

		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.data_length = rlen;
		hdr.flags = 0;
		hdr.epoch = sd_epoch;

		hdr.obj.oid = oid;

		ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
		close(fd);

		sprintf(name + strlen(name), ":%d", sd_nodes[i].nid.port);

		if (ret)
			fprintf(stderr, "Failed to connect to %s\n", name);
		else {
			cb_ret = func(name, oid, rsp, buf, data);
			if (cb_ret)
				break;
		}
	}

	free(buf);
}


static int vdi_list(int argc, char **argv)
{
	char *vdiname = argv[optind];

	if (!raw_output)
		printf("  Name        Id    Size    Used  Shared    Creation time   VDI id  Copies  Tag\n");

	if (vdiname) {
		struct get_vdi_info info;
		memset(&info, 0, sizeof(info));
		info.name = vdiname;
		if (parse_vdi(print_vdi_list, SD_INODE_SIZE, &info) < 0)
			return EXIT_SYSFAIL;
		return EXIT_SUCCESS;
	} else {
		if (parse_vdi(print_vdi_list, SD_INODE_SIZE, NULL) < 0)
			return EXIT_SYSFAIL;
		return EXIT_SUCCESS;
	}
}

static int vdi_tree(int argc, char **argv)
{
	init_tree();
	if (parse_vdi(print_vdi_tree, SD_INODE_HEADER_SIZE, NULL) < 0)
		return EXIT_SYSFAIL;
	dump_tree();

	return EXIT_SUCCESS;
}

static int vdi_graph(int argc, char **argv)
{
	/* print a header */
	printf("digraph G {\n");
	printf("  node [shape = \"box\", fontname = \"Courier\"];\n\n");
	printf("  \"0\" [shape = \"ellipse\", label = \"root\"];\n\n");

	if (parse_vdi(print_vdi_graph, SD_INODE_HEADER_SIZE, NULL) < 0)
		return EXIT_SYSFAIL;

	/* print a footer */
	printf("}\n");

	return EXIT_SUCCESS;
}

static int find_vdi_name(char *vdiname, uint32_t snapid, const char *tag,
			 uint32_t *vid, int for_snapshot)
{
	int ret, fd;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned int wlen, rlen = 0;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return -1;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, vdiname, SD_MAX_VDI_LEN);
	strncpy(buf + SD_MAX_VDI_LEN, tag, SD_MAX_VDI_TAG_LEN);

	if (for_snapshot)
		sd_init_req(&hdr, SD_OP_GET_VDI_INFO);
	else
		sd_init_req(&hdr, SD_OP_LOCK_VDI);
	wlen = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.data_length = wlen;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.vdi.snapid = snapid;

	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
	if (ret) {
		ret = -1;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Cannot get VDI info for %s %d %s: %s\n",
			vdiname, snapid, tag, sd_strerror(rsp->result));
		ret = -1;
		goto out;
	}
	*vid = rsp->vdi.vdi_id;

	ret = 0;
out:
	close(fd);
	return ret;
}

static int read_vdi_obj(char *vdiname, int snapid, const char *tag,
			uint32_t *pvid, struct sheepdog_inode *inode,
			size_t size)
{
	int ret;
	uint32_t vid;

	ret = find_vdi_name(vdiname, snapid, tag, &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to open VDI %s\n", vdiname);
		return EXIT_FAILURE;
	}

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, size, 0, true);
	if (ret != SD_RES_SUCCESS) {
		if (snapid) {
			fprintf(stderr, "Failed to read a snapshot %s:%d\n",
				vdiname, snapid);
		} else if (tag && tag[0]) {
			fprintf(stderr, "Failed to read a snapshot %s:%s\n",
				vdiname, tag);
		} else {
			fprintf(stderr, "Failed to read a vdi %s\n", vdiname);
		}
		return EXIT_FAILURE;
	}

	if (pvid)
		*pvid = vid;

	return EXIT_SUCCESS;
}

static int do_vdi_create(char *vdiname, int64_t vdi_size, uint32_t base_vid,
			 uint32_t *vdi_id, int snapshot, int nr_copies)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned int wlen, rlen = 0;
	char buf[SD_MAX_VDI_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	memset(buf, 0, sizeof(buf));
	strncpy(buf, vdiname, SD_MAX_VDI_LEN);

	wlen = SD_MAX_VDI_LEN;

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;

	hdr.vdi.base_vdi_id = base_vid;
	hdr.vdi.snapid = snapshot;
	hdr.vdi.vdi_size = roundup(vdi_size, 512);
	hdr.vdi.copies = nr_copies;

	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);

	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to send a request\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to create VDI %s: %s\n", vdiname,
				sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;

	return EXIT_SUCCESS;
}

static int vdi_create(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint64_t size;
	uint32_t vid;
	uint64_t oid;
	int idx, max_idx, ret;
	struct sheepdog_inode *inode = NULL;
	char *buf = NULL;

	if (!argv[optind]) {
		fprintf(stderr, "Please specify the VDI size\n");
		return EXIT_USAGE;
	}
	ret = parse_option_size(argv[optind], &size);
	if (ret < 0)
		return EXIT_USAGE;
	if (size > SD_MAX_VDI_SIZE) {
		fprintf(stderr, "VDI size is too large\n");
		return EXIT_USAGE;
	}

	ret = do_vdi_create(vdiname, size, 0, &vid, 0, vdi_cmd_data.nr_copies);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	inode = malloc(sizeof(*inode));
	buf = zalloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = sd_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode), 0, true);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read a newly created VDI object\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	max_idx = DIV_ROUND_UP(size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		oid = vid_to_data_oid(vid, idx);

		ret = sd_write_object(oid, 0, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, 1, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		inode->data_vdi_id[idx] = vid;
		ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
				      SD_INODE_HEADER_SIZE + sizeof(vid) * idx, 0,
				      inode->nr_copies, 0, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);
	return ret;
}

static int vdi_snapshot(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	if (vdi_cmd_data.snapshot_id != 0) {
		fprintf(stderr, "Please specify a non-integer value for "
			"a snapshot tag name\n");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	if (vdi_cmd_data.snapshot_tag[0]) {
		ret = sd_write_object(vid_to_vdi_oid(vid), 0, vdi_cmd_data.snapshot_tag,
				      SD_MAX_VDI_TAG_LEN,
				      offsetof(struct sheepdog_inode, tag),
				      0, inode->nr_copies, 0, true);
	}

	return do_vdi_create(vdiname, inode->vdi_size, vid, NULL, 1,
			     inode->nr_copies);
}

static int vdi_clone(int argc, char **argv)
{
	char *src_vdi = argv[optind++], *dst_vdi;
	uint32_t base_vid, new_vid;
	uint64_t oid;
	int idx, max_idx, ret;
	struct sheepdog_inode *inode = NULL;
	char *buf = NULL;

	dst_vdi = argv[optind];
	if (!dst_vdi) {
		fprintf(stderr, "Destination VDI name must be specified\n");
		ret = EXIT_USAGE;
		goto out;
	}

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		fprintf(stderr, "Only snapshot VDIs can be cloned\n");
		fprintf(stderr, "Please specify the '-s' option\n");
		ret = EXIT_USAGE;
		goto out;
	}

	inode = malloc(sizeof(*inode));
	if (!inode) {
		fprintf(stderr, "Failed to allocate memory\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(src_vdi, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, &base_vid, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = do_vdi_create(dst_vdi, inode->vdi_size, base_vid, &new_vid, 0,
			    vdi_cmd_data.nr_copies);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	buf = zalloc(SD_DATA_OBJ_SIZE);
	if (!buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	max_idx = DIV_ROUND_UP(inode->vdi_size, SD_DATA_OBJ_SIZE);

	for (idx = 0; idx < max_idx; idx++) {
		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, SD_DATA_OBJ_SIZE, 0, true);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, SD_DATA_OBJ_SIZE);

		oid = vid_to_data_oid(new_vid, idx);
		ret = sd_write_object(oid, 0, buf, SD_DATA_OBJ_SIZE, 0, 0,
				      inode->nr_copies, 1, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		ret = sd_write_object(vid_to_vdi_oid(new_vid), 0, &new_vid, sizeof(new_vid),
				      SD_INODE_HEADER_SIZE + sizeof(new_vid) * idx, 0,
				      inode->nr_copies, 0, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);
	return ret;
}

static int vdi_resize(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint64_t new_size;
	uint32_t vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	if (!argv[optind]) {
		fprintf(stderr, "Please specify the new size for the VDI\n");
		return EXIT_USAGE;
	}
	ret = parse_option_size(argv[optind], &new_size);
	if (ret < 0)
		return EXIT_USAGE;
	if (new_size > SD_MAX_VDI_SIZE) {
		fprintf(stderr, "New VDI size is too large\n");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	if (new_size < inode->vdi_size) {
		fprintf(stderr, "Shrinking VDIs is not implemented\n");
		return EXIT_USAGE;
	}
	inode->vdi_size = new_size;

	ret = sd_write_object(vid_to_vdi_oid(vid), 0, inode, SD_INODE_HEADER_SIZE, 0,
			      0, inode->nr_copies, 0, true);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to update an inode header\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_vdi_delete(const char *vdiname, int snap_id, const char *snap_tag)
{
	int fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;
	char data[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		return EXIT_SYSFAIL;

	rlen = 0;
	wlen = sizeof(data);

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;
	hdr.vdi.snapid = snap_id;
	memset(data, 0, sizeof(data));
	strncpy(data, vdiname, SD_MAX_VDI_LEN);
	if (snap_tag)
		strncpy(data + SD_MAX_VDI_LEN, snap_tag, SD_MAX_VDI_TAG_LEN);

	ret = exec_req(fd, &hdr, data, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to connect\n");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to delete %s: %s\n", vdiname,
				sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_VDI)
			return EXIT_MISSING;
		else
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_delete(int argc, char **argv)
{
	char *vdiname = argv[optind];

	return do_vdi_delete(vdiname, vdi_cmd_data.snapshot_id,
			     vdi_cmd_data.snapshot_tag);
}

static int vdi_rollback(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t base_vid;
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sheepdog_inode *inode = (struct sheepdog_inode *)buf;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		fprintf(stderr, "Please specify the '-s' option\n");
		return EXIT_USAGE;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, &base_vid, inode,
			   SD_INODE_HEADER_SIZE);
	if (ret < 0)
		return EXIT_FAILURE;

	ret = do_vdi_delete(vdiname, 0, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to delete the current state\n");
		return EXIT_FAILURE;
	}

	return do_vdi_create(vdiname, inode->vdi_size, base_vid, NULL,
			     inode->snap_id, vdi_cmd_data.nr_copies);
}

static int vdi_object(int argc, char **argv)
{
	char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	uint32_t vid;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(get_oid, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	if (vid == 0) {
		fprintf(stderr, "VDI not found\n");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Looking for the inode object 0x%" PRIx32 " with %d nodes\n\n",
		       vid, sd_nodes_nr);
		parse_objs(vid_to_vdi_oid(vid), do_print_obj, NULL, SD_INODE_SIZE);
	} else {
		struct get_data_oid_info oid_info = {0};

		oid_info.success = 0;
		oid_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(EXIT_FAILURE);
		}

		parse_objs(vid_to_vdi_oid(vid), get_data_oid, &oid_info, SD_DATA_OBJ_SIZE);

		if (oid_info.success) {
			if (oid_info.data_oid) {
				printf("Looking for the object 0x%" PRIx64
				       " (the inode vid 0x%" PRIx32 " idx %u) with %d nodes\n\n",
				       oid_info.data_oid, vid, idx, sd_nodes_nr);

				parse_objs(oid_info.data_oid, do_print_obj, NULL, SD_DATA_OBJ_SIZE);
			} else
				printf("The inode object 0x%" PRIx32 " idx %u is not allocated\n",
				       vid, idx);
		} else
			fprintf(stderr, "Failed to read the inode object 0x%" PRIx32 "\n", vid);
	}

	return EXIT_SUCCESS;
}

static int print_obj_epoch(uint64_t oid)
{
	int i, j, fd, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	unsigned rlen, wlen;
	struct sd_vnode vnodes[SD_MAX_VNODES];
	struct sd_vnode *vnode_buf[SD_MAX_COPIES];
	struct epoch_log *logs;
	int vnodes_nr, nr_logs, log_length;
	char host[128];

	log_length = sd_epoch * sizeof(struct epoch_log);
again:
	logs = malloc(log_length);
	if (!logs) {
		if (log_length < 10) {
			fprintf(stderr, "No memory to allocate.\n");
			return EXIT_SYSFAIL;
		}
		log_length /= 2;
		goto again;
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0)
		goto error;

	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.epoch = sd_epoch;
	hdr.data_length = log_length;

	rlen = hdr.data_length;
	wlen = 0;
	ret = exec_req(fd, &hdr, logs, &wlen, &rlen);
	close(fd);

	if (ret != 0)
		goto error;

	if (rsp->result != SD_RES_SUCCESS)
		printf("%s\n", sd_strerror(rsp->result));

	nr_logs = rsp->data_length / sizeof(struct epoch_log);
	for (i = nr_logs - 1; i >= 0; i--) {
		vnodes_nr = nodes_to_vnodes(logs[i].nodes, logs[i].nr_nodes, vnodes);
		printf("\nobj %"PRIx64" locations at epoch %d, copies = %d\n",
		       oid, logs[i].epoch, logs[i].nr_copies);
		printf("---------------------------------------------------\n");
		oid_to_vnodes(vnodes, vnodes_nr, oid, logs[i].nr_copies,
			      vnode_buf);
		for (j = 0; j < logs[i].nr_copies; j++) {
			addr_to_str(host, sizeof(host), vnode_buf[j]->nid.addr,
				    vnode_buf[j]->nid.port);
			printf("%s\n", host);
		}
	}

	free(logs);
	return EXIT_SUCCESS;
error:
	free(logs);
	return EXIT_SYSFAIL;
}

static int vdi_track(int argc, char **argv)
{
	char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	struct get_vdi_info info;
	uint32_t vid;

	memset(&info, 0, sizeof(info));
	info.name = vdiname;
	info.tag = vdi_cmd_data.snapshot_tag;
	info.vid = 0;
	info.snapid = vdi_cmd_data.snapshot_id;

	if (parse_vdi(get_oid, SD_INODE_HEADER_SIZE, &info) < 0)
		return EXIT_SYSFAIL;

	vid = info.vid;
	if (vid == 0) {
		fprintf(stderr, "VDI not found\n");
		return EXIT_MISSING;
	}

	if (idx == ~0) {
		printf("Tracking the inode object 0x%" PRIx32 " with %d nodes\n",
		       vid, sd_nodes_nr);
		print_obj_epoch(vid_to_vdi_oid(vid));
	} else {
		struct get_data_oid_info oid_info = {0};

		oid_info.success = 0;
		oid_info.idx = idx;

		if (idx >= MAX_DATA_OBJS) {
			printf("The offset is too large!\n");
			exit(EXIT_FAILURE);
		}

		parse_objs(vid_to_vdi_oid(vid), get_data_oid,
					&oid_info, SD_DATA_OBJ_SIZE);

		if (oid_info.success) {
			if (oid_info.data_oid) {
				printf("Tracking the object 0x%" PRIx64
				       " (the inode vid 0x%" PRIx32 " idx %u)"
					   " with %d nodes\n",
				       oid_info.data_oid, vid, idx, sd_nodes_nr);
				print_obj_epoch(oid_info.data_oid);

			} else
				printf("The inode object 0x%" PRIx32 " idx %u is not allocated\n",
				       vid, idx);
		} else
			fprintf(stderr, "Failed to read the inode object 0x%"PRIx32"\n", vid);
	}

	return EXIT_SUCCESS;
}

static int find_vdi_attr_oid(char *vdiname, char *tag, uint32_t snapid,
			     char *key, void *value, unsigned int value_len,
			     uint32_t *vid, uint64_t *oid, unsigned int *nr_copies,
			     int create, int excl, int delete)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned int wlen, rlen;
	struct sheepdog_vdi_attr vattr;

	memset(&vattr, 0, sizeof(vattr));
	strncpy(vattr.name, vdiname, SD_MAX_VDI_LEN);
	strncpy(vattr.tag, vdi_cmd_data.snapshot_tag, SD_MAX_VDI_TAG_LEN);
	vattr.snap_id = vdi_cmd_data.snapshot_id;
	strncpy(vattr.key, key, SD_MAX_VDI_ATTR_KEY_LEN);
	if (value && value_len) {
		vattr.value_len = value_len;
		memcpy(vattr.value, value, value_len);
	}

	fd = connect_to(sdhost, sdport);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect\n\n");
		return SD_RES_EIO;
	}

	sd_init_req(&hdr, SD_OP_GET_VDI_ATTR);
	wlen = SD_ATTR_OBJ_SIZE;
	rlen = 0;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;
	hdr.vdi.snapid = vdi_cmd_data.snapshot_id;

	if (create)
		hdr.flags |= SD_FLAG_CMD_CREAT;
	if (excl)
		hdr.flags |= SD_FLAG_CMD_EXCL;
	if (delete)
		hdr.flags |= SD_FLAG_CMD_DEL;

	ret = exec_req(fd, &hdr, &vattr, &wlen, &rlen);
	if (ret) {
		ret = SD_RES_EIO;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		ret = rsp->result;
		goto out;
	}

	*vid = rsp->vdi.vdi_id;
	*oid = vid_to_attr_oid(rsp->vdi.vdi_id, rsp->vdi.attr_id);
	*nr_copies = rsp->vdi.copies;

	ret = SD_RES_SUCCESS;
out:
	close(fd);
	return ret;
}

static int vdi_setattr(int argc, char **argv)
{
	int ret, value_len = 0;
	uint64_t attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key, *value;
	uint64_t offset;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "Please specify the attribute key\n");
		return EXIT_USAGE;
	}

	value = argv[optind++];
	if (!value && !vdi_cmd_data.delete) {
		value = malloc(SD_MAX_VDI_ATTR_VALUE_LEN);
		if (!value) {
			fprintf(stderr, "Failed to allocate memory\n");
			return EXIT_SYSFAIL;
		}

		offset = 0;
reread:
		ret = read(STDIN_FILENO, value + offset,
			   SD_MAX_VDI_ATTR_VALUE_LEN - offset);
		if (ret < 0) {
			fprintf(stderr, "Failed to read attribute value from stdin: %m\n");
			return EXIT_SYSFAIL;
		}
		if (ret > 0) {
			offset += ret;
			goto reread;
		}
	}

	if (value)
		value_len = strlen(value);

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, value,
				value_len, &vid, &attr_oid,
				&nr_copies, !vdi_cmd_data.delete,
				vdi_cmd_data.exclusive, vdi_cmd_data.delete);
	if (ret) {
		if (ret == SD_RES_VDI_EXIST) {
			fprintf(stderr, "The attribute '%s' already exists\n", key);
			return EXIT_EXISTS;
		} else if (ret == SD_RES_NO_OBJ) {
			fprintf(stderr, "Attribute '%s' not found\n", key);
			return EXIT_MISSING;
		} else if (ret == SD_RES_NO_VDI) {
			fprintf(stderr, "VDI not found\n");
			return EXIT_MISSING;
		} else
			fprintf(stderr, "Failed to set attribute: %s\n",
				sd_strerror(ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int vdi_getattr(int argc, char **argv)
{
	int ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	char *vdiname = argv[optind++], *key;
	struct sheepdog_vdi_attr vattr;

	key = argv[optind++];
	if (!key) {
		fprintf(stderr, "Please specify the attribute key\n");
		return EXIT_USAGE;
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, NULL, 0,
				&vid, &attr_oid, &nr_copies, 0, 0, 0);
	if (ret == SD_RES_NO_OBJ) {
		fprintf(stderr, "Attribute '%s' not found\n", key);
		return EXIT_MISSING;
	} else if (ret == SD_RES_NO_VDI) {
		fprintf(stderr, "VDI not found\n");
		return EXIT_MISSING;
	} else if (ret) {
		fprintf(stderr, "Failed to find attribute oid: %s\n",
			sd_strerror(ret));
		return EXIT_MISSING;
	}

	oid = attr_oid;

	ret = sd_read_object(oid, &vattr, SD_ATTR_OBJ_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read attribute oid: %s\n",
			sd_strerror(ret));
		return EXIT_SYSFAIL;
	}

	xwrite(STDOUT_FILENO, vattr.value, vattr.value_len);
	return EXIT_SUCCESS;
}

static int vdi_read(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	int ret, idx;
	struct sheepdog_inode *inode = NULL;
	uint64_t offset = 0, oid, done = 0, total = (uint64_t) -1;
	unsigned int len, remain;
	char *buf = NULL;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (offset % 512 != 0) {
			fprintf(stderr, "Read offset must be block-aligned\n");
			return EXIT_USAGE;
		}
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));
	buf = malloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	if (inode->vdi_size < offset) {
		fprintf(stderr, "Read offset is beyond the end of the VDI\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	total = roundup(total, 512);
	idx = offset / SD_DATA_OBJ_SIZE;
	offset %= SD_DATA_OBJ_SIZE;
	while (done < total) {
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);

		if (inode->data_vdi_id[idx]) {
			oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
			ret = sd_read_object(oid, buf, len, offset, false);
			if (ret != SD_RES_SUCCESS) {
				fprintf(stderr, "Failed to read VDI\n");
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, len);

		remain = len;
		while (remain) {
			ret = write(STDOUT_FILENO, buf + (len - remain), len);
			if (ret < 0) {
				fprintf(stderr, "Failed to write to stdout: %m\n");
				ret = EXIT_SYSFAIL;
				goto out;
			}
			remain -= ret;
		}

		offset = 0;
		idx++;
		done += len;
	}
	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static int vdi_write(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	uint32_t vid, flags;
	int ret, idx;
	struct sheepdog_inode *inode = NULL;
	uint64_t offset = 0, oid, old_oid, done = 0, total = (uint64_t) -1;
	unsigned int len, remain;
	char *buf = NULL;
	int create;

	if (argv[optind]) {
		ret = parse_option_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (offset % 512 != 0) {
			fprintf(stderr, "Write offset must be block-aligned\n");
			return EXIT_USAGE;
		}
		if (argv[optind]) {
			ret = parse_option_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));
	buf = malloc(SD_DATA_OBJ_SIZE);
	if (!inode || !buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(vdiname, 0, "", &vid, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	if (inode->vdi_size < offset) {
		fprintf(stderr, "Write offset is beyond the end of the VDI\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	total = min(total, inode->vdi_size - offset);
	total = roundup(total, 512);
	idx = offset / SD_DATA_OBJ_SIZE;
	offset %= SD_DATA_OBJ_SIZE;
	while (done < total) {
		create = 0;
		old_oid = 0;
		flags = 0;
		len = min(total - done, SD_DATA_OBJ_SIZE - offset);

		if (!inode->data_vdi_id[idx])
			create = 1;
		else if (!is_data_obj_writeable(inode, idx)) {
			create = 1;
			old_oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
		}

		if (vdi_cmd_data.writeback)
			flags |= SD_FLAG_CMD_CACHE;

		remain = len;
		while (remain > 0) {
			ret = read(STDIN_FILENO, buf + (len - remain), remain);
			if (ret == 0) {
				if (len == remain) {
					ret = EXIT_SUCCESS;
					goto out;
				}
				/* exit after this buffer is sent */
				memset(buf + (len - remain), 0, remain);
				total = done + len;
				break;
			}
			else if (ret < 0) {
				fprintf(stderr, "Failed to read from stdin: %m\n");
				ret = EXIT_SYSFAIL;
				goto out;
			}
			remain -= ret;
		}

		inode->data_vdi_id[idx] = inode->vdi_id;
		oid = vid_to_data_oid(inode->data_vdi_id[idx], idx);
		ret = sd_write_object(oid, old_oid, buf, len, offset, flags,
				      inode->nr_copies, create, false);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "Failed to write VDI\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (create) {
			ret = sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
					      SD_INODE_HEADER_SIZE + sizeof(vid) * idx,
					      flags, inode->nr_copies, 0, false);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		}

		offset += len;
		if (offset == SD_DATA_OBJ_SIZE) {
			offset = 0;
			idx++;
		}
		done += len;
	}
	ret = EXIT_SUCCESS;
out:
	free(inode);
	free(buf);

	return ret;
}

static void *read_object_from(struct sd_vnode *vnode, uint64_t oid)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned wlen = 0, rlen = SD_DATA_OBJ_SIZE;
	char name[128];
	void *buf;

	buf = malloc(SD_DATA_OBJ_SIZE);
	if (!buf) {
		fprintf(stderr, "Failed to allocate memory\n");
		exit(EXIT_SYSFAIL);
	}

	addr_to_str(name, sizeof(name), vnode->nid.addr, 0);
	fd = connect_to(name, vnode->nid.port);
	if (fd < 0) {
		fprintf(stderr, "failed to connect to %s:%"PRIu32"\n",
			name, vnode->nid.port);
		exit(EXIT_FAILURE);
	}

	sd_init_req(&hdr, SD_OP_READ_PEER);
	hdr.epoch = sd_epoch;
	hdr.flags = 0;
	hdr.data_length = rlen;

	hdr.obj.oid = oid;

	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to execute request\n");
		exit(EXIT_FAILURE);
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read, %s\n",
			sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
	return buf;
}

static void write_object_to(struct sd_vnode *vnode, uint64_t oid, void *buf)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int fd, ret;
	unsigned wlen = SD_DATA_OBJ_SIZE, rlen = 0;
	char name[128];

	addr_to_str(name, sizeof(name), vnode->nid.addr, 0);
	fd = connect_to(name, vnode->nid.port);
	if (fd < 0) {
		fprintf(stderr, "failed to connect to %s:%"PRIu32"\n",
			name, vnode->nid.port);
		exit(EXIT_FAILURE);
	}

	sd_init_req(&hdr, SD_OP_WRITE_PEER);
	hdr.epoch = sd_epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = wlen;

	hdr.obj.oid = oid;

	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
	close(fd);

	if (ret) {
		fprintf(stderr, "Failed to execute request\n");
		exit(EXIT_FAILURE);
	}

	if (rsp->result != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read, %s\n",
			sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
}

/*
 * Fix consistency of the replica of oid.
 *
 * XXX: The fix is rather dumb, just read the first copy and write it
 * to other replica.
 */
static void do_check_repair(uint64_t oid, int nr_copies)
{
	struct sd_vnode *tgt_vnodes[nr_copies];
	void *buf, *buf_cmp;
	int i;

	oid_to_vnodes(sd_vnodes, sd_vnodes_nr, oid, nr_copies, tgt_vnodes);
	buf = read_object_from(tgt_vnodes[0], oid);
	for (i = 1; i < nr_copies; i++) {
		buf_cmp = read_object_from(tgt_vnodes[i], oid);
		if (memcmp(buf, buf_cmp, SD_DATA_OBJ_SIZE)) {
			free(buf_cmp);
			goto fix_consistency;
		}
		free(buf_cmp);
	}
	free(buf);
	return;

fix_consistency:
	for (i = 1; i < nr_copies; i++)
		write_object_to(tgt_vnodes[i], oid, buf);
	fprintf(stdout, "fix %"PRIx64" success\n", oid);
	free(buf);
}

static int vdi_check(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	int ret;
	uint64_t total, done = 0, oid;
	uint32_t idx = 0, vid;
	struct sheepdog_inode *inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	total = inode->vdi_size;
	while(done < total) {
		vid = inode->data_vdi_id[idx];
		if (vid) {
			oid = vid_to_data_oid(vid, idx);
			do_check_repair(oid, inode->nr_copies);
		}
		done += SD_DATA_OBJ_SIZE;
		idx++;
	}

	fprintf(stdout, "finish check&repair %s\n", vdiname);
	return EXIT_SUCCESS;
out:
	return ret;
}

static int vdi_flush(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	struct sd_req hdr;
	uint32_t vid;
	int ret = EXIT_SUCCESS;

	ret = find_vdi_name(vdiname, 0, "", &vid, 0);
	if (ret < 0) {
		fprintf(stderr, "Failed to open VDI %s\n", vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_FLUSH_VDI);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = send_light_req(&hdr, sdhost, sdport);
	if (ret) {
		fprintf(stderr, "failed to execute request\n");
		return EXIT_FAILURE;
	}
out:
	return ret;
}

/* vdi backup format */

#define VDI_BACKUP_FORMAT_VERSION 1
#define VDI_BACKUP_MAGIC 0x11921192

struct backup_hdr {
	uint32_t version;
	uint32_t magic;
};

struct obj_backup {
	uint32_t idx;
	uint32_t offset;
	uint32_t length;
	uint32_t reserved;
	uint8_t data[SD_DATA_OBJ_SIZE];
};

/*
 * discards redundant area from backup data
 */
static void compact_obj_backup(struct obj_backup *backup, uint8_t *from_data)
{
	uint8_t *p1, *p2;

	p1 = backup->data;
	p2 = from_data;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 += SECTOR_SIZE;
		p2 += SECTOR_SIZE;
		backup->offset += SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}

	p1 = backup->data + SD_DATA_OBJ_SIZE - SECTOR_SIZE;
	p2 = from_data + SD_DATA_OBJ_SIZE - SECTOR_SIZE;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 -= SECTOR_SIZE;
		p2 -= SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}
}

static int get_obj_backup(int idx, uint32_t from_vid, uint32_t to_vid,
			  struct obj_backup *backup)
{
	int ret;
	uint8_t *from_data = xzalloc(SD_DATA_OBJ_SIZE);

	backup->idx = idx;
	backup->offset = 0;
	backup->length = SD_DATA_OBJ_SIZE;

	if (to_vid) {
		ret = sd_read_object(vid_to_data_oid(to_vid, idx), backup->data,
				     SD_DATA_OBJ_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "Failed to read object %"PRIx32", %d\n",
				to_vid, idx);
			return EXIT_FAILURE;
		}
	} else
		memset(backup->data, 0, SD_DATA_OBJ_SIZE);

	if (from_vid) {
		ret = sd_read_object(vid_to_data_oid(from_vid, idx), from_data,
				     SD_DATA_OBJ_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "Failed to read object %"PRIx32", %d\n",
				from_vid, idx);
			return EXIT_FAILURE;
		}
	}

	compact_obj_backup(backup, from_data);

	free(from_data);

	return EXIT_SUCCESS;
}

static int vdi_backup(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	int ret = EXIT_SUCCESS, idx, nr_objs;
	struct sheepdog_inode *from_inode = xzalloc(sizeof(*from_inode));
	struct sheepdog_inode *to_inode = xzalloc(sizeof(*to_inode));
	struct backup_hdr hdr = {
		.version = VDI_BACKUP_FORMAT_VERSION,
		.magic = VDI_BACKUP_MAGIC,
	};
	struct obj_backup *backup = xzalloc(sizeof(*backup));

	if ((!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) ||
	    (!vdi_cmd_data.from_snapshot_id &&
	     !vdi_cmd_data.from_snapshot_tag[0])) {
		fprintf(stderr, "Please specify snapshots with '-F' and '-s'"
			"options\n");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.from_snapshot_id,
			   vdi_cmd_data.from_snapshot_tag, NULL,
			   from_inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, NULL, to_inode,
			   SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	nr_objs = DIV_ROUND_UP(to_inode->vdi_size, SD_DATA_OBJ_SIZE);

	ret = xwrite(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (ret < 0) {
		fprintf(stderr, "failed to write backup header, %m\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	for (idx = 0; idx < nr_objs; idx++) {
		uint32_t from_vid = from_inode->data_vdi_id[idx];
		uint32_t to_vid = to_inode->data_vdi_id[idx];

		if (to_vid == 0 && from_vid == 0)
			continue;

		ret = get_obj_backup(idx, from_vid, to_vid, backup);
		if (ret != EXIT_SUCCESS)
			goto out;

		if (backup->length == 0)
			continue;

		ret = xwrite(STDOUT_FILENO, backup,
			     sizeof(*backup) - sizeof(backup->data));
		if (ret < 0) {
			fprintf(stderr, "failed to write backup data, %m\n");
			ret = EXIT_SYSFAIL;
			goto out;
		}
		ret = xwrite(STDOUT_FILENO, backup->data + backup->offset,
			     backup->length);
		if (ret < 0) {
			fprintf(stderr, "failed to write backup data, %m\n");
			ret = EXIT_SYSFAIL;
			goto out;
		}
	}

	/* write end marker */
	memset(backup, 0, sizeof(*backup) - sizeof(backup->data));
	backup->idx = UINT32_MAX;
	ret = xwrite(STDOUT_FILENO, backup,
		     sizeof(*backup) - sizeof(backup->data));
	if (ret < 0) {
		fprintf(stderr, "failed to write end marker, %m\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	fsync(STDOUT_FILENO);
out:
	free(from_inode);
	free(to_inode);
	free(backup);
	return ret;
}

/* restore backup data to vdi */
static int restore_obj(struct obj_backup *backup, uint32_t vid,
		       struct sheepdog_inode *parent_inode)
{
	int ret;
	uint32_t parent_vid = parent_inode->data_vdi_id[backup->idx];
	uint64_t parent_oid = 0;

	if (parent_vid)
		parent_oid = vid_to_data_oid(parent_vid, backup->idx);

	/* send a copy-on-write request */
	ret = sd_write_object(vid_to_data_oid(vid, backup->idx), parent_oid,
			      backup->data, backup->length, backup->offset,
			      0, parent_inode->nr_copies, 1, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return sd_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
			       SD_INODE_HEADER_SIZE + sizeof(vid) * backup->idx,
			       0, parent_inode->nr_copies, 0, true);
}

static uint32_t do_restore(char *vdiname, int snapid, const char *tag)
{
	int ret;
	uint32_t vid;
	struct backup_hdr hdr;
	struct obj_backup *backup = xzalloc(sizeof(*backup));
	struct sheepdog_inode *inode = xzalloc(sizeof(*inode));

	ret = xread(STDIN_FILENO, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		fprintf(stderr, "failed to read backup header, %m\n");
	}

	if (hdr.version != VDI_BACKUP_FORMAT_VERSION ||
	    hdr.magic != VDI_BACKUP_MAGIC) {
		fprintf(stderr, "The backup file is corrupted\n");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(vdiname, snapid, tag, NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = do_vdi_create(vdiname, inode->vdi_size, inode->vdi_id, &vid, 1,
			    inode->nr_copies);
	if (ret != EXIT_SUCCESS) {
		fprintf(stderr, "Failed to read VDI\n");
		goto out;
	}

	while (true) {
		ret = xread(STDIN_FILENO, backup,
			    sizeof(*backup) - sizeof(backup->data));
		if (ret != sizeof(*backup) - sizeof(backup->data)) {
			fprintf(stderr, "failed to read backup data\n");
			ret = EXIT_SYSFAIL;
			break;
		}

		if (backup->idx == UINT32_MAX) {
			ret = EXIT_SUCCESS;
			break;
		}

		ret = xread(STDIN_FILENO, backup->data, backup->length);
		if (ret != backup->length) {
			fprintf(stderr, "failed to read backup data\n");
			ret = EXIT_SYSFAIL;
			break;
		}

		ret = restore_obj(backup, vid, inode);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr, "failed to restore backup\n");
			do_vdi_delete(vdiname, 0, NULL);
			ret = EXIT_FAILURE;
			break;
		}
	}
out:
	free(backup);
	free(inode);

	return ret;
}

static int vdi_restore(int argc, char **argv)
{
	char *vdiname = argv[optind++];
	int ret;
	char buf[SD_INODE_HEADER_SIZE] = {0};
	struct sheepdog_inode *current_inode = xzalloc(sizeof(*current_inode));
	struct sheepdog_inode *parent_inode = (struct sheepdog_inode *)buf;
	bool need_current_recovery = false;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		fprintf(stderr, "We can restore a backup file only to"
			"snapshots\n");
		fprintf(stderr, "Please specify the '-s' option\n");
		ret = EXIT_USAGE;
		goto out;
	}

	/* delete the current vdi temporarily first to avoid making
	 * the current state become snapshot */
	ret = read_vdi_obj(vdiname, 0, "", NULL, current_inode,
			   SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = sd_read_object(vid_to_vdi_oid(current_inode->parent_vdi_id),
			     parent_inode, SD_INODE_HEADER_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		printf("error\n");
		goto out;
	}

	ret = do_vdi_delete(vdiname, 0, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to delete the current state\n");
		ret = EXIT_FAILURE;
		goto out;
	}
	need_current_recovery = true;

	/* restore backup data */
	ret = do_restore(vdiname, vdi_cmd_data.snapshot_id,
			 vdi_cmd_data.snapshot_tag);
out:
	if (need_current_recovery) {
		int recovery_ret;
		/* recreate the current vdi object */
		recovery_ret = do_vdi_create(vdiname, current_inode->vdi_size,
					     current_inode->parent_vdi_id, NULL,
					     parent_inode->snap_id,
					     current_inode->nr_copies);
		if (recovery_ret != EXIT_SUCCESS) {
			fprintf(stderr, "failed to resume the current vdi\n");
			ret = recovery_ret;
		}
	}
	free(current_inode);
	return ret;
}

static struct subcommand vdi_cmd[] = {
	{"check", "<vdiname>", "saph", "check and repair image's consistency",
	 NULL, SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_check, vdi_options},
	{"create", "<vdiname> <size>", "Pcaph", "create an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_create, vdi_options},
	{"snapshot", "<vdiname>", "saph", "create a snapshot",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_snapshot, vdi_options},
	{"clone", "<src vdi> <dst vdi>", "sPcaph", "clone an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_clone, vdi_options},
	{"delete", "<vdiname>", "saph", "delete an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_delete, vdi_options},
	{"rollback", "<vdiname>", "saph", "rollback to a snapshot",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_rollback, vdi_options},
	{"list", "[vdiname]", "aprh", "list images",
	 NULL, 0, vdi_list, vdi_options},
	{"tree", NULL, "aph", "show images in tree view format",
	 NULL, 0, vdi_tree, vdi_options},
	{"graph", NULL, "aph", "show images in Graphviz dot format",
	 NULL, 0, vdi_graph, vdi_options},
	{"object", "<vdiname>", "isaph", "show object information in the image",
	 NULL, SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_object, vdi_options},
	{"track", "<vdiname>", "isaph", "show the object epoch trace in the image",
	 NULL, SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_track, vdi_options},
	{"setattr", "<vdiname> <key> [value]", "dxaph", "set a VDI attribute",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_setattr, vdi_options},
	{"getattr", "<vdiname> <key>", "aph", "get a VDI attribute",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_getattr, vdi_options},
	{"resize", "<vdiname> <new size>", "aph", "resize an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_resize, vdi_options},
	{"read", "<vdiname> [<offset> [<len>]]", "saph", "read data from an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_read, vdi_options},
	{"write", "<vdiname> [<offset> [<len>]]", "apwh", "write data to an image",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_write, vdi_options},
	{"flush", "<vdiname>", "aph", "flush data to cluster",
	 NULL, SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_flush, vdi_options},
	{"backup", "<vdiname> <backup>", "sFaph", "create an incremental backup between two snapshots",
	 NULL, SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_backup, vdi_options},
	{"restore", "<vdiname> <backup>", "saph", "restore snapshot images from a backup",
	 NULL, SUBCMD_FLAG_NEED_NODELIST|SUBCMD_FLAG_NEED_THIRD_ARG,
	 vdi_restore, vdi_options},
	{NULL,},
};

static int vdi_parser(int ch, char *opt)
{
	char *p;
	int nr_copies;

	switch (ch) {
	case 'P':
		vdi_cmd_data.prealloc = 1;
		break;
	case 'i':
		vdi_cmd_data.index = strtol(opt, &p, 10);
		if (opt == p) {
			fprintf(stderr, "The index must be an integer\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		vdi_cmd_data.snapshot_id = strtol(opt, &p, 10);
		if (opt == p) {
			vdi_cmd_data.snapshot_id = 0;
			strncpy(vdi_cmd_data.snapshot_tag, opt,
				sizeof(vdi_cmd_data.snapshot_tag));
		}
		break;
	case 'x':
		vdi_cmd_data.exclusive = 1;
		break;
	case 'd':
		vdi_cmd_data.delete = 1;
		break;
	case 'w':
		vdi_cmd_data.writeback = 1;
		break;
	case 'c':
		nr_copies = strtol(opt, &p, 10);
		if (opt == p || nr_copies < 0 || nr_copies > SD_MAX_COPIES) {
			fprintf(stderr, "Invalid copies number, must be "
				"an integer between 0 and %d\n", SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		vdi_cmd_data.nr_copies = nr_copies;
	case 'F':
		vdi_cmd_data.from_snapshot_id = strtol(opt, &p, 10);
		if (opt == p) {
			vdi_cmd_data.from_snapshot_id = 0;
			strncpy(vdi_cmd_data.from_snapshot_tag, opt,
				sizeof(vdi_cmd_data.from_snapshot_tag));
		}
	}

	return 0;
}

struct command vdi_command = {
	"vdi",
	vdi_cmd,
	vdi_parser
};
