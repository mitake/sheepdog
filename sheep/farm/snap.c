/*
 * Copyright (C) 2011 Taobao Inc.
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

/*
 * Snap object is the meta data that describes the snapshot, either triggered
 * by recovery logic or end users.
 */
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "farm.h"
#include "sheep_priv.h"

int snap_init(void)
{
	int fd, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "user_snap");

	fd = open(buf.buf, O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST) {
			ret = -1;
			goto out;
		}
	} else
		close(fd);

out:
	strbuf_release(&buf);
	return ret;
}

int snap_log_write(uint32_t epoch, unsigned char *sha1)
{
	int fd, ret = -1;
	struct strbuf buf = STRBUF_INIT;
	struct snap_log log = { .epoch = epoch,
				.time = time(NULL) };

	memcpy(log.sha1, sha1, SHA1_LEN);
	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "user_snap");

	fd = open(buf.buf, O_WRONLY | O_APPEND);
	if (fd < 0) {
		dprintf("%m\n");
		goto out;
	}

	strbuf_reset(&buf);
	strbuf_add(&buf, &log, sizeof(log));
	ret = xwrite(fd, buf.buf, buf.len);
	if (ret != buf.len)
		ret = -1;

	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

void *snap_log_read(int *out_nr)
{
	struct strbuf buf = STRBUF_INIT;
	struct stat st;
	void *buffer = NULL;
	int len, fd;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "user_snap");

	fd = open(buf.buf, O_RDONLY);
	if (fd < 0) {
		dprintf("%m\n");
		goto out;
	}
	if (fstat(fd, &st) < 0) {
		dprintf("%m\n");
		goto out_close;
	}

	len = st.st_size;
	buffer = xmalloc(len);
	len = xread(fd, buffer, len);
	if (len != st.st_size) {
		free(buffer);
		buffer = NULL;
		goto out_close;
	}
	*out_nr = len / sizeof(struct snap_log);
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return buffer;
}

void *snap_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer = NULL;

	dprintf("%s\n", sha1_to_hex(sha1));
	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_SNAP) != 0) {
		free(buffer);
		return NULL;
	}

	return buffer;
}

int snap_file_write(uint32_t epoch, struct sd_node *nodes, int nr_nodes,
		    unsigned char *trunksha1, unsigned char *outsha1)
{
	int ret = 0;
	struct strbuf buf = STRBUF_INIT;
	struct sha1_file_hdr hdr;

	memcpy(hdr.tag, TAG_SNAP, TAG_LEN);
	hdr.size = nr_nodes * sizeof(*nodes) + SHA1_LEN;
	hdr.priv = epoch;
	hdr.reserved = 0;

	strbuf_add(&buf, &hdr, sizeof(hdr));
	strbuf_add(&buf, trunksha1, SHA1_LEN);
	strbuf_add(&buf, (char *)nodes, nr_nodes * sizeof(*nodes));
	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto err;
	}

	dprintf("epoch: %" PRIu32 ", sha1: %s\n", epoch, sha1_to_hex(outsha1));
err:
	strbuf_release(&buf);
	return ret;
}
