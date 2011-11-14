#include <time.h>

#include "farm.h"
#include "sheep_priv.h"

int snap_init(void)
{
	int fd, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "Snapshots");

	fd = open(buf.buf, O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST) {
			ret = -1;
			goto out;
		}
	}
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int append_sha1_and_timestamp(unsigned char *sha1)
{
	int fd, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "Snapshots");

	fd = open(buf.buf, O_WRONLY | O_APPEND);
	if (fd < 0) {
		dprintf("%s\n", strerror(errno));
		goto out;
	}

	strbuf_reset(&buf);
	strbuf_addf(&buf, "%s %" PRIu64 "\n", sha1, time(NULL));
	xwrite(fd, buf.buf, buf.len);
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

void *snap_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer = NULL;

	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_SNAP) != 0) {
		free(buffer);
		return NULL;
	}

	dprintf("snap sha1 success. buf %p\n", buffer);
	return buffer;
}

int snap_file_write(unsigned char *outsha1)
{
	int epoch = get_latest_epoch(), ret = 0;
	struct strbuf buf = STRBUF_INIT;
	struct sheepdog_node_list_entry nodes[SD_MAX_NODES];
	uint64_t epoch_size = epoch_log_read(epoch, (char *)nodes, sizeof(nodes));
	unsigned char trunk[SHA1_LEN];
	struct sha1_file_hdr hdr = { .tag = TAG_SNAP,
				     .size = epoch_size + SHA1_LEN,
				     .priv = epoch };

	if (trunk_file_write(trunk) < 0) {
		ret =  -1;
		goto err;
	}
	strbuf_add(&buf, &hdr, sizeof(hdr));
	strbuf_add(&buf, trunk, SHA1_LEN);
	strbuf_add(&buf, (char *)nodes, epoch_size);
	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto err;
	}

	append_sha1_and_timestamp(outsha1);
	dprintf("snap sha1: %s\n", sha1_to_hex(outsha1));
err:
	strbuf_release(&buf);
	return ret;
}
