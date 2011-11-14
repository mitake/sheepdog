#include "farm.h"

char farm_obj_dir[PATH_MAX];
char farm_dir[PATH_MAX];

extern char *obj_path;

int farm_init(char *p)
{
	int i, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	strbuf_addstr(&buf, "/.farm");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			perror(buf.buf);
			ret = -1;
			goto err;
		}
	}
	memcpy(farm_dir, buf.buf, buf.len);
	strbuf_addstr(&buf, "/objects");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			perror(buf.buf);
			ret = -1;
			goto err;
		}
	}
	for (i = 0; i < 256; i++) {
		strbuf_addf(&buf, "/%02x", i);
		if (mkdir(buf.buf, 0755) < 0) {
			if (errno != EEXIST) {
				perror(buf.buf);
				ret = -1;
				goto err;
			}
		}
		strbuf_remove(&buf, buf.len - 3, 3);
	}
	memcpy(farm_obj_dir, buf.buf, buf.len);

	ret = trunk_init();
	if (ret)
		goto err;
	ret = snap_init();
	if (ret)
		goto err;

	strbuf_release(&buf);
	return ret;
err:
	strbuf_release(&buf);
	return ret;
}

int farm_object_open(uint64_t oid)
{
	return 0;
}

ssize_t farm_object_get(uint64_t oid, void *buffer, int len, off_t offset)
{
	int fd;
	ssize_t ret = -1;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, obj_path);
	strbuf_addf(&buf, "/%016" PRIx64, oid);
	fd = open(buf.buf, O_RDONLY);
	if (fd < 0)
		goto err_open;
	ret = pread(fd, buffer, len, offset);
	if (ret < 0)
		goto err;
	close(fd);
	strbuf_release(&buf);
	return ret;
err:
	close(fd);
err_open:
	perror(buf.buf);
	strbuf_release(&buf);
	return ret;
}

ssize_t farm_object_put(uint64_t oid, void *buffer, int len, off_t offset)
{
	int fd;
	ssize_t ret = -1;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, obj_path);
	strbuf_addf(&buf, "/%016" PRIx64, oid);
	fd = open(buf.buf, O_WRONLY | O_CREAT, 0644);
	if (fd < 0)
		goto err_open;
	ret = pwrite(fd, buffer, len, offset);
	if (ret < 0)
		goto err;

	trunk_update_entry(oid);

	close(fd);
	strbuf_release(&buf);
	return ret;
err:
	close(fd);
err_open:
	perror(buf.buf);
	strbuf_release(&buf);
	return ret;
}

int farm_object_close(uint64_t oid)
{
	return 0;
}
