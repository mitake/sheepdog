/*
 * Taken and modfied from git by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "util.h"
#include "logger.h"

static void do_nothing(size_t size)
{
}

static void (*try_to_free_routine)(size_t size) = do_nothing;

try_to_free_t set_try_to_free_routine(try_to_free_t routine)
{
	try_to_free_t old = try_to_free_routine;
	if (!routine)
		routine = do_nothing;
	try_to_free_routine = routine;
	return old;
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret && !size)
		ret = malloc(1);
	if (!ret) {
		try_to_free_routine(size);
		ret = malloc(size);
		if (!ret && !size)
			ret = malloc(1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xzalloc(size_t size)
{
	void *ret;
	ret = xmalloc(size);
	memset(ret, 0, size);
	return ret;
}

notrace void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret && !size)
		ret = realloc(ptr, 1);
	if (!ret) {
		try_to_free_routine(size);
		ret = realloc(ptr, size);
		if (!ret && !size)
			ret = realloc(ptr, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (!ret && (!nmemb || !size))
		ret = calloc(1, 1);
	if (!ret) {
		try_to_free_routine(nmemb * size);
		ret = calloc(nmemb, size);
		if (!ret && (!nmemb || !size))
			ret = calloc(1, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

static ssize_t _read(int fd, void *buf, size_t len)
{
	ssize_t nr;
	while (1) {
		nr = read(fd, buf, len);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _write(int fd, const void *buf, size_t len)
{
	ssize_t nr;
	while (1) {
		nr = write(fd, buf, len);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xread(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _read(fd, p, count);
		if (loaded < 0)
			return -1;
		if (loaded == 0)
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
	}

	return total;
}

ssize_t xwrite(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _write(fd, p, count);
		if (written < 0)
			return -1;
		if (!written) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
	}

	return total;
}

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (1) {
		nr = pread(fd, buf, len, offset);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (1) {
		nr = pwrite(fd, buf, len, offset);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _pread(fd, p, count, offset);
		if (loaded < 0)
			return -1;
		if (loaded == 0)
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
		offset += loaded;
	}

	return total;
}

ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _pwrite(fd, p, count, offset);
		if (written < 0)
			return -1;
		if (!written) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
		offset += written;
	}

	return total;
}

/* remove directory recursively */
int rmdir_r(char *dir_path)
{
	int ret;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			eprintf("failed to open %s: %m\n", dir_path);
		return -errno;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			eprintf("failed to stat %s: %m\n", path);
			goto out;
		}
		if (S_ISDIR(s.st_mode))
			ret = rmdir_r(path);
		else
			ret = unlink(path);

		if (ret != 0) {
			eprintf("failed to remove %s %s: %m\n",
					S_ISDIR(s.st_mode) ? "directory" : "file",
					path);
			goto out;
		}
	}

	ret = rmdir(dir_path);
out:
	closedir(dir);
	return ret;
}

/* Trim zero sectors from the beginning and end of buffer */
void trim_zero_sectors(void *buf, uint64_t *offset, uint32_t *len)
{
	const uint8_t zero[SECTOR_SIZE] = {0};
	uint8_t *p = buf;

	assert(*offset == 0);

	/* trim zero sectors from the beginning of buffer */
	while (*len >= SECTOR_SIZE) {
		if (memcmp(p + *offset, zero, SECTOR_SIZE) != 0)
			break;

		*offset += SECTOR_SIZE;
		*len -= SECTOR_SIZE;
	}
	memmove(buf, p + *offset, *len);

	/* trim zero sectors from the end of buffer */
	while (*len >= SECTOR_SIZE) {
		if (memcmp(p + *len - SECTOR_SIZE, zero, SECTOR_SIZE) != 0)
			break;

		*len -= SECTOR_SIZE;
	}
}

/* Set trimmed zero sectors to the beginning and end of buffer */
void set_trimmed_sectors(void *buf, uint64_t offset, uint32_t len,
			 uint32_t requested_len)
{
	uint8_t *p = buf;

	if (offset > 0) {
		memmove(p + offset, buf, len);
		memset(p, 0, offset);
	}

	if (offset + len < requested_len)
		memset(p + offset + len, 0, requested_len- offset - len);
}
