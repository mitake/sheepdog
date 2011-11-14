#include "farm.h"
#include "util.h"

static char *get_object_directory(void)
{
	return farm_obj_dir;
}

/* I am not expected to understand it */
static void fill_sha1_path(char *pathbuf, const unsigned char *sha1)
{
	int i;
	for (i = 0; i < SHA1_LEN; i++) {
		static char hex[] = "0123456789abcdef";
		unsigned int val = sha1[i];
		char *pos = pathbuf + i*2 + (i > 0);
		*pos++ = hex[val >> 4];
		*pos = hex[val & 0xf];
	}
}

char *sha1_to_path(const unsigned char *sha1)
{

	static char buf[PATH_MAX];
	const char *objdir;
	int len;

	objdir = get_object_directory();
	len = strlen(objdir);

	/* '/' + sha1(2) + '/' + sha1(38) + '\0' */
	if (len + 43 > PATH_MAX)
		panic("insanely long object directory %s", objdir);
	memcpy(buf, objdir, len);
	buf[len] = '/';
	buf[len+3] = '/';
	buf[len+42] = '\0';
	fill_sha1_path(buf + len + 1, sha1);
	return buf;
}

static int sha1_buffer_write(const unsigned char *sha1, void *buf, unsigned int size)
{
	char *filename = sha1_to_path(sha1);
	int fd, ret = 0;

	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST)
			ret = -1;
		goto err_open;
	}
	if (write(fd, buf, size) < 0)
		ret = -1;

	close(fd);
err_open:
	return ret;
}

int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *outsha1)
{
	int size;
	unsigned char *compressed;
	z_stream stream;
	unsigned char sha1[SHA1_LEN];
	SHA_CTX c;

	memset(&stream, 0, sizeof(stream));
	deflateInit(&stream, Z_BEST_COMPRESSION);
	size = deflateBound(&stream, len);
	compressed = xmalloc(size);

	/* Compress it */
	stream.next_in = buf;
	stream.avail_in = len;
	stream.next_out = compressed;
	stream.avail_out = size;
	while (deflate(&stream, Z_FINISH) == Z_OK)
		/* nothing */;
	deflateEnd(&stream);
	size = stream.total_out;

	/* And sha1 it */
	SHA1_Init(&c);
	SHA1_Update(&c, compressed, size);
	SHA1_Final(sha1, &c);

	if (sha1_buffer_write(sha1, compressed, size) < 0)
		return -1;
	if (outsha1)
		memcpy(outsha1, sha1, 20);
	return 0;
}

static void *map_sha1_file(const unsigned char *sha1, unsigned long *size)
{
	char *filename = sha1_to_path(sha1);
	int fd = open(filename, O_RDONLY);
	struct stat st;
	void *map;

	if (fd < 0) {
		perror(filename);
		return NULL;
	}
	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (-1 == (int)(long)map)
		return NULL;
	*size = st.st_size;
	return map;
}

static void *unpack_sha1_file(void *map, unsigned long mapsize, struct sha1_file_hdr *hdr)
{
	int ret, bytes;
	z_stream stream;
	char buffer[8192];
	char *buf;

	memset(&stream, 0, sizeof(stream));
	stream.next_in = map;
	stream.avail_in = mapsize;
	stream.next_out = (unsigned char *)buffer;
	stream.avail_out = sizeof(buffer);

	inflateInit(&stream);
	ret = inflate(&stream, 0);

	memcpy(hdr, buffer, sizeof(*hdr));
	bytes = sizeof(*hdr);
	buf = xmalloc(hdr->size);

	memcpy(buf, buffer + bytes, stream.total_out - bytes);
	bytes = stream.total_out - bytes;
	if (bytes < hdr->size && ret == Z_OK) {
		stream.next_out = (unsigned char *)buf + bytes;
		stream.avail_out = hdr->size - bytes;
		while (inflate(&stream, Z_FINISH) == Z_OK)
			/* nothing */;
	}
	inflateEnd(&stream);
	return buf;
}

static int verify_sha1_file(const unsigned char *sha1, void *buf, unsigned long len)
{
	unsigned char tmp[SHA1_LEN];
	SHA_CTX c;

	SHA1_Init(&c);
	SHA1_Update(&c, buf, len);
	SHA1_Final(tmp, &c);

	if (memcmp((char *)tmp, (char *)sha1, len) != 0)
		return -1;
	return 0;
}

void *sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *hdr)
{
	unsigned long mapsize;
	void *map, *buf;

	map = map_sha1_file(sha1, &mapsize);
	if (map) {
		if (verify_sha1_file(sha1, map, mapsize) < 0)
			return NULL;
		buf = unpack_sha1_file(map, mapsize, hdr);
		munmap(map, mapsize);
		return buf;
	}
	return NULL;
}

static unsigned hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return ~0;
}

int get_sha1_hex(const char *hex, unsigned char *sha1)
{
	int i;
	for (i = 0; i < SHA1_LEN; i++) {
		unsigned int val = (hexval(hex[0]) << 4) | hexval(hex[1]);
		if (val & ~0xff)
			return -1;
		*sha1++ = val;
		hex += 2;
	}
	return 0;
}

char *sha1_to_hex(const unsigned char *sha1)
{
	static char buffer[50];
	static const char hex[] = "0123456789abcdef";
	char *buf = buffer;
	int i;

	for (i = 0; i < SHA1_LEN; i++) {
		unsigned int val = *sha1++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	return buffer;
}
