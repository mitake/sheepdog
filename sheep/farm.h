#ifndef FARM_H
#define FARM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <zlib.h>

#include "sheepdog_proto.h"
#include "sheep.h"
#include "logger.h"
#include "strbuf.h"

#define SHA1_LEN        20
#define HEX_LEN         40
#define NAME_LEN        HEX_LEN

#define TAG_LEN         6
#define TAG_DATA        "data\0\0"
#define TAG_TRUNK       "trunk\0"
#define TAG_SNAP        "snap\0\0"

struct sha1_file_hdr {
	char tag[TAG_LEN];
	uint64_t size;
	uint64_t priv;
	uint64_t reserved;
};

struct trunk_entry {
	uint64_t oid;
	unsigned char sha1[SHA1_LEN];
};

struct trunk_entry_incore {
	struct trunk_entry raw;
	int flags;
	struct list_head active_list;
	struct hlist_node hash;
};

extern char *epoch_path;

/* sha1_file.c */
extern char *sha1_to_path(const unsigned char *sha1);
extern int sha1_file_write(unsigned char *buf, unsigned len, unsigned char *outsha1);
extern void * sha1_file_read(const unsigned char *sha1, struct sha1_file_hdr *hdr);
extern char * sha1_to_hex(const unsigned char *sha1);
extern int get_sha1_hex(const char *hex, unsigned char *sha1);
extern int sha1_file_try_delete(const unsigned char *sha1);

/* trunk.c */
extern int trunk_init(void);
extern int trunk_file_write(unsigned char *outsha1, int user);
extern void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *);
extern int trunk_update_entry(uint64_t oid);
extern void trunk_reset(void);
extern void trunk_put_entry(uint64_t oid);
extern void trunk_get_entry(uint64_t oid);

#endif
