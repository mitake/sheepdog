#include <pthread.h>
#include <dirent.h>

#include "farm.h"
#include "strbuf.h"
#include "list.h"
#include "slabs.h"
#include "util.h"
#include "sheepdog_proto.h"

struct __trunk_entry {
	uint64_t oid;
	unsigned char sha1[SHA1_LEN];
};

struct trunk_entry {
	struct __trunk_entry raw;
	int flags;
	struct list_head active_list;
	struct hlist_node hash;
};

#define TRUNK_ENTRY_DIRTY	0x00000001

#define trunk_entry_size() sizeof(struct trunk_entry)

#define HASH_BITS	10
#define HASH_SIZE	(1 << HASH_BITS)

static LIST_HEAD(trunk_active_list); /* no lock protection */
static struct hlist_head trunk_hashtable[HASH_SIZE];
static pthread_mutex_t hashtable_lock[HASH_SIZE] = { [0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER };
static int trunk_slab_clsid;
static unsigned int trunk_entry_active_nr;

static inline int trunk_entry_is_dirty(struct trunk_entry *entry)
{
	return entry->flags & TRUNK_ENTRY_DIRTY;
}

static inline void mark_trunk_entry_dirty(struct trunk_entry *entry)
{
	entry->flags |= TRUNK_ENTRY_DIRTY;
}

static int hash(uint64_t oid)
{
	return hash_long(oid, HASH_BITS);
}

static inline struct trunk_entry *alloc_trunk_entry(void)
{
	return (struct trunk_entry *)slabs_alloc(trunk_slab_clsid);
}

static inline void free_trunk_entry(struct trunk_entry *entry)
{
	return slabs_free(entry, trunk_slab_clsid);
}

/* if (create == 1 && not found), then create one entry. */
static struct trunk_entry *lookup_trunk_entry(uint64_t oid, int create)
{
	int h = hash(oid);
	struct hlist_head *head = trunk_hashtable + h;
	struct trunk_entry *entry = NULL;
	struct hlist_node *node;

	pthread_mutex_lock(&hashtable_lock[h]);
	if (hlist_empty(head))
		goto not_found;

	hlist_for_each_entry(entry, node, head, hash) {
		if (entry->raw.oid == oid) {
			dprintf("found node %lx\n", oid);
			goto out;
		}
	}
not_found:
	if (create) {
		entry = alloc_trunk_entry();
		entry->raw.oid = oid;
		hlist_add_head(&entry->hash, head);
		trunk_entry_active_nr++;
		list_add(&entry->active_list, &trunk_active_list);
		dprintf("add node %lx\n", oid);
	}
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return entry;
}

int trunk_init(void)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;

	trunk_slab_clsid = slabs_clsid(trunk_entry_size());
	if (trunk_slab_clsid < 0)
		panic("failed to get a sane id");
	dprintf("slab class id: %u\n", trunk_slab_clsid);

	dir = opendir(farm_dir);
	if (!dir)
		return -1;

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0)
			continue;
		lookup_trunk_entry(oid, 1);
	}
	return 0;
}

int trunk_file_write(unsigned char *outsha1)
{
	struct strbuf buf, tmp = STRBUF_INIT;
	uint64_t data_size = sizeof(struct __trunk_entry) * trunk_entry_active_nr;
	struct sha1_file_hdr hdr = { .tag = TAG_TRUNK,
				     .size = data_size,
				     .priv = trunk_entry_active_nr };
	struct trunk_entry *entry;
	int ret = 0, fd;

	strbuf_init(&buf, sizeof(hdr) + data_size);

	strbuf_add(&buf, &hdr, sizeof(hdr));
	/* add trunk data to buf */
	list_for_each_entry(entry, &trunk_active_list, active_list) {
		if (strlen((char *)entry->raw.sha1) == 0 || trunk_entry_is_dirty(entry)) {
			int len = strlen(farm_dir);
			struct sha1_file_hdr h = { .tag = TAG_DATA, .priv = 0 };

			strbuf_add(&tmp, farm_dir, len);
			strbuf_addf(&tmp, "/%016" PRIx64, entry->raw.oid);
			fd = open(tmp.buf, O_RDONLY);
			dprintf("open %s\n", tmp.buf);
			strbuf_reset(&tmp);

			if (fd < 0) {
				ret = -1;
				goto out;
			}
			if (!strbuf_read(&tmp, fd, SD_DATA_OBJ_SIZE) == SD_DATA_OBJ_SIZE) {
				ret = -1;
				close(fd);
				goto out;
			}
			h.size = tmp.len;
			strbuf_insert(&tmp, 0, &h, sizeof(h));

			if (sha1_file_write((void *)tmp.buf, tmp.len, entry->raw.sha1) < 0) {
				ret = -1;
				close(fd);
				goto out;
			}
			strbuf_reset(&tmp);
			dprintf("dirty data sha1: %s\n", sha1_to_hex(entry->raw.sha1));
		}
		strbuf_add(&buf, &entry->raw, sizeof(struct __trunk_entry));
	}
	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto out;
	}
	dprintf("trunk sha1: %s\n", sha1_to_hex(outsha1));
out:
	strbuf_release(&buf);
	strbuf_release(&tmp);
	return ret;
}
#if 0
	raw = (struct __trunk_entry *)buffer;
	for (i = 0; i < hdr.priv; i++) {
		struct trunk_entry *ent;
		ent = lookup_trunk_entry(raw->oid, 1);
		memcpy(ent->raw.sha1, raw->sha1, SHA1_LEN);
		raw++;
	}
#endif
void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer;

	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_TRUNK) != 0) {
		free(buffer);
		return NULL;
	}

	return buffer;
}

int trunk_update_entry(uint64_t oid)
{
	struct trunk_entry *entry;

	entry = lookup_trunk_entry(oid, 1);
	if (!trunk_entry_is_dirty(entry))
		mark_trunk_entry_dirty(entry);

	return 0;
}
