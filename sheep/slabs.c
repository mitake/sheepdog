#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdint.h>

#include "slabs.h"
#include "logger.h"
#include "util.h"

struct slab_class {
	unsigned int size;      /* size of item */
	unsigned int nr_perslab;   /* how many items per slab */

	void **freed_slots;           /* array of items freed */
	unsigned int total_free;  /* size of previous array */
	unsigned int free;

	void *last_slab_ptr;         /* pointer to next free item, or 0 to ask for new slab */
	unsigned int last_slab_free; /* number of items remaining at end of last alloced slab */

	void **slab_slots;       /* array of slab pointers */
	unsigned int total_slots; /* size of slots array */
	unsigned int alloc;
};

/* Slab sizing definitions. */
#define POWER_SMALLEST 0
#define POWER_LARGEST  200
#define CHUNK_ALIGN_BYTES 8
#define MAX_NUMBER_OF_SLAB_CLASSES (POWER_LARGEST)

static struct slab_class slab_classes[MAX_NUMBER_OF_SLAB_CLASSES];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

/* N.B. So the smallest item will occupy 16 bytes and the biggest one
 * up to 128k, that is, one slab.
 */
static int min_chunk_size = 16;
static int max_chunk_size = 4096 * 32;

static pthread_mutex_t slabs_lock = PTHREAD_MUTEX_INITIALIZER;

static int try_grow_slab_slots(const unsigned int id)
{
	struct slab_class *p = &slab_classes[id];

	if (p->alloc == p->total_slots) {
		size_t new_size =  (p->total_slots != 0) ? p->total_slots * 2 : 16;
		void *new_slots = xrealloc(p->slab_slots, new_size * sizeof(void *));

		p->total_slots = new_size;
		p->slab_slots = new_slots;
		return 1;
	}
	return 0;
}

int slabs_clsid(const size_t size)
{
	int ret = POWER_SMALLEST;

	if (size == 0)
		return -1;

	while (ret <= power_largest && size > slab_classes[ret].size) {
		if (ret > power_largest)
			return -1;
		ret++;
	}
	try_grow_slab_slots(ret);
	return ret;
}

void slabs_init(const size_t limit, const double factor)
{
	int i = POWER_SMALLEST;
	unsigned int size = min_chunk_size;

	mem_limit = limit;

	while (i < POWER_LARGEST && size <= max_chunk_size) {
		if (size % CHUNK_ALIGN_BYTES)
			size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

		slab_classes[i].size = size;
		slab_classes[i].nr_perslab = max_chunk_size / size;
		if (max_chunk_size / size == 1) {
			slab_classes[i].size = max_chunk_size;
			dprintf("slab class %3d: chunk size %9u nr_perslab %7u\n",
				i, slab_classes[i].size, slab_classes[i].nr_perslab);
			power_largest = i;
			return;
		}

		dprintf("slab class %3d: chunk size %9u nr_perslab %7u\n",
			i, slab_classes[i].size, slab_classes[i].nr_perslab);
		size *= factor;
		power_largest = i;
		i++;
	}
}

static int alloc_last_slab(const unsigned int id)
{
	struct slab_class *p = &slab_classes[id];
	size_t len = p->size * p->nr_perslab;
	char *ptr;

	if (mem_limit && mem_malloced + len > mem_limit && p->alloc > 0) {
		/* FIXME: reclaim freed slots */
		eprintf("slab: out of memory limit\n");
		return 0;
	}

	if (try_grow_slab_slots(id) < 0)
		return 0;

	ptr = xzalloc(len);
	p->last_slab_ptr = ptr;
	p->last_slab_free = p->nr_perslab;

	p->slab_slots[p->alloc++] = ptr;
	mem_malloced += len;

	return 1;
}

static void *do_slabs_alloc(unsigned int id)
{
	struct slab_class *p;
	void *ret = NULL;

	if (id < POWER_SMALLEST || id > power_largest)
		goto out;

	p = &slab_classes[id];

	if (p->free != 0) {
		p->free--;
		ret = p->freed_slots[p->free];
	} else {
		if (!p->last_slab_ptr)
			if (!alloc_last_slab(id))
				goto out;

		ret = p->last_slab_ptr;
		p->last_slab_free--;
		if (p->last_slab_free > 0) {
			p->last_slab_ptr = ((char *)p->last_slab_ptr) + p->size;
		} else {
			p->last_slab_ptr = 0;
		}

	}
out:
	return ret;
}

static void do_slabs_free(void *ptr, unsigned int id)
{
	struct slab_class *p;

	if (id < POWER_SMALLEST || id > power_largest)
		return;

	p = &slab_classes[id];

	/* Grow or init ... */
	if (p->free == p->total_free) {
		int new_size = (p->total_free != 0) ? p->total_free * 2 : 16;  /* 16 is arbitrary */
		void **new_slots = xrealloc(p->freed_slots, new_size * sizeof(void *));

		p->freed_slots = new_slots;
		p->total_free = new_size;
	}

	p->freed_slots[p->free++] = ptr;

	return;
}

void *slabs_alloc(unsigned int id) {
	void *ret;

	pthread_mutex_lock(&slabs_lock);
	ret = do_slabs_alloc(id);
	pthread_mutex_unlock(&slabs_lock);
	return ret;
}

void slabs_free(void *ptr, unsigned int id) {
	pthread_mutex_lock(&slabs_lock);
	do_slabs_free(ptr, id);
	pthread_mutex_unlock(&slabs_lock);
}
