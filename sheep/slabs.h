#ifndef SLABS_H
#define SLABS_H

/* Init the subsystem. 1st argument is the limit on no. of bytes to allocate,
 *  0 if no limit. 2nd argument is the growth factor; each slab will use a chunk
 *  size equal to the previous slab's chunk size times this factor.
 */
void slabs_init(const size_t limit, const double factor);

/*
 * Given object size, return id to use when allocating/freeing memory for object
 * -1 means error: can't store such a large object
 */

int slabs_clsid(const size_t size);

void *slabs_alloc(unsigned int id);

void slabs_free(void *ptr, unsigned int id);

#endif
