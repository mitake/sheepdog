#ifndef __UTIL_H__
#define __UTIL_H__

#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "bitops.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __cpu_to_be16(x) bswap_16(x)
#define __cpu_to_be32(x) bswap_32(x)
#define __cpu_to_be64(x) bswap_64(x)
#define __be16_to_cpu(x) bswap_16(x)
#define __be32_to_cpu(x) bswap_32(x)
#define __be64_to_cpu(x) bswap_64(x)
#define __cpu_to_le32(x) (x)
#else
#define __cpu_to_be16(x) (x)
#define __cpu_to_be32(x) (x)
#define __cpu_to_be64(x) (x)
#define __be16_to_cpu(x) (x)
#define __be32_to_cpu(x) (x)
#define __be64_to_cpu(x) (x)
#define __cpu_to_le32(x) bswap_32(x)
#endif

static inline int before(uint32_t seq1, uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}

static inline int after(uint32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq2 - seq1) < 0;
}

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

static inline void *zalloc(size_t size)
{
	return calloc(1, size);
}

typedef void (*try_to_free_t)(size_t);
extern try_to_free_t set_try_to_free_routine(try_to_free_t);

extern void *xmalloc(size_t size);
extern void *xzalloc(size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
extern ssize_t xread(int fd, void *buf, size_t len);
extern ssize_t xwrite(int fd, const void *buf, size_t len);

/* Integer hash functions, taken from Linux kernel.
 * Use hash_long() to get most out of your cpu.
 */

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

#if __SIZEOF_POINTER__ == 4
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_32
#define hash_long(val, bits) hash_32(val, bits)
#elif __SIZEOF_POINTER__ == 8
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_PRIME_64
#else
#error Wordsize not 32 or 64
#endif

static inline uint64_t hash_64(uint64_t val, unsigned int bits)
{
        uint64_t hash = val;

        /*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
        uint64_t n = hash;
        n <<= 18;
        hash -= n;
        n <<= 33;
        hash -= n;
        n <<= 3;
        hash += n;
        n <<= 3;
        hash -= n;
        n <<= 4;
        hash += n;
        n <<= 2;
        hash += n;

        /* High bits are more random, so use them. */
        return hash >> (64 - bits);
}

static inline uint32_t hash_32(uint32_t val, unsigned int bits)
{
        /* On some cpus multiply is faster, on others gcc will do shifts */
        uint32_t hash = val * GOLDEN_RATIO_PRIME_32;

        /* High bits are more random, so use them. */
        return hash >> (32 - bits);
}

#endif
