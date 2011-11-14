#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

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

void *xrealloc(void *ptr, size_t size)
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
