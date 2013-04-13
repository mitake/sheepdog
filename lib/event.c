/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <signal.h>
#include <time.h>

#include "list.h"
#include "util.h"
#include "event.h"
#include "logger.h"

static int efd;
static LIST_HEAD(events_list);

#define TICK 1

struct timer_desc {
	int pipe[2];
	unsigned int msec;

	timer_t timerid;
	struct timer *t;

	struct list_head list;
};

static LIST_HEAD(timer_list);

static void timer_handler(int fd, int events, void *data)
{
	struct timer_desc *desc = data;
	struct timer *t = desc->t;
	uint64_t val;

	assert(fd == desc->pipe[0]);

	if (read(fd, &val, sizeof(val)) < 0)
		return;

	t->callback(t->data);

	timer_delete(desc->timerid);
	list_del(&desc->list);

	unregister_event(fd);
	close(desc->pipe[0]);
	close(desc->pipe[1]);

	free(desc);
}

static void insert_timer_desc(struct timer_desc *t)
{
	struct timer_desc *p;
	struct list_head *pred;

	pred = NULL;

	list_for_each_entry(p, &timer_list, list) {
		if (p->msec < t->msec)
			continue;

		pred = &p->list;
		break;
	}

	if (!pred)
		pred = &timer_list;

	list_add(&t->list, pred);
}

void add_timer(struct timer *t, unsigned int mseconds)
{
	int ret;
	struct timer_desc *desc;
	struct itimerspec it;

	desc = xzalloc(sizeof(*desc));
	desc->msec = mseconds;
	INIT_LIST_HEAD(&desc->list);

	ret = timer_create(CLOCK_MONOTONIC, NULL, &desc->timerid);
	if (ret < 0) {
		sd_eprintf("timer_create: %m");
		goto free_timer_desc;
	}

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = mseconds / 1000;
	it.it_value.tv_nsec = (mseconds % 1000) * 1000000;

	if (timer_settime(desc->timerid, 0, &it, NULL) < 0) {
		sd_eprintf("timerfd_settime: %m");
		goto del_timer;
	}

	ret = pipe(desc->pipe);
	if (ret < 0) {
		sd_eprintf("pipe: %m");
		goto del_timer;
	}

	if (register_event(desc->pipe[0], timer_handler, desc) < 0) {
		sd_eprintf("failed to register timer fd");
		goto close_pipe;
	}

	desc->t = t;
	insert_timer_desc(desc);

	return;

close_pipe:
	close(desc->pipe[0]);
	close(desc->pipe[1]);
del_timer:
	timer_delete(desc->timerid);
free_timer_desc:
	free(desc);
}

static void sigalrm_handler(int signum)
{
	struct timer_desc *t;
	uint64_t val = 0;

	assert(signum == SIGALRM);
	assert(!list_empty(&timer_list));

	t = list_first_entry(&timer_list, struct timer_desc, list);
	write(t->pipe[1], &val, sizeof(val));
}

void init_timer(void)
{
	if (install_sighandler(SIGALRM, sigalrm_handler, false) < 0)
		panic("install_sighandler() failed: %m");
}

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct list_head ei_list;
	int prio;
};

static struct epoll_event *events;
static int nr_events;

int init_event(int nr)
{
	nr_events = nr;
	events = xcalloc(nr_events, sizeof(struct epoll_event));

	efd = epoll_create(nr);
	if (efd < 0) {
		sd_eprintf("failed to create epoll fd");
		return -1;
	}
	return 0;
}

static struct event_info *lookup_event(int fd)
{
	struct event_info *ei;

	list_for_each_entry(ei, &events_list, ei_list) {
		if (ei->fd == fd)
			return ei;
	}
	return NULL;
}

int register_event_prio(int fd, event_handler_t h, void *data, int prio)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = xzalloc(sizeof(*ei));
	ei->fd = fd;
	ei->handler = h;
	ei->data = data;
	ei->prio = prio;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		sd_eprintf("failed to add epoll event: %m");
		free(ei);
	} else
		list_add(&ei->ei_list, &events_list);

	return ret;
}

void unregister_event(int fd)
{
	int ret;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei)
		return;

	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		sd_eprintf("failed to delete epoll event for fd %d: %m", fd);

	list_del(&ei->ei_list);
	free(ei);
}

int modify_event(int fd, unsigned int new_events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		sd_eprintf("event info for fd %d not found", fd);
		return 1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = new_events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		sd_eprintf("failed to delete epoll event for fd %d: %m", fd);
		return 1;
	}
	return 0;
}

static bool event_loop_refresh;

void event_force_refresh(void)
{
	event_loop_refresh = true;
}

static int epoll_event_cmp(const void *_a, const void *_b)
{
	struct event_info *a, *b;

	a = (struct event_info *)((struct epoll_event *)_a)->data.ptr;
	b = (struct event_info *)((struct epoll_event *)_b)->data.ptr;

	/* we need sort event_info array in reverse order */
	if (a->prio < b->prio)
		return 1;
	else if (b->prio < a->prio)
		return -1;

	return 0;
}

static void do_event_loop(int timeout, bool sort_with_prio)
{
	int i, nr;

refresh:
	nr = epoll_wait(efd, events, nr_events, TICK * 1000);
	if (sort_with_prio)
		qsort(events, nr, sizeof(struct epoll_event), epoll_event_cmp);

	if (nr < 0) {
		if (errno == EINTR)
			return;
		sd_eprintf("epoll_wait failed: %m");
		exit(1);
	} else if (nr) {
		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);

			if (event_loop_refresh) {
				event_loop_refresh = false;
				goto refresh;
			}
		}
	}
}

void event_loop(int timeout)
{
	do_event_loop(timeout, false);
}

void event_loop_prio(int timeout)
{
	do_event_loop(timeout, true);
}
