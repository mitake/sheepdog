/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Levin Li <xingke.lwp@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SHEEP_H_
#define __SHEEP_H_

#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/list.h>
#include <asm/atomic.h>
#include <net/inet_common.h>
#include <linux/inet.h>
#include "sheepdog_proto.h"

#define SHEEP_OBJECT_SIZE (4 * 1024 * 1024)

#define SHEEP_BLKDEV_NAME "sheep"
#define PROC_ENTRY_NAME "sheep"
#define KERNEL_SECTOR_SIZE 512
#define SHEEP_BLKDEV_MINORS 1024

#define DBPRT(fmt, args...) printk(KERN_DEBUG "sheep: " fmt, ##args)

struct sheepdev {
	struct gendisk *disk;
	struct socket *sock;
	char ip_addr[16];
	unsigned int port;
	unsigned int minor;
	unsigned int req_id;
	unsigned int vid;
	unsigned long size;
	unsigned long sectors;
	atomic_t struct_refcnt;
	unsigned int device_refcnt;
	spinlock_t dev_lock;
	spinlock_t req_lock;
	spinlock_t fin_lock;
	spinlock_t que_lock;
	spinlock_t creating_lock;
	struct task_struct *req_thread;
	struct task_struct *fin_thread;
	wait_queue_head_t req_wait;
	wait_queue_head_t fin_wait;
	wait_queue_head_t creating_wait;
	struct list_head pending_list;
	struct list_head finish_list;
	struct list_head dev_list;
	struct sheepdog_inode *inode;
};

struct sheep_request {
	int req_id;
	int idx; /* idx is only used when update inode */
	uint64_t oid;
	struct request *req;
	struct list_head list;
};

/* connect.c */
int connect_to(struct socket **sock, const char *addr, int port);
int send_req(struct socket *sock, struct sd_req *hdr, void *data,
	     unsigned int wlen);
int do_read(struct socket *sock, char *buf, const size_t length);
int exec_req(struct socket *sock, struct sd_req *hdr, void *data);

/* sheep.c */
int send_read_req(struct sheepdev *sheepdev, uint64_t oid,
		  unsigned int datalen, uint64_t offset);
int send_write_req(struct sheepdev *sheepdev, uint64_t oid, void *data,
		   unsigned int datalen, uint64_t offset, int create);
int sheep_vdi_setup(struct sheepdev *sheep_dev);

#endif
