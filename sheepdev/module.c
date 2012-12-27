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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include "sheep.h"

static int sheepdev_major;
spinlock_t devices_lock;
struct list_head dev_list;
static unsigned long *device_bitmap;
static struct proc_dir_entry *sheep_proc_entry;

static void sheepdev_get(struct sheepdev *dev)
{
	atomic_inc(&dev->struct_refcnt);
}

static void sheepdev_put(struct sheepdev *dev)
{
	if (atomic_dec_and_test(&dev->struct_refcnt))
		kfree(dev);
}

static int add_request(struct sheepdev *dev, struct request *req, uint64_t oid,
		       int idx)
{
	struct sheep_request *s_req = kmalloc(sizeof(*s_req), GFP_KERNEL);
	if (!s_req)
		return -EIO;

	s_req->req_id = dev->req_id;
	s_req->req = req;
	s_req->oid = oid;
	s_req->idx = idx;
	INIT_LIST_HEAD(&s_req->list);

	spin_lock_irq(&dev->fin_lock);
	list_add_tail(&s_req->list, &dev->finish_list);
	spin_unlock_irq(&dev->fin_lock);

	if (dev->req_id > UINT_MAX)
		dev->req_id = 1;
	else
		dev->req_id++;

	return 0;
}

static void sheep_end_request(struct request *req, int ret)
{
	struct request_queue *q = req->q;
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	__blk_end_request_all(req, ret);
	spin_unlock_irqrestore(q->queue_lock, flags);
}

static int sheep_handle_request(struct request *req)
{
	struct req_iterator iter;
	struct bio_vec *bvec;
	struct gendisk *disk = req->rq_disk;
	struct sheepdev *dev = disk->private_data;
	unsigned long sector = blk_rq_pos(req);
	unsigned long offset = sector * KERNEL_SECTOR_SIZE;
	unsigned long nbytes = blk_rq_bytes(req);
	int idx = offset / SHEEP_OBJECT_SIZE + 1;
	uint64_t oid = vid_to_data_oid(dev->vid, idx);
	uint64_t off = offset % SHEEP_OBJECT_SIZE;
	int ret = 0, len = 0, create = 0;
	int write = rq_data_dir(req);
	void *sheep_buf = NULL;

	if (!write && dev->inode->data_vdi_id[idx] != dev->vid) {
		rq_for_each_segment(bvec, req, iter) {
			void *addr = kmap(bvec->bv_page);
			memset(addr + bvec->bv_offset, 0, bvec->bv_len);
			kunmap(bvec->bv_page);
		}
		sheep_end_request(req, 0);
		return 0;
	} else if (!write) {
		ret = send_read_req(dev, oid, nbytes, off);
		if (ret)
			return -EIO;

		ret = add_request(dev, req, oid, idx);
		if (ret)
			return -EIO;

		return 0;
	}

	/* For write requests */
	sheep_buf = kmalloc(nbytes, GFP_KERNEL);
	if (!sheep_buf)
		return -EIO;

	spin_lock(&dev->creating_lock);
	if (!dev->inode->data_vdi_id[idx]) {
		dev->inode->data_vdi_id[idx] = 1;
		create = 1;
		spin_unlock(&dev->creating_lock);
	} else if (dev->inode->data_vdi_id[idx] != dev->vid){

		spin_unlock(&dev->creating_lock);
		wait_event_interruptible(dev->creating_wait,
				dev->inode->data_vdi_id[idx] == dev->vid);
	} else
		spin_unlock(&dev->creating_lock);

	rq_for_each_segment(bvec, req, iter) {
		void *addr = kmap(bvec->bv_page);

		memcpy(sheep_buf + len, addr + bvec->bv_offset, bvec->bv_len);
		len += bvec->bv_len;

		if (rq_iter_last(req, iter)) {
			ret = send_write_req(dev, oid, sheep_buf, len, off,
					     create);
			if (ret != SD_RES_SUCCESS) {
				kunmap(bvec->bv_page);
				ret = -EIO;
				goto out;
			}

			ret = add_request(dev, req, oid, idx);
			if (ret) {
				kunmap(bvec->bv_page);
				ret = -EIO;
				goto out;
			}

			if (!create)
				goto done;

			/* For create operations we need to update inode data */
			oid = vid_to_vdi_oid(dev->vid);
			off = offsetof(struct sheepdog_inode, data_vdi_id);
			off += sizeof(uint32_t) * idx;
			ret = send_write_req(dev, oid, (char *)&dev->vid,
					     sizeof(dev->vid), off, 0);
			if (ret != SD_RES_SUCCESS) {
				kunmap(bvec->bv_page);
				ret = -EIO;
				goto out;
			}

			ret = add_request(dev, req, oid, idx);
			if (ret) {
				kunmap(bvec->bv_page);
				ret = -EIO;
				goto out;
			}
done:;
		}

		kunmap(bvec->bv_page);
	}

out:
	kfree(sheep_buf);
	return ret;
}

static void sheep_request(struct request_queue *rq)
{
	struct request *req;
	struct gendisk *disk;
	struct sheepdev *dev;

	while ((req = blk_fetch_request(rq)) != NULL) {

		disk = req->rq_disk;
		dev = disk->private_data;

		if (req->cmd_type != REQ_TYPE_FS) {
			DBPRT("Skip non-fs request\n");
			__blk_end_request_all(req, -EIO);
		}

		spin_lock(&dev->req_lock);
		list_add_tail(&req->queuelist, &dev->pending_list);
		spin_unlock(&dev->req_lock);

		wake_up_interruptible(&dev->req_wait);
	}
}

static int req_process_func(void *data)
{
	struct sheepdev *dev = (struct sheepdev *)data;
	struct request *req;
	int ret;

	sheepdev_get(dev);

	while (!kthread_should_stop() || !list_empty(&dev->pending_list)) {
		wait_event_interruptible(dev->req_wait,
					 !list_empty(&dev->pending_list) ||
					 kthread_should_stop());

		spin_lock(&dev->req_lock);
		if (list_empty(&dev->pending_list)) {
			spin_unlock(&dev->req_lock);
			continue;
		}

		req = list_entry(dev->pending_list.next, struct request,
				 queuelist);
		list_del_init(&req->queuelist);
		spin_unlock(&dev->req_lock);

		ret = sheep_handle_request(req);
		if (ret)
			sheep_end_request(req, ret);
		else
			wake_up_interruptible(&dev->fin_wait);
	}

	sheepdev_put(dev);

	return 0;
}

static int sheepdev_open(struct block_device *blkdev, fmode_t mode)
{
	struct gendisk *disk = blkdev->bd_disk;
	struct sheepdev *dev = disk->private_data;

	spin_lock(&dev->dev_lock);
	dev->device_refcnt++;
	spin_unlock(&dev->dev_lock);

	return 0;
}

static int sheepdev_release(struct gendisk *disk, fmode_t mode)
{
	struct sheepdev *dev = disk->private_data;

	spin_lock(&dev->dev_lock);
	dev->device_refcnt--;
	spin_unlock(&dev->dev_lock);

	return 0;
}

static struct block_device_operations sheepdev_ops = {
	.owner = THIS_MODULE,
	.open = sheepdev_open,
	.release = sheepdev_release,
};

static int sheep_add_disk(struct sheepdev *dev)
{
	int ret;
	struct request_queue *queue;

	dev->disk = alloc_disk(SHEEP_BLKDEV_MINORS);
	if (!dev->disk) {
		DBPRT("allocate gendisk failure\n");
		ret = -EBUSY;
		return ret;
	}
	queue = blk_init_queue(sheep_request, &dev->que_lock);
	/* 4M boundary */
	blk_queue_segment_boundary(queue, 0x3fffff);
	dev->disk->major = sheepdev_major;
	dev->disk->first_minor = dev->minor * SHEEP_BLKDEV_MINORS;
	dev->disk->queue = queue;
	dev->disk->fops = &sheepdev_ops;
	dev->disk->private_data = dev;
	snprintf(dev->disk->disk_name, sizeof(dev->disk->disk_name),
		 SHEEP_BLKDEV_NAME"%c", dev->minor + 'a');

	set_capacity(dev->disk, dev->sectors);
	add_disk(dev->disk);

	return 0;
}

static struct sheep_request *find_request(struct sheepdev *dev, int id)
{
	struct sheep_request *req, *t;

	spin_lock_irq(&dev->fin_lock);
	list_for_each_entry_safe(req, t, &dev->finish_list, list) {
		if (req->req_id != id)
			continue;
		list_del_init(&req->list);
		spin_unlock_irq(&dev->fin_lock);
		return req;
	}
	spin_unlock_irq(&dev->fin_lock);

	return NULL;
}

static int read_reply(struct sheepdev *dev, int *req_id, int *result,
		      void **data)
{
	int ret;
	struct sd_rsp rsp;
	void *buf = NULL;

	*result = 0;
	*req_id = 0;
	*data = NULL;

	ret = do_read(dev->sock, (char *)&rsp, sizeof(rsp));
	if (ret < 0) {
		DBPRT("failed to read response\n");
		return -EIO;
	}

	if (rsp.data_length > 0) {
		buf = kmalloc(rsp.data_length, GFP_KERNEL);
		if (!buf) {
			DBPRT("No-mem\n");
			return -ENOMEM;
		}

		ret = do_read(dev->sock, buf, rsp.data_length);
		if (ret != rsp.data_length) {
			kfree(buf);
			return -EIO;
		}
	}

	*req_id = rsp.id;
	*result = rsp.result;
	*data = buf;

	return 0;
}

static void cleanup_finish_list(struct sheepdev *dev)
{
	struct sheep_request *req, *t;

	spin_lock(&dev->fin_lock);
	list_for_each_entry_safe(req, t, &dev->finish_list, list) {
		list_del_init(&req->list);
		sheep_end_request(req->req, -EIO);
		kfree(req);
	}

	spin_unlock(&dev->fin_lock);
}

static int fin_process_func(void *data)
{
	struct sheepdev *dev = data;
	struct sheep_request *sheep_req;
	struct request *req;
	int ret, req_id, res;

	sheepdev_get(dev);

	while (!kthread_should_stop() || !list_empty(&dev->finish_list)) {
		void *buf = NULL;

		wait_event_interruptible(dev->fin_wait,
					 !list_empty(&dev->finish_list) ||
					 kthread_should_stop());

		spin_lock_irq(&dev->fin_lock);
		if (list_empty(&dev->finish_list)) {
			spin_unlock_irq(&dev->fin_lock);
			continue;
		}
		spin_unlock_irq(&dev->fin_lock);

		ret = read_reply(dev, &req_id, &res, &buf);
		if (ret) {
			cleanup_finish_list(dev);
			continue;
		}

		sheep_req = find_request(dev, req_id);
		if (!sheep_req)
			goto next;
		req = sheep_req->req;

		if (rq_data_dir(req)) {
			int idx;

			res = (res != SD_RES_SUCCESS) ? -EIO : 0;
			if (sheep_req->oid == vid_to_vdi_oid(dev->vid)) {
				/* inode-update response */
				idx = sheep_req->idx;
			} else {
				/* oridinary write response */
				idx = data_oid_to_idx(sheep_req->oid);

				/* obj already exist */
				if (dev->inode->data_vdi_id[idx] == dev->vid) {
					sheep_end_request(req, res);
					goto next;
				}
			}

			spin_lock(&dev->creating_lock);
			if (dev->inode->data_vdi_id[idx] == 2) {
				/*
				 * Both obj-write and inode-update are complete
				 * we can end the write request and wake other
				 * requests waiting for this object.
				 */
				dev->inode->data_vdi_id[idx] = dev->vid;
				spin_unlock(&dev->creating_lock);

				sheep_end_request(req, res);
				wake_up_interruptible(&dev->creating_wait);

				goto next;
			} else {
				/*
				 * wait for obj-write or inode-update to complete
				 */
				dev->inode->data_vdi_id[idx]++;
			}
			spin_unlock(&dev->creating_lock);

		} else {
			int len = 0;
			struct req_iterator iter;
			struct bio_vec *bvec;

			if (res != SD_RES_SUCCESS) {
				sheep_end_request(req, -EIO);
				goto next;
			}

			rq_for_each_segment(bvec, req, iter) {
				void *addr = kmap(bvec->bv_page);
				memcpy(addr + bvec->bv_offset, buf + len,
				       bvec->bv_len);
				len += bvec->bv_len;
				kunmap(bvec->bv_page);
			}
			sheep_end_request(req, 0);
		}
next:
		kfree(buf);
		kfree(sheep_req);
	}

	sheepdev_put(dev);
	return 0;
}

static int dev_setup(struct sheepdev *dev)
{
	int ret;

	ret = sheep_vdi_setup(dev);
	if (ret) {
		return ret;
	}

	spin_lock_init(&dev->que_lock);
	spin_lock_init(&dev->req_lock);
	spin_lock_init(&dev->fin_lock);
	spin_lock_init(&dev->dev_lock);
	spin_lock_init(&dev->creating_lock);
	init_waitqueue_head(&dev->req_wait);
	init_waitqueue_head(&dev->fin_wait);
	init_waitqueue_head(&dev->creating_wait);
	INIT_LIST_HEAD(&dev->pending_list);
	INIT_LIST_HEAD(&dev->finish_list);
	INIT_LIST_HEAD(&dev->dev_list);

	dev->req_id = 1;
	dev->req_thread = kthread_run(req_process_func, dev,
				      "sheep_req");
	dev->fin_thread = kthread_run(fin_process_func, dev,
				      "sheep_fin");

	ret = sheep_add_disk(dev);
	if (ret) {
		return ret;
	}

	return 0;
}

#define MAX_CMD_LEN 64

static int process_add_command(char *buf, int len)
{
	int i, ret = 0;
	struct sheepdev *dev;

	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	memset(dev, 0, sizeof(*dev));

	for (i = 0; buf[i] != '\0' && buf[i] != '\n' &&
	     buf[i] != ' ' && buf[i] != ':' && i < len; i++);

	if (buf[i] != ' ' && buf[i] != ':') {
		ret = -EINVAL;
		goto out;
	}

	memcpy(dev->ip_addr, buf, i);
	dev->ip_addr[i] = '\0';
	if (buf[i] == ' ') {
		dev->port = SD_LISTEN_PORT;
		buf = &buf[i + 1];
	} else {
		/* start from ':' to ' ' */
		char *tmp = &buf[i + 1];
		len -= (i + 1);
		for (i = 0; tmp[i] != ' ' && tmp[i] != '\0' &&
		     tmp[i] != '\n' && i < len; i++);
		if (tmp[i] != ' ') {
			ret = -EINVAL;
			goto out;
		}
		tmp[i] = '\0';
		buf = &tmp[i + 1];
		dev->port = simple_strtol(tmp, NULL, 10);
	}

	dev->vid = simple_strtol(buf, NULL, 16);

	spin_lock(&devices_lock);
	dev->minor = find_next_zero_bit(device_bitmap, SHEEP_BLKDEV_MINORS, 0);
	set_bit(dev->minor, device_bitmap);
	spin_unlock(&devices_lock);

	ret = dev_setup(dev);
	if (ret) {
		clear_bit(dev->minor, device_bitmap);
		goto out;
	} else {
		sheepdev_get(dev);
		spin_lock(&devices_lock);
		list_add_tail(&dev->dev_list, &dev_list);
		spin_unlock(&devices_lock);
	}

	return ret;
out:
	kfree(dev);
	return ret;
}

static void remove_device(struct sheepdev *dev)
{
	DBPRT("remove device /dev/%s\n", dev->disk->disk_name);

	kthread_stop(dev->req_thread);
	kthread_stop(dev->fin_thread);
	wake_up_interruptible(&dev->req_wait);
	wake_up_interruptible(&dev->fin_wait);

	blk_cleanup_queue(dev->disk->queue);
	del_gendisk(dev->disk);
	put_disk(dev->disk);

	clear_bit(dev->minor, device_bitmap);
	inet_release(dev->sock);

	sheepdev_put(dev);
}

static int process_del_command(char *buf, int len)
{
	struct sheepdev *dev, *t;
	int ret = 0;

	if (buf[len - 1] != '\n')
		return -EINVAL;
	buf[len - 1] = '\0';

	spin_lock(&devices_lock);
	list_for_each_entry_safe(dev, t, &dev_list, dev_list) {
		if (strcmp(buf, dev->disk->disk_name) != 0)
			continue;

		spin_lock(&dev->dev_lock);
		if (dev->device_refcnt) {
			spin_unlock(&dev->dev_lock);
			ret = -EBUSY;
		} else {
			spin_unlock(&dev->dev_lock);
			list_del_init(&dev->dev_list);
			remove_device(dev);
		}

		break;
	}
	spin_unlock(&devices_lock);

	return ret;
}

static ssize_t sheep_proc_write(struct file *filp, const char __user *buf,
				size_t len, loff_t *offset)
{
	char *kern_buf, cmd_buf[MAX_CMD_LEN];
	int i, ret;

	kern_buf = kmalloc(len, GFP_KERNEL);
	if (!kern_buf)
		return -ENOMEM;

	if (copy_from_user(kern_buf, buf, len)) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; kern_buf[i] != '\0' && kern_buf[i] != '\n' &&
	     kern_buf[i] != ' ' && i < len; i++);

	if (i > MAX_CMD_LEN || kern_buf[i] != ' ') {
		ret = -EINVAL;
		goto out;
	}
	memcpy(cmd_buf, kern_buf, i);
	cmd_buf[i] = '\0';
	if (strcmp(cmd_buf, "add") == 0) {
		ret = process_add_command(&kern_buf[i + 1], len - i - 1);
		if (ret)
			goto out;
	} else if (strcmp(cmd_buf, "del") == 0) {
		ret = process_del_command(&kern_buf[i + 1], len - i - 1);
		if (ret)
			goto out;

	} else {
		ret = -EINVAL;
		goto out;
	}

	ret = len;
out:
	kfree(kern_buf);
	return ret;
}

static struct file_operations sheep_proc_fops = {
	.write = sheep_proc_write,
};

static int __init sheep_module_init(void)
{
	int ret;

	DBPRT("Block device driver for Sheepdog\n");

	spin_lock_init(&devices_lock);
	INIT_LIST_HEAD(&dev_list);
	device_bitmap = kmalloc(SHEEP_BLKDEV_MINORS / 8, GFP_KERNEL);
	if (!device_bitmap)
		return -ENOMEM;
	memset(device_bitmap, 0, SHEEP_BLKDEV_MINORS / 8);

	/* create proc entry for sheep control */
	sheep_proc_entry = create_proc_entry(PROC_ENTRY_NAME,
					     S_IFREG | S_IRUGO | S_IWUGO, NULL);
	if (!sheep_proc_entry)
		return -ENOMEM;

	sheep_proc_entry->proc_fops = &sheep_proc_fops;

	sheepdev_major = register_blkdev(0, SHEEP_BLKDEV_NAME);
	if (sheepdev_major < 0) {
		ret = sheepdev_major;
		goto error;
	}

	return 0;

error:
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
	return ret;
}

static void __exit sheep_module_exit(void)
{
	struct sheepdev *dev, *t;

	list_for_each_entry_safe(dev, t, &dev_list, dev_list) {
		list_del_init(&dev->dev_list);
		remove_device(dev);
	}

	remove_proc_entry(PROC_ENTRY_NAME, NULL);
	unregister_blkdev(sheepdev_major, SHEEP_BLKDEV_NAME);

	kfree(device_bitmap);

	DBPRT("Sheepdog Block Device Removed.\n");
}

module_init(sheep_module_init);
module_exit(sheep_module_exit);

MODULE_LICENSE("GPL");
