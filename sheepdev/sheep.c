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

#include "sheep.h"
#include "sheepdog_proto.h"

static void sd_init_req(struct sd_req *req, uint8_t opcode)
{
	memset(req, 0, sizeof(*req));
	req->opcode = opcode;
}

static int read_object(struct sheepdev *dev, uint64_t oid, void *data,
		       unsigned int datalen, uint64_t offset)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.id = 0;
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_req(dev->sock, &hdr, data);

	if (ret < 0) {
		DBPRT("Failed to read object %llx\n", oid);
		return SD_RES_EIO;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		DBPRT("Failed to read object %llx,%d\n", oid,
		      rsp->result);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int send_read_req(struct sheepdev *dev, uint64_t oid,
		  unsigned int datalen, uint64_t offset)
{
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.id = dev->req_id;
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = send_req(dev->sock, &hdr, NULL, 0);

	if (ret < 0) {
		DBPRT("Failed to read object %llx\n", oid);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int send_write_req(struct sheepdev *dev, uint64_t oid, void *data,
		   unsigned int datalen, uint64_t offset, int create)
{
	struct sd_req hdr;
	int ret;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);

	hdr.id = dev->req_id;
	hdr.data_length = datalen;
	hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	hdr.obj.copies = dev->inode->nr_copies;

	ret = send_req(dev->sock, &hdr, data, datalen);

	if (ret < 0) {
		DBPRT("Failed to write object %llx\n", oid);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int sheep_vdi_setup(struct sheepdev *dev)
{
	int ret;
	struct sheepdog_inode *inode;

	inode = vmalloc(sizeof(*inode));
	if (!inode)
		return -ENOMEM;
	memset(inode, 0 , sizeof(*inode));

	ret = connect_to(&dev->sock, dev->ip_addr, dev->port);
	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	ret = read_object(dev, vid_to_vdi_oid(dev->vid), inode,
			  SD_INODE_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		ret = -EFAULT;
		goto out;
	}

	dev->size = inode->vdi_size - SHEEP_OBJECT_SIZE;
	dev->sectors = dev->size / KERNEL_SECTOR_SIZE;
	dev->inode = inode;

	return 0;
out:
	vfree(inode);
	return ret;
}
