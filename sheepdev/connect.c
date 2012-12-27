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

int connect_to(struct socket **sock, const char *ip_addr, int port)
{
	int ret;
	struct sockaddr_in addr;

	ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, sock);
	if (ret) {
		DBPRT("fail to create socket\n");
		return ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = in_aton(ip_addr);

	ret = (*sock)->ops->connect(*sock, (struct sockaddr *)&addr,
				 sizeof(addr), 0);

	if (!ret)
		DBPRT("connected to %s:%d\n", ip_addr, port);

	return ret;
}

int do_read(struct socket *sock, char *buf, const size_t length)
{
	struct msghdr msg;
	struct iovec iov;
	int ret = 0, received = 0, left = length;
	mm_segment_t oldmm;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (left > 0) {
		oldmm = get_fs();
		set_fs(KERNEL_DS);
		msg.msg_iov->iov_base = buf + received;
		msg.msg_iov->iov_len = left;
		ret = sock_recvmsg(sock, &msg, left, MSG_WAITALL);
		set_fs(oldmm);
		if (ret <= 0)
			break;
		left -= ret;
		received += ret;
	}

	return ret;
}

static void forward_iov(struct msghdr *msg, int len)
{
	while (msg->msg_iov->iov_len <= len) {
		len -= msg->msg_iov->iov_len;
		msg->msg_iov++;
		msg->msg_iovlen--;
	}

	msg->msg_iov->iov_base = (char *) msg->msg_iov->iov_base + len;
	msg->msg_iov->iov_len -= len;
}


static int do_write(struct socket *sock, struct msghdr *msg, int len)
{
	int ret;
	mm_segment_t oldmm;

rewrite:
	oldmm = get_fs();
	set_fs(KERNEL_DS);
	ret = sock_sendmsg(sock, msg, len);
	set_fs(oldmm);

	if (ret < 0) {
		if (ret == -EINTR)
			goto rewrite;
		if (ret == -EBUSY) {
			DBPRT("busy\n");
			goto rewrite;
		}
		DBPRT("failed to write to socket: %d\n", ret);
		return -EFAULT;
	}

	len -= ret;
	if (len) {
		forward_iov(msg, ret);
		goto rewrite;
	}

	return 0;
}

int send_req(struct socket *sock, struct sd_req *hdr, void *data,
	     unsigned int wlen)
{
	int ret;
	struct msghdr msg;
	struct iovec iov[2];

	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = iov;

	msg.msg_iovlen = 1;
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(*hdr);

	if (wlen) {
		msg.msg_iovlen++;
		iov[1].iov_base = data;
		iov[1].iov_len = wlen;
	}

	ret = do_write(sock, &msg, sizeof(*hdr) + wlen);
	if (ret) {
		DBPRT("failed to send request %x, %d\n", hdr->opcode, wlen);
		ret = -EFAULT;
	}

	return ret;
}

int exec_req(struct socket *sock, struct sd_req *hdr, void *data)
{
	int ret;
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	unsigned int wlen, rlen;

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		wlen = hdr->data_length;
		rlen = 0;
	} else {
		wlen = 0;
		rlen = hdr->data_length;
	}

	if (send_req(sock, hdr, data, wlen))
		return -EFAULT;

	ret = do_read(sock, (char *)rsp, sizeof(*rsp));
	if (ret < 0) {
		DBPRT("failed to read a response\n");
		return -EFAULT;
	}

	if (rlen > rsp->data_length)
		rlen = rsp->data_length;

	if (rlen) {
		ret = do_read(sock, data, rlen);
		if (ret < 0) {
			DBPRT("failed to read the response data\n");
			return -EFAULT;
		}
	}

	return 0;
}
