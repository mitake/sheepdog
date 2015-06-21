/*
 * Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "sheep.h"
#include "internal_proto.h"
#include "rbtree.h"
#include "event.h"
#include "work.h"
#include "sheep_priv.h"

#include "xio.h"

#include <libxio.h>

/* server private data */
struct server_data {
	struct xio_context	*ctx;
};

static int server_on_request(struct xio_session *session,
			     struct xio_msg *xio_req,
			     int last_in_rxq,
			     void *cb_user_context)
{
	struct client_info *ci;
	struct sd_req *hdr;
	struct request *req;

	struct xio_iovec_ex *sglist = vmsg_sglist(&xio_req->in);
	int nents = vmsg_sglist_nents(&xio_req->in);

	struct xio_session_attr attr;

	memset(&attr, 0, sizeof(attr));
	xio_query_session(session, &attr, XIO_SESSION_ATTR_USER_CTX);
	ci = (struct client_info *)attr.user_context;

	sd_debug("on request: %p, %p, nents: %d", session, xio_req, nents);
	hdr = xio_req->in.header.iov_base;
	sd_debug("op: 0x%x\n", hdr->opcode);

	req = alloc_request(ci, hdr->data_length);
	memcpy(&req->rq, hdr, sizeof(req->rq));

	if (hdr->data_length && hdr->flags & SD_FLAG_CMD_WRITE) {
		sd_assert(nents == 1);
		req->data = sglist[0].iov_base;
	}

	xio_req->in.header.iov_base  = NULL;
	xio_req->in.header.iov_len  = 0;
	vmsg_sglist_set_nents(&xio_req->in, 0);

	ci->xio_req = xio_req;

	queue_request(req);

	return 0;
}

static struct client_info *xio_create_client(struct xio_session *session)
{
	struct client_info *ci;

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	ci->type = CLIENT_INFO_TYPE_XIO;

	ci->conn.session = session;
	refcount_set(&ci->refcnt, 0);

	INIT_LIST_HEAD(&ci->done_reqs);

	return ci;
}

static int server_on_new_session(struct xio_session *session,
			  struct xio_new_session_req *req,
			  void *cb_user_context)
{
	/* struct sd_xio_session *priv; */

	sd_debug("on new session: %p", session);

	/* priv->efd = eventfd(0, EFD_SEMAPHORE); */
	xio_accept(session, NULL, 0, NULL, 0);
}

static int server_on_session_event(struct xio_session *session,
				   struct xio_session_event_data *event_data,
				   void *cb_user_context)
{
	struct client_info *ci;
	struct xio_session_attr attr;

	sd_debug("session event: %s. session:%p, connection:%p, reason: %s\n",
		 xio_session_event_str(event_data->event),
		 session, event_data->conn,
		 xio_strerror(event_data->reason));

	switch (event_data->event) {
	case XIO_SESSION_NEW_CONNECTION_EVENT:
		memset(&attr, 0, sizeof(attr));

		ci = xio_create_client(session);
		attr.user_context = ci;
		xio_modify_session(session, &attr, XIO_SESSION_ATTR_USER_CTX);
		break;
	default:
		break;
	};

	return 0;
}

static void msg_prep_for_reply(struct sd_rsp *rsp,
			       void *data, struct xio_msg *msg)
{
	struct xio_vmsg* pomsg = &msg->out;
	struct xio_iovec_ex* sglist = vmsg_sglist(pomsg);

	vmsg_sglist_set_nents(pomsg, 0);
	pomsg->header.iov_len = sizeof(*rsp);
	pomsg->header.iov_base = rsp;

	if (rsp->data_length != 0) {
		vmsg_sglist_set_nents(pomsg, 1);

		sglist[0].iov_base = data;
		sglist[0].iov_len = rsp->data_length;
		sglist[0].mr = NULL;
	}
}

static int server_msg_vec_init(struct xio_msg *msg)
{
	msg->in.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->in.pdata_iov.max_nents	= 0;
	msg->in.pdata_iov.sglist	= NULL;

	msg->out.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->out.pdata_iov.max_nents	= 1;
	msg->out.pdata_iov.sglist	=
		(struct xio_iovec_ex *)calloc(1, sizeof(struct xio_iovec_ex));

	return 0;
}

main_fn void xio_send_reply(struct client_info *ci)
{
	struct request *req;
	struct xio_msg xrsp;

	req = list_first_entry(&ci->done_reqs, struct request, request_list);
	list_del(&req->request_list);

	memset(&xrsp, 0, sizeof(xrsp));
	server_msg_vec_init(&xrsp);

	msg_prep_for_reply(&req->rp, req->data, &xrsp);
	xrsp.request = ci->xio_req;
	xio_send_response(&xrsp);

	free_request(req);
}

/*---------------------------------------------------------------------------*/
/* asynchronous callbacks						     */
/*---------------------------------------------------------------------------*/
static struct xio_session_ops  portal_server_ops = {
	.on_session_event		=  server_on_session_event,
	.on_new_session			=  server_on_new_session,
	.on_msg_send_complete		=  NULL,
	.on_msg				=  server_on_request,
	.on_msg_error			=  NULL
};

static void xio_server_handler(int fd, int events, void *data)
{
	struct server_data *server_data = (struct server_data *)data;

	xio_context_poll_wait(server_data->ctx, 0);
}

int xio_create_listen_ports(const char *bindaddr, int port,
			    int (*callback)(int fd, void *), void *data)
{
	char url[256];
	struct xio_server *server;
	struct server_data *server_data;
	int xio_fd;

	server_data = xzalloc(sizeof(*server_data));
	server_data->ctx = xio_get_main_ctx();

	sprintf(url, "tcp://%s:%d", bindaddr ? bindaddr : "0.0.0.0", port);
	sd_info("accelio binding url: %s", url);

	/* bind a listener server to a portal/url */
	server = xio_bind(server_data->ctx, &portal_server_ops, url, NULL, 0,
			  server_data);
	if (server == NULL) {
		sd_err("xio_bind() failed");
		return -1;
	}

	xio_fd = xio_context_get_poll_fd(server_data->ctx);
	register_event(xio_fd, xio_server_handler, server_data);

	return 0;
}

