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
#include "xio.h"

#include <libxio.h>

static struct xio_context *main_ctx;

struct xio_context *xio_get_main_ctx(void)
{
	return main_ctx;
}

struct client_data {
	struct xio_context	*ctx;
};

static int client_on_response(struct xio_session *session,
			      struct xio_msg *rsp,
			      int last_in_rxq,
			      void *cb_user_context)
{
	struct client_data *client_data =
			(struct client_data *)cb_user_context;

	sd_debug("response on session %p", session);
	xio_context_stop_loop(client_data->ctx);

	return 0;
}

static struct xio_session_ops client_ses_ops = {
	.on_session_event = NULL,
	.on_session_established = NULL,
	.on_msg = client_on_response,
	.on_msg_error = NULL
};

static struct xio_connection *sd_xio_create_connection(struct xio_context *ctx,
					       const struct node_id *nid,
					       void *user_ctx)
{
	struct xio_connection *conn;
	struct xio_session *session;
	char url[256];
	struct xio_session_params params;
	struct xio_connection_params cparams;

	sprintf(url, "tcp://%s", addr_to_str(nid->addr, nid->port));

	memset(&params, 0, sizeof(params));
	params.type = XIO_SESSION_CLIENT;
	params.ses_ops = &client_ses_ops;
	params.uri = url;
	params.user_context = user_ctx;

	session = xio_session_create(&params);

	memset(&cparams, 0, sizeof(cparams));
	cparams.session = session;
	cparams.ctx = ctx;

	conn = xio_connect(&cparams);

	return conn;
}

static int client_msg_vec_init(struct xio_msg *msg)
{
	msg->in.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->in.pdata_iov.max_nents	= 2;
	msg->in.pdata_iov.sglist	=
		(struct xio_iovec_ex *)calloc(2, sizeof(struct xio_iovec_ex));

	msg->out.sgl_type		= XIO_SGL_TYPE_IOV_PTR;
	msg->out.pdata_iov.max_nents	= 1;
	msg->out.pdata_iov.sglist	=
		(struct xio_iovec_ex *)calloc(1, sizeof(struct xio_iovec_ex));

	return 0;
}

static void msg_prep_for_send(struct sd_req *hdr, struct sd_rsp *rsp,
			      void *data, struct xio_msg *msg)
{
	struct xio_vmsg *pomsg = &msg->out;
	struct xio_iovec_ex *osglist = vmsg_sglist(pomsg);
	struct xio_vmsg *pimsg = &msg->in;
	struct xio_iovec_ex *isglist = vmsg_sglist(pimsg);

	vmsg_sglist_set_nents(pomsg, 0);
	pomsg->header.iov_len = sizeof(*hdr);
	pomsg->header.iov_base = hdr;

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		vmsg_sglist_set_nents(pomsg, 1);

		osglist[0].iov_base = data;
		osglist[0].iov_len = hdr->data_length;
		osglist[0].mr = NULL;
	}

	vmsg_sglist_set_nents(pimsg, 1);
	isglist[0].iov_base = rsp;
	isglist[0].iov_len = sizeof(*rsp);
	isglist[0].mr = NULL;

	if (hdr->flags & SD_FLAG_CMD_PIGGYBACK) {
		vmsg_sglist_set_nents(pimsg, 2);
		isglist[1].iov_base = xzalloc(hdr->data_length);
		isglist[1].iov_len = hdr->data_length;
		isglist[1].mr = NULL;
	}
}

static void msg_finalize(struct sd_req *hdr, struct sd_rsp *rsp,
			 void *data, struct xio_msg *msg)
{
	struct xio_vmsg *pimsg = &msg->in;
	struct xio_iovec_ex *isglist = vmsg_sglist(pimsg);
	bool piggyback = !!(hdr->flags & SD_FLAG_CMD_PIGGYBACK);
	int len = hdr->data_length;

	memcpy(hdr, rsp, sizeof(*rsp));
	if (piggyback) {
		memcpy(data, isglist[1].iov_base, len);
		free(isglist[1].iov_base);
	}
}

int xio_exec_req(const struct node_id *nid, struct sd_req *hdr, void *data,
		 bool (*need_retry)(uint32_t epoch), uint32_t epoch,
		 uint32_t max_count)
{
	struct xio_context *ctx = is_main_thread() ?
		main_ctx : xio_context_create(NULL, 0, -1);
	struct client_data cli = { .ctx = ctx };
	struct xio_connection *conn = sd_xio_create_connection(ctx, nid, &cli);
	struct xio_msg xreq;
	struct sd_rsp rsp;

	memset(&xreq, 0, sizeof(xreq));
	client_msg_vec_init(&xreq);
	memset(&rsp, 0, sizeof(rsp));
	msg_prep_for_send(hdr, &rsp, data, &xreq);

	xio_send_request(conn, &xreq);
	xio_context_run_loop(ctx, XIO_INFINITE);

	msg_finalize(hdr, &rsp, data, &xreq);

	xio_connection_destroy(conn);
	if (!is_main_thread())
		xio_context_destroy(ctx);

	return 0;
}

void xio_init_main_ctx(void)
{
	/*
	 * Why do we need this main_ctx?
	 *
	 * xio_context_create() changes signal handlers of a calling thread
	 * internally, so SIGUSR1 fd of local cluster driver cannot work
	 * if we call xio_context_create() after initializing the driver.
	 */
	main_ctx = xio_context_create(NULL, 0, -1);
}

void sd_xio_init(void)
{
	int xopt = 2;		/* hdr + body */
	int reconn = 1;

	xio_init();

	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_IN_IOVLEN,
		    &xopt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_MAX_OUT_IOVLEN,
		    &xopt, sizeof(int));
	xio_set_opt(NULL,
		    XIO_OPTLEVEL_ACCELIO, XIO_OPTNAME_ENABLE_RECONNECT,
		    &reconn, sizeof(int));
}

void sd_xio_shutdown(void)
{
	xio_shutdown();
}
