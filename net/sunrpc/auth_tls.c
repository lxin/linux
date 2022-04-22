// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, 2022 Oracle.  All rights reserved.
 *
 * The AUTH_TLS credential is used only to probe a remote peer
 * for RPC-over-TLS support.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/sunrpc/clnt.h>

static const char *starttls_token = "STARTTLS";
static const size_t starttls_len = 8;

static struct rpc_auth tls_auth;
static struct rpc_cred tls_cred;

static struct rpc_auth *tls_create(const struct rpc_auth_create_args *args,
				   struct rpc_clnt *clnt)
{
	refcount_inc(&tls_auth.au_count);
	return &tls_auth;
}

static void tls_destroy(struct rpc_auth *auth)
{
}

static struct rpc_cred *tls_lookup_cred(struct rpc_auth *auth,
					struct auth_cred *acred, int flags)
{
	return get_rpccred(&tls_cred);
}

static void tls_destroy_cred(struct rpc_cred *cred)
{
}

static int tls_match(struct auth_cred *acred, struct rpc_cred *cred, int taskflags)
{
	return 1;
}

static int tls_marshal(struct rpc_task *task, struct xdr_stream *xdr)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 * XDR_UNIT);
	if (!p)
		return -EMSGSIZE;
	/* Credential */
	*p++ = rpc_auth_tls;
	*p++ = xdr_zero;
	/* Verifier */
	*p++ = rpc_auth_null;
	*p   = xdr_zero;
	return 0;
}

static int tls_refresh(struct rpc_task *task)
{
	set_bit(RPCAUTH_CRED_UPTODATE, &task->tk_rqstp->rq_cred->cr_flags);
	return 0;
}

static int tls_validate(struct rpc_task *task, struct xdr_stream *xdr)
{
	__be32 *p;
	void *str;

	p = xdr_inline_decode(xdr, XDR_UNIT);
	if (!p)
		return -EIO;
	if (*p != rpc_auth_null)
		return -EIO;
	if (xdr_stream_decode_opaque_inline(xdr, &str, starttls_len) != starttls_len)
		return -EIO;
	if (memcmp(str, starttls_token, starttls_len))
		return -EIO;
	return 0;
}

const struct rpc_authops authtls_ops = {
	.owner		= THIS_MODULE,
	.au_flavor	= RPC_AUTH_TLS,
	.au_name	= "NULL",
	.create		= tls_create,
	.destroy	= tls_destroy,
	.lookup_cred	= tls_lookup_cred,
};

static struct rpc_auth tls_auth = {
	.au_cslack	= NUL_CALLSLACK,
	.au_rslack	= NUL_REPLYSLACK,
	.au_verfsize	= NUL_REPLYSLACK,
	.au_ralign	= NUL_REPLYSLACK,
	.au_ops		= &authtls_ops,
	.au_flavor	= RPC_AUTH_TLS,
	.au_count	= REFCOUNT_INIT(1),
};

static const struct rpc_credops tls_credops = {
	.cr_name	= "AUTH_TLS",
	.crdestroy	= tls_destroy_cred,
	.crmatch	= tls_match,
	.crmarshal	= tls_marshal,
	.crwrap_req	= rpcauth_wrap_req_encode,
	.crrefresh	= tls_refresh,
	.crvalidate	= tls_validate,
	.crunwrap_resp	= rpcauth_unwrap_resp_decode,
};

static struct rpc_cred tls_cred = {
	.cr_lru		= LIST_HEAD_INIT(tls_cred.cr_lru),
	.cr_auth	= &tls_auth,
	.cr_ops		= &tls_credops,
	.cr_count	= REFCOUNT_INIT(2),
	.cr_flags	= 1UL << RPCAUTH_CRED_UPTODATE,
};
