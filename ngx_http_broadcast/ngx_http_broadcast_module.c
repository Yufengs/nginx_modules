#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ngx_current_module ngx_http_broadcast_module

static ngx_int_t
ngx_http_broadcast_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_broadcast_init(ngx_conf_t *cf);
static void *ngx_http_broadcast_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_broadcast_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_broadcast_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_broadcast_add_variable(ngx_conf_t *cf);
static char *ngx_http_broadcast(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_broadcast_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_broadcast_handler(ngx_http_request_t *r);
static void ngx_http_broadcast_request_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_broadcast_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static void ngx_http_broadcast_request_init(ngx_http_request_t *r);
static ngx_int_t ngx_http_broadcast_copy_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_broadcast_response(ngx_http_request_t *r);

extern ngx_http_upstream_srv_conf_t *ngx_http_dyups_get_upstream_by_name(ngx_http_request_t *r, ngx_str_t *upstream);

typedef struct {
    ngx_flag_t                            enable;
} ngx_http_broadcast_main_conf_t;

typedef struct {
    ngx_str_t                             upstream;
} ngx_http_broadcast_loc_conf_t;

typedef struct {
    ngx_uint_t                            status;
    ngx_str_t                            *name;
    unsigned                              done:1;
} ngx_http_broadcast_subrequest_ctx_t;

typedef struct {
    ngx_http_request_t                   *sr;
    ngx_http_post_subrequest_t            psr;
    ngx_http_broadcast_subrequest_ctx_t   ctx;
} ngx_http_broadcast_subrequest_t;

typedef struct {
    ngx_uint_t                            left;
    ngx_uint_t                            total;
    ngx_array_t                           subrequests;
    ngx_http_handler_pt                   content_handler;
} ngx_http_broadcast_ctx_t;

static ngx_str_t ngx_http_broadcast_host = ngx_string("broadcast_host");

static ngx_command_t ngx_http_broadcast_commands[] = {
    {
        ngx_string("broadcast"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
        ngx_http_broadcast,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_broadcast_module_ctx = {
    ngx_http_broadcast_add_variable,          /* preconfiguration */
    ngx_http_broadcast_init,                  /* postconfiguration */
    ngx_http_broadcast_create_main_conf,      /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_broadcast_create_loc_conf,       /* create location configration */
    ngx_http_broadcast_merge_loc_conf         /* merge location configration */
};

ngx_module_t ngx_http_broadcast_module = {
    NGX_MODULE_V1,
    &ngx_http_broadcast_module_ctx,           /* module context */
    ngx_http_broadcast_commands,              /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_broadcast_access_handler(ngx_http_request_t *r)
{
    ngx_http_broadcast_ctx_t             *ctx;
    ngx_http_broadcast_loc_conf_t        *blcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    blcf = ngx_http_get_module_loc_conf(r, ngx_current_module);
    if (!blcf->upstream.len) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "broadcast handler");

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);
    if (ctx != NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_broadcast_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_current_module);

    ctx->content_handler = r->content_handler;
    r->content_handler = ngx_http_broadcast_handler;

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_broadcast_handler(ngx_http_request_t *r)
{
    int                                   rc;
    ngx_http_broadcast_ctx_t             *ctx;
    ngx_http_upstream_srv_conf_t         *uscf;
    ngx_http_broadcast_loc_conf_t        *blcf;

    if (r != r->main) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "broadcast content handler");

    blcf = ngx_http_get_module_loc_conf(r, ngx_current_module);

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uscf = ngx_http_dyups_get_upstream_by_name(r, &blcf->upstream);
    if (uscf == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (uscf->peer.init(r, uscf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_broadcast_request_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static void ngx_http_broadcast_request_handler(ngx_http_request_t *r)
{
    ngx_http_broadcast_ctx_t     *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "broadcast request handler");

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);
    if (ctx->left) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "broadcast all subrequest done in main request");

    ngx_http_finalize_request(r, ngx_http_broadcast_response(r));
}

static void ngx_http_broadcast_request_init(ngx_http_request_t *r)
{
    int                                   rc, i;
    ngx_http_request_t                   *sr;
    ngx_http_upstream_t                  *u;
    ngx_peer_connection_t                *pc;
    ngx_http_broadcast_ctx_t             *ctx;
    ngx_http_post_subrequest_t           *ps;
    ngx_http_broadcast_subrequest_t      *bsr;
    ngx_http_upstream_rr_peers_t         *peers;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "broadcast init subrequests a:%d c:%d",
            r == r->connection->data, r->main->count);

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);

    u = r->upstream;

    pc = &u->peer;
    peers = ((ngx_http_upstream_rr_peer_data_t *)(pc->data))->peers;

    if (ngx_array_init(&ctx->subrequests, \
                       r->pool, \
                       pc->tries, \
                       sizeof(ngx_http_broadcast_subrequest_t)) != NGX_OK)
    {
        goto error;
    }

    for (i = 0; ; i++) {
        rc = pc->get(pc, pc->data);
        if ((i && peers->single) || (rc != NGX_OK)) {
            break;
        }

        bsr = ngx_array_push(&ctx->subrequests);
        if (bsr == NULL) {
            goto error;
        }

        bsr->ctx.done = 0;
        bsr->ctx.name = pc->name;

        pc->free(pc, pc->data, 0);

        ps = &bsr->psr;
        ps->handler = ngx_http_broadcast_done;
        ps->data = ctx;

        if (ngx_http_subrequest(r, &r->uri, &r->args, &bsr->sr, ps, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
        {
            goto error;
        }

        sr = bsr->sr;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "broadcast add subrequest %i %V %p",
                i + 1, pc->name, sr);

        sr->method = r->method;
        sr->method_name = r->method_name;
        sr->loc_conf = r->loc_conf;

        sr->phase_handler = r->phase_handler;
        sr->write_event_handler = ngx_http_core_run_phases;

        sr->content_handler = ctx->content_handler;

        sr->header_only = 1;

        if (ngx_http_broadcast_copy_request_body(r) != NGX_OK) {
            goto error;
        }

        ngx_http_set_ctx(sr, &bsr->ctx, ngx_current_module);
    }

    ctx->left = ctx->total = i;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "broadcast init subrequests done. n:%d", i);

    r->write_event_handler = ngx_http_broadcast_request_handler;

    return;

error:

    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static ngx_int_t ngx_http_broadcast_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_broadcast_ctx_t             *mctx = data;
    ngx_http_broadcast_subrequest_ctx_t  *ctx;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "broadcast subrequest done handler. r:%p m:%p d:%p",
            r, r->main, r->connection->data);

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);

    if (ctx == NULL || ctx->done) {
        return NGX_OK;
    }

    ctx->done = 1;

    ctx->status = r->headers_out.status;
    if (ctx->status == 0) {
        if (rc == NGX_OK) {
            rc = NGX_HTTP_OK;
        }

        if (rc == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ctx->status = rc;
        }
    }

    mctx->left --;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "broadcast subrequest done %d/%d st:%i h:%V",
            mctx->total - mctx->left, mctx->total, ctx->status,
            ctx->name);

    return rc;
}

static ngx_int_t ngx_http_broadcast_copy_request_body(ngx_http_request_t *r)
{
    ngx_temp_file_t            *tf;
    ngx_http_request_body_t    *body;

    if (!r->request_body || !r->request_body->temp_file) {
        return NGX_OK;
    }

    tf = r->request_body->temp_file;

    body = ngx_palloc(r->pool, sizeof(ngx_http_request_body_t));
    if (body == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(body, r->request_body, sizeof(ngx_http_request_body_t));

    body->temp_file = ngx_palloc(r->pool, sizeof(ngx_temp_file_t));
    if (body->temp_file == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(body->temp_file, tf, sizeof(ngx_temp_file_t));

    r->request_body = body;

    return NGX_OK;
}

static ngx_int_t ngx_http_broadcast_response(ngx_http_request_t *r)
{
    ngx_uint_t                        i;
    size_t                            size;
    ngx_int_t                         rc;
    ngx_buf_t                        *b;
    ngx_chain_t                       out;
    ngx_msec_int_t                    ms;
    ngx_http_request_t               *sr;
    ngx_http_broadcast_ctx_t         *ctx;
    ngx_http_upstream_state_t        *state;
    ngx_http_broadcast_subrequest_t  *bsr;

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);

    bsr = ctx->subrequests.elts;

    size = ctx->subrequests.nelts * (1 + // [
            NGX_SOCKADDR_STRLEN + 2 + 1 +
            3 + 1 +
            NGX_TIME_T_LEN + 4 + 1 + // ]
            1) + 2;

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    *b->last ++ = '[';
    for (i = 0; i < ctx->subrequests.nelts; i++) {
        if (i) {
            *b->last ++ = ',';
        }
        b->last = ngx_sprintf(b->last, "[\"%V\",%ui,",
                bsr[i].ctx.name, bsr[i].ctx.status);

        sr = bsr[i].sr;

        if (sr->upstream_states == NULL || sr->upstream_states->nelts != 1) {
            *b->last ++ = '-';
        } else {
            state = sr->upstream_states->elts;

#if nginx_version > 1009000
            ms = state->response_time;
#else
            ms = (ngx_msec_int_t)(state->response_sec * 1000 + state->response_msec);
#endif
            ms = ngx_max(ms, 0);
            b->last = ngx_sprintf(b->last, "%T.%03M", (time_t) ms / 1000, ms % 1000);
        }
        *b->last ++ = ']';
    }
    *b->last ++ = ']';

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_broadcast_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_broadcast_subrequest_ctx_t   *ctx;

    if (r == r->main) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_current_module);
    if (!ctx) {
        return NGX_ERROR;
    }

    v->len = ctx->name->len;
    v->data = ctx->name->data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static char *ngx_http_broadcast(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_http_broadcast_loc_conf_t   *blcf;
    ngx_http_broadcast_main_conf_t  *mlcf;

    value = cf->args->elts;

    blcf = ngx_http_conf_get_module_loc_conf(cf, ngx_current_module);
    if (blcf->upstream.len) {
        return "is duplicated";
    }

    blcf->upstream = value[1];
    if (!blcf->upstream.len) {
        return NGX_CONF_ERROR;
    }

    mlcf = ngx_http_conf_get_module_main_conf(cf, ngx_current_module);
    mlcf->enable = 1;

    return NGX_CONF_OK;
}

static void *ngx_http_broadcast_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_broadcast_main_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = 0;

    return conf;
}

static void *ngx_http_broadcast_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_broadcast_loc_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream.data = NGX_CONF_UNSET_PTR;
    conf->upstream.len = 0;

    return conf;
}

static char *ngx_http_broadcast_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_broadcast_loc_conf_t *prev = parent;
    ngx_http_broadcast_loc_conf_t *conf = child;

    if (!conf->upstream.len) {
        if (prev->upstream.len) {
            conf->upstream = prev->upstream;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_broadcast_add_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t      *var;

    var = ngx_http_add_variable(cf, &ngx_http_broadcast_host, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_broadcast_get_variable;

    return NGX_OK;
}

static ngx_int_t ngx_http_broadcast_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_broadcast_main_conf_t  *bmcf;

    bmcf = ngx_http_conf_get_module_main_conf(cf, ngx_current_module);
    if (!bmcf->enable) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_broadcast_access_handler;

    return NGX_OK;
}

