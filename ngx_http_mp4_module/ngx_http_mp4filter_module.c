#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_mp4_module.h"

typedef struct {
    ngx_chain_t *out;
    size_t       lra_sent;
    size_t       lr_sent;
    size_t       limit_ra;
    size_t       limit_r;
    size_t       last_time;
} ngx_http_mp4filter_ctx_t;


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);
static inline void
ngx_http_get_mp4_limit_rate(ngx_http_mp4filter_conf_t *conf, \
                            ngx_http_mp4filter_ctx_t *ctx, \
                            ngx_http_mp4_ctx_t *mp4_ctx, \
                            size_t left_size);
static ngx_int_t
ngx_http_calc_send_chain(ngx_http_mp4filter_ctx_t *ctx, \
                         ngx_chain_t **in, \
                         ngx_http_request_t *r, \
                         size_t size, \
                         size_t *counter, \
                         size_t *sum);
static inline ngx_int_t
ngx_http_separate_buf(ngx_http_request_t *r, \
                      ngx_chain_t *cl, \
                      size_t size);

static void *ngx_http_mp4filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_mp4filter_conf_t *mcf;
    mcf = (ngx_http_mp4filter_conf_t *)ngx_pcalloc(cf->pool, \
                                  sizeof(ngx_http_mp4filter_conf_t));
    if (mcf == NULL) return NULL;
    mcf->enable = NGX_CONF_UNSET;
    mcf->begoff_sec = NGX_CONF_UNSET_SIZE;
    mcf->steplen_sec = NGX_CONF_UNSET_SIZE;
    return mcf;
}

static ngx_command_t ngx_http_mp4filter_commands[] = {
    {
        ngx_string("rlimit"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("rlimit_begoff"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mp4filter_conf_t, begoff_sec),
        NULL
    },
    {
        ngx_string("rlimit_steplen"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_mp4filter_conf_t, steplen_sec),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_mp4filter_module_ctx = {
    NULL,
    ngx_http_write_filter_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_mp4filter_create_conf,
    NULL
};

ngx_module_t ngx_http_mp4filter_module = {
    NGX_MODULE_V1,
    &ngx_http_mp4filter_module_ctx,
    ngx_http_mp4filter_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_mp4filter_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_mp4filter_ctx_t              *ctx;
    size_t                                 size = 0;
    ngx_chain_t                           *cl;
    ngx_chain_t                          **ll;
    ngx_http_mp4filter_conf_t              *conf;
    ngx_connection_t                      *c;
    ngx_int_t                              rc;
    ngx_http_mp4_ctx_t                    *mp4_ctx;
    struct timeval                         now;

    c = r->connection;

    /*get conf and ctx*/
    conf = ngx_http_get_module_loc_conf(r, ngx_http_mp4filter_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_mp4filter_module);
    mp4_ctx = ngx_http_get_module_ctx(r, ngx_http_mp4_module);

    if (!conf->enable || !conf->steplen_sec || mp4_ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL && ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx == NULL) {
        ctx = (ngx_http_mp4filter_ctx_t *)ngx_pcalloc(r->pool, \
                              sizeof(ngx_http_mp4filter_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->out = NULL;
        ctx->lra_sent = 0;
        ctx->lr_sent = ~(size_t)0;
        ctx->limit_ra = mp4_ctx->begoff_offset;
        ctx->limit_r = 0;
        ctx->last_time = 0;
        ngx_http_set_ctx(r, ctx, ngx_http_mp4filter_module);
    }

    if (in == NULL && ctx->out == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    /*calc all output size and move in -> ctx->out*/
    ll = &(ctx->out);
    for (cl = ctx->out; cl != NULL; cl = cl->next) {
        size += ngx_buf_size(cl->buf);
        ll = &(cl->next);
    }
    for (cl = in; cl != NULL; cl = cl->next) {
        size += ngx_buf_size(cl->buf);
    }

    /*move chain*/
    *ll = in;
    in = NULL;

    /*get limit_rate_after content*/
    if (ctx->limit_ra > 0 && ctx->lra_sent < ctx->limit_ra) {
        rc = ngx_http_calc_send_chain(ctx, \
                                      &in, \
                                      r, \
                                      ctx->limit_ra, \
                                      &(ctx->lra_sent), \
                                      &size);
        if (rc != NGX_OK) {
            return rc;
        }
        c->buffered &= (~NGX_LOWLEVEL_BUFFERED);
        rc = ngx_http_next_body_filter(r, in);
        if (rc == NGX_ERROR) {
            return rc;
        }
        if (r->out == NULL && ctx->out != NULL) {
            c->write->delayed = 1;
            ngx_add_timer(c->write, 1000);
            c->buffered |= NGX_HTTP_WRITE_BUFFERED;
            return NGX_AGAIN;
        }
        return rc;
    }

    gettimeofday(&now, NULL);
    size_t diff = (now.tv_sec*1000000+now.tv_usec)/1000 - ctx->last_time;
    if (diff < 1000) {
        c->buffered |= NGX_LOWLEVEL_BUFFERED;
        rc = ngx_http_next_body_filter(r, NULL);
        if (rc == NGX_ERROR) {
            return rc;
        }
        if (r->out == NULL && ctx->out != NULL) {
            c->write->delayed = 1;
            ngx_add_timer(c->write, 1000 - diff);
            c->buffered |= NGX_HTTP_WRITE_BUFFERED;
            return NGX_AGAIN;
        }
        return rc;
    }

    /*limit rate*/
    if (ctx->lr_sent >= ctx->limit_r) {
        ctx->lr_sent = 0;
        ngx_http_get_mp4_limit_rate(conf, ctx, mp4_ctx, size);
    }
    if (ctx->limit_r > 0) {
        rc = ngx_http_calc_send_chain(ctx, \
                                      &in, \
                                      r, \
                                      ctx->limit_r, \
                                      &(ctx->lr_sent), \
                                      &size);
        if (rc != NGX_OK) {
            return rc;
        }
        ctx->last_time = (now.tv_sec*1000000+now.tv_usec)/1000;
        c->buffered &= (~NGX_LOWLEVEL_BUFFERED);
        if (size == 0) {
            return ngx_http_next_body_filter(r, in);
        }
        rc = ngx_http_next_body_filter(r, in);
        if (rc == NGX_ERROR) {
            return rc;
        }
        if (r->out == NULL && ctx->out != NULL) {
            c->write->delayed = 1;
            ngx_add_timer(c->write, 1000);
            c->buffered |= NGX_HTTP_WRITE_BUFFERED;
            return NGX_AGAIN;
        }
        return rc;
    }
    
    in = ctx->out;
    ctx->out = NULL;
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_mp4filter_body_filter;
    return NGX_OK;
}

static inline void
ngx_http_get_mp4_limit_rate(ngx_http_mp4filter_conf_t *conf, \
                            ngx_http_mp4filter_ctx_t *ctx, \
                            ngx_http_mp4_ctx_t *mp4_ctx, \
                            size_t left_size)
{
    if (!left_size) {
        ctx->limit_r = 0;
        return;
    }
    if (mp4_ctx->cl_head == NULL) {
        ctx->limit_r = left_size + 1;
        return;
    }

    ngx_chain_t *cl;

    cl = mp4_ctx->cl_head;
    ctx->limit_r = (size_t)(cl->buf);
    if (cl == mp4_ctx->cl_tail) {
        mp4_ctx->cl_head = mp4_ctx->cl_tail = NULL;
    } else {
        mp4_ctx->cl_head = cl->next;
    }
}

static ngx_int_t
ngx_http_calc_send_chain(ngx_http_mp4filter_ctx_t *ctx, \
                         ngx_chain_t **in, \
                         ngx_http_request_t *r, \
                         size_t size, \
                         size_t *counter, \
                         size_t *sum)
{
    ngx_int_t rc;
    ngx_chain_t *cl;
    size_t tmp_size = 0;
    size_t required_size = size - *counter;
    if (*sum <= required_size) {
        *in = ctx->out;
        ctx->out = NULL;
        *counter += (*sum);
        *sum = 0;
        return NGX_OK;
    }

    for (cl = ctx->out; cl != NULL; cl = cl->next) {
        tmp_size += ngx_buf_size(cl->buf);
        if (tmp_size >= required_size)
            break;
    }
    *counter += required_size;
    *sum -= required_size;
    rc = ngx_http_separate_buf(r, cl, tmp_size - required_size);
    if (rc != NGX_OK) return rc;
    *in = ctx->out;
    ctx->out = cl->next;
    cl->next = NULL;
    cl->buf->flush = 1;
    return NGX_OK;
}

static inline ngx_int_t
ngx_http_separate_buf(ngx_http_request_t *r, \
                      ngx_chain_t *cl, \
                      size_t size)
{
    if (!size) return NGX_OK;
    ngx_chain_t *new_cl = ngx_alloc_chain_link(r->pool);
    ngx_buf_t *b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    if (new_cl == NULL || b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory not enough.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    new_cl->buf = b;
    new_cl->next = cl->next;
    cl->next = new_cl;
    memcpy(b, cl->buf, sizeof(ngx_buf_t));

    b->shadow = cl->buf;
    cl->buf->shadow = b;
    b->last_shadow = 1;
    if (cl->buf->last_shadow)
        cl->buf->last_shadow = 0;

    if (ngx_buf_in_memory(b)) {
        cl->buf->last -= size;
        b->pos = b->last - size;
    } else {
        cl->buf->file_last -= size;
        b->file_pos = b->file_last - size;
    }

    return NGX_OK;
}

