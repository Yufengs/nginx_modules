/*
 * Copyright (C) Niklaus F.Schen.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_dyloc_shm_location_s {
    ngx_str_t                             server_name;
    in_port_t                             port;
    ngx_str_t                             content;
    struct ngx_http_dyloc_shm_location_s *prev;
    struct ngx_http_dyloc_shm_location_s *next;
} ngx_http_dyloc_shm_location_t;

typedef struct {
    ngx_uint_t                            dynamic:1;
    ngx_uint_t                            active:1;
    ngx_str_t                             content;
    ngx_http_core_loc_conf_t             *location;
} ngx_http_dyloc_location_t;

typedef struct {
    ngx_slab_pool_t                      *shpool;
    ngx_http_dyloc_shm_location_t        *head;
    ngx_http_dyloc_shm_location_t        *tail;
} ngx_http_dyloc_loc_chain_t;

typedef struct {
    ngx_str_t                            *server_name;
    in_port_t                             port;
    ngx_array_t                           locations;
    ngx_http_core_srv_conf_t             *server;
} ngx_http_dyloc_server_t;

typedef struct {
    ngx_conf_t                           *cf;
    ngx_pool_t                           *pool;
    ngx_array_t                           servers;
    ngx_flag_t                            enable;
    ngx_uint_t                            shm_size;
    ngx_str_t                             shm_name;
    ngx_str_t                             dir_path;
} ngx_http_dyloc_main_conf_t;

typedef struct {
    ngx_str_t                             server_name;
    ngx_str_t                             port;
} ngx_http_dyloc_params_t;

static ngx_int_t ngx_http_dyloc_pre_conf(ngx_conf_t *cf);
static ngx_int_t
ngx_http_dyloc_interface_handler(ngx_http_request_t *r);
static void *ngx_http_dyloc_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_dyloc_init_main_conf(ngx_conf_t *cf, void *conf);
static char *
ngx_http_dyloc_interface_directive_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static inline void
ngx_http_dyloc_shm_location_chain_add(ngx_http_dyloc_shm_location_t **head, ngx_http_dyloc_shm_location_t **tail, ngx_http_dyloc_shm_location_t *dl);
static inline void
ngx_http_dyloc_shm_location_chain_del(ngx_http_dyloc_shm_location_t **head, ngx_http_dyloc_shm_location_t **tail, ngx_http_dyloc_shm_location_t *dl);
static ngx_int_t
ngx_http_dyloc_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t
ngx_http_dyloc_init_add_location(ngx_http_dyloc_server_t *ds, ngx_http_core_loc_conf_t *clcf);
static ngx_array_t *ngx_http_dyloc_parse_path(ngx_pool_t *pool, ngx_str_t *path);
static void ngx_http_dyloc_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyloc_do_get(ngx_http_request_t *r, ngx_array_t *resource);
static ngx_buf_t *ngx_http_dyloc_show_list(ngx_http_request_t *r);
static ngx_array_t *ngx_http_dyloc_parse_args(ngx_http_request_t *r);
static void ngx_http_dyloc_body_handler(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyloc_read_body_from_file(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyloc_read_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyloc_add_location(ngx_http_request_t *r, ngx_buf_t *buf, ngx_str_t *rv);
static void ngx_http_dyloc_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content);
static void ngx_http_dyloc_params_set(ngx_array_t *args, ngx_http_dyloc_params_t *params);
static ngx_int_t ngx_http_dyloc_check_conf_text(ngx_buf_t *buf);
static ngx_int_t ngx_http_dyloc_do_add(ngx_http_dyloc_params_t *params, ngx_buf_t *buf, ngx_str_t *rv, ngx_http_dyloc_shm_location_t *shm);
static ngx_int_t ngx_http_dyloc_shm_do_add(ngx_http_dyloc_server_t *srv, ngx_http_dyloc_location_t *loc, ngx_buf_t *body);
static ngx_http_dyloc_server_t *ngx_http_dyloc_search_srv_by_params(ngx_http_dyloc_params_t *params);
static ngx_int_t ngx_http_dyloc_create_location(ngx_http_core_loc_conf_t **ppclcf, \
                                                ngx_http_dyloc_server_t *srv, \
                                                ngx_buf_t *buf, \
                                                ngx_str_t *rv);
static ngx_int_t
ngx_http_dyloc_core_regex_location(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf, ngx_str_t *regex, ngx_uint_t caseless);
static ngx_int_t
ngx_http_dyloc_set_location(ngx_http_dyloc_main_conf_t *dmcf, \
                            ngx_conf_t *cf, \
                            ngx_http_dyloc_server_t *srv, \
                            ngx_http_core_loc_conf_t *clcf);
static ngx_int_t ngx_http_dyloc_location_match(ngx_http_core_loc_conf_t *clcf, ngx_http_location_tree_node_t *node);
static ngx_int_t
ngx_http_dyloc_location_insert(ngx_pool_t *pool, ngx_http_core_loc_conf_t *clcf, ngx_http_location_tree_node_t **root);
static ngx_int_t ngx_http_dyloc_del_location(ngx_http_request_t *r, ngx_buf_t *buf, ngx_str_t *rv);
static ngx_int_t ngx_http_dyloc_do_del(ngx_http_request_t *r, ngx_http_dyloc_params_t *params, ngx_buf_t *buf, ngx_str_t *rv);
static ngx_int_t ngx_http_dyloc_remove_location(ngx_http_request_t *r, ngx_http_dyloc_server_t *srv, ngx_buf_t *buf);
static ngx_int_t
ngx_http_dyloc_location_static_del(ngx_http_request_t *r, \
                                   ngx_http_dyloc_server_t *srv, \
                                   ngx_http_dyloc_main_conf_t *dmcf, \
                                   ngx_http_core_loc_conf_t *del_clcf, \
                                   ngx_http_location_tree_node_t **root);
static void ngx_http_dyloc_location_shm_del(ngx_http_dyloc_server_t *srv, ngx_http_core_loc_conf_t *clcf);
static ngx_http_core_loc_conf_t *
ngx_http_dyloc_location_collect(ngx_array_t *array, ngx_http_location_tree_node_t *node, ngx_http_core_loc_conf_t *del_clcf);
static ngx_int_t ngx_http_dyloc_init_process(ngx_cycle_t *cycle);
static void ngx_http_dyloc_write_in_file(ngx_http_dyloc_params_t *params, ngx_buf_t *content, int add);
static void ngx_http_dyloc_file_lock(int fd);
static void ngx_http_dyloc_file_unlock(int fd);
static void ngx_http_dyloc_variable_sync_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_dyloc_sync_del(ngx_http_request_t *r, ngx_http_dyloc_server_t *srv, ngx_http_dyloc_location_t *loc);


static ngx_http_dyloc_loc_chain_t *g_shm_chain = NULL;

static ngx_command_t ngx_http_dyloc_commands[] = {
    {
        ngx_string("dyloc_interface"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_dyloc_interface_directive_handler,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("dyloc_shm_size"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_dyloc_main_conf_t, shm_size),
        NULL
    },
    {
        ngx_string("dyloc_dir_path"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_dyloc_main_conf_t, dir_path),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_dyloc_module_ctx = {
    ngx_http_dyloc_pre_conf,          /* preconfiguration */
    NULL,                             /* postconfiguration */
    ngx_http_dyloc_create_main_conf,  /* create main configuration */
    ngx_http_dyloc_init_main_conf,    /* init main configuration */
    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */
    NULL,                             /* create location configuration */
    NULL                              /* merge location configuration */
};

ngx_module_t ngx_http_dyloc_module = {
    NGX_MODULE_V1,
    &ngx_http_dyloc_module_ctx,    /* module context */
    ngx_http_dyloc_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_dyloc_init_process,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_dyloc_variables[] = {
    {
        ngx_string("dyloc_sync"),
        ngx_http_dyloc_variable_sync_set_handler,
        NULL,
        0,
        NGX_HTTP_VAR_CHANGEABLE,
        0
    },
    ngx_http_null_variable
};

static ngx_int_t ngx_http_dyloc_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t *cv, *v;
    for (cv = ngx_http_dyloc_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) return NGX_ERROR;
        *v = *cv;
    }

    return NGX_OK;
}

static char *
ngx_http_dyloc_interface_directive_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dyloc_main_conf_t *dmcf;
    ngx_http_core_loc_conf_t *clcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyloc_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dyloc_interface_handler;
    dmcf->enable = 1;
    return NGX_CONF_OK;
}

static void *
ngx_http_dyloc_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dyloc_main_conf_t *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyloc_main_conf_t));
    if (dmcf == NULL) return NULL;
    if (ngx_array_init(&dmcf->servers, cf->pool, 30, sizeof(ngx_http_dyloc_server_t)) != NGX_OK) {
        return NULL;
    }
    dmcf->enable = NGX_CONF_UNSET;
    dmcf->shm_size = NGX_CONF_UNSET_UINT;
    dmcf->cf = cf;
    dmcf->pool = cf->pool;
    dmcf->dir_path.data = NULL;
    dmcf->dir_path.len = 0;

    return dmcf;
}

static char *ngx_http_dyloc_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyloc_main_conf_t *dmcf = conf;
    ngx_shm_zone_t *shm_zone;
    char name[] = "ngx_http_dyloc_module_#shm";
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_conf_port_t        *cp;
    ngx_http_dyloc_server_t     *ds;
    ngx_uint_t                   i;
    ngx_http_core_loc_conf_t    *clcf, *pclcf;
    ngx_queue_t                 *locations, *q;
    ngx_http_location_queue_t   *lq;

    if (dmcf->enable == NGX_CONF_UNSET)
        dmcf->enable = 0;

    if (!dmcf->enable) return NGX_CONF_OK;

    if (dmcf->shm_size == NGX_CONF_UNSET_UINT)
        dmcf->shm_size = 10 * 1024 * 1024;

    dmcf->shm_name.data = ngx_palloc(cf->pool, sizeof(name));
    if (dmcf->shm_name.data == NULL) return NGX_CONF_ERROR;
    memcpy(dmcf->shm_name.data, name, sizeof(name)-1);
    dmcf->shm_name.len = sizeof(name)-1;
    dmcf->shm_name.data[sizeof(name)-1] = 0;

    shm_zone = ngx_shared_memory_add(cf, &dmcf->shm_name, dmcf->shm_size, &ngx_http_dyloc_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;

    shm_zone->data = &g_shm_chain;
    shm_zone->init = ngx_http_dyloc_init_shm_zone;

    ctx = dmcf->cf->ctx;
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;
    cp = cmcf->ports->elts;
    for (i = 0; i < cmcf->servers.nelts; ++i) {
        clcf = cscfp[i]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        ds = ngx_array_push(&dmcf->servers);
        if (ds == NULL) return NGX_CONF_ERROR;

        ds->server_name = &(cscfp[i]->server_name);
        ds->port = cp[i].port;
        ds->server = cscfp[i];
        if (ngx_array_init(&ds->locations, cf->pool, 30, sizeof(ngx_http_dyloc_location_t)) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        locations = clcf->locations;
        if (locations == NULL) continue;
        for (q = ngx_queue_head(locations);
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;
            pclcf = lq->exact ? lq->exact : lq->inclusive;
            if (ngx_http_dyloc_init_add_location(ds, pclcf) != NGX_OK)
                return NGX_CONF_ERROR;
        }
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dyloc_init_add_location(ngx_http_dyloc_server_t *ds, ngx_http_core_loc_conf_t *clcf)
{
    ngx_queue_t *q, *locations;
    ngx_http_location_queue_t *lq;
    ngx_http_core_loc_conf_t *pclcf;
    ngx_http_dyloc_location_t *tmp;

    locations = clcf->locations;
    if (locations != NULL) {
        for (q = ngx_queue_head(locations);
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;
            pclcf = lq->exact ? lq->exact : lq->inclusive;
            if (ngx_http_dyloc_init_add_location(ds, pclcf) != NGX_OK)
                return NGX_ERROR;
        }
    }
    tmp = ngx_array_push(&ds->locations);
    tmp->dynamic = 0;
    tmp->active = 1;
    tmp->content.data = NULL;
    tmp->content.len = 0;
    tmp->location = clcf;

    return NGX_OK;
}

static ngx_int_t
ngx_http_dyloc_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_http_dyloc_loc_chain_t **dlc = data;

    if (dlc != NULL) {
        g_shm_chain->head = (*dlc)->head;
        g_shm_chain->tail = (*dlc)->tail;
        g_shm_chain->shpool = (*dlc)->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if ((g_shm_chain = ngx_slab_alloc(shpool, sizeof(ngx_http_dyloc_loc_chain_t))) == NULL) {
        return NGX_ERROR;
    }
    g_shm_chain->shpool = shpool;
    g_shm_chain->head = g_shm_chain->tail = NULL;
    return NGX_OK;
}

static inline void
ngx_http_dyloc_shm_location_chain_add(ngx_http_dyloc_shm_location_t **head, ngx_http_dyloc_shm_location_t **tail, ngx_http_dyloc_shm_location_t *dl)
{
    dl->prev = dl->next = NULL;
    if (*head == NULL) {
        *head = *tail = dl;
        return;
    }

    (*tail)->next = dl;
    dl->prev = (*tail);
    *tail = dl;
}

static inline void
ngx_http_dyloc_shm_location_chain_del(ngx_http_dyloc_shm_location_t **head, ngx_http_dyloc_shm_location_t **tail, ngx_http_dyloc_shm_location_t *dl)
{
    if (head == NULL && tail == NULL && dl == NULL) return;

    if (*head == dl) {
        if (*tail == dl) {
            *head = *tail = NULL;
        } else {
            *head = dl->next;
            (*head)->prev = NULL;
        }
    } else {
        if (*tail == dl) {
            *tail = dl->prev;
            (*tail)->next = NULL;
        } else {
            dl->prev->next = dl->next;
            dl->next->prev = dl->prev;
        }
    }
    dl->prev = dl->next = NULL;
}

static ngx_int_t
ngx_http_dyloc_interface_handler(ngx_http_request_t *r)
{
    ngx_array_t *res;
    ngx_int_t    rc;

    res = ngx_http_dyloc_parse_path(r->pool, &r->uri);
    if (res == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (r->method == NGX_HTTP_GET) {
        return ngx_http_dyloc_do_get(r, res);
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_dyloc_body_handler);
    return rc >= NGX_HTTP_SPECIAL_RESPONSE? rc: NGX_DONE;
}

static ngx_array_t *ngx_http_dyloc_parse_path(ngx_pool_t *pool, ngx_str_t *path)
{
    u_char       *p, *last, *end;
    ngx_str_t    *str;
    ngx_array_t  *array;

    array = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (array == NULL) return NULL;

    p = path->data + 1;
    last = path->data + path->len;
    while(p < last) {
        end = ngx_strlchr(p, last, '/');
        str = ngx_array_push(array);
        if (str == NULL) return NULL;

        if (end) {
            str->data = p;
            str->len = end - p;
        } else {
            str->data = p;
            str->len = last - p;
        }
        p += str->len + 1;
    }
    return array;
}

static ngx_int_t ngx_http_dyloc_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                   rc, status;
    ngx_buf_t                  *buf;
    ngx_str_t                  *value;
    ngx_chain_t                 out;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;

    if (resource->nelts == 0) return NGX_HTTP_NOT_FOUND;

    buf = NULL;
    value = resource->elts;
    if (value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *) "list", 4) == 0) {
        if ((buf = ngx_http_dyloc_show_list(r)) == NULL) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }
    }
    if (buf != NULL && ngx_buf_size(buf) == 0) {
        status = NGX_HTTP_NO_CONTENT;
    } else {
        status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;
    }

finish:
    r->headers_out.status = status;
    if (status != NGX_HTTP_OK) {
        r->headers_out.content_length_n = 0;
    } else {
        r->headers_out.content_length_n = ngx_buf_size(buf);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) return rc;

    if (status != NGX_HTTP_OK)
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_buf_t *ngx_http_dyloc_show_list(ngx_http_request_t *r)
{
    ngx_buf_t                      *buf = NULL;
    ngx_slab_pool_t                *shpool;
    ngx_http_dyloc_shm_location_t  *loc;
    size_t                          size = 0;

    shpool = g_shm_chain->shpool;

    ngx_shmtx_lock(&shpool->mutex);

    for (loc = g_shm_chain->head; loc != NULL; loc = loc->next) {
        size += loc->server_name.len;
        size += 9;
        size += loc->content.len;
        size += 2;
    }

    if ((buf = ngx_create_temp_buf(r->pool, size)) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NULL;
    }

    for (loc = g_shm_chain->head; loc != NULL; loc = loc->next) {
        buf->last = ngx_sprintf(buf->last, "%V:%i:\n%V\n\n", &loc->server_name, loc->port, &loc->content);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return buf;
}

static ngx_array_t *ngx_http_dyloc_parse_args(ngx_http_request_t *r)
{
    size_t       i, head = 0;
    ngx_str_t   *tmp;
    ngx_array_t *res;

    res = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));
    if (res == NULL) return NULL;

    if (!r->args.len) {
        return res;
    }

    for (i = 0; i < r->args.len; ++i) {
        if (r->args.data[i] == '&') {
            tmp = ngx_array_push(res);
            if (tmp == NULL) return NULL;
            tmp->data = &(r->args.data[head]);
            tmp->len = i - head;
            head = i + 1;
        }
    }
    if (head != i) {
        tmp = ngx_array_push(res);
        if (tmp == NULL) return NULL;
        tmp->data = &(r->args.data[head]);
        tmp->len = i - head;
    }
    return res;
}

static void ngx_http_dyloc_body_handler(ngx_http_request_t *r)
{
    ngx_str_t                   *value, rv;
    ngx_int_t                    status;
    ngx_buf_t                   *body;
    ngx_array_t                 *res;

    ngx_str_set(&rv, "");

    if (r->method != NGX_HTTP_POST) {
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    if ((res = ngx_http_dyloc_parse_path(r->pool, &r->uri)) == NULL) {
        ngx_str_set(&rv, "out of memory");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        status = NGX_HTTP_NO_CONTENT;
        ngx_str_set(&rv, "no content\n");
        goto finish;
    }

    if (r->request_body->temp_file) {
        body = ngx_http_dyloc_read_body_from_file(r);
    } else {
        body = ngx_http_dyloc_read_body(r);
    }
    if (body == NULL) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_str_set(&rv, "out of memory\n");
        goto finish;
    }

    if (res->nelts != 1) {
        ngx_str_set(&rv, "not support this interface");
        status = NGX_HTTP_NOT_FOUND;
        goto finish;
    }

    value = res->elts;
    if (value[0].len == 3 && !ngx_strncasecmp(value[0].data, (u_char *) "add", 3)) {
        status = ngx_http_dyloc_add_location(r, body, &rv);
    } else if (value[0].len == 3 && !ngx_strncasecmp(value[0].data, (u_char *) "del", 3)) {
        status = ngx_http_dyloc_del_location(r, body, &rv);
    } else {
        ngx_str_set(&rv, "not support this api");
        status = NGX_HTTP_NOT_FOUND;
        goto finish;
    }

finish:
    ngx_http_dyloc_send_response(r, status, &rv);
}

static ngx_buf_t *ngx_http_dyloc_read_body_from_file(ngx_http_request_t *r)
{
    size_t        len;
    ssize_t       size;
    ngx_buf_t    *buf, *body;
    ngx_chain_t  *cl;

    len = 0;
    cl = r->request_body->bufs;
    while (cl) {
        buf = cl->buf;
        if (buf->in_file) {
            len += buf->file_last - buf->file_pos;
        } else {
            len += buf->last - buf->pos;
        }
        cl = cl->next;
    }

    body = ngx_create_temp_buf(r->pool, len);
    if (body == NULL) return NULL;

    cl = r->request_body->bufs;
    while (cl) {
        buf = cl->buf;
        if (buf->in_file) {
            size = ngx_read_file(buf->file, \
                                 body->last, \
                                 buf->file_last - buf->file_pos, \
                                 buf->file_pos);
            if (size == NGX_ERROR) return NULL;

            body->last += size;
        } else {
            body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        }
        cl = cl->next;
    }

    return body;
}

static ngx_buf_t *ngx_http_dyloc_read_body(ngx_http_request_t *r)
{
    size_t        len;
    ngx_buf_t    *buf, *next, *body;
    ngx_chain_t  *cl;

    cl = r->request_body->bufs;
    buf = cl->buf;
    if (cl->next == NULL) return buf;

    next = cl->next->buf;
    len = (buf->last - buf->pos) + (next->last - next->pos);

    body = ngx_create_temp_buf(r->pool, len);
    if (body == NULL) return NULL;
    body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
    body->last = ngx_cpymem(body->last, next->pos, next->last - next->pos);

    return body;
}

static void ngx_http_dyloc_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    r->headers_out.status = status;
    r->headers_out.content_length_n = content->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (content->len == 0) {
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_FLUSH));
        return;
    }

    b = ngx_create_temp_buf(r->pool, content->len);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b->pos = content->data;
    b->last = content->data + content->len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}

static void ngx_http_dyloc_params_set(ngx_array_t *args, ngx_http_dyloc_params_t *params)
{
    size_t i;
    ngx_str_t *s;
    for (i = 0; i < args->nelts; ++i) {
        s = &(((ngx_str_t *)(args->elts))[i]);
        if (s->len > 12 && !ngx_strncmp((char *)(s->data), "server_name=", 12)) {
            s->data += 12;
            s->len -= 12;
            if (s->len) params->server_name = *s;
        } else if (s->len > 5 && !ngx_strncmp((char *)(s->data), "port=", 5)) {
            s->data += 5;
            s->len -= 5;
            if (s->len) params->port = *s;
        }
    }
}

static ngx_int_t ngx_http_dyloc_add_location(ngx_http_request_t *r, ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_int_t                   status;
    ngx_array_t                *args;
    ngx_slab_pool_t            *shpool;
    ngx_http_dyloc_params_t     params;

    args = ngx_http_dyloc_parse_args(r);
    if (args == NULL) {
        ngx_str_set(rv, "out of memory.\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_dyloc_params_set(args, &params);
    if (!params.port.len) {
        ngx_str_set(rv, "port must be given\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    shpool = g_shm_chain->shpool;
    ngx_shmtx_lock(&shpool->mutex);
    status = ngx_http_dyloc_do_add(&params, buf, rv, NULL);
    if (status == NGX_HTTP_OK)
        ngx_http_dyloc_write_in_file(&params, buf, 1);
    ngx_shmtx_unlock(&shpool->mutex);

    return status;
}

static ngx_http_dyloc_server_t *ngx_http_dyloc_search_srv_by_params(ngx_http_dyloc_params_t *params)
{
    ngx_http_dyloc_main_conf_t *dmcf;
    ngx_http_dyloc_server_t    *srv, *psrv;
    size_t                      i;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);
    srv = dmcf->servers.elts;
    for (i = 0; i < dmcf->servers.nelts; ++i) {
        psrv = &srv[i];
        if (psrv->server_name->len == params->server_name.len
            && !ngx_strncmp(psrv->server_name->data, params->server_name.data, params->server_name.len)
            && psrv->port == (in_port_t)ngx_atoi(params->port.data, params->port.len))
        {
            return psrv;
        }
    }
    return NULL;
}

static ngx_int_t ngx_http_dyloc_shm_do_add(ngx_http_dyloc_server_t *srv, ngx_http_dyloc_location_t *loc, ngx_buf_t *body)
{
    ngx_http_dyloc_shm_location_t  *dsl;
    ngx_http_dyloc_main_conf_t     *dmcf;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);

    dsl = ngx_slab_alloc_locked(g_shm_chain->shpool, sizeof(ngx_http_dyloc_shm_location_t));
    if (dsl == NULL) {
        return NGX_ERROR;
    }

    dsl->server_name.data = ngx_slab_alloc_locked(g_shm_chain->shpool, srv->server_name->len);
    if (dsl->server_name.data == NULL) return NGX_ERROR;
    memcpy(dsl->server_name.data, srv->server_name->data, srv->server_name->len);
    dsl->server_name.len = srv->server_name->len;
    dsl->port = srv->port;

    dsl->content.data = ngx_slab_alloc_locked(g_shm_chain->shpool, body->last - body->start);
    if (dsl->content.data == NULL) {
        return NGX_ERROR;
    }
    memcpy(dsl->content.data, body->start, body->last - body->start);
    dsl->content.len = body->last - body->start;
    ngx_http_dyloc_shm_location_chain_add(&(g_shm_chain->head), &(g_shm_chain->tail), dsl);
    loc->content.data = ngx_palloc(dmcf->pool, dsl->content.len);
    if (loc->content.data == NULL) return NGX_ERROR;
    memcpy(loc->content.data, dsl->content.data, dsl->content.len);
    loc->content.len = dsl->content.len;

    return NGX_OK;
}

static ngx_int_t ngx_http_dyloc_check_conf_text(ngx_buf_t *buf)
{
    u_char *p;
    for (p = buf->start; p < buf->last; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\n')
            break;
    }
    if (buf->last - p <= 8) return NGX_ERROR;
    if (memcmp(p, "location", 8)) return NGX_ERROR;
    p += 8;
    for (; p < buf->last; ++p) {
        if (*p == 'l') {
            if (buf->last - p > 8 && !ngx_strncmp(p, "location", 8))
                return NGX_ERROR;
            if (buf->last - p > 12 && !ngx_strncmp(p, "limit_except", 12))
                return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_dyloc_do_add(ngx_http_dyloc_params_t *params, ngx_buf_t *buf, ngx_str_t *rv, ngx_http_dyloc_shm_location_t *dsl)
{
    ngx_http_dyloc_server_t    *srv;
    ngx_http_dyloc_location_t  *loc;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_int_t                   rc;
    ngx_http_dyloc_main_conf_t *dmcf;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);

    srv = ngx_http_dyloc_search_srv_by_params(params);
    if (srv == NULL) {
        ngx_str_set(rv, "cannot find server\n");
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_http_dyloc_check_conf_text(buf) != NGX_OK) {
        ngx_str_set(rv, "not support embedded location and limit_except\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    void *(*old_pcre_malloc)(size_t);
    void (*old_pcre_free)(void *);
    old_pcre_malloc = pcre_malloc;
    old_pcre_free = pcre_free;
    pcre_malloc = malloc;
    pcre_free = free;
    if ((rc = ngx_http_dyloc_create_location(&clcf, srv, buf, rv)) != NGX_HTTP_OK) {
        return rc;
    }
    pcre_malloc = old_pcre_malloc;
    pcre_free = old_pcre_free;

    loc = ngx_array_push(&srv->locations);
    loc->dynamic = 1;
    loc->active = 1;
    loc->location = clcf;
    if (dsl == NULL) {
        if (ngx_http_dyloc_shm_do_add(srv, loc, buf) != NGX_OK) {
            ngx_str_set(rv, "out of memory\n");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        loc->content.data = ngx_palloc(dmcf->pool, dsl->content.len);
        if (loc->content.data == NULL) {
            ngx_str_set(rv, "out of memory\n");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        memcpy(loc->content.data, dsl->content.data, dsl->content.len);
        loc->content.len = dsl->content.len;
    }
    return NGX_HTTP_OK;
}

static ngx_array_t *ngx_http_dyloc_parse_location_args(ngx_pool_t *pool, ngx_buf_t *buf)
{
    u_char       *p, *q;
    ngx_array_t  *array;
    ngx_str_t    *s;
    ngx_int_t     in_zone = 0, flag_loc = 0;

    array = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (array == NULL) return NULL;

    for (p = buf->start; p < buf->last; ++p) {
        if (*p == ' ' || *p == '\t' || *p == '\n') continue;
        if (*p == 'l' && buf->last - p > 8 && !ngx_strncmp(p, "location", 8)) {
            s = ngx_array_push(array);
            if (s == NULL) return NULL;
            s->data = p;
            s->len = 8;
            p += 7;
            flag_loc = 1;
            continue;
        }
        if (flag_loc) {
            if (*p == '{') {
                if (!in_zone) {
                    buf->start = buf->pos = p + 1;
                }
                ++in_zone;
                continue;
            }
            if (*p == '}') {
                if (!in_zone) {
                    return NULL;
                } else if (in_zone == 1) {
                    buf->last = buf->end = p;
                    --in_zone;
                } else {
                    --in_zone;
                }
                continue;
            }
            if (in_zone) continue;
            for (q = p; q < buf->last; ++q) {
                if (*q == ' ' || *q == '\t' || *q == '\n') {
                    s = ngx_array_push(array);
                    if (s == NULL) return NULL;
                    s->data = ngx_pcalloc(pool, q - p + 1);
                    if (s->data == NULL) return NULL;
                    memcpy(s->data, p, q - p);
                    s->len = q - p;
                    p = q;
                    break;
                }
            }
        }
    }
    if (in_zone) return NULL;

    return array;
}

static ngx_int_t
ngx_http_dyloc_core_regex_location(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf, ngx_str_t *regex, ngx_uint_t caseless)
{
#if (NGX_PCRE)
    ngx_regex_compile_t  rc;
    u_char               errstr[NGX_MAX_CONF_ERRSTR];

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
    rc.options = NGX_REGEX_CASELESS;
#else
    rc.options = caseless ? NGX_REGEX_CASELESS : 0;
#endif

    clcf->regex = ngx_http_regex_compile(cf, &rc);
    if (clcf->regex == NULL) {
        return NGX_ERROR;
    }

    clcf->name = *regex;

    return NGX_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NGX_ERROR;

#endif
}

static ngx_int_t ngx_http_dyloc_create_location(ngx_http_core_loc_conf_t **ppclcf, \
                                                ngx_http_dyloc_server_t *srv, \
                                                ngx_buf_t *buf, \
                                                ngx_str_t *rs)
{
    char                       *rv;
    u_char                     *mod;
    size_t                      len;
    ngx_str_t                  *value, *name;
    ngx_uint_t                  i, mi;
    ngx_conf_t                  save;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t        *ctx, *pctx, *http_ctx;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_array_t                *args;
    ngx_buf_t                   b;
    ngx_conf_t                  cf;
    ngx_http_dyloc_main_conf_t *dmcf;
    ngx_conf_file_t             conf_file;
    ngx_cycle_t                *cycle = (ngx_cycle_t *)ngx_cycle;
    ngx_pool_t                 *temp_pool;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);

    /* init http ctx */
    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
    conf_file.file.fd = NGX_INVALID_FILE;
    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.pool = dmcf->pool;
    temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, ngx_cycle->log);
    if (temp_pool == NULL) {
        ngx_str_set(rs, "out of memory\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cf.temp_pool = temp_pool;
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.log = ngx_cycle->log;
    cf.conf_file = &conf_file;

    http_ctx = ngx_pcalloc(dmcf->pool, sizeof(ngx_http_conf_ctx_t));
    if (http_ctx == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "create http ctx failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    http_ctx->main_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (http_ctx->main_conf == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "create http main_conf failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    http_ctx->srv_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (http_ctx->srv_conf == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "create http srv_conf failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    http_ctx->loc_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (http_ctx->loc_conf == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "create http loc_conf failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;
        mi = cycle->modules[i]->ctx_index;

        if (module->create_main_conf) {
            http_ctx->main_conf[mi] = module->create_main_conf(&cf);
            if (http_ctx->main_conf[mi] == NULL) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create_main_conf failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (module->create_srv_conf) {
            http_ctx->srv_conf[mi] = module->create_srv_conf(&cf);
            if (http_ctx->srv_conf[mi] == NULL) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create_srv_conf failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (module->create_loc_conf) {
            http_ctx->loc_conf[mi] = module->create_loc_conf(&cf);
            if (http_ctx->loc_conf[mi] == NULL) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create_loc_conf failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    cf.ctx = http_ctx;
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(&cf) != NGX_OK) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "preconfiguration failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    /* location ctx */
    b = *buf;
    if ((args = ngx_http_dyloc_parse_location_args(dmcf->pool, &b)) == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "parse location failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.temp_pool = temp_pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_SRV_CONF;
    cf.pool = dmcf->pool;
    cf.ctx = srv->server->ctx;
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.args = args;
    cf.log = ngx_cycle->log;
    
    ctx = ngx_pcalloc(cf.pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "out of memory\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    pctx = cf.ctx;
    ctx->main_conf = http_ctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "out of memory\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; cf.cycle->modules[i]; i++) {
        if (cf.cycle->modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf.cycle->modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[cf.cycle->modules[i]->ctx_index] =
                                                   module->create_loc_conf(&cf);
            if (ctx->loc_conf[cf.cycle->modules[i]->ctx_index] == NULL) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create loc_conf failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;

    value = cf.args->elts;

    if (cf.args->nelts == 3) {

        len = value[1].len;
        mod = value[1].data;
        name = &value[2];

        if (len == 1 && mod[0] == '=') {

            clcf->name = *name;
            clcf->exact_match = 1;

        } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {

            clcf->name = *name;
            clcf->noregex = 1;

        } else if (len == 1 && mod[0] == '~') {

            if (ngx_http_dyloc_core_regex_location(&cf, clcf, name, 0) != NGX_OK) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create regex location failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {

            if (ngx_http_dyloc_core_regex_location(&cf, clcf, name, 1) != NGX_OK) {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "create regex location failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            ngx_destroy_pool(temp_pool);
            ngx_str_set(rs, "invalid location modifier\n");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {

        name = &value[1];

        if (name->data[0] == '=') {

            clcf->name.len = name->len - 1;
            clcf->name.data = name->data + 1;
            clcf->exact_match = 1;

        } else if (name->data[0] == '^' && name->data[1] == '~') {

            clcf->name.len = name->len - 2;
            clcf->name.data = name->data + 2;
            clcf->noregex = 1;

        } else if (name->data[0] == '~') {

            name->len--;
            name->data++;

            if (name->data[0] == '*') {

                name->len--;
                name->data++;

                if (ngx_http_dyloc_core_regex_location(&cf, clcf, name, 1) != NGX_OK) {
                    ngx_destroy_pool(temp_pool);
                    ngx_str_set(rs, "create regex location failed\n");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

            } else {
                if (ngx_http_dyloc_core_regex_location(&cf, clcf, name, 0) != NGX_OK) {
                    ngx_destroy_pool(temp_pool);
                    ngx_str_set(rs, "create regex location failed\n");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }

        } else {

            clcf->name = *name;

            if (name->data[0] == '@') {
                clcf->named = 1;
            }
        }
    }

    clcf->error_log = ngx_cycle->log;

    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.buffer = &b;
    cf.log = ngx_cycle->log;
    cf.name = "dyloc_init_module_conf";

    save = cf;
    cf.ctx = ctx;
    cf.cmd_type = NGX_HTTP_LOC_CONF;
    cf.conf_file = &conf_file;

    rv = ngx_conf_parse(&cf, NULL);
    if (rv == NGX_CONF_ERROR) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "location parse failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cf = save;

    for (i = 0; cf.cycle->modules[i]; i++) {
        if (cf.cycle->modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf.cycle->modules[i]->ctx;

        if (module->merge_loc_conf) {
            if (module->merge_loc_conf(&cf, \
                                       srv->server->ctx->loc_conf[cf.cycle->modules[i]->ctx_index], \
                                       clcf->loc_conf[cf.cycle->modules[i]->ctx_index]) != NGX_CONF_OK)
            {
                ngx_destroy_pool(temp_pool);
                ngx_str_set(rs, "merge loc_conf failed\n");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    if (ngx_http_dyloc_set_location(dmcf, &cf, srv, clcf) != NGX_OK) {
        ngx_destroy_pool(temp_pool);
        ngx_str_set(rs, "set location failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_destroy_pool(temp_pool);

    *ppclcf = clcf;
    ngx_str_set(rs, "Succeed\n");

    return NGX_HTTP_OK;
}

static ngx_int_t
ngx_http_dyloc_set_location(ngx_http_dyloc_main_conf_t *dmcf, \
                            ngx_conf_t *cf, \
                            ngx_http_dyloc_server_t *srv, \
                            ngx_http_core_loc_conf_t *clcf)
{
    int                        n = 0, opt = 0;
    const char                *errstr;
    ngx_http_core_loc_conf_t **clcfp, **tmp;
    ngx_http_core_srv_conf_t  *cscf = srv->server;
    ngx_http_core_loc_conf_t  *pclcf;

    if (clcf->noname) return NGX_ERROR; /*not support limit_except*/

    pclcf = srv->server->ctx->loc_conf[ngx_http_core_module.ctx_index];

#if (NGX_PCRE)
    if (clcf->regex) {
        if (pclcf->regex_locations != NULL) {
            for (clcfp = pclcf->regex_locations; *clcfp != NULL; ++clcfp) {
                if ((*clcfp)->name.len == clcf->name.len
                    && !ngx_strncmp((*clcfp)->name.data, clcf->name.data, clcf->name.len))
                {
                    return NGX_ERROR;
                }
                ++n;
            }
        }
        tmp = ngx_palloc(cf->pool, (n + 2) * sizeof(ngx_http_core_loc_conf_t *));
        if (tmp == NULL) return NGX_ERROR;
        if (pclcf->regex_locations != NULL) {
            memcpy(tmp, pclcf->regex_locations, n * sizeof(ngx_http_core_loc_conf_t *));
            ngx_pfree(cf->pool, pclcf->regex_locations);
        }
        tmp[n] = clcf;
        tmp[n + 1] = NULL;
        pclcf->regex_locations = tmp;
#if (NGX_HAVE_PCRE_JIT)
        opt = PCRE_STUDY_JIT_COMPILE;
#endif
        clcf->regex->regex->extra = pcre_study(clcf->regex->regex->code, opt, &errstr);
        return NGX_OK;
    }
#endif

    if (clcf->named) {
        if (cscf->named_locations != NULL) {
            for (clcfp = cscf->named_locations; *clcfp != NULL; ++clcfp) {
                if ((*clcfp)->name.len == clcf->name.len
                    && !ngx_strncmp((*clcfp)->name.data, clcf->name.data, clcf->name.len))
                {
                    return NGX_ERROR;
                }
                ++n;
            }
        }
        tmp = ngx_palloc(cf->pool, (n + 2) * sizeof(ngx_http_core_loc_conf_t *));
        if (tmp == NULL) return NGX_ERROR;
        if (cscf->named_locations != NULL) {
            memcpy(tmp, cscf->named_locations, n * sizeof(ngx_http_core_loc_conf_t *));
            ngx_pfree(cf->pool, cscf->named_locations);
        }
        tmp[n] = clcf;
        tmp[n + 1] = NULL;
        cscf->named_locations = tmp;
        return NGX_OK;
    }

    if (ngx_http_dyloc_location_match(clcf, pclcf->static_locations) == NGX_OK) {
        return NGX_ERROR;
    }
    return ngx_http_dyloc_location_insert(cf->pool, clcf, &pclcf->static_locations);
}

static ngx_int_t ngx_http_dyloc_location_match(ngx_http_core_loc_conf_t *clcf, ngx_http_location_tree_node_t *node)
{
    ngx_int_t  rc;
    size_t     len, n;
    u_char    *pdata;

    pdata = clcf->name.data;
    len = clcf->name.len;
    for ( ;; ) {
        if (node == NULL) return NGX_ERROR;
        n = (len <= (size_t)node->len)? len: node->len;
        rc = ngx_filename_cmp(pdata, node->name, n);
        if (rc != 0) {
            node = (rc < 0)? node->left: node->right;
            continue;
        }

        if (len > (size_t)node->len) {
            if (node->inclusive) {
                node = node->tree;
                pdata += n;
                len -= n;
                continue;
            }
            node = node->right;
            continue;
        }
        if (len == (size_t)node->len) {
            if (clcf->exact_match) {
                if (node->exact != NULL) break;
                return NGX_ERROR;
            } else {
                if (node->inclusive != NULL) break;
                return NGX_ERROR;
            }
        }
        node = node->left;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_dyloc_location_insert(ngx_pool_t *pool, ngx_http_core_loc_conf_t *clcf, ngx_http_location_tree_node_t **root)
{
    ngx_http_location_tree_node_t *node, *tprev, *lprev, *rprev, *cur;
    size_t                         len, n;
    ngx_int_t                      rc;
    u_char                        *pdata;

    len = clcf->name.len;
    pdata = clcf->name.data;

    node = ngx_palloc(pool, offsetof(ngx_http_location_tree_node_t, name) + len);
    if (node == NULL) return NGX_ERROR;
    node->left = node->right = node->tree = NULL;
    node->exact = NULL;
    node->inclusive = NULL;
    if (clcf->exact_match) {
        node->exact = clcf;
    } else {
        node->inclusive = clcf;
    }
    node->auto_redirect = (u_char)((node->exact && node->exact->auto_redirect) || (node->inclusive && node->inclusive->auto_redirect));
    node->len = (u_char) len;
    ngx_memcpy(node->name, clcf->name.data, len);

    if (*root == NULL) {
        *root = node;
        return NGX_OK;
    }

    tprev = lprev = rprev = NULL;
    cur = *root;
    for ( ;; ) {
        n = (len <= (size_t)cur->len)? len: cur->len;
        rc = ngx_filename_cmp(pdata, cur->name, n);
        if (rc != 0) {
            if (rc < 0) {
                tprev = lprev = rprev = NULL;
                if (cur->left == NULL) {
                    cur->left = node;
                    break;
                } else {
                    lprev = cur;
                    cur = cur->left;
                    continue;
                }
            } else {
                tprev = lprev = rprev = NULL;
                if (cur->right == NULL) {
                    cur->right = node;
                    break;
                } else {
                    rprev = cur;
                    cur = cur->right;
                    continue;
                }
            }
        }
        if (len > (size_t)cur->len) {
            tprev = lprev = rprev = NULL;
            if (cur->inclusive) {
                pdata += n;
                len -= n;
                if (cur->tree == NULL) {
                    cur->tree = node;
                    break;
                }
                tprev = cur;
                cur = cur->tree;
            } else {
                if (cur->right == NULL) {
                    cur->right = node;
                    break;
                }
                rprev = cur;
                cur = cur->right;
            }
            continue;
        }
        if (len < (size_t)cur->len) {
            if (node->inclusive != NULL) {
                if (lprev != NULL) {
                    lprev->left = node;
                    node->tree = cur;
                } else if (rprev != NULL) {
                    rprev->right = node;
                    node->tree = cur;
                } else if (tprev != NULL) {
                    tprev->tree = node;
                    node->tree = cur;
                } else {
                    *root = node;
                    node->tree = cur;
                }
                memcpy(cur->name, cur->name+n, cur->len-n);
                cur->name[cur->len-n] = 0;
                cur->len -= n;
                break;
            } else {
                tprev = lprev = rprev = NULL;
                if (cur->left == NULL) {
                    cur->left = node;
                    break;
                }
                lprev = cur;
                cur = cur->left;
                continue;
            }
        }
        if (node->exact) {
            if (cur->exact != NULL)
                ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "[dyloc] exact should be NULL");
            cur->exact = node->exact;
        } else if (node->inclusive) {
            if (cur->inclusive != NULL) {
                ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "[dyloc] inclusive should be NULL");
            }
            cur->inclusive = node->inclusive;
        } else {
            ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0, "[dyloc] shouldn't be here");
        }
        break;
    }
    memcpy(node->name, pdata, len);
    node->name[len] = 0;
    node->len = len;
    return NGX_OK;
}

static ngx_int_t ngx_http_dyloc_del_location(ngx_http_request_t *r, ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_int_t                   status;
    ngx_array_t                *args;
    ngx_slab_pool_t            *shpool;
    ngx_http_dyloc_params_t     params;

    args = ngx_http_dyloc_parse_args(r);
    if (args == NULL) {
        ngx_str_set(rv, "out of memory.\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_dyloc_params_set(args, &params);
    if (!params.port.len) {
        ngx_str_set(rv, "port must be given\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    shpool = g_shm_chain->shpool;
    ngx_shmtx_lock(&shpool->mutex);
    status = ngx_http_dyloc_do_del(r, &params, buf, rv);
    if (status == NGX_HTTP_OK)
        ngx_http_dyloc_write_in_file(&params, buf, 0);
    ngx_shmtx_unlock(&shpool->mutex);

    return status;
}

static ngx_int_t ngx_http_dyloc_do_del(ngx_http_request_t *r, ngx_http_dyloc_params_t *params, ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_http_dyloc_server_t    *srv;

    srv = ngx_http_dyloc_search_srv_by_params(params);
    if (srv == NULL) {
        ngx_str_set(rv, "cannot find server\n");
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_http_dyloc_check_conf_text(buf) != NGX_OK) {
        ngx_str_set(rv, "not support embedded location and limit_except\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_http_dyloc_remove_location(r, srv, buf) != NGX_OK) {
        ngx_str_set(rv, "remove location failed\n");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_str_set(rv, "succeed\n");

    return NGX_HTTP_OK;
}

static ngx_int_t ngx_http_dyloc_remove_location(ngx_http_request_t *r, ngx_http_dyloc_server_t *srv, ngx_buf_t *buf)
{
    ngx_array_t                 *args;
    ngx_str_t                   *value, *name;
    u_char                      *mod;
    ngx_buf_t                    b;
    size_t                       len;
    ngx_int_t                    i = -1, n = 0;
    ngx_http_core_loc_conf_t     clcf, *pclcf;
    ngx_http_dyloc_main_conf_t  *dmcf;
    ngx_http_core_loc_conf_t   **clcfp, **tmp = NULL;
    ngx_http_core_srv_conf_t    *cscf = srv->server;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);

    b = *buf;
    if ((args = ngx_http_dyloc_parse_location_args(r->pool, &b)) == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(&clcf, sizeof(clcf));

    value = args->elts;
    if (args->nelts == 3) {
        len = value[1].len;
        mod = value[1].data;
        name = &value[2];

        if (len == 1 && mod[0] == '=') {
            clcf.name = *name;
            clcf.exact_match = 1;
        } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {
            clcf.name = *name;
            clcf.noregex = 1;
        } else if (len == 1 && mod[0] == '~') {
            clcf.name = *name;
            clcf.regex = (ngx_http_regex_t *)0xff;
        } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {
            clcf.name = *name;
            clcf.regex = (ngx_http_regex_t *)0xff;
        } else {
            return NGX_ERROR;
        }
    } else {
        name = &value[1];
        if (name->data[0] == '=') {
            clcf.name.len = name->len - 1;
            clcf.name.data = name->data + 1;
            clcf.exact_match = 1;
        } else if (name->data[0] == '^' && name->data[1] == '~') {
            clcf.name.len = name->len - 2;
            clcf.name.data = name->data + 2;
            clcf.noregex = 1;
        } else if (name->data[0] == '~') {
            name->len--;
            name->data++;
            if (name->data[0] == '*') {
                name->len--;
                name->data++;
                clcf.name = *name;
                clcf.regex = (ngx_http_regex_t *)0xff;
            } else {
                clcf.name = *name;
                clcf.regex = (ngx_http_regex_t *)0xff;
            }
        } else {
            clcf.name = *name;
            if (name->data[0] == '@') {
                clcf.named = 1;
            }
        }
    }

    if (clcf.noname) return NGX_ERROR; /*not support limit_except*/

    pclcf = srv->server->ctx->loc_conf[ngx_http_core_module.ctx_index];

    /* do not free clcf's memory. It will leak but safe */
#if (NGX_PCRE)
    if (clcf.regex) {
        if (pclcf->regex_locations == NULL) return NGX_OK;
        for (clcfp = pclcf->regex_locations; *clcfp != NULL; ++clcfp) {
            if ((*clcfp)->name.len == clcf.name.len
                && !ngx_strncmp((*clcfp)->name.data, clcf.name.data, clcf.name.len))
            {
                i = n;
            }
            ++n;
        }
        if (i < 0) return NGX_OK;
        if (n > 1) {
            tmp = ngx_palloc(dmcf->pool, n * sizeof(ngx_http_core_loc_conf_t *));
            if (tmp == NULL) return NGX_ERROR;
        }
        ngx_http_dyloc_location_shm_del(srv, pclcf->regex_locations[i]);
        if (n > 1) {
            memcpy(tmp, pclcf->regex_locations, i * sizeof(ngx_http_core_loc_conf_t *));
            memcpy(tmp+i, &pclcf->regex_locations[i+1], (n - i - 1) * sizeof(ngx_http_core_loc_conf_t *));
            tmp[n] = NULL;
            ngx_pfree(dmcf->pool, pclcf->regex_locations);
        }
        pclcf->regex_locations = tmp;
        return NGX_OK;
    }
#endif

    if (clcf.named) {
        if (cscf->named_locations == NULL) return NGX_OK;
        for (clcfp = cscf->named_locations; *clcfp != NULL; ++clcfp) {
            if ((*clcfp)->name.len == clcf.name.len
                && !ngx_strncmp((*clcfp)->name.data, clcf.name.data, clcf.name.len))
            {
                i = n;
            }
            ++n;
        }
        if (i < 0) return NGX_OK;
        if (n > 1) {
            tmp = ngx_palloc(dmcf->pool, n * sizeof(ngx_http_core_loc_conf_t *));
            if (tmp == NULL) return NGX_ERROR;
        }
        ngx_http_dyloc_location_shm_del(srv, cscf->named_locations[i]);
        if (n > 1) {
            memcpy(tmp, cscf->named_locations, i * sizeof(ngx_http_core_loc_conf_t *));
            memcpy(tmp+i, &cscf->named_locations[i+1], (n - i - 1) * sizeof(ngx_http_core_loc_conf_t *));
            tmp[n] = NULL;
            ngx_pfree(dmcf->pool, cscf->named_locations);
        }
        cscf->named_locations = tmp;
        return NGX_OK;
    }

    if (ngx_http_dyloc_location_match(&clcf, pclcf->static_locations) != NGX_OK) {
        return NGX_OK;
    }
    return ngx_http_dyloc_location_static_del(r, srv, dmcf, &clcf, &pclcf->static_locations);
}

static void ngx_http_dyloc_location_shm_del(ngx_http_dyloc_server_t *srv, ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_dyloc_shm_location_t  *dsl;
    ngx_http_dyloc_location_t      *dl, *pdl;
    size_t                          i;

    dl = srv->locations.elts;
    for (i = 0; i < srv->locations.nelts; ++i) {
        pdl = &dl[i];
        if (!pdl->active) continue;
        if (pdl->location == clcf) break;
    }
    if (i >= srv->locations.nelts) return;
    pdl->active = 0;
    if (!pdl->dynamic) return;

    for (dsl = g_shm_chain->head; dsl != NULL; dsl = dsl->next) {
        if (dsl->server_name.len == srv->server_name->len
            && !ngx_strncmp(dsl->server_name.data, srv->server_name->data, srv->server_name->len)
            && dsl->content.len == pdl->content.len
            && !ngx_strncmp(dsl->content.data, pdl->content.data, pdl->content.len))
            break;
    }
    if (dsl == NULL) return;
    ngx_http_dyloc_shm_location_chain_del(&(g_shm_chain->head), &(g_shm_chain->tail), dsl);

    if (dsl->server_name.data != NULL)
        ngx_slab_free_locked(g_shm_chain->shpool, dsl->server_name.data);
    if (dsl->content.data != NULL)
        ngx_slab_free_locked(g_shm_chain->shpool, dsl->content.data);
    ngx_slab_free_locked(g_shm_chain->shpool, dsl);
}

static ngx_int_t
ngx_http_dyloc_location_static_del(ngx_http_request_t *r, \
                                   ngx_http_dyloc_server_t *srv, \
                                   ngx_http_dyloc_main_conf_t *dmcf, \
                                   ngx_http_core_loc_conf_t *del_clcf, \
                                   ngx_http_location_tree_node_t **root)
{
    ngx_http_location_tree_node_t  *root_dup = *root;
    ngx_http_core_loc_conf_t      **clcf, *pclcf;
    ngx_array_t                    *array;
    size_t                          i;

    array = ngx_array_create(r->pool, 8, sizeof(ngx_http_core_loc_conf_t *));
    if (array == NULL) return NGX_ERROR;;
    if ((pclcf = ngx_http_dyloc_location_collect(array, *root, del_clcf)) == NULL) {
        return NGX_ERROR;
    }
    /* do not free pclcf's memory and all nodes' memory. leak but safe */
    *root = NULL;
    clcf = array->elts;
    for (i = 0; i < array->nelts; ++i) {
        if (ngx_http_dyloc_location_insert(dmcf->pool, clcf[i], root) != NGX_OK) {
            *root = root_dup;
            return NGX_ERROR;
        }
    }

    ngx_http_dyloc_location_shm_del(srv, pclcf);
    return NGX_OK;
}

static ngx_http_core_loc_conf_t *
ngx_http_dyloc_location_collect(ngx_array_t *array, ngx_http_location_tree_node_t *node, ngx_http_core_loc_conf_t *del_clcf)
{
    ngx_http_core_loc_conf_t    *clcf, **pclcf, *ret = NULL, *rv;
    ngx_http_dyloc_main_conf_t  *dmcf;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);

    if (node->exact != NULL) {
        clcf = node->exact;
        if (del_clcf->exact_match) {
            if (clcf->name.len == del_clcf->name.len && !ngx_strncmp(clcf->name.data, del_clcf->name.data, clcf->name.len)) {
                ret = clcf;
            } else {
                pclcf = ngx_array_push(array);
                if (pclcf == NULL) return NULL;
                *pclcf = clcf;
            }
        } else {
            pclcf = ngx_array_push(array);
            if (pclcf == NULL) return NULL;
            *pclcf = clcf;
        }
    }

    if (node->inclusive != NULL) {
        clcf = node->inclusive;
        if (!del_clcf->exact_match) {
            if (clcf->name.len == del_clcf->name.len && !ngx_strncmp(clcf->name.data, del_clcf->name.data, clcf->name.len)) {
                ret = clcf;
            } else {
                pclcf = ngx_array_push(array);
                if (pclcf == NULL) return NULL;
                *pclcf = clcf;
            }
        } else {
            pclcf = ngx_array_push(array);
            if (pclcf == NULL) return NULL;
            *pclcf = clcf;
        }
    }

    if (node->left != NULL) {
        rv = ngx_http_dyloc_location_collect(array, node->left, del_clcf);
        ret = ret != NULL? ret: rv;
    }
    if (node->right != NULL) {
        rv = ngx_http_dyloc_location_collect(array, node->right, del_clcf);
        ret = ret != NULL? ret: rv;
    }
    if (node->tree != NULL) {
        rv = ngx_http_dyloc_location_collect(array, node->tree, del_clcf);
        ret = ret != NULL? ret: rv;
    }

    ngx_pfree(dmcf->pool, node);

    return ret;
}

static ngx_int_t ngx_http_dyloc_init_process(ngx_cycle_t *cycle)
{
    ngx_int_t                      rc;
    ngx_buf_t                      b;
    ngx_str_t                      rv;
    char                           port[8];
    ngx_slab_pool_t               *shpool;
    ngx_http_dyloc_params_t        params;
    ngx_http_dyloc_shm_location_t *dsl;

    shpool = g_shm_chain->shpool;
    ngx_shmtx_lock(&shpool->mutex);
    for (dsl = g_shm_chain->head; dsl != NULL; dsl = dsl->next) {
        memset(port, 0, sizeof(port));
        params.port.len = snprintf(port, sizeof(port)-1, "%u", dsl->port);
        params.port.data = (u_char *)port;
        params.server_name = dsl->server_name;

        b.start = b.pos = dsl->content.data;
        b.last = b.end = dsl->content.data + dsl->content.len;

        rc = ngx_http_dyloc_do_add(&params, &b, &rv, dsl);
        if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NOT_FOUND) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "[dyloc] reload error but not fatal, %V", &rv);
        }
    }
    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static void ngx_http_dyloc_write_in_file(ngx_http_dyloc_params_t *params, ngx_buf_t *content, int add)
{
    ngx_http_dyloc_server_t    *srv;
    int                         fd, in_zone = 0;
    char                        file_path[1024] = {0}, *p, *q, *file_content, *end;
    size_t                      len, i;
    struct stat                 st;
    ngx_str_t                   loc_name = ngx_null_string;
    ngx_http_dyloc_main_conf_t *dmcf;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);
    if (!dmcf->dir_path.len) return;

    srv = ngx_http_dyloc_search_srv_by_params(params);
    if (srv == NULL) return;

    len = dmcf->dir_path.len + 1 + srv->server_name->len + 6;
    if (len > sizeof(file_path)-1) return;

    p = file_path;
    memcpy(p, dmcf->dir_path.data, dmcf->dir_path.len);
    p += dmcf->dir_path.len;
    *p++ = '/';
    memcpy(p, srv->server_name->data, srv->server_name->len);
    p += srv->server_name->len;
    *p++ = '_';
    p += snprintf(p, sizeof(file_path)-1-(p-file_path), "%d", srv->port);

    /* get loc name */
    p = (char *)(content->start);
    end = (char *)(content->end);
    for (; p < end; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\n') break;
    }
    if (end - p < 8) return;

    if (strncmp(p, "location", 8)) {
        return;
    }
    p += 8;
    for (; p < end; ++p) {
        if (*p != ' ' && *p != '\t' && *p != '\n') break;
    }
    for (q = p; q < end; ++q) {
        if (*q == '{')
            break;
    }
    if (q >= end) return;
    for (; q > p; --q) {
        if (*q != ' ' && *q != '\t' && *q != '\n')
            break;
    }
    if (q <= p) return;

    loc_name.data = (u_char *)p;
    loc_name.len = q - p;

    /* open file */
    if (!access(file_path, F_OK)) {
        fd = open(file_path, O_RDWR);
    } else {
        fd = open(file_path, O_RDWR|O_CREAT, 0755);
    }
    if (fd < 0) {
        return;
    }
    ngx_http_dyloc_file_lock(fd);
    if (fstat(fd, &st) != 0) {
        goto failed;
    }
    file_content = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (file_content == NULL) goto failed;

    /* clean old */
    for (p = file_content, end = file_content + st.st_size; p < end; ++p) {
        if (*p == 'l' && end-p > 8 && !ngx_strncmp(p, "location", 8)) {
            q = p;
            p += 8;
            for (; p < end; ++p) {
                if (*p != ' ' && *p != '\t' && *p != '\n') break;
            }
            if (p >= end) break;

            if (*p == loc_name.data[0]
                && (size_t)(end-p) > loc_name.len
                && !ngx_strncmp(p, loc_name.data, loc_name.len))
            {
                p += loc_name.len;
                for (; p < end; ++p) {
                    if (*p != ' ' && *p != '\t' && *p != '\n') break;
                }
                if (p >= end) break;
                if (*p != '{') {
                    --p;
                    break;
                }
                ++in_zone;
                for (++p; p < end; ++p) {
                    if (*p == '{') {
                        ++in_zone;
                        continue;
                    }
                    if (*p == '}') {
                        --in_zone;
                        if (!in_zone) break;
                        continue;
                    }
                }
                memset(q, ' ', p + 1 - q);
                break;
            }
        }
    }
    munmap(file_content, st.st_size);

    if (add) {
        p = (char *)(content->start);
        q = (char *)(content->end);
        for (; p < q; ++p) {
            if (*p == '{') break;
        }
        if (p++ >= q) goto failed;
        for (--q; q > p; --q) {
            if (*q == '}') break;
        }
        if (q <= p) goto failed;

        lseek(fd, 0, SEEK_END);
        write(fd, "location ", 9);
        write(fd, loc_name.data, loc_name.len);
        write(fd, " {\n", 3);
        for (i = 0, len = q - p; i < len; ++i) {
            if (p[i] == ';') {
                end = &p[i];
                write(fd, "  ", 2);
                write(fd, p, end - p);
                write(fd, ";\n", 2);
                p = (char *)(&p[i] + 1);
            }
        }
        write(fd, "}\n", 2);
    }

failed:
    ngx_http_dyloc_file_unlock(fd);
    close(fd);
}

static void ngx_http_dyloc_file_lock(int fd)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fcntl(fd, F_SETLKW, &fl);
}

static void ngx_http_dyloc_file_unlock(int fd)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fcntl(fd, F_SETLKW, &fl);
}

static void ngx_http_dyloc_variable_sync_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    v->len = 0;
    v->data = NULL;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->escape = 0;

    /* sync */
    size_t                         i, j;
    ngx_int_t                      rc;
    ngx_buf_t                      b;
    ngx_str_t                      rv;
    ngx_array_t                   *shms;
    char                           port[8];
    ngx_slab_pool_t               *shpool;
    ngx_http_dyloc_params_t        params;
    ngx_http_dyloc_shm_location_t *dsl, **ppdsl, *pdsl;
    ngx_http_dyloc_main_conf_t    *dmcf;
    ngx_http_dyloc_location_t     *loc, *ploc;
    ngx_http_dyloc_server_t       *srv, *psrv;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);
    shpool = g_shm_chain->shpool;

    shms = ngx_array_create(r->pool, 8, sizeof(ngx_http_dyloc_shm_location_t *));
    if (shms == NULL) return;

    ngx_shmtx_lock(&shpool->mutex);

    srv = dmcf->servers.elts;
    for (i = 0; i < dmcf->servers.nelts; ++i) {
        psrv = &srv[i];
        loc = psrv->locations.elts;
        for (j = 0; j < psrv->locations.nelts; ++j) {
            ploc = &loc[j];
            if (!ploc->active || !ploc->dynamic)
                 continue;
            for (dsl = g_shm_chain->head; dsl != NULL; dsl = dsl->next) {
                if (ploc->content.len == dsl->content.len
                    && !ngx_strncmp(ploc->content.data, dsl->content.data, dsl->content.len))
                {
                    break;
                }
            }
            if (dsl == NULL) {
                ngx_http_dyloc_sync_del(r, psrv, ploc);
            } else {
                ppdsl = ngx_array_push(shms);
                if (ppdsl == NULL) goto failed;
                *ppdsl = dsl;
            }
        }
    }

    for (dsl = g_shm_chain->head; dsl != NULL; dsl = dsl->next) {
        ppdsl = shms->elts;
        for (i = 0; i < shms->nelts; ++i) {
            pdsl = ppdsl[i];
            if (pdsl == dsl) break;
        }
        if (i >= shms->nelts) {
            memset(port, 0, sizeof(port));
            params.port.len = snprintf(port, sizeof(port)-1, "%u", dsl->port);
            params.port.data = (u_char *)port;
            params.server_name = dsl->server_name;

            b.start = b.pos = dsl->content.data;
            b.last = b.end = dsl->content.data + dsl->content.len;

            rc = ngx_http_dyloc_do_add(&params, &b, &rv, dsl);
            if (rc != NGX_HTTP_OK && rc != NGX_HTTP_NOT_FOUND) {
                ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "[dyloc] reload error but not fatal, %V", &rv);
            }
        }
    }

failed:
    ngx_shmtx_unlock(&shpool->mutex);
}

static void ngx_http_dyloc_sync_del(ngx_http_request_t *r, ngx_http_dyloc_server_t *srv, ngx_http_dyloc_location_t *loc)
{
    ngx_int_t                      i = -1, n = 0;
    ngx_http_core_loc_conf_t      *clcf, *pclcf;
    ngx_http_dyloc_main_conf_t    *dmcf;
    ngx_http_core_loc_conf_t     **clcfp, **tmp = NULL;
    ngx_http_core_srv_conf_t      *cscf = srv->server;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyloc_module);
    pclcf = srv->server->ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf = loc->location;

    /* do not free clcf's memory. It will leak but safe */
#if (NGX_PCRE)
    if (clcf->regex) {
        if (pclcf->regex_locations == NULL) return;
        for (clcfp = pclcf->regex_locations; *clcfp != NULL; ++clcfp) {
            if ((*clcfp)->name.len == clcf->name.len
                && !ngx_strncmp((*clcfp)->name.data, clcf->name.data, clcf->name.len))
            {
                i = n;
            }
            ++n;
        }
        if (i < 0) return;
        if (n > 1) {
            tmp = ngx_palloc(dmcf->pool, n * sizeof(ngx_http_core_loc_conf_t *));
            if (tmp == NULL) return;
        }
        ngx_http_dyloc_location_shm_del(srv, pclcf->regex_locations[i]);
        if (n > 1) {
            memcpy(tmp, pclcf->regex_locations, i * sizeof(ngx_http_core_loc_conf_t *));
            memcpy(tmp+i, &pclcf->regex_locations[i+1], (n - i - 1) * sizeof(ngx_http_core_loc_conf_t *));
            tmp[n] = NULL;
            ngx_pfree(dmcf->pool, pclcf->regex_locations);
        }
        pclcf->regex_locations = tmp;
        return;
    }
#endif

    if (clcf->named) {
        if (cscf->named_locations == NULL) return;
        for (clcfp = cscf->named_locations; *clcfp != NULL; ++clcfp) {
            if ((*clcfp)->name.len == clcf->name.len
                && !ngx_strncmp((*clcfp)->name.data, clcf->name.data, clcf->name.len))
            {
                i = n;
            }
            ++n;
        }
        if (i < 0) return;
        if (n > 1) {
            tmp = ngx_palloc(dmcf->pool, n * sizeof(ngx_http_core_loc_conf_t *));
            if (tmp == NULL) return;
        }
        ngx_http_dyloc_location_shm_del(srv, cscf->named_locations[i]);
        if (n > 1) {
            memcpy(tmp, cscf->named_locations, i * sizeof(ngx_http_core_loc_conf_t *));
            memcpy(tmp+i, &cscf->named_locations[i+1], (n - i - 1) * sizeof(ngx_http_core_loc_conf_t *));
            tmp[n] = NULL;
            ngx_pfree(dmcf->pool, cscf->named_locations);
        }
        cscf->named_locations = tmp;
        return;
    }

    if (ngx_http_dyloc_location_match(clcf, pclcf->static_locations) != NGX_OK) {
        return;
    }
    (void)ngx_http_dyloc_location_static_del(r, srv, dmcf, clcf, &pclcf->static_locations);
}

