#include <ngx_http.h>
#include <ngx_http_dyups.h>

#define NGX_DYUPS_DELETING     1
#define NGX_DYUPS_DELETED      2

#define NGX_DYUPS_SHM_NAME_LEN 32

#define NGX_DYUPS_DELETE       1
#define NGX_DYUPS_ADD          2

#if (NGX_DEBUG)
#define NGX_DYUPS_INIT_SIZE 1
#else
#define NGX_DYUPS_INIT_SIZE 1024
#endif

typedef struct {
    ngx_str_t                           *up;
    ngx_str_t                           *server;
    ngx_str_t                           *max_fails;
    ngx_str_t                           *fail_timeout;
    ngx_str_t                           *weight;
    ngx_str_t                           *backup;
    ngx_str_t                           *down;
} ngx_http_dyups_params_t;

typedef struct {
    ngx_uint_t                           idx;
    ngx_uint_t                          *ref;
    ngx_uint_t                           deleted;
    ngx_flag_t                           dynamic;
    ngx_pool_t                          *pool;
    ngx_http_conf_ctx_t                 *ctx;
    ngx_http_upstream_srv_conf_t        *upstream;
} ngx_http_dyups_srv_conf_t;

typedef struct {
    ngx_flag_t                           enable;
    ngx_array_t                          dy_upstreams; /* ngx_http_dyups_srv_conf_t */
    ngx_str_t                            shm_name;
    ngx_uint_t                           shm_size;
    ngx_str_t                            file_path;
} ngx_http_dyups_main_conf_t;

typedef struct {
    ngx_uint_t                           ref;
    ngx_http_upstream_init_peer_pt       init;
} ngx_http_dyups_upstream_srv_conf_t;

typedef struct {
    void                                *data;
    ngx_http_dyups_upstream_srv_conf_t  *scf;
    ngx_event_get_peer_pt                get;
    ngx_event_free_peer_pt               free;
#if (NGX_HTTP_SSL)
    ngx_ssl_session_t                   *ssl_session;
#endif
} ngx_http_dyups_ctx_t;

typedef struct ngx_dyups_upstream_s {
    ngx_rbtree_node_t                    node;
    ngx_str_t                            name;
    ngx_str_t                            content;
    ngx_uint_t                           version;
} ngx_dyups_upstream_t;

typedef struct ngx_dyups_shctx_s {
    ngx_uint_t                           version;
    ngx_rbtree_t                         rbtree;
    ngx_rbtree_node_t                    sentinel;
} ngx_dyups_shctx_t;

typedef struct ngx_dyups_global_ctx_s {
    ngx_slab_pool_t                     *shpool;
    ngx_dyups_shctx_t                   *sh;
    ngx_uint_t                           version;
} ngx_dyups_global_ctx_t;

typedef ngx_int_t (*ngx_dyups_add_upstream_filter_pt)
    (ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);
typedef ngx_int_t (*ngx_dyups_del_upstream_filter_pt)
    (ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);


static void
ngx_dyups_update_server_status_change_content(ngx_dyups_upstream_t *ups, \
                                              ngx_str_t *server, \
                                              int down);
static int
ngx_http_dyups_server_match(ngx_str_t *dest, ngx_str_t *src);
static void
ngx_http_dyups_update_server_buf_fill(ngx_pool_t *pool, \
                                      ngx_http_dyups_params_t *params, \
                                      ngx_dyups_upstream_t *ups, \
                                      ngx_buf_t *buf);
static void
ngx_http_dyups_remove_server_buf_fill(ngx_pool_t *pool, \
                                      ngx_http_dyups_params_t *params, \
                                      ngx_dyups_upstream_t *ups, \
                                      ngx_buf_t *buf);
static void
ngx_http_dyups_params_set(ngx_array_t *args, ngx_http_dyups_params_t *params, size_t *size);
static void
ngx_http_dyups_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content);
static ngx_int_t
ngx_dyups_init_upstream(ngx_http_dyups_srv_conf_t *duscf, ngx_str_t *name, ngx_uint_t index);
static ngx_int_t
ngx_http_variable_dyups_up(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_dyups_add_vars(ngx_conf_t *cf);
static ngx_int_t ngx_http_dyups_reload();
static void ngx_http_dyups_write_in_file(ngx_str_t *upstream_name, ngx_buf_t *content);
static void ngx_dyups_file_lock(int fd);
static void ngx_dyups_file_unlock(int fd);
static ngx_dyups_upstream_t *ngx_dyups_search_upstream(ngx_str_t *name);
static int ngx_http_dyups_parse_args(ngx_http_request_t *r, ngx_array_t **res);
static ngx_int_t ngx_http_dyups_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_dyups_init(ngx_conf_t *cf);
static void *ngx_http_dyups_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_dyups_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_dyups_interface_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyups_interface_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body_from_file(ngx_http_request_t *r);
static void ngx_http_dyups_body_handler(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_update_server(ngx_http_request_t *r, ngx_int_t *status);
static ngx_buf_t *ngx_http_dyups_add_server(ngx_http_request_t *r, ngx_int_t *status);
static ngx_buf_t *ngx_http_dyups_remove_server(ngx_http_request_t *r, ngx_int_t *status);
static ngx_int_t ngx_http_dyups_do_get(ngx_http_request_t *r, ngx_array_t *resource);
static ngx_int_t ngx_http_dyups_do_delete(ngx_http_request_t *r, ngx_array_t *resource);
static ngx_http_dyups_srv_conf_t *ngx_dyups_find_upstream(ngx_str_t *name, ngx_int_t *idx);
static ngx_int_t ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf, ngx_buf_t *buf);
static void ngx_dyups_mark_upstream_delete(ngx_http_dyups_srv_conf_t *duscf);
static ngx_int_t ngx_http_dyups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_dyups_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_dyups_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);
static void *ngx_http_dyups_create_srv_conf(ngx_conf_t *cf);
static ngx_buf_t *ngx_http_dyups_show_list(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyups_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_dyups_init_shm(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_dyups_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool);
static ngx_int_t ngx_http_dyups_init_process(ngx_cycle_t *cycle);
static void ngx_http_dyups_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_dyups_shm_update_ups(ngx_str_t *name, ngx_buf_t *body);
static ngx_int_t ngx_dyups_shm_delete_ups(ngx_str_t *name);
static void ngx_dyups_shm_free_ups(ngx_slab_pool_t *shpool, ngx_dyups_upstream_t *ups);
static ngx_array_t *ngx_dyups_parse_path(ngx_pool_t *pool, ngx_str_t *path);
static ngx_int_t ngx_dyups_do_delete(ngx_str_t *name, ngx_str_t *rv);
static ngx_int_t ngx_dyups_do_update(ngx_str_t *name, ngx_buf_t *buf, ngx_str_t *rv);
static ngx_int_t ngx_dyups_sandbox_update(ngx_buf_t *buf, ngx_str_t *rv);
static void ngx_http_dyups_clean_request(void *data);
static ngx_int_t ngx_http_variable_dyups(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_dyups_set_peer_session(ngx_peer_connection_t *pc, void *data);
static void ngx_http_dyups_save_peer_session(ngx_peer_connection_t *pc, void *data);
#endif


static ngx_int_t ngx_dyups_add_upstream_filter(
    ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_dyups_del_upstream_filter(
    ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);

static ngx_int_t (*ngx_dyups_add_upstream_top_filter)
    (ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t (*ngx_dyups_del_upstream_top_filter)
    (ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf);

static ngx_http_variable_t  ngx_http_dyups_variables[] = {
    {
        ngx_string("dyups_"),
        NULL,
        ngx_http_variable_dyups,
        0,
        NGX_HTTP_VAR_PREFIX,
        0
    },
    {
        ngx_string("_dyups_"),
        NULL,
        ngx_http_variable_dyups_up,
        0,
        NGX_HTTP_VAR_PREFIX,
        0
    },
    ngx_http_null_variable
};


static ngx_command_t  ngx_http_dyups_commands[] = {
    {
        ngx_string("dyups_interface"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_dyups_interface,
        0,
        0,
        NULL
    },
    {
        ngx_string("dyups_shm_zone_size"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_dyups_main_conf_t, shm_size),
        NULL
    },
    {
        ngx_string("dyups_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_dyups_main_conf_t, file_path),
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t  ngx_http_dyups_module_ctx = {
    ngx_http_dyups_pre_conf,          /* preconfiguration */
    ngx_http_dyups_init,              /* postconfiguration */

    ngx_http_dyups_create_main_conf,  /* create main configuration */
    ngx_http_dyups_init_main_conf,    /* init main configuration */

    ngx_http_dyups_create_srv_conf,   /* create server configuration */
    NULL,                             /* merge server configuration */

    NULL,                             /* create location configuration */
    NULL                              /* merge location configuration */
};


ngx_module_t  ngx_http_dyups_module = {
    NGX_MODULE_V1,
    &ngx_http_dyups_module_ctx,    /* module context */
    ngx_http_dyups_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_dyups_init_process,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    ngx_http_dyups_exit_process,   /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_flag_t ngx_http_dyups_api_enable = 0;
static ngx_http_upstream_srv_conf_t ngx_http_dyups_deleted_upstream;
static ngx_dyups_global_ctx_t ngx_dyups_global_ctx;
static ngx_pool_t *g_pool = NULL;

static ngx_int_t ngx_http_dyups_pre_conf(ngx_conf_t *cf)
{
    ngx_dyups_add_upstream_top_filter = ngx_dyups_add_upstream_filter;
    ngx_dyups_del_upstream_top_filter = ngx_dyups_del_upstream_filter;
    return ngx_http_dyups_add_vars(cf);
}

static ngx_int_t ngx_http_dyups_add_vars(ngx_conf_t *cf)
{
    ngx_http_variable_t *cv, *v;

    for (cv = ngx_http_dyups_variables; cv->name.len; cv++) {
        v = ngx_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) return NGX_ERROR;
        *v = *cv;
    }

    return NGX_OK;
}


static char *ngx_http_dyups_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyups_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dyups_interface_handler;
    dmcf->enable = 1;

    return NGX_CONF_OK;
}

static void *ngx_http_dyups_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyups_main_conf_t));
    if (dmcf == NULL) return NULL;

    if (ngx_array_init(&dmcf->dy_upstreams, \
                       cf->pool, \
                       NGX_DYUPS_INIT_SIZE, \
                       sizeof(ngx_http_dyups_srv_conf_t)) != NGX_OK)
    {
        return NULL;
    }
    dmcf->enable = NGX_CONF_UNSET;
    dmcf->shm_size = NGX_CONF_UNSET_UINT;
    dmcf->file_path.data = NULL;
    dmcf->file_path.len = 0;

    return dmcf;
}

static char *ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t  *dmcf = conf;

    if (dmcf->enable == NGX_CONF_UNSET) {
        dmcf->enable = 0;
    }

    dmcf->enable = dmcf->enable || ngx_http_dyups_api_enable;
    if (!dmcf->enable) {
        return NGX_CONF_OK;
    }

    if (dmcf->shm_size == NGX_CONF_UNSET_UINT) {
        dmcf->shm_size = 2 * 1024 * 1024;
    }

    return ngx_http_dyups_init_shm(cf, conf);
}

static char *ngx_http_dyups_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t *dmcf = conf;
    ngx_shm_zone_t  *shm_zone;

    if (ngx_http_dyups_get_shm_name(&dmcf->shm_name, cf->pool) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, \
                                     &dmcf->shm_name, \
                                     dmcf->shm_size, \
                                     &ngx_http_dyups_module);
    if (shm_zone == NULL) return NGX_CONF_ERROR;
    shm_zone->data = &ngx_dyups_global_ctx;
    shm_zone->init = ngx_http_dyups_init_shm_zone;

    ngx_log_error(NGX_LOG_DEBUG, \
                  cf->log, \
                  0, \
                  "[dyups] init shm:%V, size:%ui", \
                  &dmcf->shm_name,
                  dmcf->shm_size);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_dyups_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, NGX_DYUPS_SHM_NAME_LEN);
    if (shm_name->data == NULL) return NGX_ERROR;
    last = ngx_snprintf(shm_name->data, NGX_DYUPS_SHM_NAME_LEN, "%s#shm", "ngx_http_dyups_module");
    shm_name->len = last - shm_name->data;

    return NGX_OK;
}

static ngx_int_t ngx_http_dyups_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_dyups_global_ctx_t  *octx = data;
    ngx_slab_pool_t         *shpool;
    ngx_dyups_shctx_t       *sh;

    if (octx != NULL) {
        ngx_dyups_global_ctx.sh = octx->sh;
        ngx_dyups_global_ctx.shpool = octx->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = ngx_slab_alloc(shpool, sizeof(ngx_dyups_shctx_t));
    if (sh == NULL) return NGX_ERROR;

    ngx_dyups_global_ctx.sh = sh;
    ngx_dyups_global_ctx.shpool = shpool;

    sh->version = 0;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel, ngx_str_rbtree_insert_value);

    return NGX_OK;
}

static void *ngx_http_dyups_create_srv_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_dyups_upstream_srv_conf_t));
}

static ngx_int_t ngx_http_dyups_init(ngx_conf_t *cf)
{
    ngx_url_t                            u;
    ngx_uint_t                           i;
    ngx_http_dyups_srv_conf_t           *duscf;
    ngx_http_upstream_server_t          *us;
    ngx_http_dyups_main_conf_t          *dmcf;
    ngx_http_upstream_srv_conf_t       **uscfp;
    ngx_http_upstream_main_conf_t       *umcf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyups_module);
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    if (!dmcf->enable) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        duscf = ngx_array_push(&dmcf->dy_upstreams);
        if (duscf == NULL) return NGX_ERROR;

        ngx_memzero(duscf, sizeof(ngx_http_dyups_srv_conf_t));
        duscf->pool = NULL;
        duscf->upstream = uscfp[i];
        duscf->dynamic = (uscfp[i]->port == 0
                          && uscfp[i]->srv_conf && uscfp[i]->servers
                          && uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE);
        duscf->deleted = 0;
        duscf->idx = i;

        if (duscf->dynamic) {
            dscf = duscf->upstream->srv_conf[ngx_http_dyups_module.ctx_index];
            duscf->ref = &dscf->ref;
        }
    }

    /* alloc a fake upstream for upstream deletion*/
    ngx_memzero(&ngx_http_dyups_deleted_upstream, sizeof(ngx_http_upstream_srv_conf_t));
    ngx_http_dyups_deleted_upstream.srv_conf = ((ngx_http_conf_ctx_t *)(cf->ctx))->srv_conf;
    ngx_http_dyups_deleted_upstream.servers = ngx_array_create(cf->pool, 1, sizeof(ngx_http_upstream_server_t));

    us = ngx_array_push(ngx_http_dyups_deleted_upstream.servers);
    if (us == NULL) return NGX_ERROR;
    ngx_memzero(&u, sizeof(ngx_url_t));
    ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
    u.default_port = 80;
    ngx_str_set(&u.url, "0.0.0.0");
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "[dyups] %s in init", u.err);
        }
        return NGX_ERROR;
    }
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->down = 1;
    ngx_str_set(&ngx_http_dyups_deleted_upstream.host, "_dyups_upstream_down_host_");
    ngx_http_dyups_deleted_upstream.file_name = (u_char *) "dyups_upstream";

    return NGX_OK;
}

static ngx_int_t ngx_http_dyups_init_process(ngx_cycle_t *cycle)
{
    ngx_slab_pool_t             *shpool;
    ngx_http_dyups_main_conf_t  *dmcf;

    g_pool = cycle->pool;
    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyups_module);
    if (!dmcf || !dmcf->enable || ngx_process == NGX_PROCESS_HELPER) {
        ngx_http_dyups_api_enable = 0;
        return NGX_OK;
    }

    ngx_http_dyups_api_enable = 1;
    shpool = ngx_dyups_global_ctx.shpool;
    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_dyups_reload();
    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static void ngx_http_dyups_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i;
    ngx_http_dyups_srv_conf_t   *duscfs, *duscf;
    ngx_http_dyups_main_conf_t  *dumcf;

    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyups_module);
    if (dumcf == NULL) return;

    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; ++i) {
        duscf = &duscfs[i];
        if (duscf->pool) {
            ngx_destroy_pool(duscf->pool);
            duscf->pool = NULL;
        }
    }
}

static ngx_int_t ngx_http_dyups_interface_handler(ngx_http_request_t *r)
{
    ngx_array_t  *res;

    res = ngx_dyups_parse_path(r->pool, &r->uri);
    if (res == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (r->method == NGX_HTTP_GET)
        return ngx_http_dyups_do_get(r, res);

    if (r->method == NGX_HTTP_DELETE) {
        ngx_int_t rc = ngx_http_dyups_do_delete(r, res);
        return rc;
    }

    return ngx_http_dyups_interface_read_body(r);
}

ngx_int_t ngx_dyups_delete_upstream(ngx_str_t *name, ngx_str_t *rv)
{
    ngx_int_t                    status, rc;
    ngx_slab_pool_t             *shpool;

    shpool = ngx_dyups_global_ctx.shpool;

    if (!ngx_http_dyups_api_enable) {
        ngx_str_set(rv, "API disabled\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_shmtx_lock(&shpool->mutex);

    status = ngx_dyups_do_delete(name, rv);
    if (status != NGX_HTTP_OK) {
        ngx_shmtx_unlock(&shpool->mutex);
        return status;
    }

    rc = ngx_dyups_shm_delete_ups(name);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "shm delete failed");
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "[dyups] %V", &rv);
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return status;
}

static ngx_int_t ngx_http_dyups_do_get(ngx_http_request_t *r, ngx_array_t *resource)
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
    if (value[0].len == 3 && ngx_strncasecmp(value[0].data, (u_char *)"add", 3) == 0) {
        if ((buf = ngx_http_dyups_add_server(r, &status)) == NULL) {
            goto finish;
        }
    } else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"remove", 6) == 0) {
        if ((buf = ngx_http_dyups_remove_server(r, &status)) == NULL) {
            goto finish;
        }
    } else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"update", 6) == 0) {
        if ((buf = ngx_http_dyups_update_server(r, &status)) == NULL) {
            goto finish;
        }
    } else if (value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *) "list", 4) == 0) {
        if ((buf = ngx_http_dyups_show_list(r)) == NULL) {
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

static ngx_int_t ngx_http_dyups_reload()
{
    ngx_buf_t              body;
    ngx_int_t              rc;
    ngx_str_t              rv;
    ngx_dyups_shctx_t     *sh;
    ngx_rbtree_node_t     *node, *root, *sentinel;
    ngx_dyups_upstream_t  *ups;

    sh = ngx_dyups_global_ctx.sh;
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;
    if (root == sentinel) return NGX_OK;

    for (node = ngx_rbtree_min(root, sentinel); \
         node; \
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
        if (ups->version > ngx_dyups_global_ctx.version) continue;

        body.start = body.pos = ups->content.data;
        body.end = body.last = ups->content.data + ups->content.len;
        rc = ngx_dyups_do_update(&ups->name, &body, &rv);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "[dyups] sync add: %V rv: %V rc: %i",
                      &ups->name, &rv, rc);
    }

    ngx_dyups_global_ctx.version = sh->version;

    return NGX_OK;
}

static ngx_buf_t *ngx_http_dyups_update_server(ngx_http_request_t *r, ngx_int_t *status)
{
    int                      rc;
    size_t                   size = 0;
    ngx_array_t             *args;
    ngx_str_t                rv;
    ngx_http_dyups_params_t  params;
    ngx_buf_t               *buf;
    ngx_slab_pool_t         *shpool;
    ngx_dyups_shctx_t       *sh;
    ngx_rbtree_node_t       *node, *root, *sentinel;
    ngx_dyups_upstream_t    *ups = NULL;

    if ((rc = ngx_http_dyups_parse_args(r, &args)) < 0) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    if (args == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }
    ngx_memzero(&params, sizeof(ngx_http_dyups_params_t));
    ngx_http_dyups_params_set(args, &params, &size);
    if (params.up == NULL || params.server == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel); \
             node; \
             node = ngx_rbtree_next(&sh->rbtree, node))
        {
            ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
            if (ups->name.len == params.up->len
                && !ngx_strncmp(ups->name.data, params.up->data, ups->name.len))
            {
                break;
            }
        }
    }
    if (ups == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    size += ups->content.len;
    if ((buf = ngx_create_temp_buf(r->pool, size)) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    ngx_http_dyups_update_server_buf_fill(r->pool, &params, ups, buf);
    ngx_shmtx_unlock(&shpool->mutex);

    *status = ngx_dyups_update_upstream(params.up, buf, &rv);

    if ((buf = ngx_create_temp_buf(r->pool, rv.len)) == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    buf->last = ngx_sprintf(buf->last, "%V", &rv);
    return buf;
}

static void
ngx_http_dyups_update_server_buf_fill(ngx_pool_t *pool, \
                                      ngx_http_dyups_params_t *params, \
                                      ngx_dyups_upstream_t *ups, \
                                      ngx_buf_t *buf)
{
    ngx_str_t  tmp;
    size_t     i, head = 0;
    ngx_str_t *content = &ups->content;

    for (i = 0; i < content->len; ++i) {
        if (content->data[i] == ';') {
            tmp.data = &(content->data[head]);
            tmp.len = i - head;
            head = i + 1;
            if (tmp.len < params->server->len) {
                buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
            } else if (!ngx_http_dyups_server_match(&tmp, params->server)) {
                if (params->server) buf->last = ngx_sprintf(buf->last, " server %V", params->server);
                if (params->max_fails) buf->last = ngx_sprintf(buf->last, " %V", params->max_fails);
                if (params->fail_timeout) buf->last = ngx_sprintf(buf->last, " %V", params->fail_timeout);
                if (params->weight) buf->last = ngx_sprintf(buf->last, " %V", params->weight);
                if (params->backup) buf->last = ngx_sprintf(buf->last, " %V", params->backup);
                if (params->down) buf->last = ngx_sprintf(buf->last, " %V", params->down);
                buf->last = ngx_sprintf(buf->last, ";");
            } else {
                buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
            }
        }
    }
    if (head != i) {
        tmp.data = &(content->data[head]);
        tmp.len = i - head;
        if (tmp.len < params->server->len) {
            buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
        } else if (!ngx_http_dyups_server_match(&tmp, params->server)) {
            if (params->server) buf->last = ngx_sprintf(buf->last, " server %V", params->server);
            if (params->max_fails) buf->last = ngx_sprintf(buf->last, " %V", params->max_fails);
            if (params->fail_timeout) buf->last = ngx_sprintf(buf->last, " %V", params->fail_timeout);
            if (params->weight) buf->last = ngx_sprintf(buf->last, " %V", params->weight);
            if (params->backup) buf->last = ngx_sprintf(buf->last, " %V", params->backup);
            if (params->down) buf->last = ngx_sprintf(buf->last, " %V", params->down);
            buf->last = ngx_sprintf(buf->last, ";");
        } else {
            buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
        }
    }
}

static ngx_buf_t *ngx_http_dyups_add_server(ngx_http_request_t *r, ngx_int_t *status)
{
    int                      rc;
    size_t                   size = 0;
    ngx_array_t             *args;
    ngx_str_t                rv;
    ngx_http_dyups_params_t  params;
    ngx_buf_t               *buf;
    ngx_slab_pool_t         *shpool;
    ngx_dyups_shctx_t       *sh;
    ngx_rbtree_node_t       *node, *root, *sentinel;
    ngx_dyups_upstream_t    *ups;

    if ((rc = ngx_http_dyups_parse_args(r, &args)) < 0) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    if (args == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }
    ngx_memzero(&params, sizeof(ngx_http_dyups_params_t));
    ngx_http_dyups_params_set(args, &params, &size);
    if (params.up == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel); \
             node; \
             node = ngx_rbtree_next(&sh->rbtree, node))
        {
            ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
            if (ups->name.len != params.up->len
                || ngx_strncmp(ups->name.data, params.up->data, ups->name.len))
            {
                continue;
            }
            size += ups->content.len;
        }
    }

    if ((buf = ngx_create_temp_buf(r->pool, size)) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    if (sh->rbtree.sentinel != sh->rbtree.root) {
        for (node = ngx_rbtree_min(root, sentinel); \
             node; \
             node = ngx_rbtree_next(&sh->rbtree, node))
        {
            ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
            if (ups->name.len != params.up->len
                || ngx_strncmp(ups->name.data, params.up->data, ups->name.len))
            {
                continue;
            }
            memcpy(buf->last, ups->content.data, ups->content.len);
            buf->last += ups->content.len;
        }
    }
    ngx_shmtx_unlock(&shpool->mutex);

    if (params.server) buf->last = ngx_sprintf(buf->last, " server %V", params.server);
    if (params.max_fails) buf->last = ngx_sprintf(buf->last, " %V", params.max_fails);
    if (params.fail_timeout) buf->last = ngx_sprintf(buf->last, " %V", params.fail_timeout);
    if (params.weight) buf->last = ngx_sprintf(buf->last, " %V", params.weight);
    if (params.backup) buf->last = ngx_sprintf(buf->last, " %V", params.backup);
    if (params.down) buf->last = ngx_sprintf(buf->last, " %V", params.down);
    buf->last = ngx_sprintf(buf->last, ";");
    *status = ngx_dyups_update_upstream(params.up, buf, &rv);

    if ((buf = ngx_create_temp_buf(r->pool, rv.len)) == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    buf->last = ngx_sprintf(buf->last, "%V", &rv);
    return buf;
}

static ngx_buf_t *ngx_http_dyups_remove_server(ngx_http_request_t *r, ngx_int_t *status)
{
    int                      rc;
    ngx_array_t             *args;
    ngx_str_t                rv;
    ngx_http_dyups_params_t  params;
    ngx_buf_t               *buf;
    ngx_slab_pool_t         *shpool;
    ngx_dyups_shctx_t       *sh;
    ngx_rbtree_node_t       *node, *root, *sentinel;
    ngx_dyups_upstream_t    *ups = NULL;

    if ((rc = ngx_http_dyups_parse_args(r, &args)) < 0) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    if (args == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }
    ngx_memzero(&params, sizeof(ngx_http_dyups_params_t));
    ngx_http_dyups_params_set(args, &params, NULL);
    if (params.up == NULL || params.server == NULL) {
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel); \
             node; \
             node = ngx_rbtree_next(&sh->rbtree, node))
        {
            ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
            if (ups->name.len == params.up->len
                && !ngx_strncmp(ups->name.data, params.up->data, ups->name.len))
            {
                break;
            }
        }
    }
    if (ups == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        *status = NGX_HTTP_BAD_REQUEST;
        return NULL;
    }

    if ((buf = ngx_create_temp_buf(r->pool, ups->content.len)) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }

    ngx_http_dyups_remove_server_buf_fill(r->pool, &params, ups, buf);
    ngx_shmtx_unlock(&shpool->mutex);

    *status = ngx_dyups_update_upstream(params.up, buf, &rv);

    if ((buf = ngx_create_temp_buf(r->pool, rv.len)) == NULL) {
        *status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NULL;
    }
    buf->last = ngx_sprintf(buf->last, "%V", &rv);
    return buf;
}

static void
ngx_http_dyups_remove_server_buf_fill(ngx_pool_t *pool, \
                                      ngx_http_dyups_params_t *params, \
                                      ngx_dyups_upstream_t *ups, \
                                      ngx_buf_t *buf)
{
    size_t     i, head = 0;
    ngx_str_t  tmp;
    ngx_str_t *content = &ups->content;

    for (i = 0; i < content->len; ++i) {
        if (content->data[i] == ';') {
            tmp.data = &(content->data[head]);
            tmp.len = i - head;
            head = i + 1;
            if (tmp.len < params->server->len) {
                buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
            } else if (!ngx_http_dyups_server_match(&tmp, params->server)) {
                continue;
            } else {
                buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
            }
        }
    }
    if (head != i) {
        tmp.data = &(content->data[head]);
        tmp.len = i - head;
        if (tmp.len < params->server->len) {
            buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
        } else if (ngx_http_dyups_server_match(&tmp, params->server)) {
            buf->last = ngx_sprintf(buf->last, "%V;", &tmp);
        }
    }
}

static int ngx_http_dyups_server_match(ngx_str_t *dest, ngx_str_t *src)
{
    u_char *p = dest->data, *end = dest->data + dest->len;
    for (; p<end && (size_t)(end-p)>=src->len; ++p) {
        if (*p == src->data[0]) {
            if (!ngx_strncmp((char *)p, (char *)(src->data), src->len))
                return 0;
        }
    }
    return -1;
}

static void
ngx_http_dyups_params_set(ngx_array_t *args, ngx_http_dyups_params_t *params, size_t *size)
{
    size_t i;
    ngx_str_t *s;
    for (i = 0; i < args->nelts; ++i) {
        s = &(((ngx_str_t *)(args->elts))[i]);
        if (s->len > 3 && !ngx_strncmp((char *)(s->data), "up=", 3)) {
            s->data += 3;
            s->len -= 3;
            if (s->len) params->up = s;
        } else if (s->len > 7 && !ngx_strncmp((char *)(s->data), "server=", 7)) {
            s->data += 7;
            s->len -= 7;
            params->server = s;
            if (size != NULL) (*size) += (7 + s->len);
        } else if (s->len > 10 && !ngx_strncmp((char *)(s->data), "max_fails=", 10)) {
            params->max_fails = s;
            if (size != NULL) (*size) += s->len;
        } else if (s->len > 13 && !ngx_strncmp((char *)(s->data), "fail_timeout=", 13)) {
            params->fail_timeout = s;
            if (size != NULL) (*size) += s->len;
        } else if (s->len > 7 && !ngx_strncmp((char *)(s->data), "weight=", 7)) {
            params->weight = s;
            if (size != NULL) (*size) += s->len;
        } else if (s->len >= 6 && !ngx_strncmp((char *)(s->data), "backup", 6)) {
            if (s->len > 6) s->len = 6;
            params->backup = s;
            if (size != NULL) (*size) += 6;
        } else if (s->len >= 4 && !ngx_strncmp((char *)(s->data), "down", 4)) {
            if (s->len > 4) s->len = 4;
            params->down = s;
            if (size != NULL) (*size) += 4;
        }
    }
    if (size != NULL) (*size) += 10;
}

static int ngx_http_dyups_parse_args(ngx_http_request_t *r, ngx_array_t **res)
{
    size_t     i, head = 0;
    ngx_str_t *tmp;

    if (!r->args.len) {
        *res = NULL;
        return 0;
    }

    if ((*res = ngx_array_create(r->pool, 7, sizeof(ngx_str_t))) == NULL) {
        return -1;
    }

    for (i = 0; i < r->args.len; ++i) {
        if (r->args.data[i] == '&') {
            tmp = ngx_array_push(*res);
            if (tmp == NULL) return -1;
            tmp->data = &(r->args.data[head]);
            tmp->len = i - head;
            head = i + 1;
        }
    }
    if (head != i) {
        tmp = ngx_array_push(*res);
        if (tmp == NULL) return -1;
        tmp->data = &(r->args.data[head]);
        tmp->len = i - head;
    }
    return 0;
}

static ngx_buf_t *ngx_http_dyups_show_list(ngx_http_request_t *r)
{
    ngx_uint_t             len;
    ngx_buf_t             *buf;
    ngx_slab_pool_t       *shpool;
    ngx_dyups_shctx_t     *sh;
    ngx_rbtree_node_t     *node, *root, *sentinel;
    ngx_dyups_upstream_t  *ups;

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;

    if (root == sentinel) {
        ngx_shmtx_unlock(&shpool->mutex);
        return ngx_create_temp_buf(r->pool, 0);
    }

    len = 0;
    for (node = ngx_rbtree_min(root, sentinel); \
         node; \
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
        len += + ups->name.len + ups->content.len + sizeof("upstream  {\n\n}\n");
    }

    if ((buf = ngx_create_temp_buf(r->pool, len)) == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NULL;
    }

    for (node = ngx_rbtree_min(root, sentinel); \
         node; \
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
        buf->last = ngx_sprintf(buf->last, "upstream %V {\n", &ups->name);
        buf->last = ngx_sprintf(buf->last, "%V\n}\n", &ups->content);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return buf;
}

static ngx_dyups_upstream_t *ngx_dyups_search_upstream(ngx_str_t *name)
{
    ngx_dyups_shctx_t     *sh;
    ngx_rbtree_node_t     *node, *root, *sentinel;
    ngx_dyups_upstream_t  *ups;

    sh = ngx_dyups_global_ctx.sh;
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;

    if (root == sentinel) return NULL;

    for (node = ngx_rbtree_min(root, sentinel); \
         node; \
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        ups = (ngx_dyups_upstream_t*)((char*) node - offsetof(ngx_dyups_upstream_t, node));
        if (ups->name.len == name->len
            && !ngx_strncmp(ups->name.data, name->data, name->len))
        {
            break;
        }
        ups = NULL;
    }

    return ups;
}

static ngx_int_t ngx_dyups_do_delete(ngx_str_t *name, ngx_str_t *rv)
{
    ngx_int_t                   dumy;
    ngx_http_dyups_srv_conf_t  *duscf;
    ngx_str_t sandbox = ngx_string("_dyups_upstream_sandbox_");

    duscf = ngx_dyups_find_upstream(name, &dumy);

    if (duscf != NULL && !duscf->deleted)
        ngx_dyups_mark_upstream_delete(duscf);

    if (name->len != sandbox.len || ngx_strncmp(name->data, sandbox.data, name->len)) {
        if (ngx_http_upstream_health_check_update_handler(name) != NGX_OK) {
            ngx_str_set(rv, "upstream health check update failed");
        } else {
            ngx_str_set(rv, "success");
        }
    }

    return NGX_HTTP_OK;
}

static ngx_int_t ngx_http_dyups_do_delete(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_str_t   *value, name, rv;
    ngx_int_t    status, rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) return rc;

    if (resource->nelts != 2) {
        ngx_str_set(&rv, "not support this interface");
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    value = resource->elts;
    if (value[0].len != 8 || ngx_strncasecmp(value[0].data, (u_char *) "upstream", 8)) {
        ngx_str_set(&rv, "not support this api");
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }
    name = value[1];

    status = ngx_dyups_delete_upstream(&name, &rv);
    ngx_http_dyups_write_in_file(&name, NULL);

finish:
    r->headers_out.status = status;
    r->headers_out.content_length_n = rv.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) return rc;

    if (rv.len == 0)
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);

    if ((b = ngx_create_temp_buf(r->pool, rv.len)) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = rv.data;
    b->last = rv.data + rv.len;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_http_dyups_interface_read_body(ngx_http_request_t *r)
{
    ngx_int_t  rc = ngx_http_read_client_request_body(r, ngx_http_dyups_body_handler);
    return rc >= NGX_HTTP_SPECIAL_RESPONSE? rc: NGX_DONE;
}

static void ngx_http_dyups_body_handler(ngx_http_request_t *r)
{
    ngx_str_t                   *value, rv, name;
    ngx_int_t                    status;
    ngx_buf_t                   *body;
    ngx_array_t                 *res;

    ngx_str_set(&rv, "");

    if (r->method != NGX_HTTP_POST) {
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    if ((res = ngx_dyups_parse_path(r->pool, &r->uri)) == NULL) {
        ngx_str_set(&rv, "out of memory");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        status = NGX_HTTP_NO_CONTENT;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[dyups] interface no content");
        ngx_str_set(&rv, "no content\n");
        goto finish;
    }

    if (r->request_body->temp_file) {
        body = ngx_http_dyups_read_body_from_file(r);
    } else {
        body = ngx_http_dyups_read_body(r);
    }
    if (body == NULL) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_str_set(&rv, "out of memory\n");
        goto finish;
    }

    if (res->nelts != 2) {
        ngx_str_set(&rv, "not support this interface");
        status = NGX_HTTP_NOT_FOUND;
        goto finish;
    }

    value = res->elts;
    if (value[0].len != 8 || ngx_strncasecmp(value[0].data, (u_char *) "upstream", 8)) {
        ngx_str_set(&rv, "not support this api");
        status = NGX_HTTP_NOT_FOUND;
        goto finish;
    }
    name = value[1];

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "[dyups] post upstream name: %V", &name);

    status = ngx_dyups_update_upstream(&name, body, &rv);
    ngx_http_dyups_write_in_file(&name, body);

finish:
    ngx_http_dyups_send_response(r, status, &rv);
}

ngx_int_t ngx_dyups_update_upstream(ngx_str_t *name, ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_int_t                    status;
    ngx_slab_pool_t             *shpool;

    shpool = ngx_dyups_global_ctx.shpool;

    if (!ngx_http_dyups_api_enable) {
        ngx_str_set(rv, "API disabled\n");
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_shmtx_lock(&shpool->mutex);

    if ((status = ngx_dyups_sandbox_update(buf, rv)) != NGX_HTTP_OK) goto finish;

    if ((status = ngx_dyups_do_update(name, buf, rv)) == NGX_HTTP_OK) {
        if (ngx_dyups_shm_update_ups(name, buf)) {
            ngx_str_set(rv, "alert: update success but save to shm failed\n");
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

 finish:
    ngx_shmtx_unlock(&shpool->mutex);

    return status;
}

static ngx_int_t ngx_dyups_do_update(ngx_str_t *name, ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_http_dyups_srv_conf_t      *duscf;
    ngx_http_dyups_main_conf_t     *dumcf;
    ngx_http_upstream_srv_conf_t  **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_int_t                       idx, update = 1;
    ngx_str_t                       sandbox = ngx_string("_dyups_upstream_sandbox_");

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyups_module);
    duscf = ngx_dyups_find_upstream(name, &idx);
    if (duscf) {
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "[dyups] upstream reuse, idx: [%i]", idx);

        if (!duscf->deleted) {
            ngx_dyups_upstream_t *du = ngx_dyups_search_upstream(name);
            if (du != NULL) {
                if (du->content.len == (size_t)(buf->last-buf->start) && \
                    !memcmp(du->content.data, buf->start, du->content.len))
                {
                    update = 0;
                }
            }
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "[dyups] upstream delete first");
            ngx_dyups_mark_upstream_delete(duscf);
            duscf = ngx_dyups_find_upstream(name, &idx);
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "[dyups] find another, idx: [%i]", idx);
        }
    }

    if (idx == -1) {
        /* need create a new upstream */
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "[dyups] create upstream %V", name);

        duscf = ngx_array_push(&dumcf->dy_upstreams);
        if (duscf == NULL) {
            ngx_str_set(rv, "out of memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        uscfp = ngx_array_push(&umcf->upstreams);
        if (uscfp == NULL) {
            ngx_str_set(rv, "out of memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memzero(duscf, sizeof(ngx_http_dyups_srv_conf_t));
        idx = umcf->upstreams.nelts - 1;
    }

    duscf->idx = idx;
    if (ngx_dyups_init_upstream(duscf, name, idx) != NGX_OK) {
        ngx_str_set(rv, "init upstream failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* init upstream */
    if (ngx_dyups_add_server(duscf, buf) != NGX_OK) {
        ngx_str_set(rv, "update server failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (update && (name->len != sandbox.len || ngx_strncmp(name->data, sandbox.data, name->len))) {
        if (ngx_http_upstream_health_check_update_handler(name) != NGX_OK) {
            ngx_str_set(rv, "upstream health check update failed");
        } else {
            ngx_str_set(rv, "success");
        }
    }

    return NGX_HTTP_OK;
}

static void ngx_http_dyups_write_in_file(ngx_str_t *upstream_name, ngx_buf_t *content)
{
    int                         fd, in_zone = 0;
    size_t                      i, len, left;
    char                        path[1024] = {0};
    u_char                     *p, *q, *end, *file_content;
    ngx_http_dyups_main_conf_t *dumcf;
    struct stat                 st;

    if (!ngx_http_dyups_api_enable || !upstream_name->len) return;

    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyups_module);
    if (!dumcf->file_path.len) return;

    if (dumcf->file_path.data[0] == '/') {
        len = dumcf->file_path.len >= sizeof(path)? sizeof(path)-1: dumcf->file_path.len;
        memcpy(path, dumcf->file_path.data, len);
    } else {
        left = sizeof(path) - 1;
        len = ngx_cycle->conf_prefix.len > left? left: ngx_cycle->conf_prefix.len;
        memcpy(path, ngx_cycle->conf_prefix.data, len);
        left -= len;
        if (dumcf->file_path.len > left) {
            memcpy(path+len, dumcf->file_path.data, left);
        } else {
            memcpy(path+len, dumcf->file_path.data, dumcf->file_path.len);
        }
    }

    if (!access(path, F_OK)) {
        fd = open(path, O_RDWR);
    } else {
        fd = open(path, O_RDWR|O_CREAT, 0755);
    }
    if (fd < 0) {
        return;
    }
    ngx_dyups_file_lock(fd);

    if (fstat(fd, &st) != 0) {
        goto failed;
    }
    file_content = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (file_content == NULL) {
        goto failed;
    }

    for (p = file_content, end = file_content + st.st_size; p < end; ++p) {
        if (*p == 'u' && end-p > 8 && !ngx_strncmp(p, "upstream", 8)) {
            q = p;
            p += 8;
            for (; p < end; ++p) {
                if (*p != ' ' && *p != '\t' && *p != '\n') break;
            }
            if (p >= end) break;
            if (*p == upstream_name->data[0]
                && (size_t)(end-p) > upstream_name->len
                && !ngx_strncmp(p, upstream_name->data, upstream_name->len))
            {
                p += upstream_name->len;
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

    if (content != NULL) {
        lseek(fd, 0, SEEK_END);
        write(fd, "upstream ", 9);
        write(fd, upstream_name->data, upstream_name->len);
        write(fd, " {\n", 3);
        for (p = content->start, i = 0, len = content->last - content->start; i < len; ++i) {
            if (content->start[i] == ';') {
                end = &(content->start[i]);
                write(fd, "  ", 2);
                write(fd, p, end - p);
                write(fd, ";\n", 2);
                p = &(content->start[i]) + 1;
            }
        }
        write(fd, "}\n", 2);
    }

failed:
    ngx_dyups_file_unlock(fd);
    close(fd);
}

static ngx_int_t ngx_dyups_sandbox_update(ngx_buf_t *buf, ngx_str_t *rv)
{
    ngx_int_t  rc;
    ngx_str_t  dumy;
    ngx_str_t  sandbox = ngx_string("_dyups_upstream_sandbox_");

    rc = ngx_dyups_do_update(&sandbox, buf, rv);
    (void) ngx_dyups_do_delete(&sandbox, &dumy);

    return rc;
}

static char *ngx_dyups_parse_upstream(ngx_conf_t *cf, ngx_buf_t *buf)
{
    char                       *rc;
    ngx_buf_t                   b;
    ngx_str_t                   s;
    ngx_uint_t                  i;
    ngx_hash_t                  vh, vh_prev;
    ngx_array_t                 va, va_prev;
    ngx_conf_file_t             conf_file;
    ngx_http_variable_t        *v;
    ngx_hash_keys_arrays_t      vk;
    ngx_http_core_main_conf_t  *cmcf;

    b = *buf;   /* avoid modifying @buf */

    ngx_memzero(&conf_file, sizeof(ngx_conf_file_t));
    conf_file.file.fd = NGX_INVALID_FILE;
    conf_file.buffer = &b;

    cf->conf_file = &conf_file;

    rc = ngx_conf_parse(cf, NULL);
    if (rc != NGX_CONF_OK) return rc;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    va_prev = cmcf->variables;
    vh_prev = cmcf->variables_hash;

    ngx_memzero(&va, sizeof(va));
    ngx_memzero(&vh, sizeof(vh));
    ngx_memzero(&vk, sizeof(vk));

    cmcf->variables      = va;
    cmcf->variables_hash = vh;
    cmcf->variables_keys = &vk;

    v = va_prev.elts;
    for (i = 0; i < va_prev.nelts; i++) {
        if (v[i].get_handler) continue;

        s.len = v[i].name.len;
        s.data = ngx_pstrdup(ngx_cycle->pool, &v[i].name);
        if (!s.data) {
            rc = NGX_CONF_ERROR;
            break;
        }

        /*
         * variable name will be assign to cmcf->variables[idx].name directly
         * so the lifetime of v[i].name should be the same as cmcf
         */
        v[i].name = s;

        cmcf->variables.elts = &v[i];
        cmcf->variables.nelts = 1;
        if (ngx_http_variables_init_vars(cf) != NGX_OK) {
            rc = NGX_CONF_ERROR;
            break;
        }
    }

    cmcf->variables      = va_prev;
    cmcf->variables_hash = vh_prev;
    cmcf->variables_keys = NULL;

    return rc;
}

static ngx_int_t ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf, ngx_buf_t *buf)
{
    ngx_conf_t                           cf;
    ngx_http_upstream_init_pt            init;
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    uscf = duscf->upstream;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(duscf->pool, 4, sizeof(ngx_http_upstream_server_t));
        if (uscf->servers == NULL) return NGX_ERROR;
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dyups_init_module_conf";
    cf.pool = duscf->pool;
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_UPS_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = duscf->ctx;
    cf.args = ngx_array_create(duscf->pool, 10, sizeof(ngx_str_t));
    if (cf.args == NULL) return NGX_ERROR;

    if (ngx_dyups_parse_upstream(&cf, buf) != NGX_CONF_OK)
        return NGX_ERROR;

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dyups_init_upstream";
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.pool = duscf->pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = duscf->ctx;

    init = uscf->peer.init_upstream? uscf->peer.init_upstream: ngx_http_upstream_init_round_robin;
    if (init(&cf, uscf) != NGX_OK) return NGX_ERROR;

    dscf = uscf->srv_conf[ngx_http_dyups_module.ctx_index];
    dscf->init = uscf->peer.init;
    uscf->peer.init = ngx_http_dyups_init_peer;

    return NGX_OK;
}

static ngx_http_dyups_srv_conf_t *ngx_dyups_find_upstream(ngx_str_t *name, ngx_int_t *idx)
{
    ngx_uint_t                      i;
    ngx_http_dyups_srv_conf_t      *duscfs, *duscf, *duscf_del;
    ngx_http_dyups_main_conf_t     *dumcf;
    ngx_http_upstream_srv_conf_t   *uscf;

    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_dyups_module);
    *idx = -1;
    duscf_del = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "[dyups] find dynamic upstream");

    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {
        duscf = &duscfs[i];
        if (!duscf->dynamic) continue;

        if (duscf->deleted == NGX_DYUPS_DELETING) {
            ngx_log_error(NGX_LOG_DEBUG, \
                          ngx_cycle->log, \
                          0,
                          "[dyups] find upstream idx: %ui ref: %ui on %V deleting", \
                          i, \
                          *(duscf->ref), \
                          &duscf->upstream->host);
            if (*(duscf->ref) == 0) {
                ngx_log_error(NGX_LOG_INFO, \
                              ngx_cycle->log, \
                              0, \
                              "[dyups] free dynamic upstream in find upstream %ui", \
                              duscf->idx);
                duscf->deleted = NGX_DYUPS_DELETED;
                if (duscf->pool) {
                    ngx_destroy_pool(duscf->pool);
                    duscf->pool = NULL;
                }
            }
        }

        if (duscf->deleted == NGX_DYUPS_DELETING) continue;

        if (duscf->deleted == NGX_DYUPS_DELETED) {
            *idx = i;
            duscf_del = duscf;
            continue;
        }

        uscf = duscf->upstream;

        if (uscf->host.len != name->len || ngx_strncasecmp(uscf->host.data, name->data, uscf->host.len)) {
            continue;
        }

        *idx = i;

        return duscf;
    }

    return duscf_del;
}

static ngx_int_t
ngx_dyups_init_upstream(ngx_http_dyups_srv_conf_t *duscf, ngx_str_t *name, ngx_uint_t index)
{
    ngx_uint_t                           mi, m;
    ngx_conf_t                           cf;
    ngx_module_t                        **modules;
    ngx_http_module_t                   *module;
    ngx_http_conf_ctx_t                 *ctx;
    ngx_http_upstream_srv_conf_t        *uscf, **uscfp;
    ngx_http_upstream_main_conf_t       *umcf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    duscf->pool = ngx_create_pool(512, ngx_cycle->log);
    if (duscf->pool == NULL) return NGX_ERROR;

    uscf = ngx_pcalloc(duscf->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (uscf == NULL) return NGX_ERROR;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                 |NGX_HTTP_UPSTREAM_WEIGHT
#ifdef NGX_HTTP_UPSTREAM_MAX_CONNS
                 |NGX_HTTP_UPSTREAM_MAX_CONNS
#endif
                 |NGX_HTTP_UPSTREAM_MAX_FAILS
                 |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                 |NGX_HTTP_UPSTREAM_DOWN
                 |NGX_HTTP_UPSTREAM_BACKUP;

    uscf->host.data = ngx_pstrdup(duscf->pool, name);
    if (uscf->host.data == NULL) return NGX_ERROR;

    uscf->host.len = name->len;
    uscf->file_name = (u_char *) "dynamic_upstream";
    uscf->line = 0;
    uscf->port = 0;
#if nginx_version < 1011006
    uscf->default_port = 0;
#endif
    uscfp[index] = uscf;

    duscf->dynamic = 1;
    duscf->upstream = uscf;

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.pool = duscf->pool;
    cf.ctx = ngx_cycle->conf_ctx[ngx_http_module.index];
    cf.cycle = (ngx_cycle_t *) ngx_cycle;

    ctx = ngx_pcalloc(duscf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) return NGX_ERROR;

    ctx->main_conf = ((ngx_http_conf_ctx_t *)ngx_cycle->conf_ctx[ngx_http_module.index])->main_conf;

    ctx->srv_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) return NGX_ERROR;

    ctx->srv_conf[ngx_http_upstream_module.ctx_index] = uscf;
    uscf->srv_conf = ctx->srv_conf;

#if nginx_version >= 1009011
    modules = ngx_cycle->modules;
#else
    modules = ngx_modules;
#endif

    for (m = 0; modules[m]; m++) {
        if (modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }
        if (modules[m]->index == ngx_http_core_module.index) {
            continue;
        }

        module = modules[m]->ctx;
        mi = modules[m]->ctx_index;

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(&cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_ERROR;
            }
        }
    }

    dscf = uscf->srv_conf[ngx_http_dyups_module.ctx_index];
    duscf->ref = &dscf->ref;
    duscf->ctx = ctx;
    duscf->deleted = 0;

    ngx_dyups_add_upstream_top_filter(umcf, uscf);

    return NGX_OK;
}

static void ngx_dyups_mark_upstream_delete(ngx_http_dyups_srv_conf_t *duscf)
{
    ngx_uint_t                      i;
    ngx_http_upstream_server_t     *us;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    uscf = duscf->upstream;
    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "[dyups] delete upstream \"%V\"", &duscf->upstream->host);

    ngx_dyups_del_upstream_top_filter(umcf, uscf);

    us = uscf->servers->elts;
    for (i = 0; i < uscf->servers->nelts; i++) {
        us[i].down = 1;
    }

    uscfp[duscf->idx] = &ngx_http_dyups_deleted_upstream;
    duscf->deleted = NGX_DYUPS_DELETING;
}

static void ngx_http_dyups_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content)
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

static ngx_buf_t *ngx_http_dyups_read_body(ngx_http_request_t *r)
{
    size_t        len;
    ngx_buf_t    *buf, *next, *body;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[dyups] interface read post body");

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

static ngx_buf_t *ngx_http_dyups_read_body_from_file(ngx_http_request_t *r)
{
    size_t        len;
    ssize_t       size;
    ngx_buf_t    *buf, *body;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] interface read post body from file");

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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] interface read post body file size %ui", len);

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

ngx_array_t *ngx_dyups_parse_path(ngx_pool_t *pool, ngx_str_t *path)
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
#if (NGX_DEBUG)
    ngx_str_t  *arg;
    ngx_uint_t  i;

    arg = array->elts;
    for (i = 0; i < array->nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "[dyups] res[%i]:%V", i, &arg[i]);
    }
#endif

    return array;
}

static ngx_int_t ngx_http_dyups_init_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                            rc;
    ngx_pool_cleanup_t                  *cln;
    ngx_http_dyups_ctx_t                *ctx;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    dscf = us->srv_conf[ngx_http_dyups_module.ctx_index];
    rc = dscf->init(r, us);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "[dyups] dynamic upstream init peer: %i", rc);

    if (rc != NGX_OK) return rc;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dyups_ctx_t));
    if (ctx == NULL) return NGX_ERROR;

    ctx->scf = dscf;
    ctx->data = r->upstream->peer.data;
    ctx->get = r->upstream->peer.get;
    ctx->free = r->upstream->peer.free;

    r->upstream->peer.data = ctx;
    r->upstream->peer.get = ngx_http_dyups_get_peer;
    r->upstream->peer.free = ngx_http_dyups_free_peer;
#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session = ngx_http_dyups_set_peer_session;
    r->upstream->peer.save_session = ngx_http_dyups_save_peer_session;
#endif

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) return NGX_ERROR;

    dscf->ref++;

    cln->handler = ngx_http_dyups_clean_request;
    cln->data = &dscf->ref;

    return NGX_OK;
}

static ngx_int_t ngx_http_dyups_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_dyups_ctx_t  *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] dynamic upstream get handler count %i",
                   ctx->scf->ref);

    return ctx->get(pc, ctx->data);
}

static void ngx_http_dyups_free_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_dyups_ctx_t  *ctx = data;
    ngx_pool_cleanup_t  *cln;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] dynamic upstream free handler count %i",
                   ctx->scf->ref);

    /* upstream connect failed */
    if (pc->connection == NULL || pc->cached) {
        goto done;
    }

    ctx->scf->ref++;

    cln = ngx_pool_cleanup_add(pc->connection->pool, 0);
    if (cln == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "[dyups] dynamic upstream free peer may cause memleak %i",
                      ctx->scf->ref);
        goto done;
    }

    cln->handler = ngx_http_dyups_clean_request;
    cln->data = &ctx->scf->ref;

 done:
    ctx->free(pc, ctx->data, state);
}

static void ngx_http_dyups_clean_request(void *data)
{
    ngx_uint_t  *ref = data;

    (*ref)--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] http clean request count %i", *ref);
}

static ngx_int_t ngx_dyups_shm_delete_ups(ngx_str_t *name)
{
    uint32_t              hash;
    ngx_slab_pool_t      *shpool;
    ngx_dyups_shctx_t    *sh;
    ngx_dyups_upstream_t *ups;

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    hash = ngx_crc32_short(name->data, name->len);
    ups = (ngx_dyups_upstream_t *)ngx_str_rbtree_lookup(&sh->rbtree, name, hash);
    if (ups) {
        sh->version++;
        ngx_rbtree_delete(&sh->rbtree, &ups->node);
        ngx_dyups_shm_free_ups(shpool, ups);
    }

    return NGX_OK;
}

static ngx_int_t ngx_dyups_shm_update_ups(ngx_str_t *name, ngx_buf_t *body)
{
    ngx_slab_pool_t      *shpool;
    ngx_dyups_shctx_t    *sh;
    ngx_dyups_upstream_t *ups;

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ups = ngx_slab_alloc_locked(shpool, sizeof(ngx_dyups_upstream_t));
    if (ups == NULL) goto failed;

    ngx_memzero(ups, sizeof(ngx_dyups_upstream_t));

    ups->name.data = ngx_slab_alloc_locked(shpool, name->len);
    if (ups->name.data == NULL) {
        goto failed;
    }

    ngx_memcpy(ups->name.data, name->data, name->len);
    ups->name.len = name->len;

    if (body) {
        ups->content.data = ngx_slab_alloc_locked(shpool, body->last - body->pos);
        if (ups->content.data == NULL) goto failed;

        ngx_memcpy(ups->content.data, body->pos, body->last - body->pos);
        ups->content.len = body->last - body->pos;
    } else {
        ups->content.data = NULL;
        ups->content.len = 0;
    }
    sh->version++;
    if (sh->version == 0) sh->version = 1;

    ngx_dyups_shm_delete_ups(&ups->name);

    ups->node.key = ngx_crc32_short(ups->name.data, ups->name.len);
    ngx_rbtree_insert(&sh->rbtree, &ups->node);

    ups = (ngx_dyups_upstream_t *)ngx_str_rbtree_lookup(&sh->rbtree, &ups->name, ups->node.key);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                   "[dyups] update %V, version: %ui",
                   &ups->name, sh->version);

    return NGX_OK;

failed:
    if (ups) {
        ngx_dyups_shm_free_ups(shpool, ups);
    }

    return NGX_ERROR;
}

static void ngx_dyups_shm_free_ups(ngx_slab_pool_t *shpool, ngx_dyups_upstream_t *ups)
{
    if (ups->name.data) {
        ngx_slab_free_locked(shpool, ups->name.data);
    }
    if (ups->content.data) {
        ngx_slab_free_locked(shpool, ups->content.data);
    }
    ngx_slab_free_locked(shpool, ups);
}

static ngx_int_t
ngx_http_variable_dyups(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                  *name = (ngx_str_t *) data;
    size_t                      len;
    u_char                     *low, *p;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_str_t                   key, rv, uname;
    ngx_slab_pool_t            *shpool;
    ngx_dyups_shctx_t          *sh;
    ngx_dyups_upstream_t       *ups;
    ngx_http_variable_value_t  *vv;

    len = name->len - (sizeof("dyups_") - 1);
    p = name->data + sizeof("dyups_") - 1;

    low = ngx_pnalloc(r->pool, len);
    if (low == NULL) return NGX_ERROR;

    hash = ngx_hash_strlow(low, p, len);

    key.len = len;
    key.data = low;

    vv = ngx_http_get_variable(r, &key, hash);
    v->data = vv->data;
    v->len = vv->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    uname.data = v->data;
    uname.len = v->len;

    sh = ngx_dyups_global_ctx.sh;
    if (sh->version == ngx_dyups_global_ctx.version) {
        return NGX_OK;
    }

    shpool = ngx_dyups_global_ctx.shpool;
    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_dyups_reload();

    hash = ngx_crc32_short(uname.data, uname.len);
    ups = (ngx_dyups_upstream_t *)
        ngx_str_rbtree_lookup(&sh->rbtree, &uname, hash);

    if (!ups) {
        rc = ngx_dyups_do_delete(&uname, &rv);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "[dyups] sync del: %V rv: %V rc: %i", &uname, &rv, rc);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static ngx_int_t
ngx_http_variable_dyups_up(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                  *name = (ngx_str_t *) data;
    size_t                      len;
    u_char                     *q, *p;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_str_t                   rv, uname;
    ngx_slab_pool_t            *shpool;
    ngx_dyups_shctx_t          *sh;
    ngx_dyups_upstream_t       *ups;

    len = name->len - (sizeof("_dyups_") - 1);
    p = name->data + sizeof("_dyups_") - 1;
    q = ngx_pnalloc(r->pool, len);
    if (q == NULL) return NGX_ERROR;

    memcpy(q, p, len);
    v->data = q;
    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    uname.data = v->data;
    uname.len = v->len;

    sh = ngx_dyups_global_ctx.sh;
    if (sh->version == ngx_dyups_global_ctx.version) {
        return NGX_OK;
    }

    shpool = ngx_dyups_global_ctx.shpool;
    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_dyups_reload();

    hash = ngx_crc32_short(uname.data, uname.len);
    ups = (ngx_dyups_upstream_t *)
        ngx_str_rbtree_lookup(&sh->rbtree, &uname, hash);

    if (!ups) {
        rc = ngx_dyups_do_delete(&uname, &rv);
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "[dyups] sync del: %V rv: %V rc: %i", &uname, &rv, rc);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_dyups_set_peer_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_dyups_ctx_t  *ctx = data;

    ngx_int_t              rc;
    ngx_ssl_session_t     *ssl_session;

    ssl_session = ctx->ssl_session;
    rc = ngx_ssl_set_session(pc->connection, ssl_session);

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "set session: %p", ssl_session);

#else
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "set session: %p:%d", ssl_session,
                   ssl_session ? ssl_session->references : 0);
#endif

    return rc;
}

static void
ngx_http_dyups_save_peer_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_dyups_ctx_t  *ctx = data;
    ngx_ssl_session_t     *old_ssl_session, *ssl_session;

    ssl_session = ngx_ssl_get_session(pc->connection);
    if (ssl_session == NULL) return;

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p", ssl_session);

#else
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p:%d", ssl_session,
                   ssl_session->references);
#endif

    old_ssl_session = ctx->ssl_session;
    ctx->ssl_session = ssl_session;

    if (old_ssl_session) {
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p", old_ssl_session);

#else
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p:%d", old_ssl_session,
                       old_ssl_session->references);
#endif
        ngx_ssl_free_session(old_ssl_session);
    }
}
#endif

static ngx_int_t
ngx_dyups_add_upstream_filter(ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf)
{
#if (NGX_HTTP_UPSTREAM_RBTREE)
    uscf->node.key = ngx_crc32_short(uscf->host.data, uscf->host.len);
    ngx_rbtree_insert(&umcf->rbtree, &uscf->node);
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_dyups_del_upstream_filter(ngx_http_upstream_main_conf_t *umcf, ngx_http_upstream_srv_conf_t *uscf)
{
#if (NGX_HTTP_UPSTREAM_RBTREE)
    ngx_rbtree_delete(&umcf->rbtree, &uscf->node);
#endif
    return NGX_OK;
}

int ngx_dyups_update_server_status(ngx_str_t *upstream, ngx_str_t *server, int down)
{
    ngx_slab_pool_t              *shpool;
    ngx_dyups_shctx_t            *sh;
    ngx_rbtree_node_t            *node, *root, *sentinel;
    ngx_dyups_upstream_t         *ups = NULL;
    ngx_http_dyups_srv_conf_t    *duscf;
    ngx_int_t                     idx = -1;

    if (!ngx_http_dyups_api_enable) return NGX_OK;

    duscf = ngx_dyups_find_upstream(upstream, &idx);
    if (duscf != NULL && duscf->deleted != NGX_DYUPS_DELETED) {
        ngx_http_upstream_rr_peers_t *rr_peers = duscf->upstream->peer.data;
        ngx_http_upstream_rr_peer_t  *rr_peer;
        for (rr_peer = rr_peers->peer; rr_peer; rr_peer = rr_peer->next) {
             if (rr_peer->name.len == server->len && \
                 !ngx_strncmp(rr_peer->name.data, server->data, server->len))
             {
                 rr_peer->down = down;
             }
        }
    }

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);
    sentinel = sh->rbtree.sentinel;
    root = sh->rbtree.root;
    if (root != sentinel) {
        for (node = ngx_rbtree_min(root, sentinel);
             node;
             node = ngx_rbtree_next(&sh->rbtree, node))
        {
            ups = (ngx_dyups_upstream_t*)
                ((char*) node - offsetof(ngx_dyups_upstream_t, node));
            if (ups->name.len == upstream->len
                && !ngx_strncmp(ups->name.data, upstream->data, ups->name.len))
            {
                break;
            }
        }
    }
    if (ups == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    ngx_dyups_update_server_status_change_content(ups, server, down);
    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static void
ngx_dyups_update_server_status_change_content(ngx_dyups_upstream_t *ups, \
                                              ngx_str_t *server, \
                                              int down)
{
    ngx_slab_pool_t              *shpool = ngx_dyups_global_ctx.shpool;
    ngx_str_t                    *content = &ups->content;
    size_t                        i, head = 0, j;
    ngx_str_t                     tmp;
    u_char                       *p, *q;

    for (i = 0; i < content->len; ++i) {
        if (content->data[i] == ';') {
            tmp.data = &(content->data[head]);
            tmp.len = i - head;
            head = i + 1;
            if (tmp.len < server->len) continue;
            if (ngx_http_dyups_server_match(&tmp, server)) continue;
            for (j = 0; j < tmp.len; ++j) {
                if (tmp.data[j] == 'd' && tmp.len - j >= 4 && !ngx_strncmp(&(tmp.data[j]), "down", 4)) {
                    break;
                }
            }
            if (down) {
                if (j < tmp.len) break;
                p = ngx_slab_alloc_locked(shpool, content->len+6);
                if (p == NULL) return;
                memcpy(p, content->data, i);
                q = p + i;
                *q++ = ' '; *q++ = 'd'; *q++ = 'o'; *q++ = 'w'; *q++ = 'n'; *q++ = ';';
                memcpy(q, &(content->data[i+1]), content->len - i - 1);
                ngx_slab_free_locked(shpool, content->data);
                content->data = p;
                content->len = 6 + content->len - 1;
            } else {
                if (j < tmp.len) {
                    tmp.data[j++] = ' ';
                    tmp.data[j++] = ' ';
                    tmp.data[j++] = ' ';
                    tmp.data[j++] = ' ';
                }
            }
            break;
        }
    }
}

static void ngx_dyups_file_lock(int fd)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fcntl(fd, F_SETLKW, &fl);
}

static void ngx_dyups_file_unlock(int fd)
{
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fcntl(fd, F_SETLKW, &fl);
}

ngx_http_upstream_srv_conf_t *ngx_http_dyups_get_upstream_by_name(ngx_http_request_t *r, ngx_str_t *upstream)
{
    ngx_int_t idx = 0;
    ngx_http_dyups_srv_conf_t *duscf;
    size_t len;
    u_char *low;
    uint32_t                    hash;
    ngx_str_t key;
    ngx_http_variable_value_t  *vv;

    if (!ngx_http_dyups_api_enable) return NULL;

    len = upstream->len;
    low = ngx_pnalloc(r->pool, len);
    if (low == NULL) return NULL;
    hash = ngx_hash_strlow(low, upstream->data, len);
    key.len = len;
    key.data = low;
    vv = ngx_http_get_variable(r, &key, hash);
    key.data = vv->data;
    key.len = vv->len;

    duscf = ngx_dyups_find_upstream(&key, &idx);
    if (duscf == NULL || duscf->deleted == NGX_DYUPS_DELETED) return NULL;
    return duscf->upstream;
}

