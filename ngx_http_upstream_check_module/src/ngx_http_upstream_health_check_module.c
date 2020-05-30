/***************************************************************************
 * 
 * Copyright (c) 2017 Jiongjie Yin. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/
 
 /**
 * @file ngx_http_upstream_health_check_module.c
 * @author jiong(jackjiongyin@gmail.com)
 * @date 2017/12/07 12:35:29
 * @version $Revision$ 
 * @brief 
 *  
 **/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_HTTP_UPSTREAM_HEALTH_CHECK
#define NGX_HTTP_UPSTREAM_HEALTH_CHECK
#endif

#define NGX_CHECK_HTTP_STATUS_2XX 0x00000002
#define NGX_CHECK_HTTP_STATUS_3XX 0x00000004
#define NGX_CHECK_HTTP_STATUS_4XX 0x00000008
#define NGX_CHECK_HTTP_STATUS_5XX 0x00000010

#define NGX_CHECK                 0          
#define NGX_CHECK_CONNECT_DONE    1
#define NGX_CHECK_SEND_DONE       2
#define NGX_CHECK_RECV_DONE       3

#define SHM_NAME "check_shm"
#define SHM_SIZE 10 * 1024 * 1024

#define ngx_http_check_peer_lock()                         \
                                                           \
    if (check_main_conf->shpool) {                         \
        ngx_shmtx_lock(&check_main_conf->shpool->mutex);   \
    }                                         

#define ngx_http_check_peer_unlock()                       \
                                                           \
    if (check_main_conf->shpool) {                         \
        ngx_shmtx_unlock(&check_main_conf->shpool->mutex); \
    }                                         

typedef struct ngx_http_upstream_health_check_peer_s ngx_http_upstream_health_check_peer_t;
typedef struct ngx_http_upstream_check_peer_shm_s    ngx_http_upstream_check_peer_shm_t;


typedef struct {
    ngx_str_t                              name;
    ngx_str_t                              http_send;
    ngx_uint_t                             alive_http_status;
    ngx_event_handler_pt                   send_handler;
    ngx_event_handler_pt                   recv_handler;
} ngx_peer_check_type;

typedef struct {
    ngx_str_t                             *upstream_name;
    ngx_peer_check_type                    type;
    ngx_msec_t                             interval;
    ngx_msec_t                             timeout;
    ngx_uint_t                             max_fail;
    ngx_uint_t                             min_rise;
} ngx_http_upstream_health_check_conf_t;

struct ngx_http_upstream_check_peer_shm_s {
    ngx_uint_t                             index;
    ngx_int_t                              wid;
    ngx_pid_t                              pid;
    ngx_uint_t                             rise;
    ngx_uint_t                             fail;
    struct sockaddr                       *sockaddr;
    socklen_t                              socklen;
    ngx_str_t                             *name;
    ngx_http_upstream_check_peer_shm_t    *prev;
    ngx_http_upstream_check_peer_shm_t    *next;
};

typedef struct {
    ngx_uint_t                             total_peers;
    ngx_http_upstream_check_peer_shm_t    *peers;
    ngx_http_upstream_check_peer_shm_t    *dynamic_peers;
} ngx_http_upstream_check_peers_shm_t;

struct ngx_http_upstream_health_check_peer_s {
    ngx_uint_t                             index;
    ngx_int_t                              check_state;
    ngx_uint_t                             state;
    ngx_http_status_t                      status;
    struct sockaddr                        sockaddr;
    socklen_t                              socklen;
    ngx_str_t                              name;
    ngx_event_t                            check_ev;
    ngx_event_t                            check_timeout_ev;
    ngx_http_upstream_health_check_conf_t *conf;
    ngx_peer_connection_t                  pc;
    ngx_pool_t                            *pool;
    ngx_buf_t                             *send_data;
    ngx_buf_t                             *recv_data;
    ngx_http_upstream_check_peer_shm_t    *shm;
    ngx_log_t                             *log;
    ngx_uint_t                             free;
};

typedef struct {
    ngx_array_t                            peers;     /* ngx_http_upstream_health_check_peer_t */
    ngx_array_t                            confs;     /* ngx_http_upstream_health_check_conf_t */
    ngx_http_upstream_check_peers_shm_t   *peers_shm;
    ngx_slab_pool_t                       *shpool;
    ngx_shm_zone_t                        *shm_zone;
    ngx_uint_t                             shm_size;
} ngx_http_upstream_health_check_main_conf_t;


extern int ngx_dyups_update_server_status(ngx_str_t *upstream, ngx_str_t *server, int down);
static ngx_http_upstream_srv_conf_t *
ngx_http_upstream_health_check_update_find_upstream(ngx_str_t *upstream_name);
static ngx_int_t
ngx_http_upstream_health_check_update_init_peer(ngx_str_t *upstream_name, ngx_http_upstream_srv_conf_t *uscf);
static void ngx_http_upstream_health_check_update_clean_peers(ngx_str_t *upstream_name);
static int ngx_http_upstream_health_check_update_init_peer_shm(ngx_str_t *upstream_name);
static ngx_int_t
ngx_http_upstream_health_check_update_init_timers(ngx_str_t *upstream_name, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_upstream_health_check_init_process(ngx_cycle_t *cycle);
static void *ngx_http_upstream_health_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_health_check_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_upstream_health_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_peer_check_type *ngx_http_get_peer_check_type(ngx_str_t *str);
static ngx_int_t
ngx_http_upstream_health_check_init_conf(ngx_conf_t *cf, ngx_http_upstream_health_check_conf_t *conf);
static ngx_int_t ngx_http_upstream_health_check_init_peers(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_upstream_health_check_init_timers(ngx_cycle_t *cycle);
static ngx_int_t
ngx_http_upstream_health_check_add_timers(ngx_http_upstream_health_check_peer_t *peer, ngx_msec_t interval, ngx_log_t *log);
static void ngx_http_upstream_health_check_init_event_handler(ngx_event_t *ev);
static void ngx_http_upstream_health_check_timeout_handler(ngx_event_t *ev);
static void ngx_http_upstream_health_check_connect_handler(ngx_event_t *ev);
static void ngx_http_upstream_health_check_peek_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_upstream_health_check_connect_alive(ngx_connection_t *c);
static void ngx_http_upstream_health_check_update_status(ngx_http_upstream_health_check_peer_t *peer, ngx_int_t rc);
static void ngx_http_upstream_health_check_finish_handler(ngx_http_upstream_health_check_peer_t *peer, ngx_int_t need_reinit_ev);
static ngx_int_t ngx_http_upstream_health_check_need_exit(ngx_event_t *ev);
static ngx_int_t ngx_http_upstream_health_check_init_shm(ngx_shm_zone_t *shm_zone, void *data);
static ngx_http_upstream_health_check_conf_t *ngx_http_check_get_conf(ngx_conf_t *cf, ngx_array_t *confs);

static ngx_peer_check_type ngx_peer_check_types[] = {
    {
        ngx_string("tcp"),
        ngx_null_string,
        0,
        ngx_http_upstream_health_check_peek_handler,
        ngx_http_upstream_health_check_peek_handler,
    }
};

static ngx_command_t ngx_http_upstream_health_check_module_commands[] = {
    {
        ngx_string("health_check"),
        NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
        ngx_http_upstream_health_check,
        0,
        0,
        NULL
    },
    {
        ngx_string("health_check_shm_size"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_upstream_health_check_main_conf_t, shm_size),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_health_check_module_ctx = {
    NULL,                                                 /* preconfiguration */
    NULL,                                                 /* postconfiguration */
    ngx_http_upstream_health_check_create_main_conf,      /* create main configuration */
    ngx_http_upstream_health_check_init_main_conf,        /* int main configuration */
    NULL,                                                 /* create server configuration */
    NULL,                                                 /* merge server configuration */
    NULL,                                                 /* create location configuration */
    NULL,                                                 /* merge location configuration */
};

ngx_module_t ngx_http_upstream_health_check_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_health_check_module_ctx,        /* module context */
    ngx_http_upstream_health_check_module_commands,    /* module directives */
    NGX_HTTP_MODULE,                                   /* module type */
    NULL,                                              /* init master */
    NULL,                                              /* init module */
    ngx_http_upstream_health_check_init_process,       /* init process */
    NULL,                                              /* init thread */
    NULL,                                              /* exit thread */
    NULL,                                              /* exit process */
    NULL,                                              /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_upstream_health_check_main_conf_t *check_main_conf = NULL;
static ngx_int_t                                   worker_processes = 0;
static ngx_pool_t                                 *g_pool = NULL;

static void *ngx_http_upstream_health_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_health_check_main_conf_t *conf;

    g_pool = cf->pool;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_health_check_main_conf_t));
    if (conf == NULL) return NULL;

    conf->peers_shm = NGX_CONF_UNSET_PTR;
    conf->shm_zone = NGX_CONF_UNSET_PTR;
    conf->shpool = NGX_CONF_UNSET_PTR;
    conf->shm_size = NGX_CONF_UNSET_UINT;

    if (ngx_array_init(&conf->peers, cf->pool, 1024,
                       sizeof(ngx_http_upstream_health_check_peer_t)) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "[check] create main conf: init srv_conf fail");
        return NULL;
    }
    if (ngx_array_init(&conf->confs, cf->pool, 1024,
                       sizeof(ngx_http_upstream_health_check_conf_t)) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "[check] create main conf: init check_conf fail");
        return NULL;
    }

    check_main_conf = conf;

    return conf;
}

static char *ngx_http_upstream_health_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_main_conf_t              *umcf;
    ngx_http_upstream_srv_conf_t               **uscfp;
    ngx_uint_t                                  i;
    ngx_shm_zone_t                             *shm_zone;
    ngx_str_t                                   shm_name = ngx_string(SHM_NAME);

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    if (umcf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "[check] init main conf: upstream main_conf is null");
        return NGX_CONF_ERROR;
    }

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_health_check_module);
    if (ucmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[check] init main conf: check main_conf is null");
        return NGX_CONF_ERROR;
    }
    if (ucmcf->shm_size == NGX_CONF_UNSET_UINT)
        ucmcf->shm_size = SHM_SIZE;

    shm_zone = ngx_shared_memory_add(cf, &shm_name, ucmcf->shm_size, &ngx_http_upstream_health_check_module);
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[check] create main conf: create shm_zone fail");
        return NGX_CONF_ERROR;
    }
    shm_zone->init = ngx_http_upstream_health_check_init_shm;
    shm_zone->data = conf;
    shm_zone->noreuse = 1;

    ucmcf->shm_zone = shm_zone;
    if (!ucmcf->confs.nelts) return NGX_CONF_OK;

    uscfp = umcf->upstreams.elts;
    for(i = 0; i < umcf->upstreams.nelts; i++) {
        if (ngx_http_upstream_health_check_init_peers(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_upstream_health_check_init_peers(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_health_check_peer_t      *peer;
    ngx_http_upstream_health_check_conf_t      *confs, *conf;
    ngx_http_upstream_server_t                 *server;
    ngx_uint_t                                  i, j;
    ngx_array_t                                *confp, *peers;
    
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_health_check_module);

    confp = &ucmcf->confs;
    confs = confp->elts;
    conf = NULL;
    for (i = 0; i < confp->nelts; i++) {
        conf = &confs[i];
        if (ngx_strncmp(conf->upstream_name->data, uscf->host.data, uscf->host.len) == 0) {
            break;
        }
        conf = NULL;
    }

    if (conf != NULL && uscf->servers) {
        server = uscf->servers->elts;
        peers = &ucmcf->peers;

        for (i = 0; i < uscf->servers->nelts; i++) {
            if (server[i].backup || server[i].down) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer = ngx_array_push(peers);
                if (peer == NULL) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                            "[check] init peer: alloc new peer fail, %V", &(server[i].addrs[j].name));
                    return NGX_ERROR;
                }

                ngx_memzero(peer, sizeof(ngx_http_upstream_health_check_peer_t));
                ngx_memzero(&peer->status, sizeof(ngx_http_status_t));
                peer->state = 0;
                peer->check_state = NGX_CHECK;
                peer->name.data = ngx_pcalloc(cf->pool, server[i].addrs[j].name.len);
                if (peer->name.data == NULL) return NGX_ERROR;

                memcpy(peer->name.data, server[i].addrs[j].name.data, server[i].addrs[j].name.len);
                peer->name.len = server[i].addrs[j].name.len;
                memcpy(&peer->sockaddr, server[i].addrs[j].sockaddr, sizeof(struct sockaddr));
                peer->socklen = server[i].addrs[j].socklen;
                peer->conf = conf;
                peer->free = 0;
            }
        }
        return NGX_OK;
    } 

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_health_check_init_shm(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                                      len;
    u_char                                     *file;
    ngx_array_t                                *peersp;
    ngx_http_upstream_health_check_peer_t      *peers, *peer;
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_check_peer_shm_t         *peer_shm, *prev_shm;
    ngx_http_upstream_check_peers_shm_t        *peers_shm;
    ngx_slab_pool_t                            *shpool;
    ngx_uint_t                                  i;

    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    ucmcf = shm_zone->data;
    peersp = &ucmcf->peers;

    peers_shm = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_check_peers_shm_t));
    if (peers_shm == NULL) {
        return NGX_ERROR;
    }

    peers_shm->peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_check_peer_shm_t));
    if (peers_shm->peers == NULL) {
        return NGX_ERROR;
    }
    peers_shm->peers->next = NULL;
    peers_shm->peers->prev = NULL;

    peers_shm->dynamic_peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_check_peer_shm_t));
    if (peers_shm->dynamic_peers == NULL) {
        return NGX_ERROR;
    }
    peers_shm->dynamic_peers->next = NULL;
    peers_shm->dynamic_peers->prev = NULL;

    peers_shm->total_peers = 0;
    prev_shm = peers_shm->peers;

    peers = peersp->elts;

    for (i = 0; i < peersp->nelts; i++) {
        peer = &peers[i];

        peer_shm = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_check_peer_shm_t));
        if (peer_shm == NULL) {
            return NGX_ERROR;
        }

        peer_shm->wid = -1;

        peer_shm->socklen = peer->socklen;
        peer_shm->sockaddr = ngx_slab_alloc(shpool, peer_shm->socklen);
        if (peer_shm->sockaddr == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(peer_shm->sockaddr, &peer->sockaddr, peer_shm->socklen);

        peer_shm->name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
        if (peer_shm->name == NULL) {
            return NGX_ERROR;
        }
        peer_shm->name->len = peer->name.len;
        peer_shm->name->data = ngx_slab_alloc(shpool, peer_shm->name->len);
        if (peer_shm->name->data == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(peer_shm->name->data, peer->name.data, peer_shm->name->len);

        peer_shm->fail = 0;
        peer_shm->rise = 0;

        peer_shm->next = NULL;
        peer_shm->prev = prev_shm;

        prev_shm->next = peer_shm;

        prev_shm = peer_shm;

        peers_shm->total_peers += 1;

        peer_shm->index = peers_shm->total_peers;

        peer->shm = peer_shm;
    }

    ucmcf->peers_shm = peers_shm;
    shpool->data = peers_shm;
    shm_zone->data = peers_shm;

    ucmcf->shpool = shpool;
    ucmcf->shm_zone = shm_zone;

    len = sizeof("[check] in peer shm \"\"") + shm_zone->shm.name.len;
    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(shpool->log_ctx, "[check] in peer shm \"%V\"%Z", &shm_zone->shm.name);

#if (NGX_HAVE_ATOMIC_OPS)
    file = NULL;
#else
    file = ngx_pnalloc(ngx_cycle->pool, ngx_cycle->lock_file.len + shm_zone->shm.name.len);
    if (file == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(file, "%V%V%Z", &ngx_cycle->lock_file, &shm_zone->shm.name);
#endif

    if (ngx_shmtx_create(&shpool->mutex, &shpool->lock, file) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static char *
ngx_http_upstream_health_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_health_check_conf_t      *check_conf;
    ngx_int_t                                   rc;
    ngx_array_t                                *confsp; 

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_health_check_module);
    if (ucmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "[check] health check conf: main conf is null");
        return NGX_CONF_ERROR;
    }

    confsp = &ucmcf->confs;

    check_conf = ngx_http_check_get_conf(cf, confsp);
    if (check_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_http_upstream_health_check_init_conf(cf, check_conf);
    if (rc == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

static ngx_http_upstream_health_check_conf_t *
ngx_http_check_get_conf(ngx_conf_t *cf, ngx_array_t *confsp)
{
    ngx_uint_t                             i;
    ngx_http_upstream_health_check_conf_t *confs, *conf;
    ngx_http_upstream_srv_conf_t          *uscf;

    confs = confsp->elts;
    conf = NULL;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    for (i = 0; i < confsp->nelts; i++) {
        conf = &confs[i];
        if (conf->upstream_name->len == uscf->host.len && \
            !ngx_strncmp(conf->upstream_name->data, uscf->host.data, uscf->host.len))
        {
            break;
        }
        conf = NULL;
    }

    if (conf == NULL) {
        conf = ngx_array_push(confsp);
        if (conf == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[check] get conf: alloc conf fail");
            return NULL;
        }
        conf->upstream_name = ngx_pcalloc(g_pool, sizeof(ngx_str_t));
        if (conf->upstream_name == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[check] get conf: alloc upstream name fail");
            return NULL;
        }
        conf->upstream_name->data = ngx_pstrdup(g_pool, &(uscf->host));
        if (conf->upstream_name->data == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[check] get conf: dup upstream name fail");
            return NULL;
        }
        conf->upstream_name->len = uscf->host.len;
        conf->interval = NGX_CONF_UNSET_MSEC;
        conf->timeout = NGX_CONF_UNSET_MSEC;
        conf->max_fail = NGX_CONF_UNSET_UINT;
        conf->min_rise = NGX_CONF_UNSET_UINT;

        ngx_memzero(&conf->type, sizeof(ngx_peer_check_type));
    }

    return conf;
}

static ngx_int_t
ngx_http_upstream_health_check_init_conf(ngx_conf_t *cf,  ngx_http_upstream_health_check_conf_t *conf) 
{
    ngx_str_t                             *value, str;
    ngx_uint_t                             i;
    ngx_msec_t                             interval, timeout;
    ngx_uint_t                             rise, fail;
    ngx_peer_check_type                   *type;

    if (conf == NULL) return NGX_ERROR;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            if ((type = ngx_http_get_peer_check_type(&str)) != NULL) {
                ngx_str_set(&conf->type.name, type->name.data);
                if (conf->type.http_send.len == 0) {
                    ngx_str_set(&conf->type.http_send, type->http_send.data);
                }
                if (conf->type.alive_http_status == 0) {
                    conf->type.alive_http_status = type->alive_http_status;
                }

                conf->type.send_handler = type->send_handler;
                conf->type.recv_handler = type->recv_handler;
            }
            continue;
        }
        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            str.len = value[i].len - 9;
            str.data = value[i].data + 9;

            interval = ngx_atoi(str.data, str.len);
            if (interval != (ngx_msec_t)NGX_ERROR && interval != 0) {
                conf->interval = interval;
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
                        "[check] add srv conf: invalid parameter in interval, set default");
            }
            continue;
        }
        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            str.len = value[i].len - 8;
            str.data = value[i].data + 8;

            timeout = ngx_atoi(str.data, str.len);

            if (timeout != (ngx_msec_t)NGX_ERROR && timeout != 0) {
                conf->timeout = timeout;
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
                        "[check] add srv conf: invalid parameter in timeout, set default");
            }
            continue;
        }
        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            rise = ngx_atoi(str.data, str.len);
            if (rise != (ngx_uint_t)NGX_ERROR && rise != 0) {
                conf->min_rise = rise;
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
                        "[check] add srv conf: invalid parameter in rise, set default");
            }
            continue;
        }
        if (ngx_strncmp(value[i].data, "fail=", 5) == 0) {
            str.len = value[i].len - 5;
            str.data = value[i].data + 5;

            fail = ngx_atoi(str.data, str.len);
            if (fail != (ngx_uint_t)NGX_ERROR && fail != 0) {
                conf->max_fail = fail;
            } else {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
                        "[check] add srv conf: invalid parameter in fail, set default");
            }
            continue;
        }

        goto invalid;
    }

    if (conf->type.name.len == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, 
                    "[check] add srv conf: set default check type, tcp check");
        ngx_memcpy(&conf->type, ngx_peer_check_types, sizeof(ngx_peer_check_type)); // default tcp
    }

    conf->interval = (conf->interval != NGX_CONF_UNSET_MSEC) 
                        ? conf->interval : 5000;
    conf->timeout = (conf->timeout != NGX_CONF_UNSET_MSEC) 
                        ? conf->timeout : 1000;
    conf->min_rise = (conf->min_rise != NGX_CONF_UNSET_UINT) 
                        ? conf->min_rise : 5;
    conf->max_fail = (conf->max_fail != NGX_CONF_UNSET_UINT) 
                        ? conf->max_fail : 2;
    
    return NGX_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[i]);
    return NGX_ERROR;
}

static ngx_int_t ngx_http_upstream_health_check_init_process(ngx_cycle_t *cycle)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;

    ucmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_health_check_module);
    if (ucmcf == NULL) return NGX_OK;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "[check] init process: begin, %P", ngx_pid);

    return ngx_http_upstream_health_check_init_timers(cycle);
}

static ngx_int_t ngx_http_upstream_health_check_init_timers(ngx_cycle_t *cycle)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_health_check_peer_t      *peers, *peer;
    ngx_core_conf_t                            *ccf;
    ngx_uint_t                                  i;
    ngx_array_t                                *peersp;
    
    ucmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_health_check_module);
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    worker_processes = ccf->worker_processes;
    peersp = &ucmcf->peers;
    if (peersp->nelts == 0) {
        return NGX_OK;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
            "[check] init timers: wokers=%i, peers=%i, pid=%P", 
            worker_processes, peersp->nelts, ngx_pid);

    peers = peersp->elts;
    for (i = 0; i < peersp->nelts; i++) {
        peer = &peers[i];

        ngx_http_check_peer_lock();

        if (peer->free || peer->conf == NULL) {
            ngx_http_check_peer_unlock();
            continue;
        }
        if (peer->shm->wid == -1) {
            peer->shm->wid = peer->shm->index % worker_processes;
        }
        if (peer->shm->wid != (ngx_process_slot % worker_processes)) {
            ngx_http_check_peer_unlock();
            continue;
        }

        ngx_http_check_peer_unlock();

        ngx_http_upstream_health_check_add_timers(peer, peer->conf->interval, cycle->log);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_health_check_add_timers(ngx_http_upstream_health_check_peer_t *peer, ngx_msec_t interval, ngx_log_t *log)
{
    peer->log = log;

    peer->check_ev.handler = ngx_http_upstream_health_check_init_event_handler;
    peer->check_ev.data = peer;
    peer->check_ev.log = log;
    peer->check_ev.timer_set = 0;

    peer->check_timeout_ev.handler = ngx_http_upstream_health_check_timeout_handler;
    peer->check_timeout_ev.data = peer;
    peer->check_timeout_ev.log = log;
    peer->check_timeout_ev.timer_set = 0;

    ngx_memzero(&peer->pc, sizeof(ngx_peer_connection_t));

    peer->pool = ngx_create_pool(ngx_pagesize, log);

    if (peer->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "[check] init peer: alloc peer pool fail, %V", &peer->name);
        return NGX_ERROR;
    }

    ngx_add_timer(&peer->check_ev, interval);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
            "[check] add timer: peer=%V, interval=%M, current_time=%M",
            &peer->name, interval, ngx_current_msec);

    return NGX_OK;
}

static void ngx_http_upstream_health_check_init_event_handler(ngx_event_t *ev)
{
    if (ngx_http_upstream_health_check_need_exit(ev)) {
        return;
    }

    ngx_http_upstream_health_check_connect_handler(ev);
}

static void ngx_http_upstream_health_check_timeout_handler(ngx_event_t *ev)
{
    ngx_log_error(NGX_LOG_ERR, ev->log, 0,"[check] timeout: happen");

    ngx_http_upstream_health_check_peer_t *peer;

    if (ngx_http_upstream_health_check_need_exit(ev)) {
        return;
    }

    peer = ev->data;
    if (peer->conf == NULL) return;
    ngx_http_upstream_health_check_update_status(ev->data, 0);
    ngx_http_upstream_health_check_finish_handler(ev->data, 1);
}

static void ngx_http_upstream_health_check_connect_handler(ngx_event_t *ev)
{
    ngx_http_upstream_health_check_peer_t *peer;
    ngx_connection_t                      *c;
    ngx_peer_connection_t                 *pc;
    ngx_log_t                             *log;
    ngx_int_t                              rc;

    if (ngx_http_upstream_health_check_need_exit(ev)) {
        return;
    }

    peer = ev->data;
    if (peer->free || peer->conf == NULL) return;

    log = ev->log;

    pc = &peer->pc;
    if (pc->connection != NULL) {
        if (ngx_http_upstream_health_check_connect_alive(pc->connection) != NGX_OK) {
            ngx_http_upstream_health_check_finish_handler(peer, 0);
        } else {
            goto connect_done;
        }
    }
    pc->log = log;
    pc->log_error =  NGX_ERROR_ERR;
    pc->start_time = ngx_current_msec;
    pc->get = ngx_event_get_peer;
    pc->sockaddr = &peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name =  &peer->name;
    pc->cached = 0;

    rc = ngx_event_connect_peer(pc);
    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_http_upstream_health_check_update_status(peer, 0);
        ngx_http_upstream_health_check_finish_handler(peer, 1);
        return ;
    }

    c = pc->connection;
    c->data = peer;
    c->log = peer->pc.log;
    c->write->log = c->log;
    c->read->log = c->log;
    c->write->handler = peer->conf->type.send_handler;
    c->write->data = peer;
    c->read->handler = peer->conf->type.recv_handler;
    c->read->data = peer;
    c->sendfile = 0;
    
connect_done:
    peer->check_state = NGX_CHECK_CONNECT_DONE;
    ngx_add_timer(&peer->check_timeout_ev, peer->conf->timeout);
}

static ngx_int_t ngx_http_upstream_health_check_connect_alive(ngx_connection_t *c)
{
    char      buf[1];
    ngx_err_t err;
    ngx_int_t n;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "[check] check conection: %P, %z, %z", ngx_pid, n, err);

    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "[check] check conection: %P alive", ngx_pid);
        return NGX_OK;
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "[check] check conection: %P death", ngx_pid);
        return NGX_ERROR;
    }
}

static void ngx_http_upstream_health_check_peek_handler(ngx_event_t *ev)
{
    ngx_http_upstream_health_check_peer_t *peer;
    ngx_connection_t                      *c;

    peer = ev->data;
    if (peer->conf == NULL) return;
    c = peer->pc.connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0, 
            "[check] peek handler: name=%V, pid=%P", &peer->name, ngx_pid);

    if (ngx_http_upstream_health_check_need_exit(ev)) {
        return;
    }

    if (ngx_http_upstream_health_check_connect_alive(c) == NGX_OK) {
        ngx_http_upstream_health_check_update_status(peer, 1);
    } else {
        ngx_http_upstream_health_check_update_status(peer, 0);
    }

    ngx_http_upstream_health_check_finish_handler(peer, 1);
}

static void ngx_http_upstream_health_check_update_status(ngx_http_upstream_health_check_peer_t *peer, ngx_int_t rc)
{
    ngx_http_upstream_health_check_conf_t *conf;

    conf = peer->conf;

    ngx_http_check_peer_lock();

    if (rc == 1) {
         peer->shm->rise += 1;
         peer->shm->fail = 0;
    }  else {
         peer->shm->fail += 1;
         peer->shm->rise = 0;
    } 

    if (peer->shm->rise == conf->min_rise) {
        peer->shm->fail = 0;
        ngx_http_check_peer_unlock();
        if (ngx_dyups_update_server_status(conf->upstream_name, &peer->name, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, peer->log, 0, 
                "[check] update dyups module server %V status up failed.", &peer->name);
        } else {
            ngx_log_error(NGX_LOG_NOTICE, peer->log, 0, 
                "[check] update status: peer up name=%V, pid=%P", &peer->name, ngx_pid);
        }
    }  else if (peer->shm->fail == conf->max_fail) {
        peer->shm->rise = 0;
        ngx_http_check_peer_unlock();
        if (ngx_dyups_update_server_status(conf->upstream_name, &peer->name, 1) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, peer->log, 0, 
                "[check] update dyups module server %V status down failed.", &peer->name);
        } else {
            ngx_log_error(NGX_LOG_WARN, peer->log, 0, 
                "[check] update status: peer down name=%V, pid=%P", &peer->name, ngx_pid);
        }
    } else {
        ngx_http_check_peer_unlock();
    }
}

static void
ngx_http_upstream_health_check_finish_handler(ngx_http_upstream_health_check_peer_t *peer, ngx_int_t need_reinit_ev) 
{
    ngx_connection_t *c;
    ngx_buf_t        *send_buf, *recv_buf;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, peer->log, 0,
            "[check] finish handler: name=%V, pid=%P", &peer->name, ngx_pid);

    c = peer->pc.connection;
    if (c == NULL) return;
    recv_buf = peer->recv_data;
    send_buf = peer->send_data;

    if (peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer->check_timeout_ev);
    }

    if (peer->check_ev.timer_set) {
        ngx_del_timer(&peer->check_ev);
    }
 
    if (c != NULL) {
        ngx_close_connection(c);
        peer->pc.connection = NULL;
    }

    if (&peer->status != NULL) {
        ngx_memzero(&peer->status, sizeof(ngx_http_status_t));
    }

    if (recv_buf != NULL) {
        recv_buf->pos = recv_buf->last = recv_buf->start;
    }

    if (send_buf != NULL) {
        send_buf->pos = send_buf->start;
        send_buf->last = send_buf->end;
    }

    peer->check_state = NGX_CHECK;

    if (!peer->free && need_reinit_ev) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, peer->log, 0,
            "[check] finish handler: reinit check_ev, name=%V, pid=%P", &peer->name, ngx_pid);
        ngx_add_timer(&peer->check_ev, peer->conf->interval);
    }
}

static ngx_int_t ngx_http_upstream_health_check_need_exit(ngx_event_t *ev)
{
    if (ngx_terminate || ngx_quit || ngx_exiting) {
        return 1;
    }
    return 0;
}

static ngx_peer_check_type *ngx_http_get_peer_check_type(ngx_str_t *str)
{
    ngx_uint_t i;
    ngx_str_t  *name;

    for (i = 0; ngx_peer_check_types[i].name.data; i++) {
        name = &ngx_peer_check_types[i].name;
        if (ngx_strncasecmp(str->data, name->data, name->len) == 0) {
            return &ngx_peer_check_types[i];
        }
    }
    return NULL;
}

/* vim: set ts=4 sw=4 sts=4 tw=100 */
int ngx_http_upstream_health_check_update_handler(ngx_str_t *upstream_name)
{
    ngx_array_t *confsp; 
    ngx_uint_t i;
    ngx_http_upstream_health_check_conf_t *confs, *conf;
    ngx_http_upstream_srv_conf_t *uscf;

    if (!upstream_name->len || check_main_conf == NULL || !check_main_conf->confs.nelts)
        return NGX_OK;

    confsp = &check_main_conf->confs;
    confs = confsp->elts;
    for (i = 0; i < confsp->nelts; i++) {
        conf = &confs[i];
        if (conf->upstream_name->len == upstream_name->len && \
            !ngx_strncmp(conf->upstream_name->data, upstream_name->data, upstream_name->len))
        {
            break;
        }
        conf = NULL;
    }
    if (conf == NULL) return NGX_OK;

    uscf = ngx_http_upstream_health_check_update_find_upstream(upstream_name);
    ngx_http_upstream_health_check_update_clean_peers(upstream_name);

    if (uscf != NULL) {
        if (ngx_http_upstream_health_check_update_init_peer(upstream_name, uscf) != NGX_OK) {
            return NGX_ERROR;
        }
        if (ngx_http_upstream_health_check_update_init_peer_shm(upstream_name) != NGX_OK) {
            return NGX_ERROR;
        }
        if (ngx_http_upstream_health_check_update_init_timers(upstream_name, uscf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_http_upstream_srv_conf_t *
ngx_http_upstream_health_check_update_find_upstream(ngx_str_t *upstream_name)
{
    size_t i;
    ngx_http_upstream_main_conf_t              *umcf;
    ngx_http_upstream_srv_conf_t               **uscfp;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;
    for(i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len == upstream_name->len && \
            !ngx_strncmp(uscfp[i]->host.data, upstream_name->data, upstream_name->len))
        {
            return uscfp[i];
        }
    }
    return NULL;
}

static ngx_int_t
ngx_http_upstream_health_check_update_init_peer(ngx_str_t *upstream_name, ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf = check_main_conf;
    ngx_http_upstream_health_check_peer_t      *peer;
    ngx_http_upstream_health_check_conf_t      *confs, *conf;
    ngx_http_upstream_server_t                 *server;
    ngx_uint_t                                  i, j;
    ngx_array_t                                *confp, *peers;


    confp = &ucmcf->confs;
    confs = confp->elts;
    conf = NULL;
    for (i = 0; i < confp->nelts; i++) {
        conf = &confs[i];
        if (conf->upstream_name->len == upstream_name->len && \
            !ngx_strncmp(conf->upstream_name->data, upstream_name->data, upstream_name->len))
        {
            break;
        }
        conf = NULL;
    }
    if (conf == NULL) {
        return NGX_ERROR;
    }
    if (uscf->servers) {
        server = uscf->servers->elts;
        peers = &ucmcf->peers;
        for (i = 0; i < uscf->servers->nelts; i++) {
            if (server[i].backup || server[i].down) {
                continue;
            }
            for (j = 0; j < server[i].naddrs; j++) {
                peer = ngx_array_push(peers);
                if (peer == NULL) {
                    return NGX_ERROR;
                }
                ngx_memzero(peer, sizeof(ngx_http_upstream_health_check_peer_t));
                ngx_memzero(&peer->status, sizeof(ngx_http_status_t));

                peer->state = 0;
                peer->check_state = NGX_CHECK;
                peer->name.data = ngx_pcalloc(g_pool, server[i].addrs[j].name.len);
                if (peer->name.data == NULL) return NGX_ERROR;
                memcpy(peer->name.data, server[i].addrs[j].name.data, server[i].addrs[j].name.len);
                peer->name.len = server[i].addrs[j].name.len;
                memcpy(&peer->sockaddr, server[i].addrs[j].sockaddr, sizeof(struct sockaddr));
                peer->socklen = server[i].addrs[j].socklen;
                peer->conf = conf;
            }
        }
    } 

    return NGX_OK;
}

static int
ngx_http_upstream_health_check_update_init_peer_shm(ngx_str_t *upstream_name)
{
    ngx_array_t                                *peersp;
    ngx_http_upstream_health_check_peer_t      *peers, *peer;
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_check_peer_shm_t         *peer_shm, *prev_shm;
    ngx_slab_pool_t                            *shpool;
    ngx_uint_t                                  i;

    shpool = check_main_conf->shpool;

    ucmcf = check_main_conf;
    peersp = &ucmcf->peers;
    if (!peersp->nelts) {
        prev_shm = ucmcf->peers_shm->peers;
    } else {
        prev_shm = NULL;
        peers = peersp->elts;
        for (i = 0; i < peersp->nelts; ++i) {
             peer = &peers[i];
             if (peer->free || peer->conf == NULL) continue;
             prev_shm = peer->shm;
        }
        if (prev_shm == NULL) {
            prev_shm = ucmcf->peers_shm->peers;
        }
    }
    ngx_http_check_peer_lock();
    peers = peersp->elts;
    for (i = 0; i < peersp->nelts; i++) {
        peer = &peers[i];
        if (peer->free || peer->conf == NULL) continue;
        if (upstream_name->len != peer->conf->upstream_name->len || \
            ngx_strncmp(upstream_name->data, peer->conf->upstream_name->data, upstream_name->len))
            continue;
        peer_shm = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_upstream_check_peer_shm_t));
        if (peer_shm == NULL) {
            ngx_http_check_peer_unlock();
            return NGX_ERROR;
        }
        peer_shm->wid = ngx_process_slot;
        peer_shm->socklen = peer->socklen;
        peer_shm->sockaddr = ngx_slab_alloc_locked(shpool, peer_shm->socklen);
        if (peer_shm->sockaddr == NULL) {
            ngx_http_check_peer_unlock();
            return NGX_ERROR;
        }
        ngx_memcpy(peer_shm->sockaddr, &peer->sockaddr, peer_shm->socklen);

        peer_shm->name = ngx_slab_alloc_locked(shpool, sizeof(ngx_str_t));
        if (peer_shm->name == NULL) {
            ngx_http_check_peer_unlock();
            return NGX_ERROR;
        }
        peer_shm->name->len = peer->name.len;
        peer_shm->name->data = ngx_slab_alloc_locked(shpool, peer_shm->name->len);
        if (peer_shm->name->data == NULL) {
            ngx_http_check_peer_unlock();
            return NGX_ERROR;
        }
        ngx_memcpy(peer_shm->name->data, peer->name.data, peer_shm->name->len);

        peer_shm->fail = 0;
        peer_shm->rise = 0;
        peer_shm->next = NULL;
        peer_shm->prev = prev_shm;
        prev_shm->next = peer_shm;
        prev_shm = peer_shm;
        ucmcf->peers_shm->total_peers += 1;
        peer_shm->index = ucmcf->peers_shm->total_peers;
        peer->shm = peer_shm;
    }
    ngx_http_check_peer_unlock();
    
    return NGX_OK;
}

static void
ngx_http_upstream_health_check_update_clean_peers(ngx_str_t *upstream_name)
{
    ngx_uint_t                             i;
    ngx_http_upstream_health_check_peer_t *peers, *peer;

    peers = check_main_conf->peers.elts;

    ngx_http_check_peer_lock();
    for (i = 0; i < check_main_conf->peers.nelts; i++) {
        peer = &peers[i];

        if (peer->free || peer->conf == NULL) {
            continue;
        }
        if (peer->shm->wid != ngx_process_slot) {
            continue;
        }
        if (upstream_name->len != peer->conf->upstream_name->len || \
            ngx_strncmp(upstream_name->data, peer->conf->upstream_name->data, upstream_name->len))
        {
            continue;
        }
        peer->free = 1;
    }
    ngx_http_check_peer_unlock();
}

static ngx_int_t
ngx_http_upstream_health_check_update_init_timers(ngx_str_t *upstream_name, ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_http_upstream_health_check_main_conf_t *ucmcf;
    ngx_http_upstream_health_check_peer_t      *peers, *peer;
    ngx_core_conf_t                            *ccf;
    ngx_uint_t                                  i;
    ngx_array_t                                *peersp;
    
    ucmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_health_check_module);
    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx, ngx_core_module);

    worker_processes = ccf->worker_processes;
    peersp = &ucmcf->peers;

    if (peersp->nelts == 0) return NGX_OK;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
            "[check] init timers: wokers=%i, peers=%i, pid=%P", 
            worker_processes, peersp->nelts, ngx_pid);

    peers = peersp->elts;
    for (i = 0; i < peersp->nelts; i++) {
        peer = &peers[i];

        ngx_http_check_peer_lock();
            
        if (peer->free || peer->conf == NULL) {
            ngx_http_check_peer_unlock();
            continue;
        }
        if (peer->conf->upstream_name->len != upstream_name->len || \
            ngx_strncmp(peer->conf->upstream_name->data, upstream_name->data, upstream_name->len))
        {
            ngx_http_check_peer_unlock();
            continue;
        }
        if (peer->shm->wid != (ngx_process_slot % worker_processes)) {
            ngx_http_check_peer_unlock();
            continue;
        }

        ngx_http_check_peer_unlock();

        ngx_http_upstream_health_check_add_timers(peer, peer->conf->interval, ngx_cycle->log);
    }

    return NGX_OK;
}

