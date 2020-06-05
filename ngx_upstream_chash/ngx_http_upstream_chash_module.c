#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_ebtree.h>

#if (NGX_DEBUG)

#define ngx_queue_safe_remove(x) \
    do {                         \
        if ((x)->prev != NULL) { \
            ngx_queue_remove(x); \
        }                        \
    } while(0)

#else

#define ngx_queue_safe_remove(x) \
    do {                         \
        if ((x)->prev != NULL) { \
            ngx_queue_remove(x); \
            (x)->prev = NULL;    \
            (x)->next = NULL;    \
        }                        \
    } while(0)

#endif

#define ngx_queue_safe_insert_tail(h, x) \
    do {                                 \
        if ((x)->prev == NULL) {         \
            ngx_queue_insert_tail(h, x); \
        }                                \
    } while(0)

typedef struct {
    ngx_ebt_node_t                        node;
    ngx_int_t                             idx;
} ngx_http_upstream_chash_node_t;

typedef struct {
    ngx_queue_t                           queue;
    ngx_int_t                             count;
    ngx_int_t                             total;
    time_t                                down_time;
    time_t                                recovery_time;
    ngx_http_upstream_rr_peer_t          *rr;
    ngx_http_upstream_chash_node_t       *nodes;
} ngx_http_upstream_chash_peer_t;

typedef struct {
    void                                 *next;
    ngx_int_t                             count;
    ngx_int_t                             quick_recovery; /* unsigned:1 */
    time_t                                recovery_time;
    ngx_queue_t                           failed;
    ngx_ebt_root_t                        tree;
    ngx_http_upstream_rr_peers_t         *rr;
    ngx_http_upstream_chash_peer_t        peer[1];
} ngx_http_upstream_chash_peers_t;

typedef struct {
    ngx_int_t                             dups;
    ngx_http_complex_value_t              value;
    ngx_http_upstream_chash_peers_t      *peers;
    ngx_http_upstream_init_pt             init_upstream;
    ngx_http_upstream_init_peer_pt        init;
} ngx_http_upstream_chash_srv_conf_t;

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t      rrp;
    ngx_ebt_key_t                         hash;
    ngx_ebt_node_t                       *last;
    ngx_http_upstream_chash_peers_t      *peers;
    ngx_http_upstream_chash_srv_conf_t   *conf;
    time_t                                upstream_start_time;
    time_t                                peer_start_time;
    unsigned                              fail_checked:1;
    unsigned                              use_last:1;
} ngx_http_upstream_chash_peer_data_t;

static void *ngx_http_upstream_chash_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_chash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_http_upstream_chash_peers_t *ngx_http_upstream_chash_init_peers(ngx_pool_t *pool, \
                                            ngx_http_upstream_rr_peers_t *peers,
                                            ngx_http_upstream_chash_srv_conf_t   *ccf);
static ngx_int_t ngx_http_upstream_init_chash_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_chash_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static ngx_command_t ngx_http_upstream_chash_commands[] = {
    {
        ngx_string("chash"),
        NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
        ngx_http_upstream_chash,
        0,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_chash_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    ngx_http_upstream_chash_create_conf,    /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};

ngx_module_t  ngx_http_upstream_chash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_chash_module_ctx,    /* module context */
    ngx_http_upstream_chash_commands,       /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_upstream_init_chash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_rr_peers_t         *peers;
    ngx_http_upstream_chash_srv_conf_t   *ccf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "init chash");

    ccf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_chash_module);
    if (ccf->init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    peers = us->peer.data;

    ccf->peers = ngx_http_upstream_chash_init_peers(cf->pool, peers, ccf);
    if (ccf->peers == NULL) {
        return NGX_ERROR;
    }

    ccf->init = us->peer.init;
    us->peer.init = ngx_http_upstream_init_chash_peer;

    if (peers->next == NULL) {
        return NGX_OK;
    }

    ccf->peers->next = ngx_http_upstream_chash_init_peers(cf->pool, peers->next, ccf);
    if (ccf->peers->next == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_http_upstream_chash_peers_t *ngx_http_upstream_chash_init_peers(ngx_pool_t *pool, \
                                            ngx_http_upstream_rr_peers_t *peers, \
                                            ngx_http_upstream_chash_srv_conf_t *ccf)
{
    ngx_uint_t                       i;
    ngx_int_t                        j;
    ngx_ebt_root_t                   init_head = NGX_EBT_ROOT;
    ngx_http_upstream_chash_node_t  *nodes;
    ngx_http_upstream_chash_peers_t *chash_peers;
    u_char                          *p, buf[sizeof("255.255.255.255:65535-65535") - 1];

    nodes = ngx_pcalloc(pool, (peers->total_weight * ccf->dups) * sizeof(ngx_http_upstream_chash_node_t));
    if (nodes == NULL) {
        return NULL;
    }

    chash_peers = ngx_pcalloc(pool, sizeof(ngx_http_upstream_chash_peers_t)
                                  + (peers->total_weight * ccf->dups - 1)
                                  * sizeof(ngx_http_upstream_chash_peer_t));
    if (chash_peers == NULL) {
        return NULL;
    }

    chash_peers->rr = peers;
    chash_peers->tree = init_head;

    ngx_queue_init(&chash_peers->failed);

    for (i = 0; i < peers->number; i++) {
        chash_peers->peer[i].rr = &peers->peer[i];
        chash_peers->peer[i].total = peers->peer[i].weight * ccf->dups;
        chash_peers->peer[i].nodes = nodes;
        for (j = 0; j < chash_peers->peer[i].total; j++) {
            chash_peers->peer[i].nodes[j].idx = i;

            p = ngx_sprintf(buf, "%V#%ui", &peers->peer[i].name, j);
            chash_peers->peer[i].nodes[j].node.key = ngx_murmur_hash2(buf, p - buf);

            if (!peers->peer[i].down) {
                ngx_ebt_insert(&chash_peers->tree, &chash_peers->peer[i].nodes[j].node);
            }
        }
        if (!peers->peer[i].down) {
            chash_peers->peer[i].count = j;
            chash_peers->count += j;
        }
        nodes += chash_peers->peer[i].total;
    }

    return chash_peers;
}

static ngx_int_t ngx_http_upstream_init_chash_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t                                 val;
    ngx_http_upstream_chash_srv_conf_t       *ccf;
    ngx_http_upstream_chash_peer_data_t      *ccp;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "init chash peer");

    ccf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_chash_module);

    ccp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_chash_peer_data_t));
    if (ccp == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &ccp->rrp;

    if (ccf->init(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_chash_peer;
    r->upstream->peer.free = ngx_http_upstream_free_chash_peer;

    ccp->last = NULL;
    ccp->conf = ccf;
    ccp->peers = ccf->peers;

    ccp->use_last = 0;
    ccp->fail_checked = 0;
    ccp->upstream_start_time = 0;

    if (ngx_http_complex_value(r, &ccf->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ccp->hash = ngx_murmur_hash2(val.data, val.len);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "chash calced: s:\"%V\" h:%uD", &val, ccp->hash);

    return NGX_OK;
}

static ngx_http_upstream_rr_peer_t *ngx_http_upstream_chash_get_peer(ngx_http_upstream_chash_peer_data_t *ccp)
{
    time_t                            now;
    uintptr_t                         m;
    ngx_int_t                         i, n;

    ngx_queue_t                      *q, *failed;
    ngx_ebt_node_t                   *node, *start;
    ngx_http_upstream_rr_peer_t      *peer;
    ngx_http_upstream_rr_peers_t     *peers;
    ngx_http_upstream_chash_peer_t   *chash_peer;

    now = ngx_time();
    start = NULL;

    node = ccp->last;
    if (node && !NGX_EB_NODE_IN_TREE(node)) {
        node = NULL;
    }

    peers = ccp->rrp.peers;

    if (!ccp->fail_checked) {
        failed = &ccp->peers->failed;

        for (q = ngx_queue_head(failed); q != ngx_queue_sentinel(failed); q = ngx_queue_next(q)) {
            chash_peer = ngx_queue_data(q, ngx_http_upstream_chash_peer_t, queue);
            peer = chash_peer->rr;
            if (ccp->peers->quick_recovery || now - peer->checked > peer->fail_timeout) {
                i = chash_peer->nodes[0].idx;
                n = i / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));
                if (ccp->rrp.tried[n] & m) {
                    break;
                }
                node = NULL;
                ccp->fail_checked = 1;
                ngx_queue_remove(q);
                ngx_queue_insert_tail(failed, q);
                goto done;
            }
        }
    }

    ccp->fail_checked = 1;

    while (1) {
        if (!node) {
            node = ngx_ebt_lookup_ge(&ccp->peers->tree, ccp->hash);
        } else if (ccp->use_last) {
            ccp->use_last = 0;
        } else {
            node = ngx_ebt_next(node);
        }

        if (!node) {
            node = ngx_ebt_first(&ccp->peers->tree);
        }

        if (!node) {
            return NULL;
        }

        if (!start) {
            start = node;
        } else if (start == node) {
            return NULL;
        }

        i = ((ngx_http_upstream_chash_node_t *) node)->idx;

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (ccp->rrp.tried[n] & m) {
            continue;
        }

        peer = &peers->peer[i];

        if (peer->down) {
            continue;
        }

        break;
    }

done:
    ccp->rrp.current = (ngx_http_upstream_rr_peer_t *)i;
    ccp->rrp.tried[n] |= m;

    ccp->last = node;
    ccp->peer_start_time = now;
    if (!ccp->upstream_start_time) {
        ccp->upstream_start_time = now;
    }

    peer->checked = now;

    return peer;
}

static ngx_int_t ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                            rc;
    ngx_uint_t                           i, n;

    ngx_http_upstream_rr_peer_t         *peer;
    ngx_http_upstream_chash_peers_t     *chash_peers;
    ngx_http_upstream_chash_peer_data_t *ccp = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "get chash peer, try: %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    if (ccp->rrp.peers->single) {
        peer = &ccp->rrp.peers->peer[0];
        if (peer->down) {
            goto failed;
        }
    } else {
        /* there are several peers */
        peer = ngx_http_upstream_chash_get_peer(ccp);
        if (peer == NULL) {
            goto failed;
        }
        if (ccp->last == NULL && !ccp->peers->quick_recovery) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                    "check kicked chash peer: %ui (%V)",
                    ccp->rrp.current, &peer->name);
        }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                "get chash peer, current: %ui %i",
                ccp->rrp.current, peer->current_weight);
    }
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    /* ngx_unlock_mutex(rrp->peers->mutex); */
    if (pc->tries == 1 && ccp->rrp.peers->next) {
        pc->tries += ccp->rrp.peers->next->number;
    }

    return NGX_OK;

failed:

    chash_peers = ccp->peers;
    if (chash_peers->next) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "get chash peer, backup servers");

        ccp->rrp.peers = ccp->rrp.peers->next;
        pc->tries = ccp->rrp.peers->number;

        n = ccp->rrp.peers->number / (8 * sizeof(uintptr_t)) + 1;
        for (i = 0; i < n; i++) {
            ccp->rrp.tried[i] = 0;
        }

        ccp->peers = chash_peers->next;

        ccp->last = NULL;
        ccp->use_last = 0;
        ccp->fail_checked = 0;
        ccp->upstream_start_time = 0;

        rc = ngx_http_upstream_get_chash_peer(pc, ccp);

        if (rc != NGX_BUSY) {
            return rc;
        }
    }

    /* all peers failed, mark them as live for quick recovery */
    if (!chash_peers->quick_recovery && ccp->upstream_start_time > chash_peers->recovery_time) {
        chash_peers->quick_recovery = 1;

        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "chash enter quick recovery mode");
    }

    pc->name = chash_peers->rr->name;

    return NGX_BUSY;
}

static void ngx_http_upstream_free_chash_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    ngx_http_upstream_chash_peer_data_t    *ccp = data;
    time_t                                  now;
    ngx_queue_t                            *q, *failed;
    ngx_ebt_node_t                         *node;
    ngx_http_upstream_rr_peer_t            *peer;
    ngx_http_upstream_chash_peer_t         *chash_peer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "free chash peer %ui %ui", pc->tries, state);

    if (state == 0 && pc->tries == 0) {
        return;
    }

    if (ccp->rrp.peers->single) {
        pc->tries = 0;

        return;
    }

    peer = &ccp->rrp.peers->peer[(ngx_int_t)(ccp->rrp.current)];
    chash_peer = &ccp->peers->peer[(ngx_int_t)(ccp->rrp.current)];

    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, pc->log, 0,
            "free chash peer accessed:%T checked:%T count:%D "
            "peer_start_time:%T peer_recovery_time:%T "
            "upstream_start_time:%T peers_recovery_time:%T",
            peer->accessed, peer->checked, chash_peer->count,
            ccp->peer_start_time, chash_peer->recovery_time,
            ccp->upstream_start_time, ccp->peers->recovery_time);

    now = ngx_time();

    if (state & NGX_PEER_FAILED) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                "free failed chash peer: %ui %i",
                ccp->rrp.current, peer->effective_weight);

        if (ccp->peers->quick_recovery) {
            pc->tries = 0;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                    "retry disabled in quick recovery mode");
        } else if (ccp->peer_start_time > chash_peer->recovery_time) {
            peer->fails ++;
            peer->accessed = now;
            peer->checked = now;

            if (peer->max_fails && peer->fails >= peer->max_fails) {
                if (chash_peer->count > 0) {
                    ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                            "mark chash peer down: %V (%ui)",
                            &peer->name, ccp->rrp.current);

                    chash_peer->down_time = now;

                    do {
                        node = &chash_peer->nodes[--chash_peer->count].node;
                        if (ccp->last == node) {
                            ccp->last = ngx_ebt_skip_node(&ccp->peers->tree, ccp->last);
                            ccp->use_last = 1;
                        }

                        ngx_ebt_delete(node);
                    } while (chash_peer->count > 0);
                }

                ngx_queue_safe_insert_tail(&ccp->peers->failed, &chash_peer->queue);
            }
        }
    } else if (peer->accessed < peer->checked && ccp->peer_start_time > chash_peer->down_time) {
        peer->fails = 0;

        if (chash_peer->count < chash_peer->total) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                    "mark chash peer alive: %V (%ui)",
                    &peer->name, ccp->rrp.current);

            chash_peer->recovery_time = now;

            do {
                ngx_ebt_insert(&ccp->peers->tree, &chash_peer->nodes[chash_peer->count++].node);
            } while (chash_peer->count < chash_peer->total);
        }

        ngx_queue_safe_remove(&chash_peer->queue);

        if (ccp->peers->quick_recovery) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "chash leave quick recovery mode");

            ccp->peers->quick_recovery = 0;
            ccp->peers->recovery_time = now;

            failed = &ccp->peers->failed;

            for (q = ngx_queue_head(failed); q != ngx_queue_sentinel(failed); q = ngx_queue_next(q)) {
                chash_peer = ngx_queue_data(q, ngx_http_upstream_chash_peer_t, queue);
                peer = chash_peer->rr;
                peer->checked = 0;
                chash_peer->recovery_time = now;
            }
        }
    }

    if (pc->tries) {
        pc->tries --;
    }
}

static char *ngx_http_upstream_chash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                             dups;
    ngx_uint_t                            i;
    ngx_str_t                            *value;
    ngx_http_upstream_srv_conf_t         *uscf;
    ngx_http_compile_complex_value_t      ccv;
    ngx_http_upstream_chash_srv_conf_t   *ccf;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_chash_module);

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ccf->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    dups = 16;

    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "dups=", sizeof("dups=") - 1) == 0) {
            dups = ngx_atoi(value[i].data + sizeof("dups=") - 1,
                       value[i].len - (sizeof("dups=") - 1));
            if (dups == NGX_ERROR) {
                goto invalid;
            }
            continue;
        }
        goto invalid;
    }

    ccf->dups = dups;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    ccf->init_upstream = uscf->peer.init_upstream;
    uscf->peer.init_upstream = ngx_http_upstream_init_chash;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
        |NGX_HTTP_UPSTREAM_WEIGHT
        |NGX_HTTP_UPSTREAM_MAX_FAILS
        |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
        |NGX_HTTP_UPSTREAM_DOWN
        |NGX_HTTP_UPSTREAM_BACKUP;

    return NGX_CONF_OK;

invalid:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static void *ngx_http_upstream_chash_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_chash_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_chash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}
