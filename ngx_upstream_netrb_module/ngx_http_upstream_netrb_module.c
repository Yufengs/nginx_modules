#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ifaddrs.h>

#define ngx_current_module ngx_http_upstream_netrb_module

typedef struct {
    in_addr_t                             addr;
    in_addr_t                             mask;
    ngx_str_t                             name;
    ngx_str_t                             desc;
} ngx_http_upstream_netrb_segment_t;

typedef struct {
    ngx_str_t                             name;
    ngx_array_t                           segments;
    ngx_http_upstream_netrb_segment_t     default_value;
    ngx_str_t                            *desc;
} ngx_http_upstream_netrb_topology_t;

typedef struct {
    ngx_array_t                           topologies;
    ngx_array_t                          *local;
    ngx_int_t                             default_topology;
} ngx_http_upstream_netrb_main_conf_t;

typedef struct {
    ngx_str_t                             match;
    ngx_int_t                             percent;
} ngx_http_upstream_netrb_part_t;

typedef struct {
    ngx_str_t                             place;
    ngx_int_t                             count;
    ngx_http_upstream_netrb_part_t        part[0];
} ngx_http_upstream_netrb_location_t;

typedef struct {
    ngx_http_upstream_netrb_topology_t   *topology;
    ngx_http_upstream_init_pt             original_init_upstream;
    ngx_http_upstream_netrb_main_conf_t  *conf;
    ngx_array_t                          *locations;
    unsigned                              set:1;
    unsigned                              off:1;
} ngx_http_upstream_netrb_srv_conf_t;

typedef struct {
    in_addr_t                             addr;
    ngx_str_t                             name;
} ngx_http_upstream_netrb_addr_t;

typedef struct {
    ngx_int_t                             idx;
    ngx_str_t                            *desc;
    ngx_int_t                             group;
    unsigned                              backup:1;
} ngx_http_upstream_netrb_server_t;

static void *ngx_http_upstream_netrb_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_upstream_netrb_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_netrb_topology_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_netrb_rebalance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_netrb_assign(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_upstream_netrb_topology_get_local(ngx_conf_t *cf, ngx_array_t **localp);
static ngx_str_t *ngx_http_upstream_netrb_topology_get_desc(in_addr_t addr, ngx_http_upstream_netrb_topology_t *nt);
static char *ngx_http_upstream_netrb_set_handler(ngx_conf_t *cf, ngx_http_upstream_netrb_srv_conf_t *iscf);
static ngx_int_t ngx_http_upstream_netrb_desc_match(ngx_str_t *desc, ngx_str_t *short_desc);

static ngx_http_module_t ngx_http_upstream_netrb_module_ctx = {
    NULL,                                     /* preconfiguration */
    NULL,                                     /* postconfiguration */
    ngx_http_upstream_netrb_create_main_conf, /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_http_upstream_netrb_create_srv_conf,  /* create server configuration */
    NULL,                                     /* merge server configuration */
    NULL,                                     /* create location configuration */
    NULL                                      /* merge location configuration */
};

static ngx_command_t ngx_http_upstream_netrb_commands[] = {
    {
        ngx_string("net_topology"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
        ngx_http_upstream_netrb_topology_block,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("rebalance"),
        NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE12,
        ngx_http_upstream_netrb_rebalance,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("assign"),
        NGX_HTTP_UPS_CONF|NGX_CONF_2MORE,
        ngx_http_upstream_netrb_assign,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_http_upstream_netrb_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_netrb_module_ctx,    /* module context */
    ngx_http_upstream_netrb_commands,       /* module directives */
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

static ngx_int_t ngx_http_upstream_init_netrb(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                               i, n, m;
    ngx_int_t                               backup_count;
    ngx_int_t                              *group_weight = NULL;
    ngx_int_t                               do_assign;
    ngx_str_t                              *serv = NULL, *bakv, *name, *upstream;
    ngx_http_upstream_server_t             *server;
    ngx_http_upstream_netrb_addr_t         *ntaddr;
    ngx_http_upstream_netrb_server_t       *msrv;
    ngx_http_upstream_netrb_topology_t     *nt;
    ngx_http_upstream_netrb_srv_conf_t     *iscf;
    ngx_http_upstream_netrb_location_t     *loc = NULL, **ploc;
    ngx_http_upstream_netrb_main_conf_t    *imcf;

    upstream = &us->host;

    iscf = ngx_http_conf_upstream_srv_conf(us, ngx_current_module);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "upstream rebalance %V off:%d", upstream, (int)iscf->off);

    if (iscf->off) {
        goto quit;
    }

    if (us->servers == NULL || us->servers->nelts == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "upstream rebalance %V failed because of empty us->servers",
                upstream);

        return NGX_ERROR;
    }

    imcf = iscf->conf;

    if (imcf->local == NULL && ngx_http_upstream_netrb_topology_get_local(cf, &imcf->local) != NGX_OK)
    {
        return NGX_ERROR;
    }

    nt = iscf->topology;
    if (nt == NULL) {
        if (imcf->default_topology == NGX_CONF_UNSET) {
            if (imcf->topologies.nelts == 0) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                        "no net_topology defined for upstream %V", upstream);

                return NGX_ERROR;
            }

            imcf->default_topology = 0;
        }

        nt = (ngx_http_upstream_netrb_topology_t *)imcf->topologies.elts + imcf->default_topology;
        iscf->topology = nt;
    }

    if (nt->desc == NULL) {
        name = &nt->default_value.name;

        ntaddr = imcf->local->elts;

        for (i = 0; i < (ngx_int_t)imcf->local->nelts; i++) {
            serv = ngx_http_upstream_netrb_topology_get_desc(ntaddr[i].addr, nt);
            if (serv && serv != &nt->default_value.desc) {
                name = &ntaddr[i].name;
                break;
            }
        }

        if (serv == NULL) {
            if (nt->default_value.name.len) {
                serv = &nt->default_value.desc;
            } else {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                        "upstream rebalance %V failed because server address "
                        "not found in topology %V",
                        upstream, &nt->name);

                return NGX_ERROR;
            }
        }

        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                "upstream rebalance use local address %V (%V)",
                name, serv);

        nt->desc = serv;
    } else {
        serv = nt->desc;
    }

    do_assign = 0;

    if (iscf->locations) {
        ploc = iscf->locations->elts;

        for (i = 0; i < (ngx_int_t)iscf->locations->nelts; i++) {
            loc = ploc[i];

            if (ngx_http_upstream_netrb_desc_match(serv, &loc->place)) {
                do_assign = 1;

                ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                        "upstream rebalance %V use assign for \"%V\"",
                        upstream, &loc->place);

                group_weight = ngx_pcalloc(cf->pool, sizeof(ngx_int_t) * loc->count);
                if (group_weight == NULL) {
                    return NGX_ERROR;
                }

                break;
            }
        }
    }

    server = us->servers->elts;

    msrv = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_netrb_server_t) * us->servers->nelts);
    if (msrv == NULL) {
        return NGX_ERROR;
    }

    n = 0;
    backup_count = 0;

    for (i = 0; i < (ngx_int_t)us->servers->nelts; i++) {
        if (server[i].down || server[i].backup) {
            continue;
        }

        bakv = ngx_http_upstream_netrb_topology_get_desc(((struct sockaddr_in *)server[i].addrs[0].sockaddr)->sin_addr.s_addr, nt);

        if (bakv == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                    "upstream rebalance %V %V server info not found",
                    upstream, &server[i].addrs[0].name);

            return NGX_ERROR;
        }

        msrv[n].idx = i;
        msrv[n].desc = bakv;

        if (do_assign) {
            ngx_http_upstream_netrb_part_t *part = &loc->part[0];

            for (m = 0; m < loc->count; m++) {
                if (ngx_http_upstream_netrb_desc_match(bakv, &part[m].match)) {
                    break;
                }
            }

            if (m == loc->count) {
                msrv[n].backup = 1;
            } else {
                msrv[n].group = m;
                group_weight[m] += server[i].weight;
            }
        } else if (serv->len != bakv->len || ngx_strncmp(serv->data, bakv->data, bakv->len) != 0)
        {
            msrv[n].backup = 1;
        }

        if (msrv[n].backup) {
            backup_count ++;
        }

        n ++;
    }

    if (n <= 1) {
        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                "upstream rebalance %V disabled bacause of little server "
                "n:%i", upstream, n); 

        goto quit;
    }

    if (do_assign) {
        for (i = 0; i < loc->count; i++) {
            if (group_weight[i] == 0) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                        "upstream rebalance %V failed because no server "
                        "is found with group %V for %V",
                        upstream, &loc->part[i].match, &loc->place);

                return NGX_ERROR;
            }
        }
    } else if (!backup_count || backup_count == n) {
        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                "upstream rebalance %V using backend servers %d/%i",
                upstream, backup_count, n);

        goto quit;
    }

    for (i = 0; i < n; i++) {
        if (msrv[i].backup) {
            server[msrv[i].idx].backup = 1;

            ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                    "upstream rebalance %V server %V weight=%i backup #"
                    "b:%V",
                    upstream, &server[msrv[i].idx].addrs[0].name,
                    server[msrv[i].idx].weight, msrv[i].desc);

            continue;
        }

        if (do_assign && loc->count != 1) {
            server[msrv[i].idx].weight = (loc->part[msrv[i].group].percent * 
                    server[msrv[i].idx].weight) / group_weight[msrv[i].group];
        }

        ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                "upstream rebalance %V server %V weight=%i #"
                "b:%V:%s",
                upstream, &server[msrv[i].idx].addrs[0].name,
                server[msrv[i].idx].weight, msrv[i].desc,
                do_assign ? (char *)loc->part[msrv[i].group].match.data :
                "-");
    }

quit:

    if (iscf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_netrb_topology_get_local(ngx_conf_t *cf, ngx_array_t **localp)
{
    u_char                            name[NGX_INET_ADDRSTRLEN];
    in_addr_t                         addr;
    ngx_array_t                      *local;
    struct ifaddrs                   *ifa;
    struct ifaddrs                   *ifa_head = NULL;
    ngx_http_upstream_netrb_addr_t   *ntaddr;

    local = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_netrb_addr_t));
    if (local == NULL) {
        return NGX_ERROR;
    }

    *localp = local;

    getifaddrs(&ifa_head);

    for (ifa = ifa_head; ifa != NULL; ifa = ifa->ifa_next) {
        switch (ifa->ifa_addr->sa_family) {
            case AF_INET:
                addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;

                if (addr == INADDR_ANY || addr == htonl(INADDR_LOOPBACK)) {
                    ngx_inet_ntop(AF_INET, &addr, name, NGX_INET_ADDRSTRLEN);
                    break;
                }

                ntaddr = ngx_array_push(local);
                if (ntaddr == NULL) {
                    return NGX_ERROR;
                }
                ntaddr->addr = addr;
                ntaddr->name.data = ngx_palloc(cf->pool, NGX_INET_ADDRSTRLEN);
                if (ntaddr->name.data == NULL) {
                    return NGX_ERROR;
                }
                ntaddr->name.len = ngx_inet_ntop(AF_INET, &addr, ntaddr->name.data, NGX_INET_ADDRSTRLEN);

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                        "upstream rebalance add local address %s:%V",
                        ifa->ifa_name, &ntaddr->name);

                break;
            default:
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                        "upstream rebalance ignore family %d on %s",
                        (int) ifa->ifa_addr->sa_family, ifa->ifa_name);
                break;
        }
    }

    if (ifa_head != NULL) {
        freeifaddrs(ifa_head);
    }

    if (local->nelts == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "upstream rebalance can not get local address");

        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_str_t *ngx_http_upstream_netrb_topology_get_desc(in_addr_t addr, ngx_http_upstream_netrb_topology_t *nt)
{
    size_t                                i;
    ngx_http_upstream_netrb_segment_t    *seg;

    seg = nt->segments.elts;

    for (i = 0; i < nt->segments.nelts; i++) {
        if ((addr & seg[i].mask) == seg[i].addr) {
            return &seg[i].desc;
        }
    }

    if (nt->default_value.name.len) {
        return &nt->default_value.desc;
    }

    return NULL;
}

static void *ngx_http_upstream_netrb_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_netrb_main_conf_t    *imcf;

    imcf = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_upstream_netrb_main_conf_t));
    if (imcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&imcf->topologies, cf->pool, 4, sizeof(ngx_http_upstream_netrb_topology_t)) != NGX_OK)
    {
        return NULL;
    }

    imcf->default_topology = NGX_CONF_UNSET;

    return imcf;
}

static void *ngx_http_upstream_netrb_create_srv_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_netrb_srv_conf_t));
}

static char *ngx_http_upstream_netrb_topology(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t                            *value;
    ngx_int_t                             rc;
    ngx_cidr_t                            cidr;
    ngx_http_upstream_netrb_segment_t    *seg;
    ngx_http_upstream_netrb_topology_t   *nt;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid number of arguments in \"net_topology\" directive");
        return NGX_CONF_ERROR;
    }

    nt = cf->ctx;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[0].data, (u_char *)"default") == 0) {
        goto set_default;
    }

    ngx_memzero(&cidr, sizeof(ngx_cidr_t));

    rc = ngx_ptocidr(&value[0], &cidr);
    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid parameter \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }
    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "low address bits of %V are meaningless", &value[0]);
    }

    if (cidr.u.in.mask == 0) {
        goto set_default;
    }

    seg = ngx_array_push(&nt->segments);
    if (seg == NULL) {
        return NGX_CONF_ERROR;
    }

    seg->mask = cidr.u.in.mask;
    seg->addr = cidr.u.in.addr;

    goto set_value;

set_default:
    seg = &nt->default_value;
    if (seg->name.len) {
        return "is duplicate";
    }

set_value:
    seg->name = value[0];
    seg->desc = value[1];

    return NGX_CONF_OK;
}

static char *ngx_http_upstream_netrb_topology_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                                 *rv;
    size_t                                i;
    ngx_str_t                            *value;
    ngx_conf_t                            save;
    ngx_http_upstream_netrb_topology_t   *nt;
    ngx_http_upstream_netrb_main_conf_t  *imcf = conf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, (u_char *)"off") == 0) {
        return "off is reserved, please choose another name";
    }

    nt = imcf->topologies.elts;

    for (i = 0; i < imcf->topologies.nelts; i++) {
        if (nt[i].name.len == value[1].len &&
                ngx_strncasecmp(nt[i].name.data, value[1].data, value[1].len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "duplicate %V \"%V\"", &cmd->name, &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, (u_char *)"default") != 0) {
            return NGX_CONF_ERROR;
        }

        if (imcf->default_topology != NGX_CONF_UNSET) {
            return "net_topology default duplicate";
        }

        imcf->default_topology = imcf->topologies.nelts;
    }

    nt = ngx_array_push(&imcf->topologies);
    if (nt == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(nt, sizeof(*nt));

    if (ngx_array_init(&nt->segments, cf->pool, 5, sizeof(ngx_http_upstream_netrb_segment_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    nt->name = value[1];

    save = *cf;
    cf->ctx = nt;
    cf->handler = ngx_http_upstream_netrb_topology;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static char *ngx_http_upstream_netrb_rebalance(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                                   *rv;
    size_t                                  m;
    ngx_str_t                              *value;
    ngx_http_upstream_netrb_srv_conf_t     *iscf = conf;
    ngx_http_upstream_netrb_topology_t     *nt;
    ngx_http_upstream_netrb_main_conf_t    *imcf;

    if (iscf->topology) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid parameter of \"%V\"", &value[0]);

        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[1].data, (u_char *)"off") == 0) {
        iscf->off = 1;
        return NGX_CONF_OK;
    }

    imcf = ngx_http_conf_get_module_main_conf(cf, ngx_current_module);

    nt = imcf->topologies.elts;

    for (m = 0; m < imcf->topologies.nelts; m++) {
        if (ngx_strcasecmp(value[1].data, nt[m].name.data) == 0) {
            break;
        }
    }

    if (m == imcf->topologies.nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "unknown net_topology \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    iscf->topology = &nt[m];

    if (!iscf->set) {
        rv = ngx_http_upstream_netrb_set_handler(cf, iscf);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;
}

static char *ngx_http_upstream_netrb_set_handler(ngx_conf_t *cf, ngx_http_upstream_netrb_srv_conf_t *iscf)
{
    ngx_http_upstream_srv_conf_t           *uscf;
    ngx_http_upstream_netrb_main_conf_t    *imcf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    iscf->original_init_upstream = uscf->peer.init_upstream
        ? uscf->peer.init_upstream
        : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_upstream_init_netrb;

    imcf = ngx_http_conf_get_module_main_conf(cf, ngx_current_module);
    iscf->conf = imcf;

    iscf->set = 1;

    return NGX_CONF_OK;
}

static char *ngx_http_upstream_netrb_assign(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                                   *rv;
    u_char                                 *p;
    size_t                                  i;
    ngx_int_t                               total, n, last;
    ngx_str_t                              *value;
    ngx_http_upstream_netrb_location_t     *loc, **ploc;
    ngx_http_upstream_netrb_srv_conf_t     *iscf = conf;

    value = cf->args->elts;

    if (iscf->locations == NULL) {
        iscf->locations = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_netrb_location_t *));
        if (iscf->locations == NULL) {
            return NGX_CONF_ERROR;
        }
    } else {
        ploc = iscf->locations->elts;
        for (i = 0; i < iscf->locations->nelts; i++) {
            if (ploc[i]->place.len == value[1].len && ngx_strcasecmp(ploc[i]->place.data, value[1].data) == 0)
            {
                return "duplicate place";
            }
        }
    }

    loc = ngx_palloc(cf->pool,
              sizeof(ngx_http_upstream_netrb_location_t) + sizeof(ngx_http_upstream_netrb_part_t) * (cf->args->nelts - 2));
    if (loc == NULL) {
        return NGX_CONF_ERROR;
    }

    ploc = ngx_array_push(iscf->locations);
    if (ploc == NULL) {
        return NGX_CONF_ERROR;
    }
    *ploc = loc;

    loc->place = value[1];
    loc->count = cf->args->nelts - 2;

    last = total = 0;

    for (i = 2; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            goto invalid;
        }

        last = i == cf->args->nelts - 1;

        p = (u_char *)ngx_strchr(value[i].data, '=');

        loc->part[i - 2].match = value[i];

        if (p != NULL) {
            *p = '\0';
            loc->part[i - 2].match.len = p - value[i].data;
        }

        if (last) {
            if (p == NULL || p[1] == '\0' || (p[1] == '*' && p[2] == '\0')) {
                if (total >= 10000) {
                    goto invalid;
                }

                loc->part[i - 2].percent = 10000 - total;
                total = 10000;

                continue;
            }
        } else if (p == NULL) {
            goto invalid;
        }

        if (value[i].data[value[i].len - 1] != '%') {
            goto invalid;
        }

        n = ngx_atofp(p + 1, value[i].len - (p - value[i].data) - 2, 2);
        if (n == NGX_ERROR || n == 0 || (total + n) > 10000) {
            goto invalid;
        }

        loc->part[i - 2].percent = n;
        total += n;
    }

    if (total != 10000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "upstream assign total percent is not 100%% (%i%%)", total / 100);

        return NGX_CONF_ERROR;
    }

    if (!iscf->set) {
        rv = ngx_http_upstream_netrb_set_handler(cf, iscf);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid percent value \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
}

static ngx_int_t ngx_http_upstream_netrb_desc_match(ngx_str_t *desc, ngx_str_t *short_desc)
{
    if (short_desc->len > desc->len) {
        return 0;
    }
    if (short_desc->len == 1 && short_desc->data[0] == '*') {
        return 1;
    }
    if (short_desc->len == desc->len) {
        return ngx_strncmp(short_desc->data, desc->data, desc->len) == 0;
    }
    if (short_desc->data[0] != '/' && desc->data[desc->len - short_desc->len - 1] != '/') {
        return 0;
    }
    if (ngx_strncmp(desc->data + desc->len - short_desc->len, short_desc->data, short_desc->len) != 0)
    {
        return 0;
    }
    return 1;
}

