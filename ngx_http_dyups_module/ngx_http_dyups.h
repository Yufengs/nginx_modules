/*
 * Copyright (C) 2010-2015 Alibaba Group Holding Limited
 */


#ifndef _NGX_HTTP_DYUPS_H_INCLUDE_
#define _NGX_HTTP_DYUPS_H_INCLUDE_


#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_int_t ngx_dyups_update_upstream(ngx_str_t *name, ngx_buf_t *buf, ngx_str_t *rv);
extern ngx_int_t ngx_dyups_delete_upstream(ngx_str_t *name, ngx_str_t *rv);

extern int ngx_http_upstream_health_check_update_handler(ngx_str_t *upstream_name);

#endif
