
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RP_HTTP_V2_MODULE_H_INCLUDED_
#define _RP_HTTP_V2_MODULE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    size_t                          recv_buffer_size;
    u_char                         *recv_buffer;
} rp_http_v2_main_conf_t;


typedef struct {
    size_t                          pool_size;
    rp_uint_t                      concurrent_streams;
    rp_uint_t                      concurrent_pushes;
    rp_uint_t                      max_requests;
    size_t                          max_field_size;
    size_t                          max_header_size;
    size_t                          preread_size;
    rp_uint_t                      streams_index_mask;
    rp_msec_t                      recv_timeout;
    rp_msec_t                      idle_timeout;
} rp_http_v2_srv_conf_t;


typedef struct {
    size_t                          chunk_size;

    rp_flag_t                      push_preload;

    rp_flag_t                      push;
    rp_array_t                    *pushes;
} rp_http_v2_loc_conf_t;


extern rp_module_t  rp_http_v2_module;


#endif /* _RP_HTTP_V2_MODULE_H_INCLUDED_ */
