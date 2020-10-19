
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RAP_HTTP_V2_MODULE_H_INCLUDED_
#define _RAP_HTTP_V2_MODULE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    size_t                          recv_buffer_size;
    u_char                         *recv_buffer;
} rap_http_v2_main_conf_t;


typedef struct {
    size_t                          pool_size;
    rap_uint_t                      concurrent_streams;
    rap_uint_t                      concurrent_pushes;
    rap_uint_t                      max_requests;
    size_t                          max_field_size;
    size_t                          max_header_size;
    size_t                          preread_size;
    rap_uint_t                      streams_index_mask;
    rap_msec_t                      recv_timeout;
    rap_msec_t                      idle_timeout;
} rap_http_v2_srv_conf_t;


typedef struct {
    size_t                          chunk_size;

    rap_flag_t                      push_preload;

    rap_flag_t                      push;
    rap_array_t                    *pushes;
} rap_http_v2_loc_conf_t;


extern rap_module_t  rap_http_v2_module;


#endif /* _RAP_HTTP_V2_MODULE_H_INCLUDED_ */
