
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_SSI_FILTER_H_INCLUDED_
#define _RAP_HTTP_SSI_FILTER_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_SSI_MAX_PARAMS       16

#define RAP_HTTP_SSI_COMMAND_LEN      32
#define RAP_HTTP_SSI_PARAM_LEN        32
#define RAP_HTTP_SSI_PARAMS_N         4


#define RAP_HTTP_SSI_COND_IF          1
#define RAP_HTTP_SSI_COND_ELSE        2


#define RAP_HTTP_SSI_NO_ENCODING      0
#define RAP_HTTP_SSI_URL_ENCODING     1
#define RAP_HTTP_SSI_ENTITY_ENCODING  2


typedef struct {
    rap_hash_t                hash;
    rap_hash_keys_arrays_t    commands;
} rap_http_ssi_main_conf_t;


typedef struct {
    rap_buf_t                *buf;

    u_char                   *pos;
    u_char                   *copy_start;
    u_char                   *copy_end;

    rap_uint_t                key;
    rap_str_t                 command;
    rap_array_t               params;
    rap_table_elt_t          *param;
    rap_table_elt_t           params_array[RAP_HTTP_SSI_PARAMS_N];

    rap_chain_t              *in;
    rap_chain_t              *out;
    rap_chain_t             **last_out;
    rap_chain_t              *busy;
    rap_chain_t              *free;

    rap_uint_t                state;
    rap_uint_t                saved_state;
    size_t                    saved;
    size_t                    looked;

    size_t                    value_len;

    rap_list_t               *variables;
    rap_array_t              *blocks;

#if (RAP_PCRE)
    rap_uint_t                ncaptures;
    int                      *captures;
    u_char                   *captures_data;
#endif

    unsigned                  conditional:2;
    unsigned                  encoding:2;
    unsigned                  block:1;
    unsigned                  output:1;
    unsigned                  output_chosen:1;

    rap_http_request_t       *wait;
    void                     *value_buf;
    rap_str_t                 timefmt;
    rap_str_t                 errmsg;
} rap_http_ssi_ctx_t;


typedef rap_int_t (*rap_http_ssi_command_pt) (rap_http_request_t *r,
    rap_http_ssi_ctx_t *ctx, rap_str_t **);


typedef struct {
    rap_str_t                 name;
    rap_uint_t                index;

    unsigned                  mandatory:1;
    unsigned                  multiple:1;
} rap_http_ssi_param_t;


typedef struct {
    rap_str_t                 name;
    rap_http_ssi_command_pt   handler;
    rap_http_ssi_param_t     *params;

    unsigned                  conditional:2;
    unsigned                  block:1;
    unsigned                  flush:1;
} rap_http_ssi_command_t;


extern rap_module_t  rap_http_ssi_filter_module;


#endif /* _RAP_HTTP_SSI_FILTER_H_INCLUDED_ */
