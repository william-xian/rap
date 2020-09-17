
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_SSI_FILTER_H_INCLUDED_
#define _RP_HTTP_SSI_FILTER_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_SSI_MAX_PARAMS       16

#define RP_HTTP_SSI_COMMAND_LEN      32
#define RP_HTTP_SSI_PARAM_LEN        32
#define RP_HTTP_SSI_PARAMS_N         4


#define RP_HTTP_SSI_COND_IF          1
#define RP_HTTP_SSI_COND_ELSE        2


#define RP_HTTP_SSI_NO_ENCODING      0
#define RP_HTTP_SSI_URL_ENCODING     1
#define RP_HTTP_SSI_ENTITY_ENCODING  2


typedef struct {
    rp_hash_t                hash;
    rp_hash_keys_arrays_t    commands;
} rp_http_ssi_main_conf_t;


typedef struct {
    rp_buf_t                *buf;

    u_char                   *pos;
    u_char                   *copy_start;
    u_char                   *copy_end;

    rp_uint_t                key;
    rp_str_t                 command;
    rp_array_t               params;
    rp_table_elt_t          *param;
    rp_table_elt_t           params_array[RP_HTTP_SSI_PARAMS_N];

    rp_chain_t              *in;
    rp_chain_t              *out;
    rp_chain_t             **last_out;
    rp_chain_t              *busy;
    rp_chain_t              *free;

    rp_uint_t                state;
    rp_uint_t                saved_state;
    size_t                    saved;
    size_t                    looked;

    size_t                    value_len;

    rp_list_t               *variables;
    rp_array_t              *blocks;

#if (RP_PCRE)
    rp_uint_t                ncaptures;
    int                      *captures;
    u_char                   *captures_data;
#endif

    unsigned                  conditional:2;
    unsigned                  encoding:2;
    unsigned                  block:1;
    unsigned                  output:1;
    unsigned                  output_chosen:1;

    rp_http_request_t       *wait;
    void                     *value_buf;
    rp_str_t                 timefmt;
    rp_str_t                 errmsg;
} rp_http_ssi_ctx_t;


typedef rp_int_t (*rp_http_ssi_command_pt) (rp_http_request_t *r,
    rp_http_ssi_ctx_t *ctx, rp_str_t **);


typedef struct {
    rp_str_t                 name;
    rp_uint_t                index;

    unsigned                  mandatory:1;
    unsigned                  multiple:1;
} rp_http_ssi_param_t;


typedef struct {
    rp_str_t                 name;
    rp_http_ssi_command_pt   handler;
    rp_http_ssi_param_t     *params;

    unsigned                  conditional:2;
    unsigned                  block:1;
    unsigned                  flush:1;
} rp_http_ssi_command_t;


extern rp_module_t  rp_http_ssi_filter_module;


#endif /* _RP_HTTP_SSI_FILTER_H_INCLUDED_ */
