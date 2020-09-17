
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_VARIABLES_H_INCLUDED_
#define _RP_HTTP_VARIABLES_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef rp_variable_value_t  rp_http_variable_value_t;

#define rp_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct rp_http_variable_s  rp_http_variable_t;

typedef void (*rp_http_set_variable_pt) (rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
typedef rp_int_t (*rp_http_get_variable_pt) (rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);


#define RP_HTTP_VAR_CHANGEABLE   1
#define RP_HTTP_VAR_NOCACHEABLE  2
#define RP_HTTP_VAR_INDEXED      4
#define RP_HTTP_VAR_NOHASH       8
#define RP_HTTP_VAR_WEAK         16
#define RP_HTTP_VAR_PREFIX       32


struct rp_http_variable_s {
    rp_str_t                     name;   /* must be first to build the hash */
    rp_http_set_variable_pt      set_handler;
    rp_http_get_variable_pt      get_handler;
    uintptr_t                     data;
    rp_uint_t                    flags;
    rp_uint_t                    index;
};

#define rp_http_null_variable  { rp_null_string, NULL, NULL, 0, 0, 0 }


rp_http_variable_t *rp_http_add_variable(rp_conf_t *cf, rp_str_t *name,
    rp_uint_t flags);
rp_int_t rp_http_get_variable_index(rp_conf_t *cf, rp_str_t *name);
rp_http_variable_value_t *rp_http_get_indexed_variable(rp_http_request_t *r,
    rp_uint_t index);
rp_http_variable_value_t *rp_http_get_flushed_variable(rp_http_request_t *r,
    rp_uint_t index);

rp_http_variable_value_t *rp_http_get_variable(rp_http_request_t *r,
    rp_str_t *name, rp_uint_t key);

rp_int_t rp_http_variable_unknown_header(rp_http_variable_value_t *v,
    rp_str_t *var, rp_list_part_t *part, size_t prefix);


#if (RP_PCRE)

typedef struct {
    rp_uint_t                    capture;
    rp_int_t                     index;
} rp_http_regex_variable_t;


typedef struct {
    rp_regex_t                  *regex;
    rp_uint_t                    ncaptures;
    rp_http_regex_variable_t    *variables;
    rp_uint_t                    nvariables;
    rp_str_t                     name;
} rp_http_regex_t;


typedef struct {
    rp_http_regex_t             *regex;
    void                         *value;
} rp_http_map_regex_t;


rp_http_regex_t *rp_http_regex_compile(rp_conf_t *cf,
    rp_regex_compile_t *rc);
rp_int_t rp_http_regex_exec(rp_http_request_t *r, rp_http_regex_t *re,
    rp_str_t *s);

#endif


typedef struct {
    rp_hash_combined_t           hash;
#if (RP_PCRE)
    rp_http_map_regex_t         *regex;
    rp_uint_t                    nregex;
#endif
} rp_http_map_t;


void *rp_http_map_find(rp_http_request_t *r, rp_http_map_t *map,
    rp_str_t *match);


rp_int_t rp_http_variables_add_core_vars(rp_conf_t *cf);
rp_int_t rp_http_variables_init_vars(rp_conf_t *cf);


extern rp_http_variable_value_t  rp_http_variable_null_value;
extern rp_http_variable_value_t  rp_http_variable_true_value;


#endif /* _RP_HTTP_VARIABLES_H_INCLUDED_ */
