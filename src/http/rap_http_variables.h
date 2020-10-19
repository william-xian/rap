
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_VARIABLES_H_INCLUDED_
#define _RAP_HTTP_VARIABLES_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef rap_variable_value_t  rap_http_variable_value_t;

#define rap_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct rap_http_variable_s  rap_http_variable_t;

typedef void (*rap_http_set_variable_pt) (rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
typedef rap_int_t (*rap_http_get_variable_pt) (rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);


#define RAP_HTTP_VAR_CHANGEABLE   1
#define RAP_HTTP_VAR_NOCACHEABLE  2
#define RAP_HTTP_VAR_INDEXED      4
#define RAP_HTTP_VAR_NOHASH       8
#define RAP_HTTP_VAR_WEAK         16
#define RAP_HTTP_VAR_PREFIX       32


struct rap_http_variable_s {
    rap_str_t                     name;   /* must be first to build the hash */
    rap_http_set_variable_pt      set_handler;
    rap_http_get_variable_pt      get_handler;
    uintptr_t                     data;
    rap_uint_t                    flags;
    rap_uint_t                    index;
};

#define rap_http_null_variable  { rap_null_string, NULL, NULL, 0, 0, 0 }


rap_http_variable_t *rap_http_add_variable(rap_conf_t *cf, rap_str_t *name,
    rap_uint_t flags);
rap_int_t rap_http_get_variable_index(rap_conf_t *cf, rap_str_t *name);
rap_http_variable_value_t *rap_http_get_indexed_variable(rap_http_request_t *r,
    rap_uint_t index);
rap_http_variable_value_t *rap_http_get_flushed_variable(rap_http_request_t *r,
    rap_uint_t index);

rap_http_variable_value_t *rap_http_get_variable(rap_http_request_t *r,
    rap_str_t *name, rap_uint_t key);

rap_int_t rap_http_variable_unknown_header(rap_http_variable_value_t *v,
    rap_str_t *var, rap_list_part_t *part, size_t prefix);


#if (RAP_PCRE)

typedef struct {
    rap_uint_t                    capture;
    rap_int_t                     index;
} rap_http_regex_variable_t;


typedef struct {
    rap_regex_t                  *regex;
    rap_uint_t                    ncaptures;
    rap_http_regex_variable_t    *variables;
    rap_uint_t                    nvariables;
    rap_str_t                     name;
} rap_http_regex_t;


typedef struct {
    rap_http_regex_t             *regex;
    void                         *value;
} rap_http_map_regex_t;


rap_http_regex_t *rap_http_regex_compile(rap_conf_t *cf,
    rap_regex_compile_t *rc);
rap_int_t rap_http_regex_exec(rap_http_request_t *r, rap_http_regex_t *re,
    rap_str_t *s);

#endif


typedef struct {
    rap_hash_combined_t           hash;
#if (RAP_PCRE)
    rap_http_map_regex_t         *regex;
    rap_uint_t                    nregex;
#endif
} rap_http_map_t;


void *rap_http_map_find(rap_http_request_t *r, rap_http_map_t *map,
    rap_str_t *match);


rap_int_t rap_http_variables_add_core_vars(rap_conf_t *cf);
rap_int_t rap_http_variables_init_vars(rap_conf_t *cf);


extern rap_http_variable_value_t  rap_http_variable_null_value;
extern rap_http_variable_value_t  rap_http_variable_true_value;


#endif /* _RAP_HTTP_VARIABLES_H_INCLUDED_ */
