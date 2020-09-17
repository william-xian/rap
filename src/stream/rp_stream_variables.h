
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_VARIABLES_H_INCLUDED_
#define _RP_STREAM_VARIABLES_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef rp_variable_value_t  rp_stream_variable_value_t;

#define rp_stream_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct rp_stream_variable_s  rp_stream_variable_t;

typedef void (*rp_stream_set_variable_pt) (rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
typedef rp_int_t (*rp_stream_get_variable_pt) (rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);


#define RP_STREAM_VAR_CHANGEABLE   1
#define RP_STREAM_VAR_NOCACHEABLE  2
#define RP_STREAM_VAR_INDEXED      4
#define RP_STREAM_VAR_NOHASH       8
#define RP_STREAM_VAR_WEAK         16
#define RP_STREAM_VAR_PREFIX       32


struct rp_stream_variable_s {
    rp_str_t                     name;   /* must be first to build the hash */
    rp_stream_set_variable_pt    set_handler;
    rp_stream_get_variable_pt    get_handler;
    uintptr_t                     data;
    rp_uint_t                    flags;
    rp_uint_t                    index;
};

#define rp_stream_null_variable  { rp_null_string, NULL, NULL, 0, 0, 0 }


rp_stream_variable_t *rp_stream_add_variable(rp_conf_t *cf, rp_str_t *name,
    rp_uint_t flags);
rp_int_t rp_stream_get_variable_index(rp_conf_t *cf, rp_str_t *name);
rp_stream_variable_value_t *rp_stream_get_indexed_variable(
    rp_stream_session_t *s, rp_uint_t index);
rp_stream_variable_value_t *rp_stream_get_flushed_variable(
    rp_stream_session_t *s, rp_uint_t index);

rp_stream_variable_value_t *rp_stream_get_variable(rp_stream_session_t *s,
    rp_str_t *name, rp_uint_t key);


#if (RP_PCRE)

typedef struct {
    rp_uint_t                    capture;
    rp_int_t                     index;
} rp_stream_regex_variable_t;


typedef struct {
    rp_regex_t                  *regex;
    rp_uint_t                    ncaptures;
    rp_stream_regex_variable_t  *variables;
    rp_uint_t                    nvariables;
    rp_str_t                     name;
} rp_stream_regex_t;


typedef struct {
    rp_stream_regex_t           *regex;
    void                         *value;
} rp_stream_map_regex_t;


rp_stream_regex_t *rp_stream_regex_compile(rp_conf_t *cf,
    rp_regex_compile_t *rc);
rp_int_t rp_stream_regex_exec(rp_stream_session_t *s, rp_stream_regex_t *re,
    rp_str_t *str);

#endif


typedef struct {
    rp_hash_combined_t           hash;
#if (RP_PCRE)
    rp_stream_map_regex_t       *regex;
    rp_uint_t                    nregex;
#endif
} rp_stream_map_t;


void *rp_stream_map_find(rp_stream_session_t *s, rp_stream_map_t *map,
    rp_str_t *match);


rp_int_t rp_stream_variables_add_core_vars(rp_conf_t *cf);
rp_int_t rp_stream_variables_init_vars(rp_conf_t *cf);


extern rp_stream_variable_value_t  rp_stream_variable_null_value;
extern rp_stream_variable_value_t  rp_stream_variable_true_value;


#endif /* _RP_STREAM_VARIABLES_H_INCLUDED_ */
