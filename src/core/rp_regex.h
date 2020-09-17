
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_REGEX_H_INCLUDED_
#define _RP_REGEX_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>

#include <pcre.h>


#define RP_REGEX_NO_MATCHED  PCRE_ERROR_NOMATCH   /* -1 */

#define RP_REGEX_CASELESS    PCRE_CASELESS


typedef struct {
    pcre        *code;
    pcre_extra  *extra;
} rp_regex_t;


typedef struct {
    rp_str_t     pattern;
    rp_pool_t   *pool;
    rp_int_t     options;

    rp_regex_t  *regex;
    int           captures;
    int           named_captures;
    int           name_size;
    u_char       *names;
    rp_str_t     err;
} rp_regex_compile_t;


typedef struct {
    rp_regex_t  *regex;
    u_char       *name;
} rp_regex_elt_t;


void rp_regex_init(void);
rp_int_t rp_regex_compile(rp_regex_compile_t *rc);

#define rp_regex_exec(re, s, captures, size)                                \
    pcre_exec(re->code, re->extra, (const char *) (s)->data, (s)->len, 0, 0, \
              captures, size)
#define rp_regex_exec_n      "pcre_exec()"

rp_int_t rp_regex_exec_array(rp_array_t *a, rp_str_t *s, rp_log_t *log);


#endif /* _RP_REGEX_H_INCLUDED_ */
