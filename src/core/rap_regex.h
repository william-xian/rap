
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_REGEX_H_INCLUDED_
#define _RAP_REGEX_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>

#include <pcre.h>


#define RAP_REGEX_NO_MATCHED  PCRE_ERROR_NOMATCH   /* -1 */

#define RAP_REGEX_CASELESS    PCRE_CASELESS


typedef struct {
    pcre        *code;
    pcre_extra  *extra;
} rap_regex_t;


typedef struct {
    rap_str_t     pattern;
    rap_pool_t   *pool;
    rap_int_t     options;

    rap_regex_t  *regex;
    int           captures;
    int           named_captures;
    int           name_size;
    u_char       *names;
    rap_str_t     err;
} rap_regex_compile_t;


typedef struct {
    rap_regex_t  *regex;
    u_char       *name;
} rap_regex_elt_t;


void rap_regex_init(void);
rap_int_t rap_regex_compile(rap_regex_compile_t *rc);

#define rap_regex_exec(re, s, captures, size)                                \
    pcre_exec(re->code, re->extra, (const char *) (s)->data, (s)->len, 0, 0, \
              captures, size)
#define rap_regex_exec_n      "pcre_exec()"

rap_int_t rap_regex_exec_array(rap_array_t *a, rap_str_t *s, rap_log_t *log);


#endif /* _RAP_REGEX_H_INCLUDED_ */
