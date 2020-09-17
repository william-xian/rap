
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_SCRIPT_H_INCLUDED_
#define _RP_HTTP_SCRIPT_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    u_char                     *ip;
    u_char                     *pos;
    rp_http_variable_value_t  *sp;

    rp_str_t                   buf;
    rp_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    rp_int_t                   status;
    rp_http_request_t         *request;
} rp_http_script_engine_t;


typedef struct {
    rp_conf_t                 *cf;
    rp_str_t                  *source;

    rp_array_t               **flushes;
    rp_array_t               **lengths;
    rp_array_t               **values;

    rp_uint_t                  variables;
    rp_uint_t                  ncaptures;
    rp_uint_t                  captures_mask;
    rp_uint_t                  size;

    void                       *main;

    unsigned                    compile_args:1;
    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;
    unsigned                    args:1;
} rp_http_script_compile_t;


typedef struct {
    rp_str_t                   value;
    rp_uint_t                 *flushes;
    void                       *lengths;
    void                       *values;

    union {
        size_t                  size;
    } u;
} rp_http_complex_value_t;


typedef struct {
    rp_conf_t                 *cf;
    rp_str_t                  *value;
    rp_http_complex_value_t   *complex_value;

    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;
} rp_http_compile_complex_value_t;


typedef void (*rp_http_script_code_pt) (rp_http_script_engine_t *e);
typedef size_t (*rp_http_script_len_code_pt) (rp_http_script_engine_t *e);


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   len;
} rp_http_script_copy_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   index;
} rp_http_script_var_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    rp_http_set_variable_pt    handler;
    uintptr_t                   data;
} rp_http_script_var_handler_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   n;
} rp_http_script_copy_capture_code_t;


#if (RP_PCRE)

typedef struct {
    rp_http_script_code_pt     code;
    rp_http_regex_t           *regex;
    rp_array_t                *lengths;
    uintptr_t                   size;
    uintptr_t                   status;
    uintptr_t                   next;

    unsigned                    test:1;
    unsigned                    negative_test:1;
    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
    unsigned                    break_cycle:1;

    rp_str_t                   name;
} rp_http_script_regex_code_t;


typedef struct {
    rp_http_script_code_pt     code;

    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
} rp_http_script_regex_end_code_t;

#endif


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} rp_http_script_full_name_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   status;
    rp_http_complex_value_t    text;
} rp_http_script_return_code_t;


typedef enum {
    rp_http_script_file_plain = 0,
    rp_http_script_file_not_plain,
    rp_http_script_file_dir,
    rp_http_script_file_not_dir,
    rp_http_script_file_exists,
    rp_http_script_file_not_exists,
    rp_http_script_file_exec,
    rp_http_script_file_not_exec
} rp_http_script_file_op_e;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   op;
} rp_http_script_file_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} rp_http_script_if_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    rp_array_t                *lengths;
} rp_http_script_complex_value_code_t;


typedef struct {
    rp_http_script_code_pt     code;
    uintptr_t                   value;
    uintptr_t                   text_len;
    uintptr_t                   text_data;
} rp_http_script_value_code_t;


void rp_http_script_flush_complex_value(rp_http_request_t *r,
    rp_http_complex_value_t *val);
rp_int_t rp_http_complex_value(rp_http_request_t *r,
    rp_http_complex_value_t *val, rp_str_t *value);
size_t rp_http_complex_value_size(rp_http_request_t *r,
    rp_http_complex_value_t *val, size_t default_value);
rp_int_t rp_http_compile_complex_value(rp_http_compile_complex_value_t *ccv);
char *rp_http_set_complex_value_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
char *rp_http_set_complex_value_size_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


rp_int_t rp_http_test_predicates(rp_http_request_t *r,
    rp_array_t *predicates);
rp_int_t rp_http_test_required_predicates(rp_http_request_t *r,
    rp_array_t *predicates);
char *rp_http_set_predicate_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

rp_uint_t rp_http_script_variables_count(rp_str_t *value);
rp_int_t rp_http_script_compile(rp_http_script_compile_t *sc);
u_char *rp_http_script_run(rp_http_request_t *r, rp_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void rp_http_script_flush_no_cacheable_variables(rp_http_request_t *r,
    rp_array_t *indices);

void *rp_http_script_start_code(rp_pool_t *pool, rp_array_t **codes,
    size_t size);
void *rp_http_script_add_code(rp_array_t *codes, size_t size, void *code);

size_t rp_http_script_copy_len_code(rp_http_script_engine_t *e);
void rp_http_script_copy_code(rp_http_script_engine_t *e);
size_t rp_http_script_copy_var_len_code(rp_http_script_engine_t *e);
void rp_http_script_copy_var_code(rp_http_script_engine_t *e);
size_t rp_http_script_copy_capture_len_code(rp_http_script_engine_t *e);
void rp_http_script_copy_capture_code(rp_http_script_engine_t *e);
size_t rp_http_script_mark_args_code(rp_http_script_engine_t *e);
void rp_http_script_start_args_code(rp_http_script_engine_t *e);
#if (RP_PCRE)
void rp_http_script_regex_start_code(rp_http_script_engine_t *e);
void rp_http_script_regex_end_code(rp_http_script_engine_t *e);
#endif
void rp_http_script_return_code(rp_http_script_engine_t *e);
void rp_http_script_break_code(rp_http_script_engine_t *e);
void rp_http_script_if_code(rp_http_script_engine_t *e);
void rp_http_script_equal_code(rp_http_script_engine_t *e);
void rp_http_script_not_equal_code(rp_http_script_engine_t *e);
void rp_http_script_file_code(rp_http_script_engine_t *e);
void rp_http_script_complex_value_code(rp_http_script_engine_t *e);
void rp_http_script_value_code(rp_http_script_engine_t *e);
void rp_http_script_set_var_code(rp_http_script_engine_t *e);
void rp_http_script_var_set_handler_code(rp_http_script_engine_t *e);
void rp_http_script_var_code(rp_http_script_engine_t *e);
void rp_http_script_nop_code(rp_http_script_engine_t *e);


#endif /* _RP_HTTP_SCRIPT_H_INCLUDED_ */
