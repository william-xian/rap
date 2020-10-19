
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_SCRIPT_H_INCLUDED_
#define _RAP_HTTP_SCRIPT_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    u_char                     *ip;
    u_char                     *pos;
    rap_http_variable_value_t  *sp;

    rap_str_t                   buf;
    rap_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    rap_int_t                   status;
    rap_http_request_t         *request;
} rap_http_script_engine_t;


typedef struct {
    rap_conf_t                 *cf;
    rap_str_t                  *source;

    rap_array_t               **flushes;
    rap_array_t               **lengths;
    rap_array_t               **values;

    rap_uint_t                  variables;
    rap_uint_t                  ncaptures;
    rap_uint_t                  captures_mask;
    rap_uint_t                  size;

    void                       *main;

    unsigned                    compile_args:1;
    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;
    unsigned                    args:1;
} rap_http_script_compile_t;


typedef struct {
    rap_str_t                   value;
    rap_uint_t                 *flushes;
    void                       *lengths;
    void                       *values;

    union {
        size_t                  size;
    } u;
} rap_http_complex_value_t;


typedef struct {
    rap_conf_t                 *cf;
    rap_str_t                  *value;
    rap_http_complex_value_t   *complex_value;

    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;
} rap_http_compile_complex_value_t;


typedef void (*rap_http_script_code_pt) (rap_http_script_engine_t *e);
typedef size_t (*rap_http_script_len_code_pt) (rap_http_script_engine_t *e);


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   len;
} rap_http_script_copy_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   index;
} rap_http_script_var_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    rap_http_set_variable_pt    handler;
    uintptr_t                   data;
} rap_http_script_var_handler_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   n;
} rap_http_script_copy_capture_code_t;


#if (RAP_PCRE)

typedef struct {
    rap_http_script_code_pt     code;
    rap_http_regex_t           *regex;
    rap_array_t                *lengths;
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

    rap_str_t                   name;
} rap_http_script_regex_code_t;


typedef struct {
    rap_http_script_code_pt     code;

    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
} rap_http_script_regex_end_code_t;

#endif


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} rap_http_script_full_name_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   status;
    rap_http_complex_value_t    text;
} rap_http_script_return_code_t;


typedef enum {
    rap_http_script_file_plain = 0,
    rap_http_script_file_not_plain,
    rap_http_script_file_dir,
    rap_http_script_file_not_dir,
    rap_http_script_file_exists,
    rap_http_script_file_not_exists,
    rap_http_script_file_exec,
    rap_http_script_file_not_exec
} rap_http_script_file_op_e;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   op;
} rap_http_script_file_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} rap_http_script_if_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    rap_array_t                *lengths;
} rap_http_script_complex_value_code_t;


typedef struct {
    rap_http_script_code_pt     code;
    uintptr_t                   value;
    uintptr_t                   text_len;
    uintptr_t                   text_data;
} rap_http_script_value_code_t;


void rap_http_script_flush_complex_value(rap_http_request_t *r,
    rap_http_complex_value_t *val);
rap_int_t rap_http_complex_value(rap_http_request_t *r,
    rap_http_complex_value_t *val, rap_str_t *value);
size_t rap_http_complex_value_size(rap_http_request_t *r,
    rap_http_complex_value_t *val, size_t default_value);
rap_int_t rap_http_compile_complex_value(rap_http_compile_complex_value_t *ccv);
char *rap_http_set_complex_value_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
char *rap_http_set_complex_value_size_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


rap_int_t rap_http_test_predicates(rap_http_request_t *r,
    rap_array_t *predicates);
rap_int_t rap_http_test_required_predicates(rap_http_request_t *r,
    rap_array_t *predicates);
char *rap_http_set_predicate_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

rap_uint_t rap_http_script_variables_count(rap_str_t *value);
rap_int_t rap_http_script_compile(rap_http_script_compile_t *sc);
u_char *rap_http_script_run(rap_http_request_t *r, rap_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void rap_http_script_flush_no_cacheable_variables(rap_http_request_t *r,
    rap_array_t *indices);

void *rap_http_script_start_code(rap_pool_t *pool, rap_array_t **codes,
    size_t size);
void *rap_http_script_add_code(rap_array_t *codes, size_t size, void *code);

size_t rap_http_script_copy_len_code(rap_http_script_engine_t *e);
void rap_http_script_copy_code(rap_http_script_engine_t *e);
size_t rap_http_script_copy_var_len_code(rap_http_script_engine_t *e);
void rap_http_script_copy_var_code(rap_http_script_engine_t *e);
size_t rap_http_script_copy_capture_len_code(rap_http_script_engine_t *e);
void rap_http_script_copy_capture_code(rap_http_script_engine_t *e);
size_t rap_http_script_mark_args_code(rap_http_script_engine_t *e);
void rap_http_script_start_args_code(rap_http_script_engine_t *e);
#if (RAP_PCRE)
void rap_http_script_regex_start_code(rap_http_script_engine_t *e);
void rap_http_script_regex_end_code(rap_http_script_engine_t *e);
#endif
void rap_http_script_return_code(rap_http_script_engine_t *e);
void rap_http_script_break_code(rap_http_script_engine_t *e);
void rap_http_script_if_code(rap_http_script_engine_t *e);
void rap_http_script_equal_code(rap_http_script_engine_t *e);
void rap_http_script_not_equal_code(rap_http_script_engine_t *e);
void rap_http_script_file_code(rap_http_script_engine_t *e);
void rap_http_script_complex_value_code(rap_http_script_engine_t *e);
void rap_http_script_value_code(rap_http_script_engine_t *e);
void rap_http_script_set_var_code(rap_http_script_engine_t *e);
void rap_http_script_var_set_handler_code(rap_http_script_engine_t *e);
void rap_http_script_var_code(rap_http_script_engine_t *e);
void rap_http_script_nop_code(rap_http_script_engine_t *e);


#endif /* _RAP_HTTP_SCRIPT_H_INCLUDED_ */
