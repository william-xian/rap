
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_STREAM_SCRIPT_H_INCLUDED_
#define _RAP_STREAM_SCRIPT_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    u_char                       *ip;
    u_char                       *pos;
    rap_stream_variable_value_t  *sp;

    rap_str_t                     buf;
    rap_str_t                     line;

    unsigned                      flushed:1;
    unsigned                      skip:1;

    rap_stream_session_t         *session;
} rap_stream_script_engine_t;


typedef struct {
    rap_conf_t                   *cf;
    rap_str_t                    *source;

    rap_array_t                 **flushes;
    rap_array_t                 **lengths;
    rap_array_t                 **values;

    rap_uint_t                    variables;
    rap_uint_t                    ncaptures;
    rap_uint_t                    size;

    void                         *main;

    unsigned                      complete_lengths:1;
    unsigned                      complete_values:1;
    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} rap_stream_script_compile_t;


typedef struct {
    rap_str_t                     value;
    rap_uint_t                   *flushes;
    void                         *lengths;
    void                         *values;

    union {
        size_t                    size;
    } u;
} rap_stream_complex_value_t;


typedef struct {
    rap_conf_t                   *cf;
    rap_str_t                    *value;
    rap_stream_complex_value_t   *complex_value;

    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} rap_stream_compile_complex_value_t;


typedef void (*rap_stream_script_code_pt) (rap_stream_script_engine_t *e);
typedef size_t (*rap_stream_script_len_code_pt) (rap_stream_script_engine_t *e);


typedef struct {
    rap_stream_script_code_pt     code;
    uintptr_t                     len;
} rap_stream_script_copy_code_t;


typedef struct {
    rap_stream_script_code_pt     code;
    uintptr_t                     index;
} rap_stream_script_var_code_t;


typedef struct {
    rap_stream_script_code_pt     code;
    uintptr_t                     n;
} rap_stream_script_copy_capture_code_t;


typedef struct {
    rap_stream_script_code_pt     code;
    uintptr_t                     conf_prefix;
} rap_stream_script_full_name_code_t;


void rap_stream_script_flush_complex_value(rap_stream_session_t *s,
    rap_stream_complex_value_t *val);
rap_int_t rap_stream_complex_value(rap_stream_session_t *s,
    rap_stream_complex_value_t *val, rap_str_t *value);
size_t rap_stream_complex_value_size(rap_stream_session_t *s,
    rap_stream_complex_value_t *val, size_t default_value);
rap_int_t rap_stream_compile_complex_value(
    rap_stream_compile_complex_value_t *ccv);
char *rap_stream_set_complex_value_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
char *rap_stream_set_complex_value_size_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


rap_uint_t rap_stream_script_variables_count(rap_str_t *value);
rap_int_t rap_stream_script_compile(rap_stream_script_compile_t *sc);
u_char *rap_stream_script_run(rap_stream_session_t *s, rap_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void rap_stream_script_flush_no_cacheable_variables(rap_stream_session_t *s,
    rap_array_t *indices);

void *rap_stream_script_add_code(rap_array_t *codes, size_t size, void *code);

size_t rap_stream_script_copy_len_code(rap_stream_script_engine_t *e);
void rap_stream_script_copy_code(rap_stream_script_engine_t *e);
size_t rap_stream_script_copy_var_len_code(rap_stream_script_engine_t *e);
void rap_stream_script_copy_var_code(rap_stream_script_engine_t *e);
size_t rap_stream_script_copy_capture_len_code(rap_stream_script_engine_t *e);
void rap_stream_script_copy_capture_code(rap_stream_script_engine_t *e);

#endif /* _RAP_STREAM_SCRIPT_H_INCLUDED_ */
