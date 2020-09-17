
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_SCRIPT_H_INCLUDED_
#define _RP_STREAM_SCRIPT_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    u_char                       *ip;
    u_char                       *pos;
    rp_stream_variable_value_t  *sp;

    rp_str_t                     buf;
    rp_str_t                     line;

    unsigned                      flushed:1;
    unsigned                      skip:1;

    rp_stream_session_t         *session;
} rp_stream_script_engine_t;


typedef struct {
    rp_conf_t                   *cf;
    rp_str_t                    *source;

    rp_array_t                 **flushes;
    rp_array_t                 **lengths;
    rp_array_t                 **values;

    rp_uint_t                    variables;
    rp_uint_t                    ncaptures;
    rp_uint_t                    size;

    void                         *main;

    unsigned                      complete_lengths:1;
    unsigned                      complete_values:1;
    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} rp_stream_script_compile_t;


typedef struct {
    rp_str_t                     value;
    rp_uint_t                   *flushes;
    void                         *lengths;
    void                         *values;

    union {
        size_t                    size;
    } u;
} rp_stream_complex_value_t;


typedef struct {
    rp_conf_t                   *cf;
    rp_str_t                    *value;
    rp_stream_complex_value_t   *complex_value;

    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} rp_stream_compile_complex_value_t;


typedef void (*rp_stream_script_code_pt) (rp_stream_script_engine_t *e);
typedef size_t (*rp_stream_script_len_code_pt) (rp_stream_script_engine_t *e);


typedef struct {
    rp_stream_script_code_pt     code;
    uintptr_t                     len;
} rp_stream_script_copy_code_t;


typedef struct {
    rp_stream_script_code_pt     code;
    uintptr_t                     index;
} rp_stream_script_var_code_t;


typedef struct {
    rp_stream_script_code_pt     code;
    uintptr_t                     n;
} rp_stream_script_copy_capture_code_t;


typedef struct {
    rp_stream_script_code_pt     code;
    uintptr_t                     conf_prefix;
} rp_stream_script_full_name_code_t;


void rp_stream_script_flush_complex_value(rp_stream_session_t *s,
    rp_stream_complex_value_t *val);
rp_int_t rp_stream_complex_value(rp_stream_session_t *s,
    rp_stream_complex_value_t *val, rp_str_t *value);
size_t rp_stream_complex_value_size(rp_stream_session_t *s,
    rp_stream_complex_value_t *val, size_t default_value);
rp_int_t rp_stream_compile_complex_value(
    rp_stream_compile_complex_value_t *ccv);
char *rp_stream_set_complex_value_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
char *rp_stream_set_complex_value_size_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


rp_uint_t rp_stream_script_variables_count(rp_str_t *value);
rp_int_t rp_stream_script_compile(rp_stream_script_compile_t *sc);
u_char *rp_stream_script_run(rp_stream_session_t *s, rp_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void rp_stream_script_flush_no_cacheable_variables(rp_stream_session_t *s,
    rp_array_t *indices);

void *rp_stream_script_add_code(rp_array_t *codes, size_t size, void *code);

size_t rp_stream_script_copy_len_code(rp_stream_script_engine_t *e);
void rp_stream_script_copy_code(rp_stream_script_engine_t *e);
size_t rp_stream_script_copy_var_len_code(rp_stream_script_engine_t *e);
void rp_stream_script_copy_var_code(rp_stream_script_engine_t *e);
size_t rp_stream_script_copy_capture_len_code(rp_stream_script_engine_t *e);
void rp_stream_script_copy_capture_code(rp_stream_script_engine_t *e);

#endif /* _RP_STREAM_SCRIPT_H_INCLUDED_ */
