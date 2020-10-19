
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    uint32_t                      percent;
    rap_stream_variable_value_t   value;
} rap_stream_split_clients_part_t;


typedef struct {
    rap_stream_complex_value_t    value;
    rap_array_t                   parts;
} rap_stream_split_clients_ctx_t;


static char *rap_conf_split_clients_block(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_split_clients(rap_conf_t *cf, rap_command_t *dummy,
    void *conf);

static rap_command_t  rap_stream_split_clients_commands[] = {

    { rap_string("split_clients"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE2,
      rap_conf_split_clients_block,
      RAP_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_split_clients_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rap_module_t  rap_stream_split_clients_module = {
    RAP_MODULE_V1,
    &rap_stream_split_clients_module_ctx,  /* module context */
    rap_stream_split_clients_commands,     /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_stream_split_clients_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_stream_split_clients_ctx_t *ctx =
                                       (rap_stream_split_clients_ctx_t *) data;

    uint32_t                          hash;
    rap_str_t                         val;
    rap_uint_t                        i;
    rap_stream_split_clients_part_t  *part;

    *v = rap_stream_variable_null_value;

    if (rap_stream_complex_value(s, &ctx->value, &val) != RAP_OK) {
        return RAP_OK;
    }

    hash = rap_murmur_hash2(val.data, val.len);

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        rap_log_debug2(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream split: %uD %uD", hash, part[i].percent);

        if (hash < part[i].percent || part[i].percent == 0) {
            *v = part[i].value;
            return RAP_OK;
        }
    }

    return RAP_OK;
}


static char *
rap_conf_split_clients_block(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char                                *rv;
    uint32_t                             sum, last;
    rap_str_t                           *value, name;
    rap_uint_t                           i;
    rap_conf_t                           save;
    rap_stream_variable_t               *var;
    rap_stream_split_clients_ctx_t      *ctx;
    rap_stream_split_clients_part_t     *part;
    rap_stream_compile_complex_value_t   ccv;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_stream_split_clients_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->value;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RAP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = rap_stream_add_variable(cf, &name, RAP_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return RAP_CONF_ERROR;
    }

    var->get_handler = rap_stream_split_clients_variable;
    var->data = (uintptr_t) ctx;

    if (rap_array_init(&ctx->parts, cf->pool, 2,
                       sizeof(rap_stream_split_clients_part_t))
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = rap_stream_split_clients;
    cf->handler_conf = conf;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    sum = 0;
    last = 0;
    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {
        sum = part[i].percent ? sum + part[i].percent : 10000;
        if (sum > 10000) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "percent total is greater than 100%%");
            return RAP_CONF_ERROR;
        }

        if (part[i].percent) {
            last += part[i].percent * (uint64_t) 0xffffffff / 10000;
            part[i].percent = last;
        }
    }

    return rv;
}


static char *
rap_stream_split_clients(rap_conf_t *cf, rap_command_t *dummy, void *conf)
{
    rap_int_t                         n;
    rap_str_t                        *value;
    rap_stream_split_clients_ctx_t   *ctx;
    rap_stream_split_clients_part_t  *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    part = rap_array_push(&ctx->parts);
    if (part == NULL) {
        return RAP_CONF_ERROR;
    }

    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->percent = 0;

    } else {
        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        n = rap_atofp(value[0].data, value[0].len - 1, 2);
        if (n == RAP_ERROR || n == 0) {
            goto invalid;
        }

        part->percent = (uint32_t) n;
    }

    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid percent value \"%V\"", &value[0]);
    return RAP_CONF_ERROR;
}
