
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    uint32_t                      percent;
    rp_stream_variable_value_t   value;
} rp_stream_split_clients_part_t;


typedef struct {
    rp_stream_complex_value_t    value;
    rp_array_t                   parts;
} rp_stream_split_clients_ctx_t;


static char *rp_conf_split_clients_block(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_split_clients(rp_conf_t *cf, rp_command_t *dummy,
    void *conf);

static rp_command_t  rp_stream_split_clients_commands[] = {

    { rp_string("split_clients"),
      RP_STREAM_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE2,
      rp_conf_split_clients_block,
      RP_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_split_clients_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_split_clients_module = {
    RP_MODULE_V1,
    &rp_stream_split_clients_module_ctx,  /* module context */
    rp_stream_split_clients_commands,     /* module directives */
    RP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_stream_split_clients_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_stream_split_clients_ctx_t *ctx =
                                       (rp_stream_split_clients_ctx_t *) data;

    uint32_t                          hash;
    rp_str_t                         val;
    rp_uint_t                        i;
    rp_stream_split_clients_part_t  *part;

    *v = rp_stream_variable_null_value;

    if (rp_stream_complex_value(s, &ctx->value, &val) != RP_OK) {
        return RP_OK;
    }

    hash = rp_murmur_hash2(val.data, val.len);

    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {

        rp_log_debug2(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream split: %uD %uD", hash, part[i].percent);

        if (hash < part[i].percent || part[i].percent == 0) {
            *v = part[i].value;
            return RP_OK;
        }
    }

    return RP_OK;
}


static char *
rp_conf_split_clients_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                                *rv;
    uint32_t                             sum, last;
    rp_str_t                           *value, name;
    rp_uint_t                           i;
    rp_conf_t                           save;
    rp_stream_variable_t               *var;
    rp_stream_split_clients_ctx_t      *ctx;
    rp_stream_split_clients_part_t     *part;
    rp_stream_compile_complex_value_t   ccv;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_stream_split_clients_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->value;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = rp_stream_add_variable(cf, &name, RP_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return RP_CONF_ERROR;
    }

    var->get_handler = rp_stream_split_clients_variable;
    var->data = (uintptr_t) ctx;

    if (rp_array_init(&ctx->parts, cf->pool, 2,
                       sizeof(rp_stream_split_clients_part_t))
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->handler = rp_stream_split_clients;
    cf->handler_conf = conf;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RP_CONF_OK) {
        return rv;
    }

    sum = 0;
    last = 0;
    part = ctx->parts.elts;

    for (i = 0; i < ctx->parts.nelts; i++) {
        sum = part[i].percent ? sum + part[i].percent : 10000;
        if (sum > 10000) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "percent total is greater than 100%%");
            return RP_CONF_ERROR;
        }

        if (part[i].percent) {
            last += part[i].percent * (uint64_t) 0xffffffff / 10000;
            part[i].percent = last;
        }
    }

    return rv;
}


static char *
rp_stream_split_clients(rp_conf_t *cf, rp_command_t *dummy, void *conf)
{
    rp_int_t                         n;
    rp_str_t                        *value;
    rp_stream_split_clients_ctx_t   *ctx;
    rp_stream_split_clients_part_t  *part;

    ctx = cf->ctx;
    value = cf->args->elts;

    part = rp_array_push(&ctx->parts);
    if (part == NULL) {
        return RP_CONF_ERROR;
    }

    if (value[0].len == 1 && value[0].data[0] == '*') {
        part->percent = 0;

    } else {
        if (value[0].len == 0 || value[0].data[value[0].len - 1] != '%') {
            goto invalid;
        }

        n = rp_atofp(value[0].data, value[0].len - 1, 2);
        if (n == RP_ERROR || n == 0) {
            goto invalid;
        }

        part->percent = (uint32_t) n;
    }

    part->value.len = value[1].len;
    part->value.valid = 1;
    part->value.no_cacheable = 0;
    part->value.not_found = 0;
    part->value.data = value[1].data;

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid percent value \"%V\"", &value[0]);
    return RP_CONF_ERROR;
}
