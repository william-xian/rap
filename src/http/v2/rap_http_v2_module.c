
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_http_v2_module.h>


static rap_int_t rap_http_v2_add_variables(rap_conf_t *cf);

static rap_int_t rap_http_v2_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_v2_module_init(rap_cycle_t *cycle);

static void *rap_http_v2_create_main_conf(rap_conf_t *cf);
static char *rap_http_v2_init_main_conf(rap_conf_t *cf, void *conf);
static void *rap_http_v2_create_srv_conf(rap_conf_t *cf);
static char *rap_http_v2_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);
static void *rap_http_v2_create_loc_conf(rap_conf_t *cf);
static char *rap_http_v2_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);

static char *rap_http_v2_push(rap_conf_t *cf, rap_command_t *cmd, void *conf);

static char *rap_http_v2_recv_buffer_size(rap_conf_t *cf, void *post,
    void *data);
static char *rap_http_v2_pool_size(rap_conf_t *cf, void *post, void *data);
static char *rap_http_v2_preread_size(rap_conf_t *cf, void *post, void *data);
static char *rap_http_v2_streams_index_mask(rap_conf_t *cf, void *post,
    void *data);
static char *rap_http_v2_chunk_size(rap_conf_t *cf, void *post, void *data);
static char *rap_http_v2_spdy_deprecated(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_conf_post_t  rap_http_v2_recv_buffer_size_post =
    { rap_http_v2_recv_buffer_size };
static rap_conf_post_t  rap_http_v2_pool_size_post =
    { rap_http_v2_pool_size };
static rap_conf_post_t  rap_http_v2_preread_size_post =
    { rap_http_v2_preread_size };
static rap_conf_post_t  rap_http_v2_streams_index_mask_post =
    { rap_http_v2_streams_index_mask };
static rap_conf_post_t  rap_http_v2_chunk_size_post =
    { rap_http_v2_chunk_size };


static rap_command_t  rap_http_v2_commands[] = {

    { rap_string("http2_recv_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_v2_main_conf_t, recv_buffer_size),
      &rap_http_v2_recv_buffer_size_post },

    { rap_string("http2_pool_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, pool_size),
      &rap_http_v2_pool_size_post },

    { rap_string("http2_max_concurrent_streams"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, concurrent_streams),
      NULL },

    { rap_string("http2_max_concurrent_pushes"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, concurrent_pushes),
      NULL },

    { rap_string("http2_max_requests"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, max_requests),
      NULL },

    { rap_string("http2_max_field_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, max_field_size),
      NULL },

    { rap_string("http2_max_header_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, max_header_size),
      NULL },

    { rap_string("http2_body_preread_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, preread_size),
      &rap_http_v2_preread_size_post },

    { rap_string("http2_streams_index_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, streams_index_mask),
      &rap_http_v2_streams_index_mask_post },

    { rap_string("http2_recv_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, recv_timeout),
      NULL },

    { rap_string("http2_idle_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_SRV_CONF_OFFSET,
      offsetof(rap_http_v2_srv_conf_t, idle_timeout),
      NULL },

    { rap_string("http2_chunk_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_v2_loc_conf_t, chunk_size),
      &rap_http_v2_chunk_size_post },

    { rap_string("http2_push_preload"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_v2_loc_conf_t, push_preload),
      NULL },

    { rap_string("http2_push"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_v2_push,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_recv_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_pool_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_max_concurrent_streams"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_streams_index_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_recv_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_keepalive_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_headers_comp"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("spdy_chunk_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_v2_spdy_deprecated,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_v2_module_ctx = {
    rap_http_v2_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_v2_create_main_conf,          /* create main configuration */
    rap_http_v2_init_main_conf,            /* init main configuration */

    rap_http_v2_create_srv_conf,           /* create server configuration */
    rap_http_v2_merge_srv_conf,            /* merge server configuration */

    rap_http_v2_create_loc_conf,           /* create location configuration */
    rap_http_v2_merge_loc_conf             /* merge location configuration */
};


rap_module_t  rap_http_v2_module = {
    RAP_MODULE_V1,
    &rap_http_v2_module_ctx,               /* module context */
    rap_http_v2_commands,                  /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    rap_http_v2_module_init,               /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_variable_t  rap_http_v2_vars[] = {

    { rap_string("http2"), NULL,
      rap_http_v2_variable, 0, 0, 0 },

      rap_http_null_variable
};


static rap_int_t
rap_http_v2_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_v2_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{

    if (r->stream) {
#if (RAP_HTTP_SSL)

        if (r->connection->ssl) {
            v->len = sizeof("h2") - 1;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = (u_char *) "h2";

            return RAP_OK;
        }

#endif
        v->len = sizeof("h2c") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h2c";

        return RAP_OK;
    }

    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static rap_int_t
rap_http_v2_module_init(rap_cycle_t *cycle)
{
    return RAP_OK;
}


static void *
rap_http_v2_create_main_conf(rap_conf_t *cf)
{
    rap_http_v2_main_conf_t  *h2mcf;

    h2mcf = rap_pcalloc(cf->pool, sizeof(rap_http_v2_main_conf_t));
    if (h2mcf == NULL) {
        return NULL;
    }

    h2mcf->recv_buffer_size = RAP_CONF_UNSET_SIZE;

    return h2mcf;
}


static char *
rap_http_v2_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_http_v2_main_conf_t *h2mcf = conf;

    rap_conf_init_size_value(h2mcf->recv_buffer_size, 256 * 1024);

    return RAP_CONF_OK;
}


static void *
rap_http_v2_create_srv_conf(rap_conf_t *cf)
{
    rap_http_v2_srv_conf_t  *h2scf;

    h2scf = rap_pcalloc(cf->pool, sizeof(rap_http_v2_srv_conf_t));
    if (h2scf == NULL) {
        return NULL;
    }

    h2scf->pool_size = RAP_CONF_UNSET_SIZE;

    h2scf->concurrent_streams = RAP_CONF_UNSET_UINT;
    h2scf->concurrent_pushes = RAP_CONF_UNSET_UINT;
    h2scf->max_requests = RAP_CONF_UNSET_UINT;

    h2scf->max_field_size = RAP_CONF_UNSET_SIZE;
    h2scf->max_header_size = RAP_CONF_UNSET_SIZE;

    h2scf->preread_size = RAP_CONF_UNSET_SIZE;

    h2scf->streams_index_mask = RAP_CONF_UNSET_UINT;

    h2scf->recv_timeout = RAP_CONF_UNSET_MSEC;
    h2scf->idle_timeout = RAP_CONF_UNSET_MSEC;

    return h2scf;
}


static char *
rap_http_v2_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_v2_srv_conf_t *prev = parent;
    rap_http_v2_srv_conf_t *conf = child;

    rap_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);

    rap_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 128);
    rap_conf_merge_uint_value(conf->concurrent_pushes,
                              prev->concurrent_pushes, 10);
    rap_conf_merge_uint_value(conf->max_requests, prev->max_requests, 1000);

    rap_conf_merge_size_value(conf->max_field_size, prev->max_field_size,
                              4096);
    rap_conf_merge_size_value(conf->max_header_size, prev->max_header_size,
                              16384);

    rap_conf_merge_size_value(conf->preread_size, prev->preread_size, 65536);

    rap_conf_merge_uint_value(conf->streams_index_mask,
                              prev->streams_index_mask, 32 - 1);

    rap_conf_merge_msec_value(conf->recv_timeout,
                              prev->recv_timeout, 30000);
    rap_conf_merge_msec_value(conf->idle_timeout,
                              prev->idle_timeout, 180000);

    return RAP_CONF_OK;
}


static void *
rap_http_v2_create_loc_conf(rap_conf_t *cf)
{
    rap_http_v2_loc_conf_t  *h2lcf;

    h2lcf = rap_pcalloc(cf->pool, sizeof(rap_http_v2_loc_conf_t));
    if (h2lcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     h2lcf->pushes = NULL;
     */

    h2lcf->chunk_size = RAP_CONF_UNSET_SIZE;

    h2lcf->push_preload = RAP_CONF_UNSET;
    h2lcf->push = RAP_CONF_UNSET;

    return h2lcf;
}


static char *
rap_http_v2_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_v2_loc_conf_t *prev = parent;
    rap_http_v2_loc_conf_t *conf = child;

    rap_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 8 * 1024);

    rap_conf_merge_value(conf->push, prev->push, 1);

    if (conf->push && conf->pushes == NULL) {
        conf->pushes = prev->pushes;
    }

    rap_conf_merge_value(conf->push_preload, prev->push_preload, 0);

    return RAP_CONF_OK;
}


static char *
rap_http_v2_push(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_v2_loc_conf_t *h2lcf = conf;

    rap_str_t                         *value;
    rap_http_complex_value_t          *cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {

        if (h2lcf->pushes) {
            return "\"off\" parameter cannot be used with URI";
        }

        if (h2lcf->push == 0) {
            return "is duplicate";
        }

        h2lcf->push = 0;
        return RAP_CONF_OK;
    }

    if (h2lcf->push == 0) {
        return "URI cannot be used with \"off\" parameter";
    }

    h2lcf->push = 1;

    if (h2lcf->pushes == NULL) {
        h2lcf->pushes = rap_array_create(cf->pool, 1,
                                         sizeof(rap_http_complex_value_t));
        if (h2lcf->pushes == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    cv = rap_array_push(h2lcf->pushes);
    if (cv == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_v2_recv_buffer_size(rap_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp <= 2 * RAP_HTTP_V2_STATE_BUFFER_SIZE) {
        return "value is too small";
    }

    return RAP_CONF_OK;
}


static char *
rap_http_v2_pool_size(rap_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < RAP_MIN_POOL_SIZE) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           RAP_MIN_POOL_SIZE);

        return RAP_CONF_ERROR;
    }

    if (*sp % RAP_POOL_ALIGNMENT) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           RAP_POOL_ALIGNMENT);

        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_v2_preread_size(rap_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp > RAP_HTTP_V2_MAX_WINDOW) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the maximum body preread buffer size is %uz",
                           RAP_HTTP_V2_MAX_WINDOW);

        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_v2_streams_index_mask(rap_conf_t *cf, void *post, void *data)
{
    rap_uint_t *np = data;

    rap_uint_t  mask;

    mask = *np - 1;

    if (*np == 0 || (*np & mask)) {
        return "must be a power of two";
    }

    *np = mask;

    return RAP_CONF_OK;
}


static char *
rap_http_v2_chunk_size(rap_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the http2 chunk size cannot be zero");

        return RAP_CONF_ERROR;
    }

    if (*sp > RAP_HTTP_V2_MAX_FRAME_SIZE) {
        *sp = RAP_HTTP_V2_MAX_FRAME_SIZE;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_v2_spdy_deprecated(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "invalid directive \"%V\": rap_http_spdy_module "
                       "was superseded by rap_http_v2_module", &cmd->name);

    return RAP_CONF_OK;
}
