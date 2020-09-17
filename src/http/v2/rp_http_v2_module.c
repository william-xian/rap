
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_http_v2_module.h>


static rp_int_t rp_http_v2_add_variables(rp_conf_t *cf);

static rp_int_t rp_http_v2_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_v2_module_init(rp_cycle_t *cycle);

static void *rp_http_v2_create_main_conf(rp_conf_t *cf);
static char *rp_http_v2_init_main_conf(rp_conf_t *cf, void *conf);
static void *rp_http_v2_create_srv_conf(rp_conf_t *cf);
static char *rp_http_v2_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static void *rp_http_v2_create_loc_conf(rp_conf_t *cf);
static char *rp_http_v2_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);

static char *rp_http_v2_push(rp_conf_t *cf, rp_command_t *cmd, void *conf);

static char *rp_http_v2_recv_buffer_size(rp_conf_t *cf, void *post,
    void *data);
static char *rp_http_v2_pool_size(rp_conf_t *cf, void *post, void *data);
static char *rp_http_v2_preread_size(rp_conf_t *cf, void *post, void *data);
static char *rp_http_v2_streams_index_mask(rp_conf_t *cf, void *post,
    void *data);
static char *rp_http_v2_chunk_size(rp_conf_t *cf, void *post, void *data);
static char *rp_http_v2_spdy_deprecated(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_conf_post_t  rp_http_v2_recv_buffer_size_post =
    { rp_http_v2_recv_buffer_size };
static rp_conf_post_t  rp_http_v2_pool_size_post =
    { rp_http_v2_pool_size };
static rp_conf_post_t  rp_http_v2_preread_size_post =
    { rp_http_v2_preread_size };
static rp_conf_post_t  rp_http_v2_streams_index_mask_post =
    { rp_http_v2_streams_index_mask };
static rp_conf_post_t  rp_http_v2_chunk_size_post =
    { rp_http_v2_chunk_size };


static rp_command_t  rp_http_v2_commands[] = {

    { rp_string("http2_recv_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_v2_main_conf_t, recv_buffer_size),
      &rp_http_v2_recv_buffer_size_post },

    { rp_string("http2_pool_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, pool_size),
      &rp_http_v2_pool_size_post },

    { rp_string("http2_max_concurrent_streams"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, concurrent_streams),
      NULL },

    { rp_string("http2_max_concurrent_pushes"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, concurrent_pushes),
      NULL },

    { rp_string("http2_max_requests"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, max_requests),
      NULL },

    { rp_string("http2_max_field_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, max_field_size),
      NULL },

    { rp_string("http2_max_header_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, max_header_size),
      NULL },

    { rp_string("http2_body_preread_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, preread_size),
      &rp_http_v2_preread_size_post },

    { rp_string("http2_streams_index_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, streams_index_mask),
      &rp_http_v2_streams_index_mask_post },

    { rp_string("http2_recv_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, recv_timeout),
      NULL },

    { rp_string("http2_idle_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_SRV_CONF_OFFSET,
      offsetof(rp_http_v2_srv_conf_t, idle_timeout),
      NULL },

    { rp_string("http2_chunk_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_v2_loc_conf_t, chunk_size),
      &rp_http_v2_chunk_size_post },

    { rp_string("http2_push_preload"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_v2_loc_conf_t, push_preload),
      NULL },

    { rp_string("http2_push"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_v2_push,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_recv_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_pool_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_max_concurrent_streams"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_streams_index_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_recv_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_keepalive_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_headers_comp"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("spdy_chunk_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_v2_spdy_deprecated,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_v2_module_ctx = {
    rp_http_v2_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_v2_create_main_conf,          /* create main configuration */
    rp_http_v2_init_main_conf,            /* init main configuration */

    rp_http_v2_create_srv_conf,           /* create server configuration */
    rp_http_v2_merge_srv_conf,            /* merge server configuration */

    rp_http_v2_create_loc_conf,           /* create location configuration */
    rp_http_v2_merge_loc_conf             /* merge location configuration */
};


rp_module_t  rp_http_v2_module = {
    RP_MODULE_V1,
    &rp_http_v2_module_ctx,               /* module context */
    rp_http_v2_commands,                  /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    rp_http_v2_module_init,               /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_variable_t  rp_http_v2_vars[] = {

    { rp_string("http2"), NULL,
      rp_http_v2_variable, 0, 0, 0 },

      rp_http_null_variable
};


static rp_int_t
rp_http_v2_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_v2_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_v2_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{

    if (r->stream) {
#if (RP_HTTP_SSL)

        if (r->connection->ssl) {
            v->len = sizeof("h2") - 1;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = (u_char *) "h2";

            return RP_OK;
        }

#endif
        v->len = sizeof("h2c") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h2c";

        return RP_OK;
    }

    *v = rp_http_variable_null_value;

    return RP_OK;
}


static rp_int_t
rp_http_v2_module_init(rp_cycle_t *cycle)
{
    return RP_OK;
}


static void *
rp_http_v2_create_main_conf(rp_conf_t *cf)
{
    rp_http_v2_main_conf_t  *h2mcf;

    h2mcf = rp_pcalloc(cf->pool, sizeof(rp_http_v2_main_conf_t));
    if (h2mcf == NULL) {
        return NULL;
    }

    h2mcf->recv_buffer_size = RP_CONF_UNSET_SIZE;

    return h2mcf;
}


static char *
rp_http_v2_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_http_v2_main_conf_t *h2mcf = conf;

    rp_conf_init_size_value(h2mcf->recv_buffer_size, 256 * 1024);

    return RP_CONF_OK;
}


static void *
rp_http_v2_create_srv_conf(rp_conf_t *cf)
{
    rp_http_v2_srv_conf_t  *h2scf;

    h2scf = rp_pcalloc(cf->pool, sizeof(rp_http_v2_srv_conf_t));
    if (h2scf == NULL) {
        return NULL;
    }

    h2scf->pool_size = RP_CONF_UNSET_SIZE;

    h2scf->concurrent_streams = RP_CONF_UNSET_UINT;
    h2scf->concurrent_pushes = RP_CONF_UNSET_UINT;
    h2scf->max_requests = RP_CONF_UNSET_UINT;

    h2scf->max_field_size = RP_CONF_UNSET_SIZE;
    h2scf->max_header_size = RP_CONF_UNSET_SIZE;

    h2scf->preread_size = RP_CONF_UNSET_SIZE;

    h2scf->streams_index_mask = RP_CONF_UNSET_UINT;

    h2scf->recv_timeout = RP_CONF_UNSET_MSEC;
    h2scf->idle_timeout = RP_CONF_UNSET_MSEC;

    return h2scf;
}


static char *
rp_http_v2_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_v2_srv_conf_t *prev = parent;
    rp_http_v2_srv_conf_t *conf = child;

    rp_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);

    rp_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 128);
    rp_conf_merge_uint_value(conf->concurrent_pushes,
                              prev->concurrent_pushes, 10);
    rp_conf_merge_uint_value(conf->max_requests, prev->max_requests, 1000);

    rp_conf_merge_size_value(conf->max_field_size, prev->max_field_size,
                              4096);
    rp_conf_merge_size_value(conf->max_header_size, prev->max_header_size,
                              16384);

    rp_conf_merge_size_value(conf->preread_size, prev->preread_size, 65536);

    rp_conf_merge_uint_value(conf->streams_index_mask,
                              prev->streams_index_mask, 32 - 1);

    rp_conf_merge_msec_value(conf->recv_timeout,
                              prev->recv_timeout, 30000);
    rp_conf_merge_msec_value(conf->idle_timeout,
                              prev->idle_timeout, 180000);

    return RP_CONF_OK;
}


static void *
rp_http_v2_create_loc_conf(rp_conf_t *cf)
{
    rp_http_v2_loc_conf_t  *h2lcf;

    h2lcf = rp_pcalloc(cf->pool, sizeof(rp_http_v2_loc_conf_t));
    if (h2lcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     h2lcf->pushes = NULL;
     */

    h2lcf->chunk_size = RP_CONF_UNSET_SIZE;

    h2lcf->push_preload = RP_CONF_UNSET;
    h2lcf->push = RP_CONF_UNSET;

    return h2lcf;
}


static char *
rp_http_v2_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_v2_loc_conf_t *prev = parent;
    rp_http_v2_loc_conf_t *conf = child;

    rp_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 8 * 1024);

    rp_conf_merge_value(conf->push, prev->push, 1);

    if (conf->push && conf->pushes == NULL) {
        conf->pushes = prev->pushes;
    }

    rp_conf_merge_value(conf->push_preload, prev->push_preload, 0);

    return RP_CONF_OK;
}


static char *
rp_http_v2_push(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_v2_loc_conf_t *h2lcf = conf;

    rp_str_t                         *value;
    rp_http_complex_value_t          *cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {

        if (h2lcf->pushes) {
            return "\"off\" parameter cannot be used with URI";
        }

        if (h2lcf->push == 0) {
            return "is duplicate";
        }

        h2lcf->push = 0;
        return RP_CONF_OK;
    }

    if (h2lcf->push == 0) {
        return "URI cannot be used with \"off\" parameter";
    }

    h2lcf->push = 1;

    if (h2lcf->pushes == NULL) {
        h2lcf->pushes = rp_array_create(cf->pool, 1,
                                         sizeof(rp_http_complex_value_t));
        if (h2lcf->pushes == NULL) {
            return RP_CONF_ERROR;
        }
    }

    cv = rp_array_push(h2lcf->pushes);
    if (cv == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_v2_recv_buffer_size(rp_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp <= 2 * RP_HTTP_V2_STATE_BUFFER_SIZE) {
        return "value is too small";
    }

    return RP_CONF_OK;
}


static char *
rp_http_v2_pool_size(rp_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < RP_MIN_POOL_SIZE) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           RP_MIN_POOL_SIZE);

        return RP_CONF_ERROR;
    }

    if (*sp % RP_POOL_ALIGNMENT) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           RP_POOL_ALIGNMENT);

        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_v2_preread_size(rp_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp > RP_HTTP_V2_MAX_WINDOW) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the maximum body preread buffer size is %uz",
                           RP_HTTP_V2_MAX_WINDOW);

        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_v2_streams_index_mask(rp_conf_t *cf, void *post, void *data)
{
    rp_uint_t *np = data;

    rp_uint_t  mask;

    mask = *np - 1;

    if (*np == 0 || (*np & mask)) {
        return "must be a power of two";
    }

    *np = mask;

    return RP_CONF_OK;
}


static char *
rp_http_v2_chunk_size(rp_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the http2 chunk size cannot be zero");

        return RP_CONF_ERROR;
    }

    if (*sp > RP_HTTP_V2_MAX_FRAME_SIZE) {
        *sp = RP_HTTP_V2_MAX_FRAME_SIZE;
    }

    return RP_CONF_OK;
}


static char *
rp_http_v2_spdy_deprecated(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "invalid directive \"%V\": rp_http_spdy_module "
                       "was superseded by rp_http_v2_module", &cmd->name);

    return RP_CONF_OK;
}
