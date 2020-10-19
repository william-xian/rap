
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_stream_complex_value_t   text;
} rap_stream_return_srv_conf_t;


typedef struct {
    rap_chain_t                 *out;
} rap_stream_return_ctx_t;


static void rap_stream_return_handler(rap_stream_session_t *s);
static void rap_stream_return_write_handler(rap_event_t *ev);

static void *rap_stream_return_create_srv_conf(rap_conf_t *cf);
static char *rap_stream_return(rap_conf_t *cf, rap_command_t *cmd, void *conf);


static rap_command_t  rap_stream_return_commands[] = {

    { rap_string("return"),
      RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_return,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_return_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_stream_return_create_srv_conf,     /* create server configuration */
    NULL                                   /* merge server configuration */
};


rap_module_t  rap_stream_return_module = {
    RAP_MODULE_V1,
    &rap_stream_return_module_ctx,         /* module context */
    rap_stream_return_commands,            /* module directives */
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


static void
rap_stream_return_handler(rap_stream_session_t *s)
{
    rap_str_t                      text;
    rap_buf_t                     *b;
    rap_connection_t              *c;
    rap_stream_return_ctx_t       *ctx;
    rap_stream_return_srv_conf_t  *rscf;

    c = s->connection;

    c->log->action = "returning text";

    rscf = rap_stream_get_module_srv_conf(s, rap_stream_return_module);

    if (rap_stream_complex_value(s, &rscf->text, &text) != RAP_OK) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream return text: \"%V\"", &text);

    if (text.len == 0) {
        rap_stream_finalize_session(s, RAP_STREAM_OK);
        return;
    }

    ctx = rap_pcalloc(c->pool, sizeof(rap_stream_return_ctx_t));
    if (ctx == NULL) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_stream_set_ctx(s, ctx, rap_stream_return_module);

    b = rap_calloc_buf(c->pool);
    if (b == NULL) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    b->memory = 1;
    b->pos = text.data;
    b->last = text.data + text.len;
    b->last_buf = 1;

    ctx->out = rap_alloc_chain_link(c->pool);
    if (ctx->out == NULL) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out->buf = b;
    ctx->out->next = NULL;

    c->write->handler = rap_stream_return_write_handler;

    rap_stream_return_write_handler(c->write);
}


static void
rap_stream_return_write_handler(rap_event_t *ev)
{
    rap_connection_t         *c;
    rap_stream_session_t     *s;
    rap_stream_return_ctx_t  *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        rap_connection_error(c, RAP_ETIMEDOUT, "connection timed out");
        rap_stream_finalize_session(s, RAP_STREAM_OK);
        return;
    }

    ctx = rap_stream_get_module_ctx(s, rap_stream_return_module);

    if (rap_stream_top_filter(s, ctx->out, 1) == RAP_ERROR) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out = NULL;

    if (!c->buffered) {
        rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream return done sending");
        rap_stream_finalize_session(s, RAP_STREAM_OK);
        return;
    }

    if (rap_handle_write_event(ev, 0) != RAP_OK) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_add_timer(ev, 5000);
}


static void *
rap_stream_return_create_srv_conf(rap_conf_t *cf)
{
    rap_stream_return_srv_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_stream_return_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rap_stream_return(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_return_srv_conf_t *rscf = conf;

    rap_str_t                           *value;
    rap_stream_core_srv_conf_t          *cscf;
    rap_stream_compile_complex_value_t   ccv;

    if (rscf->text.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &rscf->text;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    cscf = rap_stream_conf_get_module_srv_conf(cf, rap_stream_core_module);

    cscf->handler = rap_stream_return_handler;

    return RAP_CONF_OK;
}
