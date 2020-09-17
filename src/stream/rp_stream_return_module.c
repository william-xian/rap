
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_stream_complex_value_t   text;
} rp_stream_return_srv_conf_t;


typedef struct {
    rp_chain_t                 *out;
} rp_stream_return_ctx_t;


static void rp_stream_return_handler(rp_stream_session_t *s);
static void rp_stream_return_write_handler(rp_event_t *ev);

static void *rp_stream_return_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_return(rp_conf_t *cf, rp_command_t *cmd, void *conf);


static rp_command_t  rp_stream_return_commands[] = {

    { rp_string("return"),
      RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_return,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_return_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_return_create_srv_conf,     /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_return_module = {
    RP_MODULE_V1,
    &rp_stream_return_module_ctx,         /* module context */
    rp_stream_return_commands,            /* module directives */
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


static void
rp_stream_return_handler(rp_stream_session_t *s)
{
    rp_str_t                      text;
    rp_buf_t                     *b;
    rp_connection_t              *c;
    rp_stream_return_ctx_t       *ctx;
    rp_stream_return_srv_conf_t  *rscf;

    c = s->connection;

    c->log->action = "returning text";

    rscf = rp_stream_get_module_srv_conf(s, rp_stream_return_module);

    if (rp_stream_complex_value(s, &rscf->text, &text) != RP_OK) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream return text: \"%V\"", &text);

    if (text.len == 0) {
        rp_stream_finalize_session(s, RP_STREAM_OK);
        return;
    }

    ctx = rp_pcalloc(c->pool, sizeof(rp_stream_return_ctx_t));
    if (ctx == NULL) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_stream_set_ctx(s, ctx, rp_stream_return_module);

    b = rp_calloc_buf(c->pool);
    if (b == NULL) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    b->memory = 1;
    b->pos = text.data;
    b->last = text.data + text.len;
    b->last_buf = 1;

    ctx->out = rp_alloc_chain_link(c->pool);
    if (ctx->out == NULL) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out->buf = b;
    ctx->out->next = NULL;

    c->write->handler = rp_stream_return_write_handler;

    rp_stream_return_write_handler(c->write);
}


static void
rp_stream_return_write_handler(rp_event_t *ev)
{
    rp_connection_t         *c;
    rp_stream_session_t     *s;
    rp_stream_return_ctx_t  *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        rp_connection_error(c, RP_ETIMEDOUT, "connection timed out");
        rp_stream_finalize_session(s, RP_STREAM_OK);
        return;
    }

    ctx = rp_stream_get_module_ctx(s, rp_stream_return_module);

    if (rp_stream_top_filter(s, ctx->out, 1) == RP_ERROR) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out = NULL;

    if (!c->buffered) {
        rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                       "stream return done sending");
        rp_stream_finalize_session(s, RP_STREAM_OK);
        return;
    }

    if (rp_handle_write_event(ev, 0) != RP_OK) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_add_timer(ev, 5000);
}


static void *
rp_stream_return_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_return_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_return_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rp_stream_return(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_return_srv_conf_t *rscf = conf;

    rp_str_t                           *value;
    rp_stream_core_srv_conf_t          *cscf;
    rp_stream_compile_complex_value_t   ccv;

    if (rscf->text.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &rscf->text;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    cscf = rp_stream_conf_get_module_srv_conf(cf, rp_stream_core_module);

    cscf->handler = rp_stream_return_handler;

    return RP_CONF_OK;
}
