
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_bufs_t  bufs;
} rp_http_copy_filter_conf_t;


#if (RP_HAVE_FILE_AIO)
static void rp_http_copy_aio_handler(rp_output_chain_ctx_t *ctx,
    rp_file_t *file);
static void rp_http_copy_aio_event_handler(rp_event_t *ev);
#if (RP_HAVE_AIO_SENDFILE)
static ssize_t rp_http_copy_aio_sendfile_preload(rp_buf_t *file);
static void rp_http_copy_aio_sendfile_event_handler(rp_event_t *ev);
#endif
#endif
#if (RP_THREADS)
static rp_int_t rp_http_copy_thread_handler(rp_thread_task_t *task,
    rp_file_t *file);
static void rp_http_copy_thread_event_handler(rp_event_t *ev);
#endif

static void *rp_http_copy_filter_create_conf(rp_conf_t *cf);
static char *rp_http_copy_filter_merge_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_copy_filter_init(rp_conf_t *cf);


static rp_command_t  rp_http_copy_filter_commands[] = {

    { rp_string("output_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_copy_filter_conf_t, bufs),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_copy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_copy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_copy_filter_create_conf,      /* create location configuration */
    rp_http_copy_filter_merge_conf        /* merge location configuration */
};


rp_module_t  rp_http_copy_filter_module = {
    RP_MODULE_V1,
    &rp_http_copy_filter_module_ctx,      /* module context */
    rp_http_copy_filter_commands,         /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_copy_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                     rc;
    rp_connection_t             *c;
    rp_output_chain_ctx_t       *ctx;
    rp_http_core_loc_conf_t     *clcf;
    rp_http_copy_filter_conf_t  *conf;

    c = r->connection;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: \"%V?%V\"", &r->uri, &r->args);

    ctx = rp_http_get_module_ctx(r, rp_http_copy_filter_module);

    if (ctx == NULL) {
        ctx = rp_pcalloc(r->pool, sizeof(rp_output_chain_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_http_set_ctx(r, ctx, rp_http_copy_filter_module);

        conf = rp_http_get_module_loc_conf(r, rp_http_copy_filter_module);
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        ctx->sendfile = c->sendfile;
        ctx->need_in_memory = r->main_filter_need_in_memory
                              || r->filter_need_in_memory;
        ctx->need_in_temp = r->filter_need_temporary;

        ctx->alignment = clcf->directio_alignment;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (rp_buf_tag_t) &rp_http_copy_filter_module;

        ctx->output_filter = (rp_output_chain_filter_pt)
                                  rp_http_next_body_filter;
        ctx->filter_ctx = r;

#if (RP_HAVE_FILE_AIO)
        if (rp_file_aio && clcf->aio == RP_HTTP_AIO_ON) {
            ctx->aio_handler = rp_http_copy_aio_handler;
#if (RP_HAVE_AIO_SENDFILE)
            ctx->aio_preload = rp_http_copy_aio_sendfile_preload;
#endif
        }
#endif

#if (RP_THREADS)
        if (clcf->aio == RP_HTTP_AIO_THREADS) {
            ctx->thread_handler = rp_http_copy_thread_handler;
        }
#endif

        if (in && in->buf && rp_buf_size(in->buf)) {
            r->request_output = 1;
        }
    }

#if (RP_HAVE_FILE_AIO || RP_THREADS)
    ctx->aio = r->aio;
#endif

    rc = rp_output_chain(ctx, in);

    if (ctx->in == NULL) {
        r->buffered &= ~RP_HTTP_COPY_BUFFERED;

    } else {
        r->buffered |= RP_HTTP_COPY_BUFFERED;
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);

    return rc;
}


#if (RP_HAVE_FILE_AIO)

static void
rp_http_copy_aio_handler(rp_output_chain_ctx_t *ctx, rp_file_t *file)
{
    rp_http_request_t *r;

    r = ctx->filter_ctx;

    file->aio->data = r;
    file->aio->handler = rp_http_copy_aio_event_handler;

    r->main->blocked++;
    r->aio = 1;
    ctx->aio = 1;
}


static void
rp_http_copy_aio_event_handler(rp_event_t *ev)
{
    rp_event_aio_t     *aio;
    rp_connection_t    *c;
    rp_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rp_http_run_posted_requests(c);
}


#if (RP_HAVE_AIO_SENDFILE)

static ssize_t
rp_http_copy_aio_sendfile_preload(rp_buf_t *file)
{
    ssize_t                  n;
    static u_char            buf[1];
    rp_event_aio_t         *aio;
    rp_http_request_t      *r;
    rp_output_chain_ctx_t  *ctx;

    n = rp_file_aio_read(file->file, buf, 1, file->file_pos, NULL);

    if (n == RP_AGAIN) {
        aio = file->file->aio;
        aio->handler = rp_http_copy_aio_sendfile_event_handler;

        r = aio->data;
        r->main->blocked++;
        r->aio = 1;

        ctx = rp_http_get_module_ctx(r, rp_http_copy_filter_module);
        ctx->aio = 1;
    }

    return n;
}


static void
rp_http_copy_aio_sendfile_event_handler(rp_event_t *ev)
{
    rp_event_aio_t     *aio;
    rp_http_request_t  *r;

    aio = ev->data;
    r = aio->data;

    r->main->blocked--;
    r->aio = 0;
    ev->complete = 0;

    r->connection->write->handler(r->connection->write);
}

#endif
#endif


#if (RP_THREADS)

static rp_int_t
rp_http_copy_thread_handler(rp_thread_task_t *task, rp_file_t *file)
{
    rp_str_t                  name;
    rp_thread_pool_t         *tp;
    rp_http_request_t        *r;
    rp_output_chain_ctx_t    *ctx;
    rp_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rp_http_complex_value(r, clcf->thread_pool_value, &name)
            != RP_OK)
        {
            return RP_ERROR;
        }

        tp = rp_thread_pool_get((rp_cycle_t *) rp_cycle, &name);

        if (tp == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rp_http_copy_thread_event_handler;

    if (rp_thread_task_post(tp, task) != RP_OK) {
        return RP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    ctx = rp_http_get_module_ctx(r, rp_http_copy_filter_module);
    ctx->aio = 1;

    return RP_OK;
}


static void
rp_http_copy_thread_event_handler(rp_event_t *ev)
{
    rp_connection_t    *c;
    rp_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    if (r->done) {
        /*
         * trigger connection event handler if the subrequest was
         * already finalized; this can happen if the handler is used
         * for sendfile() in threads
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        rp_http_run_posted_requests(c);
    }
}

#endif


static void *
rp_http_copy_filter_create_conf(rp_conf_t *cf)
{
    rp_http_copy_filter_conf_t *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_copy_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bufs.num = 0;

    return conf;
}


static char *
rp_http_copy_filter_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_copy_filter_conf_t *prev = parent;
    rp_http_copy_filter_conf_t *conf = child;

    rp_conf_merge_bufs_value(conf->bufs, prev->bufs, 2, 32768);

    return NULL;
}


static rp_int_t
rp_http_copy_filter_init(rp_conf_t *cf)
{
    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_copy_filter;

    return RP_OK;
}

