
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_bufs_t  bufs;
} rap_http_copy_filter_conf_t;


#if (RAP_HAVE_FILE_AIO)
static void rap_http_copy_aio_handler(rap_output_chain_ctx_t *ctx,
    rap_file_t *file);
static void rap_http_copy_aio_event_handler(rap_event_t *ev);
#if (RAP_HAVE_AIO_SENDFILE)
static ssize_t rap_http_copy_aio_sendfile_preload(rap_buf_t *file);
static void rap_http_copy_aio_sendfile_event_handler(rap_event_t *ev);
#endif
#endif
#if (RAP_THREADS)
static rap_int_t rap_http_copy_thread_handler(rap_thread_task_t *task,
    rap_file_t *file);
static void rap_http_copy_thread_event_handler(rap_event_t *ev);
#endif

static void *rap_http_copy_filter_create_conf(rap_conf_t *cf);
static char *rap_http_copy_filter_merge_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_copy_filter_init(rap_conf_t *cf);


static rap_command_t  rap_http_copy_filter_commands[] = {

    { rap_string("output_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_copy_filter_conf_t, bufs),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_copy_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_copy_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_copy_filter_create_conf,      /* create location configuration */
    rap_http_copy_filter_merge_conf        /* merge location configuration */
};


rap_module_t  rap_http_copy_filter_module = {
    RAP_MODULE_V1,
    &rap_http_copy_filter_module_ctx,      /* module context */
    rap_http_copy_filter_commands,         /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_copy_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                     rc;
    rap_connection_t             *c;
    rap_output_chain_ctx_t       *ctx;
    rap_http_core_loc_conf_t     *clcf;
    rap_http_copy_filter_conf_t  *conf;

    c = r->connection;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: \"%V?%V\"", &r->uri, &r->args);

    ctx = rap_http_get_module_ctx(r, rap_http_copy_filter_module);

    if (ctx == NULL) {
        ctx = rap_pcalloc(r->pool, sizeof(rap_output_chain_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_http_set_ctx(r, ctx, rap_http_copy_filter_module);

        conf = rap_http_get_module_loc_conf(r, rap_http_copy_filter_module);
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        ctx->sendfile = c->sendfile;
        ctx->need_in_memory = r->main_filter_need_in_memory
                              || r->filter_need_in_memory;
        ctx->need_in_temp = r->filter_need_temporary;

        ctx->alignment = clcf->directio_alignment;

        ctx->pool = r->pool;
        ctx->bufs = conf->bufs;
        ctx->tag = (rap_buf_tag_t) &rap_http_copy_filter_module;

        ctx->output_filter = (rap_output_chain_filter_pt)
                                  rap_http_next_body_filter;
        ctx->filter_ctx = r;

#if (RAP_HAVE_FILE_AIO)
        if (rap_file_aio && clcf->aio == RAP_HTTP_AIO_ON) {
            ctx->aio_handler = rap_http_copy_aio_handler;
#if (RAP_HAVE_AIO_SENDFILE)
            ctx->aio_preload = rap_http_copy_aio_sendfile_preload;
#endif
        }
#endif

#if (RAP_THREADS)
        if (clcf->aio == RAP_HTTP_AIO_THREADS) {
            ctx->thread_handler = rap_http_copy_thread_handler;
        }
#endif

        if (in && in->buf && rap_buf_size(in->buf)) {
            r->request_output = 1;
        }
    }

#if (RAP_HAVE_FILE_AIO || RAP_THREADS)
    ctx->aio = r->aio;
#endif

    rc = rap_output_chain(ctx, in);

    if (ctx->in == NULL) {
        r->buffered &= ~RAP_HTTP_COPY_BUFFERED;

    } else {
        r->buffered |= RAP_HTTP_COPY_BUFFERED;
    }

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http copy filter: %i \"%V?%V\"", rc, &r->uri, &r->args);

    return rc;
}


#if (RAP_HAVE_FILE_AIO)

static void
rap_http_copy_aio_handler(rap_output_chain_ctx_t *ctx, rap_file_t *file)
{
    rap_http_request_t *r;

    r = ctx->filter_ctx;

    file->aio->data = r;
    file->aio->handler = rap_http_copy_aio_event_handler;

    r->main->blocked++;
    r->aio = 1;
    ctx->aio = 1;
}


static void
rap_http_copy_aio_event_handler(rap_event_t *ev)
{
    rap_event_aio_t     *aio;
    rap_connection_t    *c;
    rap_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rap_http_run_posted_requests(c);
}


#if (RAP_HAVE_AIO_SENDFILE)

static ssize_t
rap_http_copy_aio_sendfile_preload(rap_buf_t *file)
{
    ssize_t                  n;
    static u_char            buf[1];
    rap_event_aio_t         *aio;
    rap_http_request_t      *r;
    rap_output_chain_ctx_t  *ctx;

    n = rap_file_aio_read(file->file, buf, 1, file->file_pos, NULL);

    if (n == RAP_AGAIN) {
        aio = file->file->aio;
        aio->handler = rap_http_copy_aio_sendfile_event_handler;

        r = aio->data;
        r->main->blocked++;
        r->aio = 1;

        ctx = rap_http_get_module_ctx(r, rap_http_copy_filter_module);
        ctx->aio = 1;
    }

    return n;
}


static void
rap_http_copy_aio_sendfile_event_handler(rap_event_t *ev)
{
    rap_event_aio_t     *aio;
    rap_http_request_t  *r;

    aio = ev->data;
    r = aio->data;

    r->main->blocked--;
    r->aio = 0;
    ev->complete = 0;

    r->connection->write->handler(r->connection->write);
}

#endif
#endif


#if (RAP_THREADS)

static rap_int_t
rap_http_copy_thread_handler(rap_thread_task_t *task, rap_file_t *file)
{
    rap_str_t                  name;
    rap_thread_pool_t         *tp;
    rap_http_request_t        *r;
    rap_output_chain_ctx_t    *ctx;
    rap_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rap_http_complex_value(r, clcf->thread_pool_value, &name)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        tp = rap_thread_pool_get((rap_cycle_t *) rap_cycle, &name);

        if (tp == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RAP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rap_http_copy_thread_event_handler;

    if (rap_thread_task_post(tp, task) != RAP_OK) {
        return RAP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    ctx = rap_http_get_module_ctx(r, rap_http_copy_filter_module);
    ctx->aio = 1;

    return RAP_OK;
}


static void
rap_http_copy_thread_event_handler(rap_event_t *ev)
{
    rap_connection_t    *c;
    rap_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
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
        rap_http_run_posted_requests(c);
    }
}

#endif


static void *
rap_http_copy_filter_create_conf(rap_conf_t *cf)
{
    rap_http_copy_filter_conf_t *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_copy_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->bufs.num = 0;

    return conf;
}


static char *
rap_http_copy_filter_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_copy_filter_conf_t *prev = parent;
    rap_http_copy_filter_conf_t *conf = child;

    rap_conf_merge_bufs_value(conf->bufs, prev->bufs, 2, 32768);

    return NULL;
}


static rap_int_t
rap_http_copy_filter_init(rap_conf_t *cf)
{
    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_copy_filter;

    return RAP_OK;
}

