
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#if (RAP_ZLIB)
#include <zlib.h>
#endif


typedef struct rap_http_log_op_s  rap_http_log_op_t;

typedef u_char *(*rap_http_log_op_run_pt) (rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);

typedef size_t (*rap_http_log_op_getlen_pt) (rap_http_request_t *r,
    uintptr_t data);


struct rap_http_log_op_s {
    size_t                      len;
    rap_http_log_op_getlen_pt   getlen;
    rap_http_log_op_run_pt      run;
    uintptr_t                   data;
};


typedef struct {
    rap_str_t                   name;
    rap_array_t                *flushes;
    rap_array_t                *ops;        /* array of rap_http_log_op_t */
} rap_http_log_fmt_t;


typedef struct {
    rap_array_t                 formats;    /* array of rap_http_log_fmt_t */
    rap_uint_t                  combined_used; /* unsigned  combined_used:1 */
} rap_http_log_main_conf_t;


typedef struct {
    u_char                     *start;
    u_char                     *pos;
    u_char                     *last;

    rap_event_t                *event;
    rap_msec_t                  flush;
    rap_int_t                   gzip;
} rap_http_log_buf_t;


typedef struct {
    rap_array_t                *lengths;
    rap_array_t                *values;
} rap_http_log_script_t;


typedef struct {
    rap_open_file_t            *file;
    rap_http_log_script_t      *script;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    rap_syslog_peer_t          *syslog_peer;
    rap_http_log_fmt_t         *format;
    rap_http_complex_value_t   *filter;
} rap_http_log_t;


typedef struct {
    rap_array_t                *logs;       /* array of rap_http_log_t */

    rap_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    rap_uint_t                  open_file_cache_min_uses;

    rap_uint_t                  off;        /* unsigned  off:1 */
} rap_http_log_loc_conf_t;


typedef struct {
    rap_str_t                   name;
    size_t                      len;
    rap_http_log_op_run_pt      run;
} rap_http_log_var_t;


#define RAP_HTTP_LOG_ESCAPE_DEFAULT  0
#define RAP_HTTP_LOG_ESCAPE_JSON     1
#define RAP_HTTP_LOG_ESCAPE_NONE     2


static void rap_http_log_write(rap_http_request_t *r, rap_http_log_t *log,
    u_char *buf, size_t len);
static ssize_t rap_http_log_script_write(rap_http_request_t *r,
    rap_http_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (RAP_ZLIB)
static ssize_t rap_http_log_gzip(rap_fd_t fd, u_char *buf, size_t len,
    rap_int_t level, rap_log_t *log);

static void *rap_http_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void rap_http_log_gzip_free(void *opaque, void *address);
#endif

static void rap_http_log_flush(rap_open_file_t *file, rap_log_t *log);
static void rap_http_log_flush_handler(rap_event_t *ev);

static u_char *rap_http_log_pipe(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_time(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_iso8601(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_msec(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_request_time(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_status(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_bytes_sent(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static u_char *rap_http_log_body_bytes_sent(rap_http_request_t *r,
    u_char *buf, rap_http_log_op_t *op);
static u_char *rap_http_log_request_length(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);

static rap_int_t rap_http_log_variable_compile(rap_conf_t *cf,
    rap_http_log_op_t *op, rap_str_t *value, rap_uint_t escape);
static size_t rap_http_log_variable_getlen(rap_http_request_t *r,
    uintptr_t data);
static u_char *rap_http_log_variable(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static uintptr_t rap_http_log_escape(u_char *dst, u_char *src, size_t size);
static size_t rap_http_log_json_variable_getlen(rap_http_request_t *r,
    uintptr_t data);
static u_char *rap_http_log_json_variable(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op);
static size_t rap_http_log_unescaped_variable_getlen(rap_http_request_t *r,
    uintptr_t data);
static u_char *rap_http_log_unescaped_variable(rap_http_request_t *r,
    u_char *buf, rap_http_log_op_t *op);


static void *rap_http_log_create_main_conf(rap_conf_t *cf);
static void *rap_http_log_create_loc_conf(rap_conf_t *cf);
static char *rap_http_log_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_log_set_log(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_log_set_format(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_log_compile_format(rap_conf_t *cf,
    rap_array_t *flushes, rap_array_t *ops, rap_array_t *args, rap_uint_t s);
static char *rap_http_log_open_file_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_log_init(rap_conf_t *cf);


static rap_command_t  rap_http_log_commands[] = {

    { rap_string("log_format"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_2MORE,
      rap_http_log_set_format,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("access_log"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_HTTP_LMT_CONF|RAP_CONF_1MORE,
      rap_http_log_set_log,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("open_log_file_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1234,
      rap_http_log_open_file_cache,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_log_init,                     /* postconfiguration */

    rap_http_log_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_log_create_loc_conf,          /* create location configuration */
    rap_http_log_merge_loc_conf            /* merge location configuration */
};


rap_module_t  rap_http_log_module = {
    RAP_MODULE_V1,
    &rap_http_log_module_ctx,              /* module context */
    rap_http_log_commands,                 /* module directives */
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


static rap_str_t  rap_http_access_log = rap_string(RAP_HTTP_LOG_PATH);


static rap_str_t  rap_http_combined_fmt =
    rap_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");


static rap_http_log_var_t  rap_http_log_vars[] = {
    { rap_string("pipe"), 1, rap_http_log_pipe },
    { rap_string("time_local"), sizeof("28/Sep/1970:12:00:00 +0600") - 1,
                          rap_http_log_time },
    { rap_string("time_iso8601"), sizeof("1970-09-28T12:00:00+06:00") - 1,
                          rap_http_log_iso8601 },
    { rap_string("msec"), RAP_TIME_T_LEN + 4, rap_http_log_msec },
    { rap_string("request_time"), RAP_TIME_T_LEN + 4,
                          rap_http_log_request_time },
    { rap_string("status"), RAP_INT_T_LEN, rap_http_log_status },
    { rap_string("bytes_sent"), RAP_OFF_T_LEN, rap_http_log_bytes_sent },
    { rap_string("body_bytes_sent"), RAP_OFF_T_LEN,
                          rap_http_log_body_bytes_sent },
    { rap_string("request_length"), RAP_SIZE_T_LEN,
                          rap_http_log_request_length },

    { rap_null_string, 0, NULL }
};


static rap_int_t
rap_http_log_handler(rap_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len, size;
    ssize_t                   n;
    rap_str_t                 val;
    rap_uint_t                i, l;
    rap_http_log_t           *log;
    rap_http_log_op_t        *op;
    rap_http_log_buf_t       *buffer;
    rap_http_log_loc_conf_t  *lcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log handler");

    lcf = rap_http_get_module_loc_conf(r, rap_http_log_module);

    if (lcf->off) {
        return RAP_OK;
    }

    log = lcf->logs->elts;
    for (l = 0; l < lcf->logs->nelts; l++) {

        if (log[l].filter) {
            if (rap_http_complex_value(r, log[l].filter, &val) != RAP_OK) {
                return RAP_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        if (rap_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        rap_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + rap_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += RAP_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        if (buffer) {

            if (len > (size_t) (buffer->last - buffer->pos)) {

                rap_http_log_write(r, &log[l], buffer->start,
                                   buffer->pos - buffer->start);

                buffer->pos = buffer->start;
            }

            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                if (buffer->event && p == buffer->start) {
                    rap_add_timer(buffer->event, buffer->flush);
                }

                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(r, p, &op[i]);
                }

                rap_linefeed(p);

                buffer->pos = p;

                continue;
            }

            if (buffer->event && buffer->event->timer_set) {
                rap_del_timer(buffer->event);
            }
        }

    alloc_line:

        line = rap_pnalloc(r->pool, len);
        if (line == NULL) {
            return RAP_ERROR;
        }

        p = line;

        if (log[l].syslog_peer) {
            p = rap_syslog_add_header(log[l].syslog_peer, line);
        }

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        if (log[l].syslog_peer) {

            size = p - line;

            n = rap_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                rap_log_error(RAP_LOG_WARN, r->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                rap_log_error(RAP_LOG_WARN, r->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        rap_linefeed(p);

        rap_http_log_write(r, &log[l], line, p - line);
    }

    return RAP_OK;
}


static void
rap_http_log_write(rap_http_request_t *r, rap_http_log_t *log, u_char *buf,
    size_t len)
{
    u_char              *name;
    time_t               now;
    ssize_t              n;
    rap_err_t            err;
#if (RAP_ZLIB)
    rap_http_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {
        name = log->file->name.data;

#if (RAP_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = rap_http_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                  r->connection->log);
        } else {
            n = rap_write_fd(log->file->fd, buf, len);
        }
#else
        n = rap_write_fd(log->file->fd, buf, len);
#endif

    } else {
        name = NULL;
        n = rap_http_log_script_write(r, log->script, &name, buf, len);
    }

    if (n == (ssize_t) len) {
        return;
    }

    now = rap_time();

    if (n == -1) {
        err = rap_errno;

        if (err == RAP_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            rap_log_error(RAP_LOG_ALERT, r->connection->log, err,
                          rap_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      rap_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}


static ssize_t
rap_http_log_script_write(rap_http_request_t *r, rap_http_log_script_t *script,
    u_char **name, u_char *buf, size_t len)
{
    size_t                     root;
    ssize_t                    n;
    rap_str_t                  log, path;
    rap_open_file_info_t       of;
    rap_http_log_loc_conf_t   *llcf;
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!r->root_tested) {

        /* test root directory existence */

        if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            /* simulate successful logging */
            return len;
        }

        path.data[root] = '\0';

        rap_memzero(&of, sizeof(rap_open_file_info_t));

        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.test_dir = 1;
        of.test_only = 1;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;

        if (rap_http_set_disable_symlinks(r, clcf, &path, &of) != RAP_OK) {
            /* simulate successful logging */
            return len;
        }

        if (rap_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
            != RAP_OK)
        {
            if (of.err == 0) {
                /* simulate successful logging */
                return len;
            }

            rap_log_error(RAP_LOG_ERR, r->connection->log, of.err,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }

        if (!of.is_dir) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, RAP_ENOTDIR,
                          "testing \"%s\" existence failed", path.data);

            /* simulate successful logging */
            return len;
        }
    }

    if (rap_http_script_run(r, &log, script->lengths->elts, 1,
                            script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log \"%s\"", log.data);

    llcf = rap_http_get_module_loc_conf(r, rap_http_log_module);

    rap_memzero(&of, sizeof(rap_open_file_info_t));

    of.log = 1;
    of.valid = llcf->open_file_cache_valid;
    of.min_uses = llcf->open_file_cache_min_uses;
    of.directio = RAP_OPEN_FILE_DIRECTIO_OFF;

    if (rap_http_set_disable_symlinks(r, clcf, &log, &of) != RAP_OK) {
        /* simulate successful logging */
        return len;
    }

    if (rap_open_cached_file(llcf->open_file_cache, &log, &of, r->pool)
        != RAP_OK)
    {
        if (of.err == 0) {
            /* simulate successful logging */
            return len;
        }

        rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http log #%d", of.fd);

    n = rap_write_fd(of.fd, buf, len);

    return n;
}


#if (RAP_ZLIB)

static ssize_t
rap_http_log_gzip(rap_fd_t fd, u_char *buf, size_t len, rap_int_t level,
    rap_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    rap_err_t    err;
    rap_pool_t  *pool;

    wbits = MAX_WBITS;
    memlevel = MAX_MEM_LEVEL - 1;

    while ((ssize_t) len < ((1 << (wbits - 1)) - 262)) {
        wbits--;
        memlevel--;
    }

    /*
     * This is a formula from deflateBound() for conservative upper bound of
     * compressed data plus 18 bytes of gzip wrapper.
     */

    size = len + ((len + 7) >> 3) + ((len + 63) >> 6) + 5 + 18;

    rap_memzero(&zstream, sizeof(z_stream));

    pool = rap_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = rap_http_log_gzip_alloc;
    zstream.zfree = rap_http_log_gzip_free;
    zstream.opaque = pool;

    out = rap_pnalloc(pool, size);
    if (out == NULL) {
        goto done;
    }

    zstream.next_in = buf;
    zstream.avail_in = len;
    zstream.next_out = out;
    zstream.avail_out = size;

    rc = deflateInit2(&zstream, (int) level, Z_DEFLATED, wbits + 16, memlevel,
                      Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    rap_log_debug5(RAP_LOG_DEBUG_HTTP, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = rap_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? rap_errno : 0;

        rap_destroy_pool(pool);

        rap_set_errno(err);
        return -1;
    }

done:

    rap_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
rap_http_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    rap_pool_t *pool = opaque;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, pool->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return rap_palloc(pool, items * size);
}


static void
rap_http_log_gzip_free(void *opaque, void *address)
{
#if 0
    rap_pool_t *pool = opaque;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pool->log, 0, "gzip free: %p", address);
#endif
}

#endif


static void
rap_http_log_flush(rap_open_file_t *file, rap_log_t *log)
{
    size_t               len;
    ssize_t              n;
    rap_http_log_buf_t  *buffer;

    buffer = file->data;

    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (RAP_ZLIB)
    if (buffer->gzip) {
        n = rap_http_log_gzip(file->fd, buffer->start, len, buffer->gzip, log);
    } else {
        n = rap_write_fd(file->fd, buffer->start, len);
    }
#else
    n = rap_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      rap_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    buffer->pos = buffer->start;

    if (buffer->event && buffer->event->timer_set) {
        rap_del_timer(buffer->event);
    }
}


static void
rap_http_log_flush_handler(rap_event_t *ev)
{
    rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "http log buffer flush handler");

    rap_http_log_flush(ev->data, ev->log);
}


static u_char *
rap_http_log_copy_short(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    size_t     len;
    uintptr_t  data;

    len = op->len;
    data = op->data;

    while (len--) {
        *buf++ = (u_char) (data & 0xff);
        data >>= 8;
    }

    return buf;
}


static u_char *
rap_http_log_copy_long(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    return rap_cpymem(buf, (u_char *) op->data, op->len);
}


static u_char *
rap_http_log_pipe(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    if (r->pipeline) {
        *buf = 'p';
    } else {
        *buf = '.';
    }

    return buf + 1;
}


static u_char *
rap_http_log_time(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    return rap_cpymem(buf, rap_cached_http_log_time.data,
                      rap_cached_http_log_time.len);
}

static u_char *
rap_http_log_iso8601(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    return rap_cpymem(buf, rap_cached_http_log_iso8601.data,
                      rap_cached_http_log_iso8601.len);
}

static u_char *
rap_http_log_msec(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    rap_time_t  *tp;

    tp = rap_timeofday();

    return rap_sprintf(buf, "%T.%03M", tp->sec, tp->msec);
}


static u_char *
rap_http_log_request_time(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    rap_time_t      *tp;
    rap_msec_int_t   ms;

    tp = rap_timeofday();

    ms = (rap_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = rap_max(ms, 0);

    return rap_sprintf(buf, "%T.%03M", (time_t) ms / 1000, ms % 1000);
}


static u_char *
rap_http_log_status(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    rap_uint_t  status;

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == RAP_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    return rap_sprintf(buf, "%03ui", status);
}


static u_char *
rap_http_log_bytes_sent(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    return rap_sprintf(buf, "%O", r->connection->sent);
}


/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */

static u_char *
rap_http_log_body_bytes_sent(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    off_t  length;

    length = r->connection->sent - r->header_size;

    if (length > 0) {
        return rap_sprintf(buf, "%O", length);
    }

    *buf = '0';

    return buf + 1;
}


static u_char *
rap_http_log_request_length(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    return rap_sprintf(buf, "%O", r->request_length);
}


static rap_int_t
rap_http_log_variable_compile(rap_conf_t *cf, rap_http_log_op_t *op,
    rap_str_t *value, rap_uint_t escape)
{
    rap_int_t  index;

    index = rap_http_get_variable_index(cf, value);
    if (index == RAP_ERROR) {
        return RAP_ERROR;
    }

    op->len = 0;

    switch (escape) {
    case RAP_HTTP_LOG_ESCAPE_JSON:
        op->getlen = rap_http_log_json_variable_getlen;
        op->run = rap_http_log_json_variable;
        break;

    case RAP_HTTP_LOG_ESCAPE_NONE:
        op->getlen = rap_http_log_unescaped_variable_getlen;
        op->run = rap_http_log_unescaped_variable;
        break;

    default: /* RAP_HTTP_LOG_ESCAPE_DEFAULT */
        op->getlen = rap_http_log_variable_getlen;
        op->run = rap_http_log_variable;
    }

    op->data = index;

    return RAP_OK;
}


static size_t
rap_http_log_variable_getlen(rap_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = rap_http_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
rap_http_log_variable(rap_http_request_t *r, u_char *buf, rap_http_log_op_t *op)
{
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return rap_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) rap_http_log_escape(buf, value->data, value->len);
    }
}


static uintptr_t
rap_http_log_escape(u_char *dst, u_char *src, size_t size)
{
    rap_uint_t      n;
    static u_char   hex[] = "0123456789ABCDEF";

    static uint32_t   escape[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000004, /* 0000 0000 0000 0000  0000 0000 0000 0100 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x10000000, /* 0001 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };


    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = '\\';
            *dst++ = 'x';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


static size_t
rap_http_log_json_variable_getlen(rap_http_request_t *r, uintptr_t data)
{
    uintptr_t                   len;
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    len = rap_escape_json(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len;
}


static u_char *
rap_http_log_json_variable(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    if (value->escape == 0) {
        return rap_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) rap_escape_json(buf, value->data, value->len);
    }
}


static size_t
rap_http_log_unescaped_variable_getlen(rap_http_request_t *r, uintptr_t data)
{
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    value->escape = 0;

    return value->len;
}


static u_char *
rap_http_log_unescaped_variable(rap_http_request_t *r, u_char *buf,
    rap_http_log_op_t *op)
{
    rap_http_variable_value_t  *value;

    value = rap_http_get_indexed_variable(r, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    return rap_cpymem(buf, value->data, value->len);
}


static void *
rap_http_log_create_main_conf(rap_conf_t *cf)
{
    rap_http_log_main_conf_t  *conf;

    rap_http_log_fmt_t  *fmt;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (rap_array_init(&conf->formats, cf->pool, 4, sizeof(rap_http_log_fmt_t))
        != RAP_OK)
    {
        return NULL;
    }

    fmt = rap_array_push(&conf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    rap_str_set(&fmt->name, "combined");

    fmt->flushes = NULL;

    fmt->ops = rap_array_create(cf->pool, 16, sizeof(rap_http_log_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    return conf;
}


static void *
rap_http_log_create_loc_conf(rap_conf_t *cf)
{
    rap_http_log_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_log_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->open_file_cache = RAP_CONF_UNSET_PTR;

    return conf;
}


static char *
rap_http_log_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_log_loc_conf_t *prev = parent;
    rap_http_log_loc_conf_t *conf = child;

    rap_http_log_t            *log;
    rap_http_log_fmt_t        *fmt;
    rap_http_log_main_conf_t  *lmcf;

    if (conf->open_file_cache == RAP_CONF_UNSET_PTR) {

        conf->open_file_cache = prev->open_file_cache;
        conf->open_file_cache_valid = prev->open_file_cache_valid;
        conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;

        if (conf->open_file_cache == RAP_CONF_UNSET_PTR) {
            conf->open_file_cache = NULL;
        }
    }

    if (conf->logs || conf->off) {
        return RAP_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return RAP_CONF_OK;
    }

    conf->logs = rap_array_create(cf->pool, 2, sizeof(rap_http_log_t));
    if (conf->logs == NULL) {
        return RAP_CONF_ERROR;
    }

    log = rap_array_push(conf->logs);
    if (log == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(log, sizeof(rap_http_log_t));

    log->file = rap_conf_open_file(cf->cycle, &rap_http_access_log);
    if (log->file == NULL) {
        return RAP_CONF_ERROR;
    }

    lmcf = rap_http_conf_get_module_main_conf(cf, rap_http_log_module);
    fmt = lmcf->formats.elts;

    /* the default "combined" format */
    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return RAP_CONF_OK;
}


static char *
rap_http_log_set_log(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_log_loc_conf_t *llcf = conf;

    ssize_t                            size;
    rap_int_t                          gzip;
    rap_uint_t                         i, n;
    rap_msec_t                         flush;
    rap_str_t                         *value, name, s;
    rap_http_log_t                    *log;
    rap_syslog_peer_t                 *peer;
    rap_http_log_buf_t                *buffer;
    rap_http_log_fmt_t                *fmt;
    rap_http_log_main_conf_t          *lmcf;
    rap_http_script_compile_t          sc;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        if (cf->args->nelts == 2) {
            return RAP_CONF_OK;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RAP_CONF_ERROR;
    }

    if (llcf->logs == NULL) {
        llcf->logs = rap_array_create(cf->pool, 2, sizeof(rap_http_log_t));
        if (llcf->logs == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    lmcf = rap_http_conf_get_module_main_conf(cf, rap_http_log_module);

    log = rap_array_push(llcf->logs);
    if (log == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(log, sizeof(rap_http_log_t));


    if (rap_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = rap_pcalloc(cf->pool, sizeof(rap_syslog_peer_t));
        if (peer == NULL) {
            return RAP_CONF_ERROR;
        }

        if (rap_syslog_process_conf(cf, peer) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    n = rap_http_script_variables_count(&value[1]);

    if (n == 0) {
        log->file = rap_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return RAP_CONF_ERROR;
        }

    } else {
        if (rap_conf_full_name(cf->cycle, &value[1], 0) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        log->script = rap_pcalloc(cf->pool, sizeof(rap_http_log_script_t));
        if (log->script == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

process_formats:

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (rap_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }

    } else {
        rap_str_set(&name, "combined");
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && rap_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return RAP_CONF_ERROR;
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = rap_parse_size(&s);

            if (size == RAP_ERROR || size == 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = rap_parse_time(&s, 0);

            if (flush == (rap_msec_t) RAP_ERROR || flush == 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (RAP_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = rap_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return RAP_CONF_ERROR;
            }

            continue;

#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "rap was built without zlib support");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = rap_palloc(cf->pool,
                                           sizeof(rap_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return RAP_CONF_ERROR;
            }

            if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (flush && size == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return RAP_CONF_ERROR;
    }

    if (size) {

        if (log->script) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return RAP_CONF_ERROR;
        }

        if (log->syslog_peer) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return RAP_CONF_ERROR;
        }

        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return RAP_CONF_ERROR;
            }

            return RAP_CONF_OK;
        }

        buffer = rap_pcalloc(cf->pool, sizeof(rap_http_log_buf_t));
        if (buffer == NULL) {
            return RAP_CONF_ERROR;
        }

        buffer->start = rap_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return RAP_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {
            buffer->event = rap_pcalloc(cf->pool, sizeof(rap_event_t));
            if (buffer->event == NULL) {
                return RAP_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = rap_http_log_flush_handler;
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = rap_http_log_flush;
        log->file->data = buffer;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_log_set_format(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_log_main_conf_t *lmcf = conf;

    rap_str_t           *value;
    rap_uint_t           i;
    rap_http_log_fmt_t  *fmt;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && rap_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return RAP_CONF_ERROR;
        }
    }

    fmt = rap_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return RAP_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->flushes = rap_array_create(cf->pool, 4, sizeof(rap_int_t));
    if (fmt->flushes == NULL) {
        return RAP_CONF_ERROR;
    }

    fmt->ops = rap_array_create(cf->pool, 16, sizeof(rap_http_log_op_t));
    if (fmt->ops == NULL) {
        return RAP_CONF_ERROR;
    }

    return rap_http_log_compile_format(cf, fmt->flushes, fmt->ops, cf->args, 2);
}


static char *
rap_http_log_compile_format(rap_conf_t *cf, rap_array_t *flushes,
    rap_array_t *ops, rap_array_t *args, rap_uint_t s)
{
    u_char              *data, *p, ch;
    size_t               i, len;
    rap_str_t           *value, var;
    rap_int_t           *flush;
    rap_uint_t           bracket, escape;
    rap_http_log_op_t   *op;
    rap_http_log_var_t  *v;

    escape = RAP_HTTP_LOG_ESCAPE_DEFAULT;
    value = args->elts;

    if (s < args->nelts && rap_strncmp(value[s].data, "escape=", 7) == 0) {
        data = value[s].data + 7;

        if (rap_strcmp(data, "json") == 0) {
            escape = RAP_HTTP_LOG_ESCAPE_JSON;

        } else if (rap_strcmp(data, "none") == 0) {
            escape = RAP_HTTP_LOG_ESCAPE_NONE;

        } else if (rap_strcmp(data, "default") != 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "unknown log format escaping \"%s\"", data);
            return RAP_CONF_ERROR;
        }

        s++;
    }

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = rap_array_push(ops);
            if (op == NULL) {
                return RAP_CONF_ERROR;
            }

            data = &value[s].data[i];

            if (value[s].data[i] == '$') {

                if (++i == value[s].len) {
                    goto invalid;
                }

                if (value[s].data[i] == '{') {
                    bracket = 1;

                    if (++i == value[s].len) {
                        goto invalid;
                    }

                    var.data = &value[s].data[i];

                } else {
                    bracket = 0;
                    var.data = &value[s].data[i];
                }

                for (var.len = 0; i < value[s].len; i++, var.len++) {
                    ch = value[s].data[i];

                    if (ch == '}' && bracket) {
                        i++;
                        bracket = 0;
                        break;
                    }

                    if ((ch >= 'A' && ch <= 'Z')
                        || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9')
                        || ch == '_')
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return RAP_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                for (v = rap_http_log_vars; v->name.len; v++) {

                    if (v->name.len == var.len
                        && rap_strncmp(v->name.data, var.data, var.len) == 0)
                    {
                        op->len = v->len;
                        op->getlen = NULL;
                        op->run = v->run;
                        op->data = 0;

                        goto found;
                    }
                }

                if (rap_http_log_variable_compile(cf, op, &var, escape)
                    != RAP_OK)
                {
                    return RAP_CONF_ERROR;
                }

                if (flushes) {

                    flush = rap_array_push(flushes);
                    if (flush == NULL) {
                        return RAP_CONF_ERROR;
                    }

                    *flush = op->data; /* variable index */
                }

            found:

                continue;
            }

            i++;

            while (i < value[s].len && value[s].data[i] != '$') {
                i++;
            }

            len = &value[s].data[i] - data;

            if (len) {

                op->len = len;
                op->getlen = NULL;

                if (len <= sizeof(uintptr_t)) {
                    op->run = rap_http_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = rap_http_log_copy_long;

                    p = rap_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return RAP_CONF_ERROR;
                    }

                    rap_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return RAP_CONF_ERROR;
}


static char *
rap_http_log_open_file_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_log_loc_conf_t *llcf = conf;

    time_t       inactive, valid;
    rap_str_t   *value, s;
    rap_int_t    max, min_uses;
    rap_uint_t   i;

    if (llcf->open_file_cache != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "max=", 4) == 0) {

            max = rap_atoi(value[i].data + 4, value[i].len - 4);
            if (max == RAP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rap_parse_time(&s, 1);
            if (inactive == (time_t) RAP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = rap_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == RAP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = rap_parse_time(&s, 1);
            if (valid == (time_t) RAP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rap_strcmp(value[i].data, "off") == 0) {

            llcf->open_file_cache = NULL;

            continue;
        }

    failed:

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return RAP_CONF_ERROR;
    }

    if (llcf->open_file_cache == NULL) {
        return RAP_CONF_OK;
    }

    if (max == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return RAP_CONF_ERROR;
    }

    llcf->open_file_cache = rap_open_file_cache_init(cf->pool, max, inactive);

    if (llcf->open_file_cache) {

        llcf->open_file_cache_valid = valid;
        llcf->open_file_cache_min_uses = min_uses;

        return RAP_CONF_OK;
    }

    return RAP_CONF_ERROR;
}


static rap_int_t
rap_http_log_init(rap_conf_t *cf)
{
    rap_str_t                  *value;
    rap_array_t                 a;
    rap_http_handler_pt        *h;
    rap_http_log_fmt_t         *fmt;
    rap_http_log_main_conf_t   *lmcf;
    rap_http_core_main_conf_t  *cmcf;

    lmcf = rap_http_conf_get_module_main_conf(cf, rap_http_log_module);

    if (lmcf->combined_used) {
        if (rap_array_init(&a, cf->pool, 1, sizeof(rap_str_t)) != RAP_OK) {
            return RAP_ERROR;
        }

        value = rap_array_push(&a);
        if (value == NULL) {
            return RAP_ERROR;
        }

        *value = rap_http_combined_fmt;
        fmt = lmcf->formats.elts;

        if (rap_http_log_compile_format(cf, NULL, fmt->ops, &a, 0)
            != RAP_CONF_OK)
        {
            return RAP_ERROR;
        }
    }

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_log_handler;

    return RAP_OK;
}
