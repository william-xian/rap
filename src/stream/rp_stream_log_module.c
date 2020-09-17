
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>

#if (RP_ZLIB)
#include <zlib.h>
#endif


typedef struct rp_stream_log_op_s  rp_stream_log_op_t;

typedef u_char *(*rp_stream_log_op_run_pt) (rp_stream_session_t *s,
    u_char *buf, rp_stream_log_op_t *op);

typedef size_t (*rp_stream_log_op_getlen_pt) (rp_stream_session_t *s,
    uintptr_t data);


struct rp_stream_log_op_s {
    size_t                       len;
    rp_stream_log_op_getlen_pt  getlen;
    rp_stream_log_op_run_pt     run;
    uintptr_t                    data;
};


typedef struct {
    rp_str_t                    name;
    rp_array_t                 *flushes;
    rp_array_t                 *ops;        /* array of rp_stream_log_op_t */
} rp_stream_log_fmt_t;


typedef struct {
    rp_array_t                  formats;    /* array of rp_stream_log_fmt_t */
} rp_stream_log_main_conf_t;


typedef struct {
    u_char                      *start;
    u_char                      *pos;
    u_char                      *last;

    rp_event_t                 *event;
    rp_msec_t                   flush;
    rp_int_t                    gzip;
} rp_stream_log_buf_t;


typedef struct {
    rp_array_t                 *lengths;
    rp_array_t                 *values;
} rp_stream_log_script_t;


typedef struct {
    rp_open_file_t             *file;
    rp_stream_log_script_t     *script;
    time_t                       disk_full_time;
    time_t                       error_log_time;
    rp_syslog_peer_t           *syslog_peer;
    rp_stream_log_fmt_t        *format;
    rp_stream_complex_value_t  *filter;
} rp_stream_log_t;


typedef struct {
    rp_array_t                 *logs;       /* array of rp_stream_log_t */

    rp_open_file_cache_t       *open_file_cache;
    time_t                       open_file_cache_valid;
    rp_uint_t                   open_file_cache_min_uses;

    rp_uint_t                   off;        /* unsigned  off:1 */
} rp_stream_log_srv_conf_t;


typedef struct {
    rp_str_t                    name;
    size_t                       len;
    rp_stream_log_op_run_pt     run;
} rp_stream_log_var_t;


#define RP_STREAM_LOG_ESCAPE_DEFAULT  0
#define RP_STREAM_LOG_ESCAPE_JSON     1
#define RP_STREAM_LOG_ESCAPE_NONE     2


static void rp_stream_log_write(rp_stream_session_t *s, rp_stream_log_t *log,
    u_char *buf, size_t len);
static ssize_t rp_stream_log_script_write(rp_stream_session_t *s,
    rp_stream_log_script_t *script, u_char **name, u_char *buf, size_t len);

#if (RP_ZLIB)
static ssize_t rp_stream_log_gzip(rp_fd_t fd, u_char *buf, size_t len,
    rp_int_t level, rp_log_t *log);

static void *rp_stream_log_gzip_alloc(void *opaque, u_int items, u_int size);
static void rp_stream_log_gzip_free(void *opaque, void *address);
#endif

static void rp_stream_log_flush(rp_open_file_t *file, rp_log_t *log);
static void rp_stream_log_flush_handler(rp_event_t *ev);

static rp_int_t rp_stream_log_variable_compile(rp_conf_t *cf,
    rp_stream_log_op_t *op, rp_str_t *value, rp_uint_t escape);
static size_t rp_stream_log_variable_getlen(rp_stream_session_t *s,
    uintptr_t data);
static u_char *rp_stream_log_variable(rp_stream_session_t *s, u_char *buf,
    rp_stream_log_op_t *op);
static uintptr_t rp_stream_log_escape(u_char *dst, u_char *src, size_t size);
static size_t rp_stream_log_json_variable_getlen(rp_stream_session_t *s,
    uintptr_t data);
static u_char *rp_stream_log_json_variable(rp_stream_session_t *s,
    u_char *buf, rp_stream_log_op_t *op);
static size_t rp_stream_log_unescaped_variable_getlen(rp_stream_session_t *s,
    uintptr_t data);
static u_char *rp_stream_log_unescaped_variable(rp_stream_session_t *s,
    u_char *buf, rp_stream_log_op_t *op);


static void *rp_stream_log_create_main_conf(rp_conf_t *cf);
static void *rp_stream_log_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_log_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_stream_log_set_log(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_log_set_format(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_log_compile_format(rp_conf_t *cf,
    rp_array_t *flushes, rp_array_t *ops, rp_array_t *args, rp_uint_t s);
static char *rp_stream_log_open_file_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_stream_log_init(rp_conf_t *cf);


static rp_command_t  rp_stream_log_commands[] = {

    { rp_string("log_format"),
      RP_STREAM_MAIN_CONF|RP_CONF_2MORE,
      rp_stream_log_set_format,
      RP_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rp_string("access_log"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_stream_log_set_log,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("open_log_file_cache"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1234,
      rp_stream_log_open_file_cache,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_log_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_stream_log_init,                   /* postconfiguration */

    rp_stream_log_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_log_create_srv_conf,        /* create server configuration */
    rp_stream_log_merge_srv_conf          /* merge server configuration */
};


rp_module_t  rp_stream_log_module = {
    RP_MODULE_V1,
    &rp_stream_log_module_ctx,            /* module context */
    rp_stream_log_commands,               /* module directives */
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
rp_stream_log_handler(rp_stream_session_t *s)
{
    u_char                     *line, *p;
    size_t                      len, size;
    ssize_t                     n;
    rp_str_t                   val;
    rp_uint_t                  i, l;
    rp_stream_log_t           *log;
    rp_stream_log_op_t        *op;
    rp_stream_log_buf_t       *buffer;
    rp_stream_log_srv_conf_t  *lscf;

    rp_log_debug0(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log handler");

    lscf = rp_stream_get_module_srv_conf(s, rp_stream_log_module);

    if (lscf->off || lscf->logs == NULL) {
        return RP_OK;
    }

    log = lscf->logs->elts;
    for (l = 0; l < lscf->logs->nelts; l++) {

        if (log[l].filter) {
            if (rp_stream_complex_value(s, log[l].filter, &val) != RP_OK) {
                return RP_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
                continue;
            }
        }

        if (rp_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        rp_stream_script_flush_no_cacheable_variables(s,
                                                       log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(s, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        if (log[l].syslog_peer) {

            /* length of syslog's PRI and HEADER message parts */
            len += sizeof("<255>Jan 01 00:00:00 ") - 1
                   + rp_cycle->hostname.len + 1
                   + log[l].syslog_peer->tag.len + 2;

            goto alloc_line;
        }

        len += RP_LINEFEED_SIZE;

        buffer = log[l].file ? log[l].file->data : NULL;

        if (buffer) {

            if (len > (size_t) (buffer->last - buffer->pos)) {

                rp_stream_log_write(s, &log[l], buffer->start,
                                     buffer->pos - buffer->start);

                buffer->pos = buffer->start;
            }

            if (len <= (size_t) (buffer->last - buffer->pos)) {

                p = buffer->pos;

                if (buffer->event && p == buffer->start) {
                    rp_add_timer(buffer->event, buffer->flush);
                }

                for (i = 0; i < log[l].format->ops->nelts; i++) {
                    p = op[i].run(s, p, &op[i]);
                }

                rp_linefeed(p);

                buffer->pos = p;

                continue;
            }

            if (buffer->event && buffer->event->timer_set) {
                rp_del_timer(buffer->event);
            }
        }

    alloc_line:

        line = rp_pnalloc(s->connection->pool, len);
        if (line == NULL) {
            return RP_ERROR;
        }

        p = line;

        if (log[l].syslog_peer) {
            p = rp_syslog_add_header(log[l].syslog_peer, line);
        }

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(s, p, &op[i]);
        }

        if (log[l].syslog_peer) {

            size = p - line;

            n = rp_syslog_send(log[l].syslog_peer, line, size);

            if (n < 0) {
                rp_log_error(RP_LOG_WARN, s->connection->log, 0,
                              "send() to syslog failed");

            } else if ((size_t) n != size) {
                rp_log_error(RP_LOG_WARN, s->connection->log, 0,
                              "send() to syslog has written only %z of %uz",
                              n, size);
            }

            continue;
        }

        rp_linefeed(p);

        rp_stream_log_write(s, &log[l], line, p - line);
    }

    return RP_OK;
}


static void
rp_stream_log_write(rp_stream_session_t *s, rp_stream_log_t *log,
    u_char *buf, size_t len)
{
    u_char                *name;
    time_t                 now;
    ssize_t                n;
    rp_err_t              err;
#if (RP_ZLIB)
    rp_stream_log_buf_t  *buffer;
#endif

    if (log->script == NULL) {
        name = log->file->name.data;

#if (RP_ZLIB)
        buffer = log->file->data;

        if (buffer && buffer->gzip) {
            n = rp_stream_log_gzip(log->file->fd, buf, len, buffer->gzip,
                                    s->connection->log);
        } else {
            n = rp_write_fd(log->file->fd, buf, len);
        }
#else
        n = rp_write_fd(log->file->fd, buf, len);
#endif

    } else {
        name = NULL;
        n = rp_stream_log_script_write(s, log->script, &name, buf, len);
    }

    if (n == (ssize_t) len) {
        return;
    }

    now = rp_time();

    if (n == -1) {
        err = rp_errno;

        if (err == RP_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            rp_log_error(RP_LOG_ALERT, s->connection->log, err,
                          rp_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
        rp_log_error(RP_LOG_ALERT, s->connection->log, 0,
                      rp_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}


static ssize_t
rp_stream_log_script_write(rp_stream_session_t *s,
    rp_stream_log_script_t *script, u_char **name, u_char *buf, size_t len)
{
    ssize_t                     n;
    rp_str_t                   log;
    rp_open_file_info_t        of;
    rp_stream_log_srv_conf_t  *lscf;

    if (rp_stream_script_run(s, &log, script->lengths->elts, 1,
                              script->values->elts)
        == NULL)
    {
        /* simulate successful logging */
        return len;
    }

    log.data[log.len - 1] = '\0';
    *name = log.data;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log \"%s\"", log.data);

    lscf = rp_stream_get_module_srv_conf(s, rp_stream_log_module);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.log = 1;
    of.valid = lscf->open_file_cache_valid;
    of.min_uses = lscf->open_file_cache_min_uses;
    of.directio = RP_OPEN_FILE_DIRECTIO_OFF;

    if (rp_open_cached_file(lscf->open_file_cache, &log, &of,
                             s->connection->pool)
        != RP_OK)
    {
        if (of.err == 0) {
            /* simulate successful logging */
            return len;
        }

        rp_log_error(RP_LOG_CRIT, s->connection->log, rp_errno,
                      "%s \"%s\" failed", of.failed, log.data);
        /* simulate successful logging */
        return len;
    }

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream log #%d", of.fd);

    n = rp_write_fd(of.fd, buf, len);

    return n;
}


#if (RP_ZLIB)

static ssize_t
rp_stream_log_gzip(rp_fd_t fd, u_char *buf, size_t len, rp_int_t level,
    rp_log_t *log)
{
    int          rc, wbits, memlevel;
    u_char      *out;
    size_t       size;
    ssize_t      n;
    z_stream     zstream;
    rp_err_t    err;
    rp_pool_t  *pool;

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

    rp_memzero(&zstream, sizeof(z_stream));

    pool = rp_create_pool(256, log);
    if (pool == NULL) {
        /* simulate successful logging */
        return len;
    }

    pool->log = log;

    zstream.zalloc = rp_stream_log_gzip_alloc;
    zstream.zfree = rp_stream_log_gzip_free;
    zstream.opaque = pool;

    out = rp_pnalloc(pool, size);
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
        rp_log_error(RP_LOG_ALERT, log, 0, "deflateInit2() failed: %d", rc);
        goto done;
    }

    rp_log_debug4(RP_LOG_DEBUG_STREAM, log, 0,
                   "deflate in: ni:%p no:%p ai:%ud ao:%ud",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out);

    rc = deflate(&zstream, Z_FINISH);

    if (rc != Z_STREAM_END) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "deflate(Z_FINISH) failed: %d", rc);
        goto done;
    }

    rp_log_debug5(RP_LOG_DEBUG_STREAM, log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   zstream.next_in, zstream.next_out,
                   zstream.avail_in, zstream.avail_out,
                   rc);

    size -= zstream.avail_out;

    rc = deflateEnd(&zstream);

    if (rc != Z_OK) {
        rp_log_error(RP_LOG_ALERT, log, 0, "deflateEnd() failed: %d", rc);
        goto done;
    }

    n = rp_write_fd(fd, out, size);

    if (n != (ssize_t) size) {
        err = (n == -1) ? rp_errno : 0;

        rp_destroy_pool(pool);

        rp_set_errno(err);
        return -1;
    }

done:

    rp_destroy_pool(pool);

    /* simulate successful logging */
    return len;
}


static void *
rp_stream_log_gzip_alloc(void *opaque, u_int items, u_int size)
{
    rp_pool_t *pool = opaque;

    rp_log_debug2(RP_LOG_DEBUG_STREAM, pool->log, 0,
                   "gzip alloc: n:%ud s:%ud", items, size);

    return rp_palloc(pool, items * size);
}


static void
rp_stream_log_gzip_free(void *opaque, void *address)
{
#if 0
    rp_pool_t *pool = opaque;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, pool->log, 0,
                   "gzip free: %p", address);
#endif
}

#endif


static void
rp_stream_log_flush(rp_open_file_t *file, rp_log_t *log)
{
    size_t                 len;
    ssize_t                n;
    rp_stream_log_buf_t  *buffer;

    buffer = file->data;

    len = buffer->pos - buffer->start;

    if (len == 0) {
        return;
    }

#if (RP_ZLIB)
    if (buffer->gzip) {
        n = rp_stream_log_gzip(file->fd, buffer->start, len, buffer->gzip,
                                log);
    } else {
        n = rp_write_fd(file->fd, buffer->start, len);
    }
#else
    n = rp_write_fd(file->fd, buffer->start, len);
#endif

    if (n == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_write_fd_n " to \"%s\" failed",
                      file->name.data);

    } else if ((size_t) n != len) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      rp_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      file->name.data, n, len);
    }

    buffer->pos = buffer->start;

    if (buffer->event && buffer->event->timer_set) {
        rp_del_timer(buffer->event);
    }
}


static void
rp_stream_log_flush_handler(rp_event_t *ev)
{
    rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "stream log buffer flush handler");

    rp_stream_log_flush(ev->data, ev->log);
}


static u_char *
rp_stream_log_copy_short(rp_stream_session_t *s, u_char *buf,
    rp_stream_log_op_t *op)
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
rp_stream_log_copy_long(rp_stream_session_t *s, u_char *buf,
    rp_stream_log_op_t *op)
{
    return rp_cpymem(buf, (u_char *) op->data, op->len);
}


static rp_int_t
rp_stream_log_variable_compile(rp_conf_t *cf, rp_stream_log_op_t *op,
    rp_str_t *value, rp_uint_t escape)
{
    rp_int_t  index;

    index = rp_stream_get_variable_index(cf, value);
    if (index == RP_ERROR) {
        return RP_ERROR;
    }

    op->len = 0;

    switch (escape) {
    case RP_STREAM_LOG_ESCAPE_JSON:
        op->getlen = rp_stream_log_json_variable_getlen;
        op->run = rp_stream_log_json_variable;
        break;

    case RP_STREAM_LOG_ESCAPE_NONE:
        op->getlen = rp_stream_log_unescaped_variable_getlen;
        op->run = rp_stream_log_unescaped_variable;
        break;

    default: /* RP_STREAM_LOG_ESCAPE_DEFAULT */
        op->getlen = rp_stream_log_variable_getlen;
        op->run = rp_stream_log_variable;
    }

    op->data = index;

    return RP_OK;
}


static size_t
rp_stream_log_variable_getlen(rp_stream_session_t *s, uintptr_t data)
{
    uintptr_t                     len;
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, data);

    if (value == NULL || value->not_found) {
        return 1;
    }

    len = rp_stream_log_escape(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len * 3;
}


static u_char *
rp_stream_log_variable(rp_stream_session_t *s, u_char *buf,
    rp_stream_log_op_t *op)
{
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, op->data);

    if (value == NULL || value->not_found) {
        *buf = '-';
        return buf + 1;
    }

    if (value->escape == 0) {
        return rp_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) rp_stream_log_escape(buf, value->data, value->len);
    }
}


static uintptr_t
rp_stream_log_escape(u_char *dst, u_char *src, size_t size)
{
    rp_uint_t      n;
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
rp_stream_log_json_variable_getlen(rp_stream_session_t *s, uintptr_t data)
{
    uintptr_t                     len;
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    len = rp_escape_json(NULL, value->data, value->len);

    value->escape = len ? 1 : 0;

    return value->len + len;
}


static u_char *
rp_stream_log_json_variable(rp_stream_session_t *s, u_char *buf,
    rp_stream_log_op_t *op)
{
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    if (value->escape == 0) {
        return rp_cpymem(buf, value->data, value->len);

    } else {
        return (u_char *) rp_escape_json(buf, value->data, value->len);
    }
}


static size_t
rp_stream_log_unescaped_variable_getlen(rp_stream_session_t *s,
    uintptr_t data)
{
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, data);

    if (value == NULL || value->not_found) {
        return 0;
    }

    value->escape = 0;

    return value->len;
}


static u_char *
rp_stream_log_unescaped_variable(rp_stream_session_t *s, u_char *buf,
                                  rp_stream_log_op_t *op)
{
    rp_stream_variable_value_t  *value;

    value = rp_stream_get_indexed_variable(s, op->data);

    if (value == NULL || value->not_found) {
        return buf;
    }

    return rp_cpymem(buf, value->data, value->len);
}


static void *
rp_stream_log_create_main_conf(rp_conf_t *cf)
{
    rp_stream_log_main_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_log_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    if (rp_array_init(&conf->formats, cf->pool, 4,
                       sizeof(rp_stream_log_fmt_t))
        != RP_OK)
    {
        return NULL;
    }

    return conf;
}


static void *
rp_stream_log_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_log_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_log_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->open_file_cache = RP_CONF_UNSET_PTR;

    return conf;
}


static char *
rp_stream_log_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_log_srv_conf_t *prev = parent;
    rp_stream_log_srv_conf_t *conf = child;

    if (conf->open_file_cache == RP_CONF_UNSET_PTR) {

        conf->open_file_cache = prev->open_file_cache;
        conf->open_file_cache_valid = prev->open_file_cache_valid;
        conf->open_file_cache_min_uses = prev->open_file_cache_min_uses;

        if (conf->open_file_cache == RP_CONF_UNSET_PTR) {
            conf->open_file_cache = NULL;
        }
    }

    if (conf->logs || conf->off) {
        return RP_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    return RP_CONF_OK;
}


static char *
rp_stream_log_set_log(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_log_srv_conf_t *lscf = conf;

    ssize_t                              size;
    rp_int_t                            gzip;
    rp_uint_t                           i, n;
    rp_msec_t                           flush;
    rp_str_t                           *value, name, s;
    rp_stream_log_t                    *log;
    rp_syslog_peer_t                   *peer;
    rp_stream_log_buf_t                *buffer;
    rp_stream_log_fmt_t                *fmt;
    rp_stream_script_compile_t          sc;
    rp_stream_log_main_conf_t          *lmcf;
    rp_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        lscf->off = 1;
        if (cf->args->nelts == 2) {
            return RP_CONF_OK;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RP_CONF_ERROR;
    }

    if (lscf->logs == NULL) {
        lscf->logs = rp_array_create(cf->pool, 2, sizeof(rp_stream_log_t));
        if (lscf->logs == NULL) {
            return RP_CONF_ERROR;
        }
    }

    lmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_log_module);

    log = rp_array_push(lscf->logs);
    if (log == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(log, sizeof(rp_stream_log_t));


    if (rp_strncmp(value[1].data, "syslog:", 7) == 0) {

        peer = rp_pcalloc(cf->pool, sizeof(rp_syslog_peer_t));
        if (peer == NULL) {
            return RP_CONF_ERROR;
        }

        if (rp_syslog_process_conf(cf, peer) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }

        log->syslog_peer = peer;

        goto process_formats;
    }

    n = rp_stream_script_variables_count(&value[1]);

    if (n == 0) {
        log->file = rp_conf_open_file(cf->cycle, &value[1]);
        if (log->file == NULL) {
            return RP_CONF_ERROR;
        }

    } else {
        if (rp_conf_full_name(cf->cycle, &value[1], 0) != RP_OK) {
            return RP_CONF_ERROR;
        }

        log->script = rp_pcalloc(cf->pool, sizeof(rp_stream_log_script_t));
        if (log->script == NULL) {
            return RP_CONF_ERROR;
        }

        rp_memzero(&sc, sizeof(rp_stream_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &log->script->lengths;
        sc.values = &log->script->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rp_stream_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

process_formats:

    if (cf->args->nelts >= 3) {
        name = value[2];

    } else {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "log format is not specified");
        return RP_CONF_ERROR;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && rp_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            break;
        }
    }

    if (log->format == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "unknown log format \"%V\"", &name);
        return RP_CONF_ERROR;
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for (i = 3; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "buffer=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            size = rp_parse_size(&s);

            if (size == RP_ERROR || size == 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid buffer size \"%V\"", &s);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "flush=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            flush = rp_parse_time(&s, 0);

            if (flush == (rp_msec_t) RP_ERROR || flush == 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid flush time \"%V\"", &s);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "gzip", 4) == 0
            && (value[i].len == 4 || value[i].data[4] == '='))
        {
#if (RP_ZLIB)
            if (size == 0) {
                size = 64 * 1024;
            }

            if (value[i].len == 4) {
                gzip = Z_BEST_SPEED;
                continue;
            }

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            gzip = rp_atoi(s.data, s.len);

            if (gzip < 1 || gzip > 9) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid compression level \"%V\"", &s);
                return RP_CONF_ERROR;
            }

            continue;

#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "rap was built without zlib support");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strncmp(value[i].data, "if=", 3) == 0) {
            s.len = value[i].len - 3;
            s.data = value[i].data + 3;

            rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = rp_palloc(cf->pool,
                                           sizeof(rp_stream_complex_value_t));
            if (ccv.complex_value == NULL) {
                return RP_CONF_ERROR;
            }

            if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
                return RP_CONF_ERROR;
            }

            log->filter = ccv.complex_value;

            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RP_CONF_ERROR;
    }

    if (flush && size == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "no buffer is defined for access_log \"%V\"",
                           &value[1]);
        return RP_CONF_ERROR;
    }

    if (size) {

        if (log->script) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "buffered logs cannot have variables in name");
            return RP_CONF_ERROR;
        }

        if (log->syslog_peer) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "logs to syslog cannot be buffered");
            return RP_CONF_ERROR;
        }

        if (log->file->data) {
            buffer = log->file->data;

            if (buffer->last - buffer->start != size
                || buffer->flush != flush
                || buffer->gzip != gzip)
            {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "access_log \"%V\" already defined "
                                   "with conflicting parameters",
                                   &value[1]);
                return RP_CONF_ERROR;
            }

            return RP_CONF_OK;
        }

        buffer = rp_pcalloc(cf->pool, sizeof(rp_stream_log_buf_t));
        if (buffer == NULL) {
            return RP_CONF_ERROR;
        }

        buffer->start = rp_pnalloc(cf->pool, size);
        if (buffer->start == NULL) {
            return RP_CONF_ERROR;
        }

        buffer->pos = buffer->start;
        buffer->last = buffer->start + size;

        if (flush) {
            buffer->event = rp_pcalloc(cf->pool, sizeof(rp_event_t));
            if (buffer->event == NULL) {
                return RP_CONF_ERROR;
            }

            buffer->event->data = log->file;
            buffer->event->handler = rp_stream_log_flush_handler;
            buffer->event->log = &cf->cycle->new_log;
            buffer->event->cancelable = 1;

            buffer->flush = flush;
        }

        buffer->gzip = gzip;

        log->file->flush = rp_stream_log_flush;
        log->file->data = buffer;
    }

    return RP_CONF_OK;
}


static char *
rp_stream_log_set_format(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_log_main_conf_t *lmcf = conf;

    rp_str_t             *value;
    rp_uint_t             i;
    rp_stream_log_fmt_t  *fmt;

    value = cf->args->elts;

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len
            && rp_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return RP_CONF_ERROR;
        }
    }

    fmt = rp_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return RP_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->flushes = rp_array_create(cf->pool, 4, sizeof(rp_int_t));
    if (fmt->flushes == NULL) {
        return RP_CONF_ERROR;
    }

    fmt->ops = rp_array_create(cf->pool, 16, sizeof(rp_stream_log_op_t));
    if (fmt->ops == NULL) {
        return RP_CONF_ERROR;
    }

    return rp_stream_log_compile_format(cf, fmt->flushes, fmt->ops,
                                         cf->args, 2);
}


static char *
rp_stream_log_compile_format(rp_conf_t *cf, rp_array_t *flushes,
    rp_array_t *ops, rp_array_t *args, rp_uint_t s)
{
    u_char                *data, *p, ch;
    size_t                 i, len;
    rp_str_t             *value, var;
    rp_int_t             *flush;
    rp_uint_t             bracket, escape;
    rp_stream_log_op_t   *op;

    escape = RP_STREAM_LOG_ESCAPE_DEFAULT;
    value = args->elts;

    if (s < args->nelts && rp_strncmp(value[s].data, "escape=", 7) == 0) {
        data = value[s].data + 7;

        if (rp_strcmp(data, "json") == 0) {
            escape = RP_STREAM_LOG_ESCAPE_JSON;

        } else if (rp_strcmp(data, "none") == 0) {
            escape = RP_STREAM_LOG_ESCAPE_NONE;

        } else if (rp_strcmp(data, "default") != 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "unknown log format escaping \"%s\"", data);
            return RP_CONF_ERROR;
        }

        s++;
    }

    for ( /* void */ ; s < args->nelts; s++) {

        i = 0;

        while (i < value[s].len) {

            op = rp_array_push(ops);
            if (op == NULL) {
                return RP_CONF_ERROR;
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
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "the closing bracket in \"%V\" "
                                       "variable is missing", &var);
                    return RP_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                if (rp_stream_log_variable_compile(cf, op, &var, escape)
                    != RP_OK)
                {
                    return RP_CONF_ERROR;
                }

                if (flushes) {

                    flush = rp_array_push(flushes);
                    if (flush == NULL) {
                        return RP_CONF_ERROR;
                    }

                    *flush = op->data; /* variable index */
                }

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
                    op->run = rp_stream_log_copy_short;
                    op->data = 0;

                    while (len--) {
                        op->data <<= 8;
                        op->data |= data[len];
                    }

                } else {
                    op->run = rp_stream_log_copy_long;

                    p = rp_pnalloc(cf->pool, len);
                    if (p == NULL) {
                        return RP_CONF_ERROR;
                    }

                    rp_memcpy(p, data, len);
                    op->data = (uintptr_t) p;
                }
            }
        }
    }

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return RP_CONF_ERROR;
}


static char *
rp_stream_log_open_file_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_log_srv_conf_t *lscf = conf;

    time_t       inactive, valid;
    rp_str_t   *value, s;
    rp_int_t    max, min_uses;
    rp_uint_t   i;

    if (lscf->open_file_cache != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "max=", 4) == 0) {

            max = rp_atoi(value[i].data + 4, value[i].len - 4);
            if (max == RP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rp_parse_time(&s, 1);
            if (inactive == (time_t) RP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = rp_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == RP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = rp_parse_time(&s, 1);
            if (valid == (time_t) RP_ERROR) {
                goto failed;
            }

            continue;
        }

        if (rp_strcmp(value[i].data, "off") == 0) {

            lscf->open_file_cache = NULL;

            continue;
        }

    failed:

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return RP_CONF_ERROR;
    }

    if (lscf->open_file_cache == NULL) {
        return RP_CONF_OK;
    }

    if (max == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return RP_CONF_ERROR;
    }

    lscf->open_file_cache = rp_open_file_cache_init(cf->pool, max, inactive);

    if (lscf->open_file_cache) {

        lscf->open_file_cache_valid = valid;
        lscf->open_file_cache_min_uses = min_uses;

        return RP_CONF_OK;
    }

    return RP_CONF_ERROR;
}


static rp_int_t
rp_stream_log_init(rp_conf_t *cf)
{
    rp_stream_handler_pt        *h;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    h = rp_array_push(&cmcf->phases[RP_STREAM_LOG_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_stream_log_handler;

    return RP_OK;
}
