
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


static char *rp_error_log(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_log_set_levels(rp_conf_t *cf, rp_log_t *log);
static void rp_log_insert(rp_log_t *log, rp_log_t *new_log);


#if (RP_DEBUG)

static void rp_log_memory_writer(rp_log_t *log, rp_uint_t level,
    u_char *buf, size_t len);
static void rp_log_memory_cleanup(void *data);


typedef struct {
    u_char        *start;
    u_char        *end;
    u_char        *pos;
    rp_atomic_t   written;
} rp_log_memory_buf_t;

#endif


static rp_command_t  rp_errlog_commands[] = {

    { rp_string("error_log"),
      RP_MAIN_CONF|RP_CONF_1MORE,
      rp_error_log,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_errlog_module_ctx = {
    rp_string("errlog"),
    NULL,
    NULL
};


rp_module_t  rp_errlog_module = {
    RP_MODULE_V1,
    &rp_errlog_module_ctx,                /* module context */
    rp_errlog_commands,                   /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_log_t        rp_log;
static rp_open_file_t  rp_log_file;
rp_uint_t              rp_use_stderr = 1;


static rp_str_t err_levels[] = {
    rp_null_string,
    rp_string("emerg"),
    rp_string("alert"),
    rp_string("crit"),
    rp_string("error"),
    rp_string("warn"),
    rp_string("notice"),
    rp_string("info"),
    rp_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


#if (RP_HAVE_VARIADIC_MACROS)

void
rp_log_error_core(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, ...)

#else

void
rp_log_error_core(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (RP_HAVE_VARIADIC_MACROS)
    va_list      args;
#endif
    u_char      *p, *last, *msg;
    ssize_t      n;
    rp_uint_t   wrote_stderr, debug_connection;
    u_char       errstr[RP_MAX_ERROR_STR];

    last = errstr + RP_MAX_ERROR_STR;

    p = rp_cpymem(errstr, rp_cached_err_log_time.data,
                   rp_cached_err_log_time.len);

    p = rp_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = rp_slprintf(p, last, "%P#" RP_TID_T_FMT ": ",
                    rp_log_pid, rp_log_tid);

    if (log->connection) {
        p = rp_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;

#if (RP_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = rp_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = rp_vslprintf(p, last, fmt, args);

#endif

    if (err) {
        p = rp_log_errno(p, last, err);
    }

    if (level != RP_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - RP_LINEFEED_SIZE) {
        p = last - RP_LINEFEED_SIZE;
    }

    rp_linefeed(p);

    wrote_stderr = 0;
    debug_connection = (log->log_level & RP_LOG_DEBUG_CONNECTION) != 0;

    while (log) {

        if (log->log_level < level && !debug_connection) {
            break;
        }

        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        if (rp_time() == log->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        n = rp_write_fd(log->file->fd, errstr, p - errstr);

        if (n == -1 && rp_errno == RP_ENOSPC) {
            log->disk_full_time = rp_time();
        }

        if (log->file->fd == rp_stderr) {
            wrote_stderr = 1;
        }

    next:

        log = log->next;
    }

    if (!rp_use_stderr
        || level > RP_LOG_WARN
        || wrote_stderr)
    {
        return;
    }

    msg -= (7 + err_levels[level].len + 3);

    (void) rp_sprintf(msg, "rap: [%V] ", &err_levels[level]);

    (void) rp_write_console(rp_stderr, msg, p - msg);
}


#if !(RP_HAVE_VARIADIC_MACROS)

void rp_cdecl
rp_log_error(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        rp_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void rp_cdecl
rp_log_debug_core(rp_log_t *log, rp_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    rp_log_error_core(RP_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void rp_cdecl
rp_log_abort(rp_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[RP_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = rp_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    rp_log_error(RP_LOG_ALERT, rp_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void rp_cdecl
rp_log_stderr(rp_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[RP_MAX_ERROR_STR];

    last = errstr + RP_MAX_ERROR_STR;

    p = rp_cpymem(errstr, "rap: ", 5);

    va_start(args, fmt);
    p = rp_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = rp_log_errno(p, last, err);
    }

    if (p > last - RP_LINEFEED_SIZE) {
        p = last - RP_LINEFEED_SIZE;
    }

    rp_linefeed(p);

    (void) rp_write_console(rp_stderr, errstr, p - errstr);
}


u_char *
rp_log_errno(u_char *buf, u_char *last, rp_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (RP_WIN32)
    buf = rp_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = rp_slprintf(buf, last, " (%d: ", err);
#endif

    buf = rp_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


rp_log_t *
rp_log_init(u_char *prefix)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    rp_log.file = &rp_log_file;
    rp_log.log_level = RP_LOG_NOTICE;

    name = (u_char *) RP_ERROR_LOG_PATH;

    /*
     * we use rp_strlen() here since BCC warns about
     * condition is always false and unreachable code
     */

    nlen = rp_strlen(name);

    if (nlen == 0) {
        rp_log_file.fd = rp_stderr;
        return &rp_log;
    }

    p = NULL;

#if (RP_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = rp_strlen(prefix);

        } else {
#ifdef RP_PREFIX
            prefix = (u_char *) RP_PREFIX;
            plen = rp_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = rp_cpymem(name, prefix, plen);

            if (!rp_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            rp_cpystrn(p, (u_char *) RP_ERROR_LOG_PATH, nlen + 1);

            p = name;
        }
    }

    rp_log_file.fd = rp_open_file(name, RP_FILE_APPEND,
                                    RP_FILE_CREATE_OR_OPEN,
                                    RP_FILE_DEFAULT_ACCESS);

    if (rp_log_file.fd == RP_INVALID_FILE) {
        rp_log_stderr(rp_errno,
                       "[alert] could not open error log file: "
                       rp_open_file_n " \"%s\" failed", name);
#if (RP_WIN32)
        rp_event_log(rp_errno,
                       "could not open error log file: "
                       rp_open_file_n " \"%s\" failed", name);
#endif

        rp_log_file.fd = rp_stderr;
    }

    if (p) {
        rp_free(p);
    }

    return &rp_log;
}


rp_int_t
rp_log_open_default(rp_cycle_t *cycle)
{
    rp_log_t         *log;
    static rp_str_t   error_log = rp_string(RP_ERROR_LOG_PATH);

    if (rp_log_get_file_log(&cycle->new_log) != NULL) {
        return RP_OK;
    }

    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = rp_pcalloc(cycle->pool, sizeof(rp_log_t));
        if (log == NULL) {
            return RP_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    log->log_level = RP_LOG_ERR;

    log->file = rp_conf_open_file(cycle, &error_log);
    if (log->file == NULL) {
        return RP_ERROR;
    }

    if (log != &cycle->new_log) {
        rp_log_insert(&cycle->new_log, log);
    }

    return RP_OK;
}


rp_int_t
rp_log_redirect_stderr(rp_cycle_t *cycle)
{
    rp_fd_t  fd;

    if (cycle->log_use_stderr) {
        return RP_OK;
    }

    /* file log always exists when we are called */
    fd = rp_log_get_file_log(cycle->log)->file->fd;

    if (fd != rp_stderr) {
        if (rp_set_stderr(fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          rp_set_stderr_n " failed");

            return RP_ERROR;
        }
    }

    return RP_OK;
}


rp_log_t *
rp_log_get_file_log(rp_log_t *head)
{
    rp_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


static char *
rp_log_set_levels(rp_conf_t *cf, rp_log_t *log)
{
    rp_uint_t   i, n, d, found;
    rp_str_t   *value;

    if (cf->args->nelts == 2) {
        log->log_level = RP_LOG_ERR;
        return RP_CONF_OK;
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= RP_LOG_DEBUG; n++) {
            if (rp_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return RP_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = RP_LOG_DEBUG_FIRST; d <= RP_LOG_DEBUG_LAST; d <<= 1) {
            if (rp_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~RP_LOG_DEBUG_ALL) {
                    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return RP_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }
    }

    if (log->log_level == RP_LOG_DEBUG) {
        log->log_level = RP_LOG_DEBUG_ALL;
    }

    return RP_CONF_OK;
}


static char *
rp_error_log(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    return rp_log_set_log(cf, &dummy);
}


char *
rp_log_set_log(rp_conf_t *cf, rp_log_t **head)
{
    rp_log_t          *new_log;
    rp_str_t          *value, name;
    rp_syslog_peer_t  *peer;

    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = rp_pcalloc(cf->pool, sizeof(rp_log_t));
        if (new_log == NULL) {
            return RP_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "stderr") == 0) {
        rp_str_null(&name);
        cf->cycle->log_use_stderr = 1;

        new_log->file = rp_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return RP_CONF_ERROR;
        }

    } else if (rp_strncmp(value[1].data, "memory:", 7) == 0) {

#if (RP_DEBUG)
        size_t                 size, needed;
        rp_pool_cleanup_t    *cln;
        rp_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        needed = sizeof("MEMLOG  :" RP_LINEFEED)
                 + cf->conf_file->file.name.len
                 + RP_SIZE_T_LEN
                 + RP_INT_T_LEN
                 + RP_MAX_ERROR_STR;

        size = rp_parse_size(&value[1]);

        if (size == (size_t) RP_ERROR || size < needed) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        buf = rp_pcalloc(cf->pool, sizeof(rp_log_memory_buf_t));
        if (buf == NULL) {
            return RP_CONF_ERROR;
        }

        buf->start = rp_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return RP_CONF_ERROR;
        }

        buf->end = buf->start + size;

        buf->pos = rp_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        rp_memset(buf->pos, ' ', buf->end - buf->pos);

        cln = rp_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return RP_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = rp_log_memory_cleanup;

        new_log->writer = rp_log_memory_writer;
        new_log->wdata = buf;

#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "rap was built without debug support");
        return RP_CONF_ERROR;
#endif

    } else if (rp_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = rp_pcalloc(cf->pool, sizeof(rp_syslog_peer_t));
        if (peer == NULL) {
            return RP_CONF_ERROR;
        }

        if (rp_syslog_process_conf(cf, peer) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }

        new_log->writer = rp_syslog_writer;
        new_log->wdata = peer;

    } else {
        new_log->file = rp_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return RP_CONF_ERROR;
        }
    }

    if (rp_log_set_levels(cf, new_log) != RP_CONF_OK) {
        return RP_CONF_ERROR;
    }

    if (*head != new_log) {
        rp_log_insert(*head, new_log);
    }

    return RP_CONF_OK;
}


static void
rp_log_insert(rp_log_t *log, rp_log_t *new_log)
{
    rp_log_t  tmp;

    if (new_log->log_level > log->log_level) {

        /*
         * list head address is permanent, insert new log after
         * head and swap its contents with head
         */

        tmp = *log;
        *log = *new_log;
        *new_log = tmp;

        log->next = new_log;
        return;
    }

    while (log->next) {
        if (new_log->log_level > log->next->log_level) {
            new_log->next = log->next;
            log->next = new_log;
            return;
        }

        log = log->next;
    }

    log->next = new_log;
}


#if (RP_DEBUG)

static void
rp_log_memory_writer(rp_log_t *log, rp_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    rp_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    written = rp_atomic_fetch_add(&mem->written, len);

    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        rp_memcpy(p, buf, len);

    } else {
        rp_memcpy(p, buf, avail);
        rp_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
rp_log_memory_cleanup(void *data)
{
    rp_log_t *log = data;

    rp_log_debug0(RP_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

#endif
