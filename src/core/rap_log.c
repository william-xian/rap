
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


static char *rap_error_log(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_log_set_levels(rap_conf_t *cf, rap_log_t *log);
static void rap_log_insert(rap_log_t *log, rap_log_t *new_log);


#if (RAP_DEBUG)

static void rap_log_memory_writer(rap_log_t *log, rap_uint_t level,
    u_char *buf, size_t len);
static void rap_log_memory_cleanup(void *data);


typedef struct {
    u_char        *start;
    u_char        *end;
    u_char        *pos;
    rap_atomic_t   written;
} rap_log_memory_buf_t;

#endif


static rap_command_t  rap_errlog_commands[] = {

    { rap_string("error_log"),
      RAP_MAIN_CONF|RAP_CONF_1MORE,
      rap_error_log,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_errlog_module_ctx = {
    rap_string("errlog"),
    NULL,
    NULL
};


rap_module_t  rap_errlog_module = {
    RAP_MODULE_V1,
    &rap_errlog_module_ctx,                /* module context */
    rap_errlog_commands,                   /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_log_t        rap_log;
static rap_open_file_t  rap_log_file;
rap_uint_t              rap_use_stderr = 1;


static rap_str_t err_levels[] = {
    rap_null_string,
    rap_string("emerg"),
    rap_string("alert"),
    rap_string("crit"),
    rap_string("error"),
    rap_string("warn"),
    rap_string("notice"),
    rap_string("info"),
    rap_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


#if (RAP_HAVE_VARIADIC_MACROS)

void
rap_log_error_core(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, ...)

#else

void
rap_log_error_core(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (RAP_HAVE_VARIADIC_MACROS)
    va_list      args;
#endif
    u_char      *p, *last, *msg;
    ssize_t      n;
    rap_uint_t   wrote_stderr, debug_connection;
    u_char       errstr[RAP_MAX_ERROR_STR];

    last = errstr + RAP_MAX_ERROR_STR;

    p = rap_cpymem(errstr, rap_cached_err_log_time.data,
                   rap_cached_err_log_time.len);

    p = rap_slprintf(p, last, " [%V] ", &err_levels[level]);

    /* pid#tid */
    p = rap_slprintf(p, last, "%P#" RAP_TID_T_FMT ": ",
                    rap_log_pid, rap_log_tid);

    if (log->connection) {
        p = rap_slprintf(p, last, "*%uA ", log->connection);
    }

    msg = p;

#if (RAP_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = rap_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = rap_vslprintf(p, last, fmt, args);

#endif

    if (err) {
        p = rap_log_errno(p, last, err);
    }

    if (level != RAP_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    if (p > last - RAP_LINEFEED_SIZE) {
        p = last - RAP_LINEFEED_SIZE;
    }

    rap_linefeed(p);

    wrote_stderr = 0;
    debug_connection = (log->log_level & RAP_LOG_DEBUG_CONNECTION) != 0;

    while (log) {

        if (log->log_level < level && !debug_connection) {
            break;
        }

        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        if (rap_time() == log->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        n = rap_write_fd(log->file->fd, errstr, p - errstr);

        if (n == -1 && rap_errno == RAP_ENOSPC) {
            log->disk_full_time = rap_time();
        }

        if (log->file->fd == rap_stderr) {
            wrote_stderr = 1;
        }

    next:

        log = log->next;
    }

    if (!rap_use_stderr
        || level > RAP_LOG_WARN
        || wrote_stderr)
    {
        return;
    }

    msg -= (7 + err_levels[level].len + 3);

    (void) rap_sprintf(msg, "rap: [%V] ", &err_levels[level]);

    (void) rap_write_console(rap_stderr, msg, p - msg);
}


#if !(RAP_HAVE_VARIADIC_MACROS)

void rap_cdecl
rap_log_error(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        rap_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void rap_cdecl
rap_log_debug_core(rap_log_t *log, rap_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    rap_log_error_core(RAP_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


void rap_cdecl
rap_log_abort(rap_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[RAP_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = rap_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    rap_log_error(RAP_LOG_ALERT, rap_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


void rap_cdecl
rap_log_stderr(rap_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[RAP_MAX_ERROR_STR];

    last = errstr + RAP_MAX_ERROR_STR;

    p = rap_cpymem(errstr, "rap: ", 5);

    va_start(args, fmt);
    p = rap_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = rap_log_errno(p, last, err);
    }

    if (p > last - RAP_LINEFEED_SIZE) {
        p = last - RAP_LINEFEED_SIZE;
    }

    rap_linefeed(p);

    (void) rap_write_console(rap_stderr, errstr, p - errstr);
}


u_char *
rap_log_errno(u_char *buf, u_char *last, rap_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (RAP_WIN32)
    buf = rap_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = rap_slprintf(buf, last, " (%d: ", err);
#endif

    buf = rap_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


rap_log_t *
rap_log_init(u_char *prefix)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    rap_log.file = &rap_log_file;
    rap_log.log_level = RAP_LOG_NOTICE;

    name = (u_char *) RAP_ERROR_LOG_PATH;

    /*
     * we use rap_strlen() here since BCC warns about
     * condition is always false and unreachable code
     */

    nlen = rap_strlen(name);

    if (nlen == 0) {
        rap_log_file.fd = rap_stderr;
        return &rap_log;
    }

    p = NULL;

#if (RAP_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        if (prefix) {
            plen = rap_strlen(prefix);

        } else {
#ifdef RAP_PREFIX
            prefix = (u_char *) RAP_PREFIX;
            plen = rap_strlen(prefix);
#else
            plen = 0;
#endif
        }

        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = rap_cpymem(name, prefix, plen);

            if (!rap_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            rap_cpystrn(p, (u_char *) RAP_ERROR_LOG_PATH, nlen + 1);

            p = name;
        }
    }

    rap_log_file.fd = rap_open_file(name, RAP_FILE_APPEND,
                                    RAP_FILE_CREATE_OR_OPEN,
                                    RAP_FILE_DEFAULT_ACCESS);

    if (rap_log_file.fd == RAP_INVALID_FILE) {
        rap_log_stderr(rap_errno,
                       "[alert] could not open error log file: "
                       rap_open_file_n " \"%s\" failed", name);
#if (RAP_WIN32)
        rap_event_log(rap_errno,
                       "could not open error log file: "
                       rap_open_file_n " \"%s\" failed", name);
#endif

        rap_log_file.fd = rap_stderr;
    }

    if (p) {
        rap_free(p);
    }

    return &rap_log;
}


rap_int_t
rap_log_open_default(rap_cycle_t *cycle)
{
    rap_log_t         *log;
    static rap_str_t   error_log = rap_string(RAP_ERROR_LOG_PATH);

    if (rap_log_get_file_log(&cycle->new_log) != NULL) {
        return RAP_OK;
    }

    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = rap_pcalloc(cycle->pool, sizeof(rap_log_t));
        if (log == NULL) {
            return RAP_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    log->log_level = RAP_LOG_ERR;

    log->file = rap_conf_open_file(cycle, &error_log);
    if (log->file == NULL) {
        return RAP_ERROR;
    }

    if (log != &cycle->new_log) {
        rap_log_insert(&cycle->new_log, log);
    }

    return RAP_OK;
}


rap_int_t
rap_log_redirect_stderr(rap_cycle_t *cycle)
{
    rap_fd_t  fd;

    if (cycle->log_use_stderr) {
        return RAP_OK;
    }

    /* file log always exists when we are called */
    fd = rap_log_get_file_log(cycle->log)->file->fd;

    if (fd != rap_stderr) {
        if (rap_set_stderr(fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          rap_set_stderr_n " failed");

            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


rap_log_t *
rap_log_get_file_log(rap_log_t *head)
{
    rap_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


static char *
rap_log_set_levels(rap_conf_t *cf, rap_log_t *log)
{
    rap_uint_t   i, n, d, found;
    rap_str_t   *value;

    if (cf->args->nelts == 2) {
        log->log_level = RAP_LOG_ERR;
        return RAP_CONF_OK;
    }

    value = cf->args->elts;

    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= RAP_LOG_DEBUG; n++) {
            if (rap_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return RAP_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = RAP_LOG_DEBUG_FIRST; d <= RAP_LOG_DEBUG_LAST; d <<= 1) {
            if (rap_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~RAP_LOG_DEBUG_ALL) {
                    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return RAP_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }
    }

    if (log->log_level == RAP_LOG_DEBUG) {
        log->log_level = RAP_LOG_DEBUG_ALL;
    }

    return RAP_CONF_OK;
}


static char *
rap_error_log(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    return rap_log_set_log(cf, &dummy);
}


char *
rap_log_set_log(rap_conf_t *cf, rap_log_t **head)
{
    rap_log_t          *new_log;
    rap_str_t          *value, name;
    rap_syslog_peer_t  *peer;

    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = rap_pcalloc(cf->pool, sizeof(rap_log_t));
        if (new_log == NULL) {
            return RAP_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "stderr") == 0) {
        rap_str_null(&name);
        cf->cycle->log_use_stderr = 1;

        new_log->file = rap_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return RAP_CONF_ERROR;
        }

    } else if (rap_strncmp(value[1].data, "memory:", 7) == 0) {

#if (RAP_DEBUG)
        size_t                 size, needed;
        rap_pool_cleanup_t    *cln;
        rap_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        needed = sizeof("MEMLOG  :" RAP_LINEFEED)
                 + cf->conf_file->file.name.len
                 + RAP_SIZE_T_LEN
                 + RAP_INT_T_LEN
                 + RAP_MAX_ERROR_STR;

        size = rap_parse_size(&value[1]);

        if (size == (size_t) RAP_ERROR || size < needed) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        buf = rap_pcalloc(cf->pool, sizeof(rap_log_memory_buf_t));
        if (buf == NULL) {
            return RAP_CONF_ERROR;
        }

        buf->start = rap_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return RAP_CONF_ERROR;
        }

        buf->end = buf->start + size;

        buf->pos = rap_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        rap_memset(buf->pos, ' ', buf->end - buf->pos);

        cln = rap_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return RAP_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = rap_log_memory_cleanup;

        new_log->writer = rap_log_memory_writer;
        new_log->wdata = buf;

#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "rap was built without debug support");
        return RAP_CONF_ERROR;
#endif

    } else if (rap_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = rap_pcalloc(cf->pool, sizeof(rap_syslog_peer_t));
        if (peer == NULL) {
            return RAP_CONF_ERROR;
        }

        if (rap_syslog_process_conf(cf, peer) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }

        new_log->writer = rap_syslog_writer;
        new_log->wdata = peer;

    } else {
        new_log->file = rap_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    if (rap_log_set_levels(cf, new_log) != RAP_CONF_OK) {
        return RAP_CONF_ERROR;
    }

    if (*head != new_log) {
        rap_log_insert(*head, new_log);
    }

    return RAP_CONF_OK;
}


static void
rap_log_insert(rap_log_t *log, rap_log_t *new_log)
{
    rap_log_t  tmp;

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


#if (RAP_DEBUG)

static void
rap_log_memory_writer(rap_log_t *log, rap_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    rap_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    written = rap_atomic_fetch_add(&mem->written, len);

    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        rap_memcpy(p, buf, len);

    } else {
        rap_memcpy(p, buf, avail);
        rap_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
rap_log_memory_cleanup(void *data)
{
    rap_log_t *log = data;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

#endif
