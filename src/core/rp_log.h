
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_LOG_H_INCLUDED_
#define _RP_LOG_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_LOG_STDERR            0
#define RP_LOG_EMERG             1
#define RP_LOG_ALERT             2
#define RP_LOG_CRIT              3
#define RP_LOG_ERR               4
#define RP_LOG_WARN              5
#define RP_LOG_NOTICE            6
#define RP_LOG_INFO              7
#define RP_LOG_DEBUG             8

#define RP_LOG_DEBUG_CORE        0x010
#define RP_LOG_DEBUG_ALLOC       0x020
#define RP_LOG_DEBUG_MUTEX       0x040
#define RP_LOG_DEBUG_EVENT       0x080
#define RP_LOG_DEBUG_HTTP        0x100
#define RP_LOG_DEBUG_MAIL        0x200
#define RP_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/rp_log.c
 * after the adding a new debug level
 */

#define RP_LOG_DEBUG_FIRST       RP_LOG_DEBUG_CORE
#define RP_LOG_DEBUG_LAST        RP_LOG_DEBUG_STREAM
#define RP_LOG_DEBUG_CONNECTION  0x80000000
#define RP_LOG_DEBUG_ALL         0x7ffffff0


typedef u_char *(*rp_log_handler_pt) (rp_log_t *log, u_char *buf, size_t len);
typedef void (*rp_log_writer_pt) (rp_log_t *log, rp_uint_t level,
    u_char *buf, size_t len);


struct rp_log_s {
    rp_uint_t           log_level;
    rp_open_file_t     *file;

    rp_atomic_uint_t    connection;

    time_t               disk_full_time;

    rp_log_handler_pt   handler;
    void                *data;

    rp_log_writer_pt    writer;
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    char                *action;

    rp_log_t           *next;
};


#define RP_MAX_ERROR_STR   2048


/*********************************/

#if (RP_HAVE_C99_VARIADIC_MACROS)

#define RP_HAVE_VARIADIC_MACROS  1

#define rp_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level) rp_log_error_core(level, log, __VA_ARGS__)

void rp_log_error_core(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, ...);

#define rp_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        rp_log_error_core(RP_LOG_DEBUG, log, __VA_ARGS__)

/*********************************/

#elif (RP_HAVE_GCC_VARIADIC_MACROS)

#define RP_HAVE_VARIADIC_MACROS  1

#define rp_log_error(level, log, args...)                                    \
    if ((log)->log_level >= level) rp_log_error_core(level, log, args)

void rp_log_error_core(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, ...);

#define rp_log_debug(level, log, args...)                                    \
    if ((log)->log_level & level)                                             \
        rp_log_error_core(RP_LOG_DEBUG, log, args)

/*********************************/

#else /* no variadic macros */

#define RP_HAVE_VARIADIC_MACROS  0

void rp_cdecl rp_log_error(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, ...);
void rp_log_error_core(rp_uint_t level, rp_log_t *log, rp_err_t err,
    const char *fmt, va_list args);
void rp_cdecl rp_log_debug_core(rp_log_t *log, rp_err_t err,
    const char *fmt, ...);


#endif /* variadic macros */


/*********************************/

#if (RP_DEBUG)

#if (RP_HAVE_VARIADIC_MACROS)

#define rp_log_debug0(level, log, err, fmt)                                  \
        rp_log_debug(level, log, err, fmt)

#define rp_log_debug1(level, log, err, fmt, arg1)                            \
        rp_log_debug(level, log, err, fmt, arg1)

#define rp_log_debug2(level, log, err, fmt, arg1, arg2)                      \
        rp_log_debug(level, log, err, fmt, arg1, arg2)

#define rp_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
        rp_log_debug(level, log, err, fmt, arg1, arg2, arg3)

#define rp_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
        rp_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)

#define rp_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
        rp_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define rp_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
        rp_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6)

#define rp_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
        rp_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define rp_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
        rp_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)


#else /* no variadic macros */

#define rp_log_debug0(level, log, err, fmt)                                  \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt)

#define rp_log_debug1(level, log, err, fmt, arg1)                            \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1)

#define rp_log_debug2(level, log, err, fmt, arg1, arg2)                      \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1, arg2)

#define rp_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1, arg2, arg3)

#define rp_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)

#define rp_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define rp_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)

#define rp_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define rp_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
    if ((log)->log_level & level)                                             \
        rp_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#endif

#else /* !RP_DEBUG */

#define rp_log_debug0(level, log, err, fmt)
#define rp_log_debug1(level, log, err, fmt, arg1)
#define rp_log_debug2(level, log, err, fmt, arg1, arg2)
#define rp_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define rp_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define rp_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define rp_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define rp_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define rp_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)

#endif

/*********************************/

rp_log_t *rp_log_init(u_char *prefix);
void rp_cdecl rp_log_abort(rp_err_t err, const char *fmt, ...);
void rp_cdecl rp_log_stderr(rp_err_t err, const char *fmt, ...);
u_char *rp_log_errno(u_char *buf, u_char *last, rp_err_t err);
rp_int_t rp_log_open_default(rp_cycle_t *cycle);
rp_int_t rp_log_redirect_stderr(rp_cycle_t *cycle);
rp_log_t *rp_log_get_file_log(rp_log_t *head);
char *rp_log_set_log(rp_conf_t *cf, rp_log_t **head);


/*
 * rp_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * rp_write_fd() is used instead of rp_write_console(), since
 * CharToOemBuff() inside rp_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for rp_write_stderr() anyway.
 */
static rp_inline void
rp_write_stderr(char *text)
{
    (void) rp_write_fd(rp_stderr, text, rp_strlen(text));
}


static rp_inline void
rp_write_stdout(char *text)
{
    (void) rp_write_fd(rp_stdout, text, rp_strlen(text));
}


extern rp_module_t  rp_errlog_module;
extern rp_uint_t    rp_use_stderr;


#endif /* _RP_LOG_H_INCLUDED_ */
