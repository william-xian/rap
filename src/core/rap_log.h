
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_LOG_H_INCLUDED_
#define _RAP_LOG_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_LOG_STDERR            0
#define RAP_LOG_EMERG             1
#define RAP_LOG_ALERT             2
#define RAP_LOG_CRIT              3
#define RAP_LOG_ERR               4
#define RAP_LOG_WARN              5
#define RAP_LOG_NOTICE            6
#define RAP_LOG_INFO              7
#define RAP_LOG_DEBUG             8

#define RAP_LOG_DEBUG_CORE        0x010
#define RAP_LOG_DEBUG_ALLOC       0x020
#define RAP_LOG_DEBUG_MUTEX       0x040
#define RAP_LOG_DEBUG_EVENT       0x080
#define RAP_LOG_DEBUG_HTTP        0x100
#define RAP_LOG_DEBUG_MAIL        0x200
#define RAP_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/rap_log.c
 * after the adding a new debug level
 */

#define RAP_LOG_DEBUG_FIRST       RAP_LOG_DEBUG_CORE
#define RAP_LOG_DEBUG_LAST        RAP_LOG_DEBUG_STREAM
#define RAP_LOG_DEBUG_CONNECTION  0x80000000
#define RAP_LOG_DEBUG_ALL         0x7ffffff0


typedef u_char *(*rap_log_handler_pt) (rap_log_t *log, u_char *buf, size_t len);
typedef void (*rap_log_writer_pt) (rap_log_t *log, rap_uint_t level,
    u_char *buf, size_t len);


struct rap_log_s {
    rap_uint_t           log_level;
    rap_open_file_t     *file;

    rap_atomic_uint_t    connection;

    time_t               disk_full_time;

    rap_log_handler_pt   handler;
    void                *data;

    rap_log_writer_pt    writer;
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    char                *action;

    rap_log_t           *next;
};


#define RAP_MAX_ERROR_STR   2048


/*********************************/

#if (RAP_HAVE_C99_VARIADIC_MACROS)

#define RAP_HAVE_VARIADIC_MACROS  1

#define rap_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level) rap_log_error_core(level, log, __VA_ARGS__)

void rap_log_error_core(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, ...);

#define rap_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        rap_log_error_core(RAP_LOG_DEBUG, log, __VA_ARGS__)

/*********************************/

#elif (RAP_HAVE_GCC_VARIADIC_MACROS)

#define RAP_HAVE_VARIADIC_MACROS  1

#define rap_log_error(level, log, args...)                                    \
    if ((log)->log_level >= level) rap_log_error_core(level, log, args)

void rap_log_error_core(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, ...);

#define rap_log_debug(level, log, args...)                                    \
    if ((log)->log_level & level)                                             \
        rap_log_error_core(RAP_LOG_DEBUG, log, args)

/*********************************/

#else /* no variadic macros */

#define RAP_HAVE_VARIADIC_MACROS  0

void rap_cdecl rap_log_error(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, ...);
void rap_log_error_core(rap_uint_t level, rap_log_t *log, rap_err_t err,
    const char *fmt, va_list args);
void rap_cdecl rap_log_debug_core(rap_log_t *log, rap_err_t err,
    const char *fmt, ...);


#endif /* variadic macros */


/*********************************/

#if (RAP_DEBUG)

#if (RAP_HAVE_VARIADIC_MACROS)

#define rap_log_debug0(level, log, err, fmt)                                  \
        rap_log_debug(level, log, err, fmt)

#define rap_log_debug1(level, log, err, fmt, arg1)                            \
        rap_log_debug(level, log, err, fmt, arg1)

#define rap_log_debug2(level, log, err, fmt, arg1, arg2)                      \
        rap_log_debug(level, log, err, fmt, arg1, arg2)

#define rap_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
        rap_log_debug(level, log, err, fmt, arg1, arg2, arg3)

#define rap_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
        rap_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)

#define rap_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
        rap_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define rap_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
        rap_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6)

#define rap_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
        rap_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define rap_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
        rap_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)


#else /* no variadic macros */

#define rap_log_debug0(level, log, err, fmt)                                  \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt)

#define rap_log_debug1(level, log, err, fmt, arg1)                            \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1)

#define rap_log_debug2(level, log, err, fmt, arg1, arg2)                      \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1, arg2)

#define rap_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1, arg2, arg3)

#define rap_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)

#define rap_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define rap_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)

#define rap_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define rap_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
    if ((log)->log_level & level)                                             \
        rap_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#endif

#else /* !RAP_DEBUG */

#define rap_log_debug0(level, log, err, fmt)
#define rap_log_debug1(level, log, err, fmt, arg1)
#define rap_log_debug2(level, log, err, fmt, arg1, arg2)
#define rap_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define rap_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define rap_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define rap_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define rap_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define rap_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)

#endif

/*********************************/

rap_log_t *rap_log_init(u_char *prefix);
void rap_cdecl rap_log_abort(rap_err_t err, const char *fmt, ...);
void rap_cdecl rap_log_stderr(rap_err_t err, const char *fmt, ...);
u_char *rap_log_errno(u_char *buf, u_char *last, rap_err_t err);
rap_int_t rap_log_open_default(rap_cycle_t *cycle);
rap_int_t rap_log_redirect_stderr(rap_cycle_t *cycle);
rap_log_t *rap_log_get_file_log(rap_log_t *head);
char *rap_log_set_log(rap_conf_t *cf, rap_log_t **head);


/*
 * rap_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * rap_write_fd() is used instead of rap_write_console(), since
 * CharToOemBuff() inside rap_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for rap_write_stderr() anyway.
 */
static rap_inline void
rap_write_stderr(char *text)
{
    (void) rap_write_fd(rap_stderr, text, rap_strlen(text));
}


static rap_inline void
rap_write_stdout(char *text)
{
    (void) rap_write_fd(rap_stdout, text, rap_strlen(text));
}


extern rap_module_t  rap_errlog_module;
extern rap_uint_t    rap_use_stderr;


#endif /* _RAP_LOG_H_INCLUDED_ */
