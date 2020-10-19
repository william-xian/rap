
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_MODULE_H_INCLUDED_
#define _RAP_MODULE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap.h>


#define RAP_MODULE_UNSET_INDEX  (rap_uint_t) -1


#define RAP_MODULE_SIGNATURE_0                                                \
    rap_value(RAP_PTR_SIZE) ","                                               \
    rap_value(RAP_SIG_ATOMIC_T_SIZE) ","                                      \
    rap_value(RAP_TIME_T_SIZE) ","

#if (RAP_HAVE_KQUEUE)
#define RAP_MODULE_SIGNATURE_1   "1"
#else
#define RAP_MODULE_SIGNATURE_1   "0"
#endif

#if (RAP_HAVE_IOCP)
#define RAP_MODULE_SIGNATURE_2   "1"
#else
#define RAP_MODULE_SIGNATURE_2   "0"
#endif

#if (RAP_HAVE_FILE_AIO || RAP_COMPAT)
#define RAP_MODULE_SIGNATURE_3   "1"
#else
#define RAP_MODULE_SIGNATURE_3   "0"
#endif

#if (RAP_HAVE_AIO_SENDFILE || RAP_COMPAT)
#define RAP_MODULE_SIGNATURE_4   "1"
#else
#define RAP_MODULE_SIGNATURE_4   "0"
#endif

#if (RAP_HAVE_EVENTFD)
#define RAP_MODULE_SIGNATURE_5   "1"
#else
#define RAP_MODULE_SIGNATURE_5   "0"
#endif

#if (RAP_HAVE_EPOLL)
#define RAP_MODULE_SIGNATURE_6   "1"
#else
#define RAP_MODULE_SIGNATURE_6   "0"
#endif

#if (RAP_HAVE_KEEPALIVE_TUNABLE)
#define RAP_MODULE_SIGNATURE_7   "1"
#else
#define RAP_MODULE_SIGNATURE_7   "0"
#endif

#if (RAP_HAVE_INET6)
#define RAP_MODULE_SIGNATURE_8   "1"
#else
#define RAP_MODULE_SIGNATURE_8   "0"
#endif

#define RAP_MODULE_SIGNATURE_9   "1"
#define RAP_MODULE_SIGNATURE_10  "1"

#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
#define RAP_MODULE_SIGNATURE_11  "1"
#else
#define RAP_MODULE_SIGNATURE_11  "0"
#endif

#define RAP_MODULE_SIGNATURE_12  "1"

#if (RAP_HAVE_SETFIB)
#define RAP_MODULE_SIGNATURE_13  "1"
#else
#define RAP_MODULE_SIGNATURE_13  "0"
#endif

#if (RAP_HAVE_TCP_FASTOPEN)
#define RAP_MODULE_SIGNATURE_14  "1"
#else
#define RAP_MODULE_SIGNATURE_14  "0"
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
#define RAP_MODULE_SIGNATURE_15  "1"
#else
#define RAP_MODULE_SIGNATURE_15  "0"
#endif

#if (RAP_HAVE_VARIADIC_MACROS)
#define RAP_MODULE_SIGNATURE_16  "1"
#else
#define RAP_MODULE_SIGNATURE_16  "0"
#endif

#define RAP_MODULE_SIGNATURE_17  "0"
#define RAP_MODULE_SIGNATURE_18  "0"

#if (RAP_HAVE_OPENAT)
#define RAP_MODULE_SIGNATURE_19  "1"
#else
#define RAP_MODULE_SIGNATURE_19  "0"
#endif

#if (RAP_HAVE_ATOMIC_OPS)
#define RAP_MODULE_SIGNATURE_20  "1"
#else
#define RAP_MODULE_SIGNATURE_20  "0"
#endif

#if (RAP_HAVE_POSIX_SEM)
#define RAP_MODULE_SIGNATURE_21  "1"
#else
#define RAP_MODULE_SIGNATURE_21  "0"
#endif

#if (RAP_THREADS || RAP_COMPAT)
#define RAP_MODULE_SIGNATURE_22  "1"
#else
#define RAP_MODULE_SIGNATURE_22  "0"
#endif

#if (RAP_PCRE)
#define RAP_MODULE_SIGNATURE_23  "1"
#else
#define RAP_MODULE_SIGNATURE_23  "0"
#endif

#if (RAP_HTTP_SSL || RAP_COMPAT)
#define RAP_MODULE_SIGNATURE_24  "1"
#else
#define RAP_MODULE_SIGNATURE_24  "0"
#endif

#define RAP_MODULE_SIGNATURE_25  "1"

#if (RAP_HTTP_GZIP)
#define RAP_MODULE_SIGNATURE_26  "1"
#else
#define RAP_MODULE_SIGNATURE_26  "0"
#endif

#define RAP_MODULE_SIGNATURE_27  "1"

#if (RAP_HTTP_X_FORWARDED_FOR)
#define RAP_MODULE_SIGNATURE_28  "1"
#else
#define RAP_MODULE_SIGNATURE_28  "0"
#endif

#if (RAP_HTTP_REALIP)
#define RAP_MODULE_SIGNATURE_29  "1"
#else
#define RAP_MODULE_SIGNATURE_29  "0"
#endif

#if (RAP_HTTP_HEADERS)
#define RAP_MODULE_SIGNATURE_30  "1"
#else
#define RAP_MODULE_SIGNATURE_30  "0"
#endif

#if (RAP_HTTP_DAV)
#define RAP_MODULE_SIGNATURE_31  "1"
#else
#define RAP_MODULE_SIGNATURE_31  "0"
#endif

#if (RAP_HTTP_CACHE)
#define RAP_MODULE_SIGNATURE_32  "1"
#else
#define RAP_MODULE_SIGNATURE_32  "0"
#endif

#if (RAP_HTTP_UPSTREAM_ZONE)
#define RAP_MODULE_SIGNATURE_33  "1"
#else
#define RAP_MODULE_SIGNATURE_33  "0"
#endif

#if (RAP_COMPAT)
#define RAP_MODULE_SIGNATURE_34  "1"
#else
#define RAP_MODULE_SIGNATURE_34  "0"
#endif

#define RAP_MODULE_SIGNATURE                                                  \
    RAP_MODULE_SIGNATURE_0 RAP_MODULE_SIGNATURE_1 RAP_MODULE_SIGNATURE_2      \
    RAP_MODULE_SIGNATURE_3 RAP_MODULE_SIGNATURE_4 RAP_MODULE_SIGNATURE_5      \
    RAP_MODULE_SIGNATURE_6 RAP_MODULE_SIGNATURE_7 RAP_MODULE_SIGNATURE_8      \
    RAP_MODULE_SIGNATURE_9 RAP_MODULE_SIGNATURE_10 RAP_MODULE_SIGNATURE_11    \
    RAP_MODULE_SIGNATURE_12 RAP_MODULE_SIGNATURE_13 RAP_MODULE_SIGNATURE_14   \
    RAP_MODULE_SIGNATURE_15 RAP_MODULE_SIGNATURE_16 RAP_MODULE_SIGNATURE_17   \
    RAP_MODULE_SIGNATURE_18 RAP_MODULE_SIGNATURE_19 RAP_MODULE_SIGNATURE_20   \
    RAP_MODULE_SIGNATURE_21 RAP_MODULE_SIGNATURE_22 RAP_MODULE_SIGNATURE_23   \
    RAP_MODULE_SIGNATURE_24 RAP_MODULE_SIGNATURE_25 RAP_MODULE_SIGNATURE_26   \
    RAP_MODULE_SIGNATURE_27 RAP_MODULE_SIGNATURE_28 RAP_MODULE_SIGNATURE_29   \
    RAP_MODULE_SIGNATURE_30 RAP_MODULE_SIGNATURE_31 RAP_MODULE_SIGNATURE_32   \
    RAP_MODULE_SIGNATURE_33 RAP_MODULE_SIGNATURE_34


#define RAP_MODULE_V1                                                         \
    RAP_MODULE_UNSET_INDEX, RAP_MODULE_UNSET_INDEX,                           \
    NULL, 0, 0, rap_version, RAP_MODULE_SIGNATURE

#define RAP_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0


struct rap_module_s {
    rap_uint_t            ctx_index;
    rap_uint_t            index;

    char                 *name;

    rap_uint_t            spare0;
    rap_uint_t            spare1;

    rap_uint_t            version;
    const char           *signature;

    void                 *ctx;
    rap_command_t        *commands;
    rap_uint_t            type;

    rap_int_t           (*init_master)(rap_log_t *log);

    rap_int_t           (*init_module)(rap_cycle_t *cycle);

    rap_int_t           (*init_process)(rap_cycle_t *cycle);
    rap_int_t           (*init_thread)(rap_cycle_t *cycle);
    void                (*exit_thread)(rap_cycle_t *cycle);
    void                (*exit_process)(rap_cycle_t *cycle);

    void                (*exit_master)(rap_cycle_t *cycle);

    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


typedef struct {
    rap_str_t             name;
    void               *(*create_conf)(rap_cycle_t *cycle);
    char               *(*init_conf)(rap_cycle_t *cycle, void *conf);
} rap_core_module_t;


rap_int_t rap_preinit_modules(void);
rap_int_t rap_cycle_modules(rap_cycle_t *cycle);
rap_int_t rap_init_modules(rap_cycle_t *cycle);
rap_int_t rap_count_modules(rap_cycle_t *cycle, rap_uint_t type);


rap_int_t rap_add_module(rap_conf_t *cf, rap_str_t *file,
    rap_module_t *module, char **order);


extern rap_module_t  *rap_modules[];
extern rap_uint_t     rap_max_module;

extern char          *rap_module_names[];


#endif /* _RAP_MODULE_H_INCLUDED_ */
