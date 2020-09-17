
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_MODULE_H_INCLUDED_
#define _RP_MODULE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rap.h>


#define RP_MODULE_UNSET_INDEX  (rp_uint_t) -1


#define RP_MODULE_SIGNATURE_0                                                \
    rp_value(RP_PTR_SIZE) ","                                               \
    rp_value(RP_SIG_ATOMIC_T_SIZE) ","                                      \
    rp_value(RP_TIME_T_SIZE) ","

#if (RP_HAVE_KQUEUE)
#define RP_MODULE_SIGNATURE_1   "1"
#else
#define RP_MODULE_SIGNATURE_1   "0"
#endif

#if (RP_HAVE_IOCP)
#define RP_MODULE_SIGNATURE_2   "1"
#else
#define RP_MODULE_SIGNATURE_2   "0"
#endif

#if (RP_HAVE_FILE_AIO || RP_COMPAT)
#define RP_MODULE_SIGNATURE_3   "1"
#else
#define RP_MODULE_SIGNATURE_3   "0"
#endif

#if (RP_HAVE_AIO_SENDFILE || RP_COMPAT)
#define RP_MODULE_SIGNATURE_4   "1"
#else
#define RP_MODULE_SIGNATURE_4   "0"
#endif

#if (RP_HAVE_EVENTFD)
#define RP_MODULE_SIGNATURE_5   "1"
#else
#define RP_MODULE_SIGNATURE_5   "0"
#endif

#if (RP_HAVE_EPOLL)
#define RP_MODULE_SIGNATURE_6   "1"
#else
#define RP_MODULE_SIGNATURE_6   "0"
#endif

#if (RP_HAVE_KEEPALIVE_TUNABLE)
#define RP_MODULE_SIGNATURE_7   "1"
#else
#define RP_MODULE_SIGNATURE_7   "0"
#endif

#if (RP_HAVE_INET6)
#define RP_MODULE_SIGNATURE_8   "1"
#else
#define RP_MODULE_SIGNATURE_8   "0"
#endif

#define RP_MODULE_SIGNATURE_9   "1"
#define RP_MODULE_SIGNATURE_10  "1"

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
#define RP_MODULE_SIGNATURE_11  "1"
#else
#define RP_MODULE_SIGNATURE_11  "0"
#endif

#define RP_MODULE_SIGNATURE_12  "1"

#if (RP_HAVE_SETFIB)
#define RP_MODULE_SIGNATURE_13  "1"
#else
#define RP_MODULE_SIGNATURE_13  "0"
#endif

#if (RP_HAVE_TCP_FASTOPEN)
#define RP_MODULE_SIGNATURE_14  "1"
#else
#define RP_MODULE_SIGNATURE_14  "0"
#endif

#if (RP_HAVE_UNIX_DOMAIN)
#define RP_MODULE_SIGNATURE_15  "1"
#else
#define RP_MODULE_SIGNATURE_15  "0"
#endif

#if (RP_HAVE_VARIADIC_MACROS)
#define RP_MODULE_SIGNATURE_16  "1"
#else
#define RP_MODULE_SIGNATURE_16  "0"
#endif

#define RP_MODULE_SIGNATURE_17  "0"
#define RP_MODULE_SIGNATURE_18  "0"

#if (RP_HAVE_OPENAT)
#define RP_MODULE_SIGNATURE_19  "1"
#else
#define RP_MODULE_SIGNATURE_19  "0"
#endif

#if (RP_HAVE_ATOMIC_OPS)
#define RP_MODULE_SIGNATURE_20  "1"
#else
#define RP_MODULE_SIGNATURE_20  "0"
#endif

#if (RP_HAVE_POSIX_SEM)
#define RP_MODULE_SIGNATURE_21  "1"
#else
#define RP_MODULE_SIGNATURE_21  "0"
#endif

#if (RP_THREADS || RP_COMPAT)
#define RP_MODULE_SIGNATURE_22  "1"
#else
#define RP_MODULE_SIGNATURE_22  "0"
#endif

#if (RP_PCRE)
#define RP_MODULE_SIGNATURE_23  "1"
#else
#define RP_MODULE_SIGNATURE_23  "0"
#endif

#if (RP_HTTP_SSL || RP_COMPAT)
#define RP_MODULE_SIGNATURE_24  "1"
#else
#define RP_MODULE_SIGNATURE_24  "0"
#endif

#define RP_MODULE_SIGNATURE_25  "1"

#if (RP_HTTP_GZIP)
#define RP_MODULE_SIGNATURE_26  "1"
#else
#define RP_MODULE_SIGNATURE_26  "0"
#endif

#define RP_MODULE_SIGNATURE_27  "1"

#if (RP_HTTP_X_FORWARDED_FOR)
#define RP_MODULE_SIGNATURE_28  "1"
#else
#define RP_MODULE_SIGNATURE_28  "0"
#endif

#if (RP_HTTP_REALIP)
#define RP_MODULE_SIGNATURE_29  "1"
#else
#define RP_MODULE_SIGNATURE_29  "0"
#endif

#if (RP_HTTP_HEADERS)
#define RP_MODULE_SIGNATURE_30  "1"
#else
#define RP_MODULE_SIGNATURE_30  "0"
#endif

#if (RP_HTTP_DAV)
#define RP_MODULE_SIGNATURE_31  "1"
#else
#define RP_MODULE_SIGNATURE_31  "0"
#endif

#if (RP_HTTP_CACHE)
#define RP_MODULE_SIGNATURE_32  "1"
#else
#define RP_MODULE_SIGNATURE_32  "0"
#endif

#if (RP_HTTP_UPSTREAM_ZONE)
#define RP_MODULE_SIGNATURE_33  "1"
#else
#define RP_MODULE_SIGNATURE_33  "0"
#endif

#if (RP_COMPAT)
#define RP_MODULE_SIGNATURE_34  "1"
#else
#define RP_MODULE_SIGNATURE_34  "0"
#endif

#define RP_MODULE_SIGNATURE                                                  \
    RP_MODULE_SIGNATURE_0 RP_MODULE_SIGNATURE_1 RP_MODULE_SIGNATURE_2      \
    RP_MODULE_SIGNATURE_3 RP_MODULE_SIGNATURE_4 RP_MODULE_SIGNATURE_5      \
    RP_MODULE_SIGNATURE_6 RP_MODULE_SIGNATURE_7 RP_MODULE_SIGNATURE_8      \
    RP_MODULE_SIGNATURE_9 RP_MODULE_SIGNATURE_10 RP_MODULE_SIGNATURE_11    \
    RP_MODULE_SIGNATURE_12 RP_MODULE_SIGNATURE_13 RP_MODULE_SIGNATURE_14   \
    RP_MODULE_SIGNATURE_15 RP_MODULE_SIGNATURE_16 RP_MODULE_SIGNATURE_17   \
    RP_MODULE_SIGNATURE_18 RP_MODULE_SIGNATURE_19 RP_MODULE_SIGNATURE_20   \
    RP_MODULE_SIGNATURE_21 RP_MODULE_SIGNATURE_22 RP_MODULE_SIGNATURE_23   \
    RP_MODULE_SIGNATURE_24 RP_MODULE_SIGNATURE_25 RP_MODULE_SIGNATURE_26   \
    RP_MODULE_SIGNATURE_27 RP_MODULE_SIGNATURE_28 RP_MODULE_SIGNATURE_29   \
    RP_MODULE_SIGNATURE_30 RP_MODULE_SIGNATURE_31 RP_MODULE_SIGNATURE_32   \
    RP_MODULE_SIGNATURE_33 RP_MODULE_SIGNATURE_34


#define RP_MODULE_V1                                                         \
    RP_MODULE_UNSET_INDEX, RP_MODULE_UNSET_INDEX,                           \
    NULL, 0, 0, rap_version, RP_MODULE_SIGNATURE

#define RP_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0


struct rp_module_s {
    rp_uint_t            ctx_index;
    rp_uint_t            index;

    char                 *name;

    rp_uint_t            spare0;
    rp_uint_t            spare1;

    rp_uint_t            version;
    const char           *signature;

    void                 *ctx;
    rp_command_t        *commands;
    rp_uint_t            type;

    rp_int_t           (*init_master)(rp_log_t *log);

    rp_int_t           (*init_module)(rp_cycle_t *cycle);

    rp_int_t           (*init_process)(rp_cycle_t *cycle);
    rp_int_t           (*init_thread)(rp_cycle_t *cycle);
    void                (*exit_thread)(rp_cycle_t *cycle);
    void                (*exit_process)(rp_cycle_t *cycle);

    void                (*exit_master)(rp_cycle_t *cycle);

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
    rp_str_t             name;
    void               *(*create_conf)(rp_cycle_t *cycle);
    char               *(*init_conf)(rp_cycle_t *cycle, void *conf);
} rp_core_module_t;


rp_int_t rp_preinit_modules(void);
rp_int_t rp_cycle_modules(rp_cycle_t *cycle);
rp_int_t rp_init_modules(rp_cycle_t *cycle);
rp_int_t rp_count_modules(rp_cycle_t *cycle, rp_uint_t type);


rp_int_t rp_add_module(rp_conf_t *cf, rp_str_t *file,
    rp_module_t *module, char **order);


extern rp_module_t  *rp_modules[];
extern rp_uint_t     rp_max_module;

extern char          *rp_module_names[];


#endif /* _RP_MODULE_H_INCLUDED_ */
