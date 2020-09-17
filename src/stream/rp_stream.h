
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_H_INCLUDED_
#define _RP_STREAM_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>

#if (RP_STREAM_SSL)
#include <rp_stream_ssl_module.h>
#endif


typedef struct rp_stream_session_s  rp_stream_session_t;


#include <rp_stream_variables.h>
#include <rp_stream_script.h>
#include <rp_stream_upstream.h>
#include <rp_stream_upstream_round_robin.h>


#define RP_STREAM_OK                        200
#define RP_STREAM_BAD_REQUEST               400
#define RP_STREAM_FORBIDDEN                 403
#define RP_STREAM_INTERNAL_SERVER_ERROR     500
#define RP_STREAM_BAD_GATEWAY               502
#define RP_STREAM_SERVICE_UNAVAILABLE       503


typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} rp_stream_conf_ctx_t;


typedef struct {
    struct sockaddr               *sockaddr;
    socklen_t                      socklen;
    rp_str_t                      addr_text;

    /* server ctx */
    rp_stream_conf_ctx_t         *ctx;

    unsigned                       bind:1;
    unsigned                       wildcard:1;
    unsigned                       ssl:1;
#if (RP_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif
    unsigned                       reuseport:1;
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;
#if (RP_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif
    int                            backlog;
    int                            rcvbuf;
    int                            sndbuf;
    int                            type;
} rp_stream_listen_t;


typedef struct {
    rp_stream_conf_ctx_t         *ctx;
    rp_str_t                      addr_text;
    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
} rp_stream_addr_conf_t;

typedef struct {
    in_addr_t                      addr;
    rp_stream_addr_conf_t         conf;
} rp_stream_in_addr_t;


#if (RP_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    rp_stream_addr_conf_t         conf;
} rp_stream_in6_addr_t;

#endif


typedef struct {
    /* rp_stream_in_addr_t or rp_stream_in6_addr_t */
    void                          *addrs;
    rp_uint_t                     naddrs;
} rp_stream_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    rp_array_t                    addrs; /* array of rp_stream_conf_addr_t */
} rp_stream_conf_port_t;


typedef struct {
    rp_stream_listen_t            opt;
} rp_stream_conf_addr_t;


typedef enum {
    RP_STREAM_POST_ACCEPT_PHASE = 0,
    RP_STREAM_PREACCESS_PHASE,
    RP_STREAM_ACCESS_PHASE,
    RP_STREAM_SSL_PHASE,
    RP_STREAM_PREREAD_PHASE,
    RP_STREAM_CONTENT_PHASE,
    RP_STREAM_LOG_PHASE
} rp_stream_phases;


typedef struct rp_stream_phase_handler_s  rp_stream_phase_handler_t;

typedef rp_int_t (*rp_stream_phase_handler_pt)(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph);
typedef rp_int_t (*rp_stream_handler_pt)(rp_stream_session_t *s);
typedef void (*rp_stream_content_handler_pt)(rp_stream_session_t *s);


struct rp_stream_phase_handler_s {
    rp_stream_phase_handler_pt    checker;
    rp_stream_handler_pt          handler;
    rp_uint_t                     next;
};


typedef struct {
    rp_stream_phase_handler_t    *handlers;
} rp_stream_phase_engine_t;


typedef struct {
    rp_array_t                    handlers;
} rp_stream_phase_t;


typedef struct {
    rp_array_t                    servers;     /* rp_stream_core_srv_conf_t */
    rp_array_t                    listen;      /* rp_stream_listen_t */

    rp_stream_phase_engine_t      phase_engine;

    rp_hash_t                     variables_hash;

    rp_array_t                    variables;        /* rp_stream_variable_t */
    rp_array_t                    prefix_variables; /* rp_stream_variable_t */
    rp_uint_t                     ncaptures;

    rp_uint_t                     variables_hash_max_size;
    rp_uint_t                     variables_hash_bucket_size;

    rp_hash_keys_arrays_t        *variables_keys;

    rp_stream_phase_t             phases[RP_STREAM_LOG_PHASE + 1];
} rp_stream_core_main_conf_t;


typedef struct {
    rp_stream_content_handler_pt  handler;

    rp_stream_conf_ctx_t         *ctx;

    u_char                        *file_name;
    rp_uint_t                     line;

    rp_flag_t                     tcp_nodelay;
    size_t                         preread_buffer_size;
    rp_msec_t                     preread_timeout;

    rp_log_t                     *error_log;

    rp_msec_t                     resolver_timeout;
    rp_resolver_t                *resolver;

    rp_msec_t                     proxy_protocol_timeout;

    rp_uint_t                     listen;  /* unsigned  listen:1; */
} rp_stream_core_srv_conf_t;


struct rp_stream_session_s {
    uint32_t                       signature;         /* "STRM" */

    rp_connection_t              *connection;

    off_t                          received;
    time_t                         start_sec;
    rp_msec_t                     start_msec;

    rp_log_handler_pt             log_handler;

    void                         **ctx;
    void                         **main_conf;
    void                         **srv_conf;

    rp_stream_upstream_t         *upstream;
    rp_array_t                   *upstream_states;
                                           /* of rp_stream_upstream_state_t */
    rp_stream_variable_value_t   *variables;

#if (RP_PCRE)
    rp_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

    rp_int_t                      phase_handler;
    rp_uint_t                     status;

    unsigned                       ssl:1;

    unsigned                       stat_processing:1;

    unsigned                       health_check:1;

    unsigned                       limit_conn_status:2;
};


typedef struct {
    rp_int_t                    (*preconfiguration)(rp_conf_t *cf);
    rp_int_t                    (*postconfiguration)(rp_conf_t *cf);

    void                        *(*create_main_conf)(rp_conf_t *cf);
    char                        *(*init_main_conf)(rp_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(rp_conf_t *cf);
    char                        *(*merge_srv_conf)(rp_conf_t *cf, void *prev,
                                                   void *conf);
} rp_stream_module_t;


#define RP_STREAM_MODULE       0x4d525453     /* "STRM" */

#define RP_STREAM_MAIN_CONF    0x02000000
#define RP_STREAM_SRV_CONF     0x04000000
#define RP_STREAM_UPS_CONF     0x08000000


#define RP_STREAM_MAIN_CONF_OFFSET  offsetof(rp_stream_conf_ctx_t, main_conf)
#define RP_STREAM_SRV_CONF_OFFSET   offsetof(rp_stream_conf_ctx_t, srv_conf)


#define rp_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define rp_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define rp_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define rp_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define rp_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define rp_stream_conf_get_module_main_conf(cf, module)                       \
    ((rp_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define rp_stream_conf_get_module_srv_conf(cf, module)                        \
    ((rp_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define rp_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[rp_stream_module.index] ?                                \
        ((rp_stream_conf_ctx_t *) cycle->conf_ctx[rp_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


#define RP_STREAM_WRITE_BUFFERED  0x10


void rp_stream_core_run_phases(rp_stream_session_t *s);
rp_int_t rp_stream_core_generic_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph);
rp_int_t rp_stream_core_preread_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph);
rp_int_t rp_stream_core_content_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph);


void rp_stream_init_connection(rp_connection_t *c);
void rp_stream_session_handler(rp_event_t *rev);
void rp_stream_finalize_session(rp_stream_session_t *s, rp_uint_t rc);


extern rp_module_t  rp_stream_module;
extern rp_uint_t    rp_stream_max_module;
extern rp_module_t  rp_stream_core_module;


typedef rp_int_t (*rp_stream_filter_pt)(rp_stream_session_t *s,
    rp_chain_t *chain, rp_uint_t from_upstream);


extern rp_stream_filter_pt  rp_stream_top_filter;


#endif /* _RP_STREAM_H_INCLUDED_ */
