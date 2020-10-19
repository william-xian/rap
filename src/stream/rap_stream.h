
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_STREAM_H_INCLUDED_
#define _RAP_STREAM_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>

#if (RAP_STREAM_SSL)
#include <rap_stream_ssl_module.h>
#endif


typedef struct rap_stream_session_s  rap_stream_session_t;


#include <rap_stream_variables.h>
#include <rap_stream_script.h>
#include <rap_stream_upstream.h>
#include <rap_stream_upstream_round_robin.h>


#define RAP_STREAM_OK                        200
#define RAP_STREAM_BAD_REQUEST               400
#define RAP_STREAM_FORBIDDEN                 403
#define RAP_STREAM_INTERNAL_SERVER_ERROR     500
#define RAP_STREAM_BAD_GATEWAY               502
#define RAP_STREAM_SERVICE_UNAVAILABLE       503


typedef struct {
    void                         **main_conf;
    void                         **srv_conf;
} rap_stream_conf_ctx_t;


typedef struct {
    struct sockaddr               *sockaddr;
    socklen_t                      socklen;
    rap_str_t                      addr_text;

    /* server ctx */
    rap_stream_conf_ctx_t         *ctx;

    unsigned                       bind:1;
    unsigned                       wildcard:1;
    unsigned                       ssl:1;
#if (RAP_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif
    unsigned                       reuseport:1;
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;
#if (RAP_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif
    int                            backlog;
    int                            rcvbuf;
    int                            sndbuf;
    int                            type;
} rap_stream_listen_t;


typedef struct {
    rap_stream_conf_ctx_t         *ctx;
    rap_str_t                      addr_text;
    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
} rap_stream_addr_conf_t;

typedef struct {
    in_addr_t                      addr;
    rap_stream_addr_conf_t         conf;
} rap_stream_in_addr_t;


#if (RAP_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    rap_stream_addr_conf_t         conf;
} rap_stream_in6_addr_t;

#endif


typedef struct {
    /* rap_stream_in_addr_t or rap_stream_in6_addr_t */
    void                          *addrs;
    rap_uint_t                     naddrs;
} rap_stream_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    rap_array_t                    addrs; /* array of rap_stream_conf_addr_t */
} rap_stream_conf_port_t;


typedef struct {
    rap_stream_listen_t            opt;
} rap_stream_conf_addr_t;


typedef enum {
    RAP_STREAM_POST_ACCEPT_PHASE = 0,
    RAP_STREAM_PREACCESS_PHASE,
    RAP_STREAM_ACCESS_PHASE,
    RAP_STREAM_SSL_PHASE,
    RAP_STREAM_PREREAD_PHASE,
    RAP_STREAM_CONTENT_PHASE,
    RAP_STREAM_LOG_PHASE
} rap_stream_phases;


typedef struct rap_stream_phase_handler_s  rap_stream_phase_handler_t;

typedef rap_int_t (*rap_stream_phase_handler_pt)(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph);
typedef rap_int_t (*rap_stream_handler_pt)(rap_stream_session_t *s);
typedef void (*rap_stream_content_handler_pt)(rap_stream_session_t *s);


struct rap_stream_phase_handler_s {
    rap_stream_phase_handler_pt    checker;
    rap_stream_handler_pt          handler;
    rap_uint_t                     next;
};


typedef struct {
    rap_stream_phase_handler_t    *handlers;
} rap_stream_phase_engine_t;


typedef struct {
    rap_array_t                    handlers;
} rap_stream_phase_t;


typedef struct {
    rap_array_t                    servers;     /* rap_stream_core_srv_conf_t */
    rap_array_t                    listen;      /* rap_stream_listen_t */

    rap_stream_phase_engine_t      phase_engine;

    rap_hash_t                     variables_hash;

    rap_array_t                    variables;        /* rap_stream_variable_t */
    rap_array_t                    prefix_variables; /* rap_stream_variable_t */
    rap_uint_t                     ncaptures;

    rap_uint_t                     variables_hash_max_size;
    rap_uint_t                     variables_hash_bucket_size;

    rap_hash_keys_arrays_t        *variables_keys;

    rap_stream_phase_t             phases[RAP_STREAM_LOG_PHASE + 1];
} rap_stream_core_main_conf_t;


typedef struct {
    rap_stream_content_handler_pt  handler;

    rap_stream_conf_ctx_t         *ctx;

    u_char                        *file_name;
    rap_uint_t                     line;

    rap_flag_t                     tcp_nodelay;
    size_t                         preread_buffer_size;
    rap_msec_t                     preread_timeout;

    rap_log_t                     *error_log;

    rap_msec_t                     resolver_timeout;
    rap_resolver_t                *resolver;

    rap_msec_t                     proxy_protocol_timeout;

    rap_uint_t                     listen;  /* unsigned  listen:1; */
} rap_stream_core_srv_conf_t;


struct rap_stream_session_s {
    uint32_t                       signature;         /* "STRM" */

    rap_connection_t              *connection;

    off_t                          received;
    time_t                         start_sec;
    rap_msec_t                     start_msec;

    rap_log_handler_pt             log_handler;

    void                         **ctx;
    void                         **main_conf;
    void                         **srv_conf;

    rap_stream_upstream_t         *upstream;
    rap_array_t                   *upstream_states;
                                           /* of rap_stream_upstream_state_t */
    rap_stream_variable_value_t   *variables;

#if (RAP_PCRE)
    rap_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

    rap_int_t                      phase_handler;
    rap_uint_t                     status;

    unsigned                       ssl:1;

    unsigned                       stat_processing:1;

    unsigned                       health_check:1;

    unsigned                       limit_conn_status:2;
};


typedef struct {
    rap_int_t                    (*preconfiguration)(rap_conf_t *cf);
    rap_int_t                    (*postconfiguration)(rap_conf_t *cf);

    void                        *(*create_main_conf)(rap_conf_t *cf);
    char                        *(*init_main_conf)(rap_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(rap_conf_t *cf);
    char                        *(*merge_srv_conf)(rap_conf_t *cf, void *prev,
                                                   void *conf);
} rap_stream_module_t;


#define RAP_STREAM_MODULE       0x4d525453     /* "STRM" */

#define RAP_STREAM_MAIN_CONF    0x02000000
#define RAP_STREAM_SRV_CONF     0x04000000
#define RAP_STREAM_UPS_CONF     0x08000000


#define RAP_STREAM_MAIN_CONF_OFFSET  offsetof(rap_stream_conf_ctx_t, main_conf)
#define RAP_STREAM_SRV_CONF_OFFSET   offsetof(rap_stream_conf_ctx_t, srv_conf)


#define rap_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define rap_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define rap_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define rap_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define rap_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define rap_stream_conf_get_module_main_conf(cf, module)                       \
    ((rap_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define rap_stream_conf_get_module_srv_conf(cf, module)                        \
    ((rap_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define rap_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[rap_stream_module.index] ?                                \
        ((rap_stream_conf_ctx_t *) cycle->conf_ctx[rap_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


#define RAP_STREAM_WRITE_BUFFERED  0x10


void rap_stream_core_run_phases(rap_stream_session_t *s);
rap_int_t rap_stream_core_generic_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph);
rap_int_t rap_stream_core_preread_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph);
rap_int_t rap_stream_core_content_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph);


void rap_stream_init_connection(rap_connection_t *c);
void rap_stream_session_handler(rap_event_t *rev);
void rap_stream_finalize_session(rap_stream_session_t *s, rap_uint_t rc);


extern rap_module_t  rap_stream_module;
extern rap_uint_t    rap_stream_max_module;
extern rap_module_t  rap_stream_core_module;


typedef rap_int_t (*rap_stream_filter_pt)(rap_stream_session_t *s,
    rap_chain_t *chain, rap_uint_t from_upstream);


extern rap_stream_filter_pt  rap_stream_top_filter;


#endif /* _RAP_STREAM_H_INCLUDED_ */
