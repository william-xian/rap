
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_STREAM_UPSTREAM_H_INCLUDED_
#define _RAP_STREAM_UPSTREAM_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>
#include <rap_event_connect.h>


#define RAP_STREAM_UPSTREAM_CREATE        0x0001
#define RAP_STREAM_UPSTREAM_WEIGHT        0x0002
#define RAP_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define RAP_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define RAP_STREAM_UPSTREAM_DOWN          0x0010
#define RAP_STREAM_UPSTREAM_BACKUP        0x0020
#define RAP_STREAM_UPSTREAM_MAX_CONNS     0x0100


#define RAP_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1


typedef struct {
    rap_array_t                        upstreams;
                                           /* rap_stream_upstream_srv_conf_t */
} rap_stream_upstream_main_conf_t;


typedef struct rap_stream_upstream_srv_conf_s  rap_stream_upstream_srv_conf_t;


typedef rap_int_t (*rap_stream_upstream_init_pt)(rap_conf_t *cf,
    rap_stream_upstream_srv_conf_t *us);
typedef rap_int_t (*rap_stream_upstream_init_peer_pt)(rap_stream_session_t *s,
    rap_stream_upstream_srv_conf_t *us);


typedef struct {
    rap_stream_upstream_init_pt        init_upstream;
    rap_stream_upstream_init_peer_pt   init;
    void                              *data;
} rap_stream_upstream_peer_t;


typedef struct {
    rap_str_t                          name;
    rap_addr_t                        *addrs;
    rap_uint_t                         naddrs;
    rap_uint_t                         weight;
    rap_uint_t                         max_conns;
    rap_uint_t                         max_fails;
    time_t                             fail_timeout;
    rap_msec_t                         slow_start;
    rap_uint_t                         down;

    unsigned                           backup:1;

    RAP_COMPAT_BEGIN(4)
    RAP_COMPAT_END
} rap_stream_upstream_server_t;


struct rap_stream_upstream_srv_conf_s {
    rap_stream_upstream_peer_t         peer;
    void                             **srv_conf;

    rap_array_t                       *servers;
                                              /* rap_stream_upstream_server_t */

    rap_uint_t                         flags;
    rap_str_t                          host;
    u_char                            *file_name;
    rap_uint_t                         line;
    in_port_t                          port;
    rap_uint_t                         no_port;  /* unsigned no_port:1 */

#if (RAP_STREAM_UPSTREAM_ZONE)
    rap_shm_zone_t                    *shm_zone;
#endif
};


typedef struct {
    rap_msec_t                         response_time;
    rap_msec_t                         connect_time;
    rap_msec_t                         first_byte_time;
    off_t                              bytes_sent;
    off_t                              bytes_received;

    rap_str_t                         *peer;
} rap_stream_upstream_state_t;


typedef struct {
    rap_str_t                          host;
    in_port_t                          port;
    rap_uint_t                         no_port; /* unsigned no_port:1 */

    rap_uint_t                         naddrs;
    rap_resolver_addr_t               *addrs;

    struct sockaddr                   *sockaddr;
    socklen_t                          socklen;
    rap_str_t                          name;

    rap_resolver_ctx_t                *ctx;
} rap_stream_upstream_resolved_t;


typedef struct {
    rap_peer_connection_t              peer;

    rap_buf_t                          downstream_buf;
    rap_buf_t                          upstream_buf;

    rap_chain_t                       *free;
    rap_chain_t                       *upstream_out;
    rap_chain_t                       *upstream_busy;
    rap_chain_t                       *downstream_out;
    rap_chain_t                       *downstream_busy;

    off_t                              received;
    time_t                             start_sec;
    rap_uint_t                         requests;
    rap_uint_t                         responses;
    rap_msec_t                         start_time;

    size_t                             upload_rate;
    size_t                             download_rate;

    rap_str_t                          ssl_name;

    rap_stream_upstream_srv_conf_t    *upstream;
    rap_stream_upstream_resolved_t    *resolved;
    rap_stream_upstream_state_t       *state;
    unsigned                           connected:1;
    unsigned                           proxy_protocol:1;
} rap_stream_upstream_t;


rap_stream_upstream_srv_conf_t *rap_stream_upstream_add(rap_conf_t *cf,
    rap_url_t *u, rap_uint_t flags);


#define rap_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern rap_module_t  rap_stream_upstream_module;


#endif /* _RAP_STREAM_UPSTREAM_H_INCLUDED_ */
