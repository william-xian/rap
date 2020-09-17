
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_UPSTREAM_H_INCLUDED_
#define _RP_STREAM_UPSTREAM_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>
#include <rp_event_connect.h>


#define RP_STREAM_UPSTREAM_CREATE        0x0001
#define RP_STREAM_UPSTREAM_WEIGHT        0x0002
#define RP_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define RP_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define RP_STREAM_UPSTREAM_DOWN          0x0010
#define RP_STREAM_UPSTREAM_BACKUP        0x0020
#define RP_STREAM_UPSTREAM_MAX_CONNS     0x0100


#define RP_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1


typedef struct {
    rp_array_t                        upstreams;
                                           /* rp_stream_upstream_srv_conf_t */
} rp_stream_upstream_main_conf_t;


typedef struct rp_stream_upstream_srv_conf_s  rp_stream_upstream_srv_conf_t;


typedef rp_int_t (*rp_stream_upstream_init_pt)(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us);
typedef rp_int_t (*rp_stream_upstream_init_peer_pt)(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us);


typedef struct {
    rp_stream_upstream_init_pt        init_upstream;
    rp_stream_upstream_init_peer_pt   init;
    void                              *data;
} rp_stream_upstream_peer_t;


typedef struct {
    rp_str_t                          name;
    rp_addr_t                        *addrs;
    rp_uint_t                         naddrs;
    rp_uint_t                         weight;
    rp_uint_t                         max_conns;
    rp_uint_t                         max_fails;
    time_t                             fail_timeout;
    rp_msec_t                         slow_start;
    rp_uint_t                         down;

    unsigned                           backup:1;

    RP_COMPAT_BEGIN(4)
    RP_COMPAT_END
} rp_stream_upstream_server_t;


struct rp_stream_upstream_srv_conf_s {
    rp_stream_upstream_peer_t         peer;
    void                             **srv_conf;

    rp_array_t                       *servers;
                                              /* rp_stream_upstream_server_t */

    rp_uint_t                         flags;
    rp_str_t                          host;
    u_char                            *file_name;
    rp_uint_t                         line;
    in_port_t                          port;
    rp_uint_t                         no_port;  /* unsigned no_port:1 */

#if (RP_STREAM_UPSTREAM_ZONE)
    rp_shm_zone_t                    *shm_zone;
#endif
};


typedef struct {
    rp_msec_t                         response_time;
    rp_msec_t                         connect_time;
    rp_msec_t                         first_byte_time;
    off_t                              bytes_sent;
    off_t                              bytes_received;

    rp_str_t                         *peer;
} rp_stream_upstream_state_t;


typedef struct {
    rp_str_t                          host;
    in_port_t                          port;
    rp_uint_t                         no_port; /* unsigned no_port:1 */

    rp_uint_t                         naddrs;
    rp_resolver_addr_t               *addrs;

    struct sockaddr                   *sockaddr;
    socklen_t                          socklen;
    rp_str_t                          name;

    rp_resolver_ctx_t                *ctx;
} rp_stream_upstream_resolved_t;


typedef struct {
    rp_peer_connection_t              peer;

    rp_buf_t                          downstream_buf;
    rp_buf_t                          upstream_buf;

    rp_chain_t                       *free;
    rp_chain_t                       *upstream_out;
    rp_chain_t                       *upstream_busy;
    rp_chain_t                       *downstream_out;
    rp_chain_t                       *downstream_busy;

    off_t                              received;
    time_t                             start_sec;
    rp_uint_t                         requests;
    rp_uint_t                         responses;
    rp_msec_t                         start_time;

    size_t                             upload_rate;
    size_t                             download_rate;

    rp_str_t                          ssl_name;

    rp_stream_upstream_srv_conf_t    *upstream;
    rp_stream_upstream_resolved_t    *resolved;
    rp_stream_upstream_state_t       *state;
    unsigned                           connected:1;
    unsigned                           proxy_protocol:1;
} rp_stream_upstream_t;


rp_stream_upstream_srv_conf_t *rp_stream_upstream_add(rp_conf_t *cf,
    rp_url_t *u, rp_uint_t flags);


#define rp_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern rp_module_t  rp_stream_upstream_module;


#endif /* _RP_STREAM_UPSTREAM_H_INCLUDED_ */
