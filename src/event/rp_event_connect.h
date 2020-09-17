
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_CONNECT_H_INCLUDED_
#define _RP_EVENT_CONNECT_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define RP_PEER_KEEPALIVE           1
#define RP_PEER_NEXT                2
#define RP_PEER_FAILED              4


typedef struct rp_peer_connection_s  rp_peer_connection_t;

typedef rp_int_t (*rp_event_get_peer_pt)(rp_peer_connection_t *pc,
    void *data);
typedef void (*rp_event_free_peer_pt)(rp_peer_connection_t *pc, void *data,
    rp_uint_t state);
typedef void (*rp_event_notify_peer_pt)(rp_peer_connection_t *pc,
    void *data, rp_uint_t type);
typedef rp_int_t (*rp_event_set_peer_session_pt)(rp_peer_connection_t *pc,
    void *data);
typedef void (*rp_event_save_peer_session_pt)(rp_peer_connection_t *pc,
    void *data);


struct rp_peer_connection_s {
    rp_connection_t                *connection;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    rp_str_t                       *name;

    rp_uint_t                       tries;
    rp_msec_t                       start_time;

    rp_event_get_peer_pt            get;
    rp_event_free_peer_pt           free;
    rp_event_notify_peer_pt         notify;
    void                            *data;

#if (RP_SSL || RP_COMPAT)
    rp_event_set_peer_session_pt    set_session;
    rp_event_save_peer_session_pt   save_session;
#endif

    rp_addr_t                      *local;

    int                              type;
    int                              rcvbuf;

    rp_log_t                       *log;

    unsigned                         cached:1;
    unsigned                         transparent:1;
    unsigned                         so_keepalive:1;
    unsigned                         down:1;

                                     /* rp_connection_log_error_e */
    unsigned                         log_error:2;

    RP_COMPAT_BEGIN(2)
    RP_COMPAT_END
};


rp_int_t rp_event_connect_peer(rp_peer_connection_t *pc);
rp_int_t rp_event_get_peer(rp_peer_connection_t *pc, void *data);


#endif /* _RP_EVENT_CONNECT_H_INCLUDED_ */
