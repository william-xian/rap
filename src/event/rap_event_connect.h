
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_CONNECT_H_INCLUDED_
#define _RAP_EVENT_CONNECT_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define RAP_PEER_KEEPALIVE           1
#define RAP_PEER_NEXT                2
#define RAP_PEER_FAILED              4


typedef struct rap_peer_connection_s  rap_peer_connection_t;

typedef rap_int_t (*rap_event_get_peer_pt)(rap_peer_connection_t *pc,
    void *data);
typedef void (*rap_event_free_peer_pt)(rap_peer_connection_t *pc, void *data,
    rap_uint_t state);
typedef void (*rap_event_notify_peer_pt)(rap_peer_connection_t *pc,
    void *data, rap_uint_t type);
typedef rap_int_t (*rap_event_set_peer_session_pt)(rap_peer_connection_t *pc,
    void *data);
typedef void (*rap_event_save_peer_session_pt)(rap_peer_connection_t *pc,
    void *data);


struct rap_peer_connection_s {
    rap_connection_t                *connection;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    rap_str_t                       *name;

    rap_uint_t                       tries;
    rap_msec_t                       start_time;

    rap_event_get_peer_pt            get;
    rap_event_free_peer_pt           free;
    rap_event_notify_peer_pt         notify;
    void                            *data;

#if (RAP_SSL || RAP_COMPAT)
    rap_event_set_peer_session_pt    set_session;
    rap_event_save_peer_session_pt   save_session;
#endif

    rap_addr_t                      *local;

    int                              type;
    int                              rcvbuf;

    rap_log_t                       *log;

    unsigned                         cached:1;
    unsigned                         transparent:1;
    unsigned                         so_keepalive:1;
    unsigned                         down:1;

                                     /* rap_connection_log_error_e */
    unsigned                         log_error:2;

    RAP_COMPAT_BEGIN(2)
    RAP_COMPAT_END
};


rap_int_t rap_event_connect_peer(rap_peer_connection_t *pc);
rap_int_t rap_event_get_peer(rap_peer_connection_t *pc, void *data);


#endif /* _RAP_EVENT_CONNECT_H_INCLUDED_ */
