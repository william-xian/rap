
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _RAP_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct rap_http_upstream_rr_peer_s   rap_http_upstream_rr_peer_t;

struct rap_http_upstream_rr_peer_s {
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    rap_str_t                       name;
    rap_str_t                       server;

    rap_int_t                       current_weight;
    rap_int_t                       effective_weight;
    rap_int_t                       weight;

    rap_uint_t                      conns;
    rap_uint_t                      max_conns;

    rap_uint_t                      fails;
    time_t                          accessed;
    time_t                          checked;

    rap_uint_t                      max_fails;
    time_t                          fail_timeout;
    rap_msec_t                      slow_start;
    rap_msec_t                      start_time;

    rap_uint_t                      down;

#if (RAP_HTTP_SSL || RAP_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (RAP_HTTP_UPSTREAM_ZONE)
    rap_atomic_t                    lock;
#endif

    rap_http_upstream_rr_peer_t    *next;

    RAP_COMPAT_BEGIN(32)
    RAP_COMPAT_END
};


typedef struct rap_http_upstream_rr_peers_s  rap_http_upstream_rr_peers_t;

struct rap_http_upstream_rr_peers_s {
    rap_uint_t                      number;

#if (RAP_HTTP_UPSTREAM_ZONE)
    rap_slab_pool_t                *shpool;
    rap_atomic_t                    rwlock;
    rap_http_upstream_rr_peers_t   *zone_next;
#endif

    rap_uint_t                      total_weight;

    unsigned                        single:1;
    unsigned                        weighted:1;

    rap_str_t                      *name;

    rap_http_upstream_rr_peers_t   *next;

    rap_http_upstream_rr_peer_t    *peer;
};


#if (RAP_HTTP_UPSTREAM_ZONE)

#define rap_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        rap_rwlock_rlock(&peers->rwlock);                                     \
    }

#define rap_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        rap_rwlock_wlock(&peers->rwlock);                                     \
    }

#define rap_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        rap_rwlock_unlock(&peers->rwlock);                                    \
    }


#define rap_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        rap_rwlock_wlock(&peer->lock);                                        \
    }

#define rap_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        rap_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define rap_http_upstream_rr_peers_rlock(peers)
#define rap_http_upstream_rr_peers_wlock(peers)
#define rap_http_upstream_rr_peers_unlock(peers)
#define rap_http_upstream_rr_peer_lock(peers, peer)
#define rap_http_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    rap_uint_t                      config;
    rap_http_upstream_rr_peers_t   *peers;
    rap_http_upstream_rr_peer_t    *current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} rap_http_upstream_rr_peer_data_t;


rap_int_t rap_http_upstream_init_round_robin(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us);
rap_int_t rap_http_upstream_init_round_robin_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
rap_int_t rap_http_upstream_create_round_robin_peer(rap_http_request_t *r,
    rap_http_upstream_resolved_t *ur);
rap_int_t rap_http_upstream_get_round_robin_peer(rap_peer_connection_t *pc,
    void *data);
void rap_http_upstream_free_round_robin_peer(rap_peer_connection_t *pc,
    void *data, rap_uint_t state);

#if (RAP_HTTP_SSL)
rap_int_t
    rap_http_upstream_set_round_robin_peer_session(rap_peer_connection_t *pc,
    void *data);
void rap_http_upstream_save_round_robin_peer_session(rap_peer_connection_t *pc,
    void *data);
#endif


#endif /* _RAP_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
