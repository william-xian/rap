
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _RP_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct rp_stream_upstream_rr_peer_s   rp_stream_upstream_rr_peer_t;

struct rp_stream_upstream_rr_peer_s {
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    rp_str_t                        name;
    rp_str_t                        server;

    rp_int_t                        current_weight;
    rp_int_t                        effective_weight;
    rp_int_t                        weight;

    rp_uint_t                       conns;
    rp_uint_t                       max_conns;

    rp_uint_t                       fails;
    time_t                           accessed;
    time_t                           checked;

    rp_uint_t                       max_fails;
    time_t                           fail_timeout;
    rp_msec_t                       slow_start;
    rp_msec_t                       start_time;

    rp_uint_t                       down;

    void                            *ssl_session;
    int                              ssl_session_len;

#if (RP_STREAM_UPSTREAM_ZONE)
    rp_atomic_t                     lock;
#endif

    rp_stream_upstream_rr_peer_t   *next;

    RP_COMPAT_BEGIN(25)
    RP_COMPAT_END
};


typedef struct rp_stream_upstream_rr_peers_s  rp_stream_upstream_rr_peers_t;

struct rp_stream_upstream_rr_peers_s {
    rp_uint_t                       number;

#if (RP_STREAM_UPSTREAM_ZONE)
    rp_slab_pool_t                 *shpool;
    rp_atomic_t                     rwlock;
    rp_stream_upstream_rr_peers_t  *zone_next;
#endif

    rp_uint_t                       total_weight;

    unsigned                         single:1;
    unsigned                         weighted:1;

    rp_str_t                       *name;

    rp_stream_upstream_rr_peers_t  *next;

    rp_stream_upstream_rr_peer_t   *peer;
};


#if (RP_STREAM_UPSTREAM_ZONE)

#define rp_stream_upstream_rr_peers_rlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        rp_rwlock_rlock(&peers->rwlock);                                     \
    }

#define rp_stream_upstream_rr_peers_wlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        rp_rwlock_wlock(&peers->rwlock);                                     \
    }

#define rp_stream_upstream_rr_peers_unlock(peers)                            \
                                                                              \
    if (peers->shpool) {                                                      \
        rp_rwlock_unlock(&peers->rwlock);                                    \
    }


#define rp_stream_upstream_rr_peer_lock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        rp_rwlock_wlock(&peer->lock);                                        \
    }

#define rp_stream_upstream_rr_peer_unlock(peers, peer)                       \
                                                                              \
    if (peers->shpool) {                                                      \
        rp_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define rp_stream_upstream_rr_peers_rlock(peers)
#define rp_stream_upstream_rr_peers_wlock(peers)
#define rp_stream_upstream_rr_peers_unlock(peers)
#define rp_stream_upstream_rr_peer_lock(peers, peer)
#define rp_stream_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    rp_uint_t                       config;
    rp_stream_upstream_rr_peers_t  *peers;
    rp_stream_upstream_rr_peer_t   *current;
    uintptr_t                       *tried;
    uintptr_t                        data;
} rp_stream_upstream_rr_peer_data_t;


rp_int_t rp_stream_upstream_init_round_robin(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us);
rp_int_t rp_stream_upstream_init_round_robin_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us);
rp_int_t rp_stream_upstream_create_round_robin_peer(rp_stream_session_t *s,
    rp_stream_upstream_resolved_t *ur);
rp_int_t rp_stream_upstream_get_round_robin_peer(rp_peer_connection_t *pc,
    void *data);
void rp_stream_upstream_free_round_robin_peer(rp_peer_connection_t *pc,
    void *data, rp_uint_t state);


#endif /* _RP_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
