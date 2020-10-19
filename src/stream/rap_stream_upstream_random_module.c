
/*
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_stream_upstream_rr_peer_t          *peer;
    rap_uint_t                              range;
} rap_stream_upstream_random_range_t;


typedef struct {
    rap_uint_t                              two;
    rap_stream_upstream_random_range_t     *ranges;
} rap_stream_upstream_random_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    rap_stream_upstream_rr_peer_data_t      rrp;

    rap_stream_upstream_random_srv_conf_t  *conf;
    u_char                                  tries;
} rap_stream_upstream_random_peer_data_t;


static rap_int_t rap_stream_upstream_init_random(rap_conf_t *cf,
    rap_stream_upstream_srv_conf_t *us);
static rap_int_t rap_stream_upstream_update_random(rap_pool_t *pool,
    rap_stream_upstream_srv_conf_t *us);

static rap_int_t rap_stream_upstream_init_random_peer(rap_stream_session_t *s,
    rap_stream_upstream_srv_conf_t *us);
static rap_int_t rap_stream_upstream_get_random_peer(rap_peer_connection_t *pc,
    void *data);
static rap_int_t rap_stream_upstream_get_random2_peer(rap_peer_connection_t *pc,
    void *data);
static rap_uint_t rap_stream_upstream_peek_random_peer(
    rap_stream_upstream_rr_peers_t *peers,
    rap_stream_upstream_random_peer_data_t *rp);
static void *rap_stream_upstream_random_create_conf(rap_conf_t *cf);
static char *rap_stream_upstream_random(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_stream_upstream_random_commands[] = {

    { rap_string("random"),
      RAP_STREAM_UPS_CONF|RAP_CONF_NOARGS|RAP_CONF_TAKE12,
      rap_stream_upstream_random,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_upstream_random_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    rap_stream_upstream_random_create_conf,  /* create server configuration */
    NULL                                     /* merge server configuration */
};


rap_module_t  rap_stream_upstream_random_module = {
    RAP_MODULE_V1,
    &rap_stream_upstream_random_module_ctx,  /* module context */
    rap_stream_upstream_random_commands,     /* module directives */
    RAP_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_stream_upstream_init_random(rap_conf_t *cf,
    rap_stream_upstream_srv_conf_t *us)
{
    rap_log_debug0(RAP_LOG_DEBUG_STREAM, cf->log, 0, "init random");

    if (rap_stream_upstream_init_round_robin(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    us->peer.init = rap_stream_upstream_init_random_peer;

#if (RAP_STREAM_UPSTREAM_ZONE)
    if (us->shm_zone) {
        return RAP_OK;
    }
#endif

    return rap_stream_upstream_update_random(cf->pool, us);
}


static rap_int_t
rap_stream_upstream_update_random(rap_pool_t *pool,
    rap_stream_upstream_srv_conf_t *us)
{
    size_t                                  size;
    rap_uint_t                              i, total_weight;
    rap_stream_upstream_rr_peer_t          *peer;
    rap_stream_upstream_rr_peers_t         *peers;
    rap_stream_upstream_random_range_t     *ranges;
    rap_stream_upstream_random_srv_conf_t  *rcf;

    rcf = rap_stream_conf_upstream_srv_conf(us,
                                            rap_stream_upstream_random_module);
    peers = us->peer.data;

    size = peers->number * sizeof(rap_stream_upstream_random_range_t);

    ranges = pool ? rap_palloc(pool, size) : rap_alloc(size, rap_cycle->log);
    if (ranges == NULL) {
        return RAP_ERROR;
    }

    total_weight = 0;

    for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
        ranges[i].peer = peer;
        ranges[i].range = total_weight;
        total_weight += peer->weight;
    }

    rcf->ranges = ranges;

    return RAP_OK;
}


static rap_int_t
rap_stream_upstream_init_random_peer(rap_stream_session_t *s,
    rap_stream_upstream_srv_conf_t *us)
{
    rap_stream_upstream_random_srv_conf_t   *rcf;
    rap_stream_upstream_random_peer_data_t  *rp;

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init random peer");

    rcf = rap_stream_conf_upstream_srv_conf(us,
                                            rap_stream_upstream_random_module);

    rp = rap_palloc(s->connection->pool,
                    sizeof(rap_stream_upstream_random_peer_data_t));
    if (rp == NULL) {
        return RAP_ERROR;
    }

    s->upstream->peer.data = &rp->rrp;

    if (rap_stream_upstream_init_round_robin_peer(s, us) != RAP_OK) {
        return RAP_ERROR;
    }

    if (rcf->two) {
        s->upstream->peer.get = rap_stream_upstream_get_random2_peer;

    } else {
        s->upstream->peer.get = rap_stream_upstream_get_random_peer;
    }

    rp->conf = rcf;
    rp->tries = 0;

    rap_stream_upstream_rr_peers_rlock(rp->rrp.peers);

#if (RAP_STREAM_UPSTREAM_ZONE)
    if (rp->rrp.peers->shpool && rcf->ranges == NULL) {
        if (rap_stream_upstream_update_random(NULL, us) != RAP_OK) {
            rap_stream_upstream_rr_peers_unlock(rp->rrp.peers);
            return RAP_ERROR;
        }
    }
#endif

    rap_stream_upstream_rr_peers_unlock(rp->rrp.peers);

    return RAP_OK;
}


static rap_int_t
rap_stream_upstream_get_random_peer(rap_peer_connection_t *pc, void *data)
{
    rap_stream_upstream_random_peer_data_t  *rp = data;

    time_t                               now;
    uintptr_t                            m;
    rap_uint_t                           i, n;
    rap_stream_upstream_rr_peer_t       *peer;
    rap_stream_upstream_rr_peers_t      *peers;
    rap_stream_upstream_rr_peer_data_t  *rrp;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, pc->log, 0,
                   "get random peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    rap_stream_upstream_rr_peers_rlock(peers);

    if (rp->tries > 20 || peers->single) {
        rap_stream_upstream_rr_peers_unlock(peers);
        return rap_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rap_time();

    for ( ;; ) {

        i = rap_stream_upstream_peek_random_peer(peers, rp);

        peer = rp->conf->ranges[i].peer;

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            goto next;
        }

        rap_stream_upstream_rr_peer_lock(peers, peer);

        if (peer->down) {
            rap_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rap_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rap_stream_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        break;

    next:

        if (++rp->tries > 20) {
            rap_stream_upstream_rr_peers_unlock(peers);
            return rap_stream_upstream_get_round_robin_peer(pc, rrp);
        }
    }

    rrp->current = peer;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    rap_stream_upstream_rr_peer_unlock(peers, peer);
    rap_stream_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return RAP_OK;
}


static rap_int_t
rap_stream_upstream_get_random2_peer(rap_peer_connection_t *pc, void *data)
{
    rap_stream_upstream_random_peer_data_t  *rp = data;

    time_t                               now;
    uintptr_t                            m;
    rap_uint_t                           i, n, p;
    rap_stream_upstream_rr_peer_t       *peer, *prev;
    rap_stream_upstream_rr_peers_t      *peers;
    rap_stream_upstream_rr_peer_data_t  *rrp;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, pc->log, 0,
                   "get random2 peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    rap_stream_upstream_rr_peers_wlock(peers);

    if (rp->tries > 20 || peers->single) {
        rap_stream_upstream_rr_peers_unlock(peers);
        return rap_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rap_time();

    prev = NULL;

#if (RAP_SUPPRESS_WARN)
    p = 0;
#endif

    for ( ;; ) {

        i = rap_stream_upstream_peek_random_peer(peers, rp);

        peer = rp->conf->ranges[i].peer;

        if (peer == prev) {
            goto next;
        }

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            goto next;
        }

        if (peer->down) {
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }

        if (prev) {
            if (peer->conns * prev->weight > prev->conns * peer->weight) {
                peer = prev;
                n = p / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));
            }

            break;
        }

        prev = peer;
        p = i;

    next:

        if (++rp->tries > 20) {
            rap_stream_upstream_rr_peers_unlock(peers);
            return rap_stream_upstream_get_round_robin_peer(pc, rrp);
        }
    }

    rrp->current = peer;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    rap_stream_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return RAP_OK;
}


static rap_uint_t
rap_stream_upstream_peek_random_peer(rap_stream_upstream_rr_peers_t *peers,
    rap_stream_upstream_random_peer_data_t *rp)
{
    rap_uint_t  i, j, k, x;

    x = rap_random() % peers->total_weight;

    i = 0;
    j = peers->number;

    while (j - i > 1) {
        k = (i + j) / 2;

        if (x < rp->conf->ranges[k].range) {
            j = k;

        } else {
            i = k;
        }
    }

    return i;
}


static void *
rap_stream_upstream_random_create_conf(rap_conf_t *cf)
{
    rap_stream_upstream_random_srv_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_stream_upstream_random_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->two = 0;
     */

    return conf;
}


static char *
rap_stream_upstream_random(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_upstream_random_srv_conf_t  *rcf = conf;

    rap_str_t                       *value;
    rap_stream_upstream_srv_conf_t  *uscf;

    uscf = rap_stream_conf_get_module_srv_conf(cf, rap_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rap_stream_upstream_init_random;

    uscf->flags = RAP_STREAM_UPSTREAM_CREATE
                  |RAP_STREAM_UPSTREAM_WEIGHT
                  |RAP_STREAM_UPSTREAM_MAX_CONNS
                  |RAP_STREAM_UPSTREAM_MAX_FAILS
                  |RAP_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |RAP_STREAM_UPSTREAM_DOWN;

    if (cf->args->nelts == 1) {
        return RAP_CONF_OK;
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "two") == 0) {
        rcf->two = 1;

    } else {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[2].data, "least_conn") != 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
