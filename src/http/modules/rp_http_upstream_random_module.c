
/*
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_http_upstream_rr_peer_t          *peer;
    rp_uint_t                            range;
} rp_http_upstream_random_range_t;


typedef struct {
    rp_uint_t                            two;
    rp_http_upstream_random_range_t     *ranges;
} rp_http_upstream_random_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    rp_http_upstream_rr_peer_data_t      rrp;

    rp_http_upstream_random_srv_conf_t  *conf;
    u_char                                tries;
} rp_http_upstream_random_peer_data_t;


static rp_int_t rp_http_upstream_init_random(rp_conf_t *cf,
    rp_http_upstream_srv_conf_t *us);
static rp_int_t rp_http_upstream_update_random(rp_pool_t *pool,
    rp_http_upstream_srv_conf_t *us);

static rp_int_t rp_http_upstream_init_random_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us);
static rp_int_t rp_http_upstream_get_random_peer(rp_peer_connection_t *pc,
    void *data);
static rp_int_t rp_http_upstream_get_random2_peer(rp_peer_connection_t *pc,
    void *data);
static rp_uint_t rp_http_upstream_peek_random_peer(
    rp_http_upstream_rr_peers_t *peers,
    rp_http_upstream_random_peer_data_t *rp);
static void *rp_http_upstream_random_create_conf(rp_conf_t *cf);
static char *rp_http_upstream_random(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_upstream_random_commands[] = {

    { rp_string("random"),
      RP_HTTP_UPS_CONF|RP_CONF_NOARGS|RP_CONF_TAKE12,
      rp_http_upstream_random,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_upstream_random_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_http_upstream_random_create_conf,  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_upstream_random_module = {
    RP_MODULE_V1,
    &rp_http_upstream_random_module_ctx,  /* module context */
    rp_http_upstream_random_commands,     /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_http_upstream_init_random(rp_conf_t *cf, rp_http_upstream_srv_conf_t *us)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, cf->log, 0, "init random");

    if (rp_http_upstream_init_round_robin(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    us->peer.init = rp_http_upstream_init_random_peer;

#if (RP_HTTP_UPSTREAM_ZONE)
    if (us->shm_zone) {
        return RP_OK;
    }
#endif

    return rp_http_upstream_update_random(cf->pool, us);
}


static rp_int_t
rp_http_upstream_update_random(rp_pool_t *pool,
    rp_http_upstream_srv_conf_t *us)
{
    size_t                                size;
    rp_uint_t                            i, total_weight;
    rp_http_upstream_rr_peer_t          *peer;
    rp_http_upstream_rr_peers_t         *peers;
    rp_http_upstream_random_range_t     *ranges;
    rp_http_upstream_random_srv_conf_t  *rcf;

    rcf = rp_http_conf_upstream_srv_conf(us, rp_http_upstream_random_module);

    peers = us->peer.data;

    size = peers->number * sizeof(rp_http_upstream_random_range_t);

    ranges = pool ? rp_palloc(pool, size) : rp_alloc(size, rp_cycle->log);
    if (ranges == NULL) {
        return RP_ERROR;
    }

    total_weight = 0;

    for (peer = peers->peer, i = 0; peer; peer = peer->next, i++) {
        ranges[i].peer = peer;
        ranges[i].range = total_weight;
        total_weight += peer->weight;
    }

    rcf->ranges = ranges;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_init_random_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us)
{
    rp_http_upstream_random_srv_conf_t   *rcf;
    rp_http_upstream_random_peer_data_t  *rp;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init random peer");

    rcf = rp_http_conf_upstream_srv_conf(us, rp_http_upstream_random_module);

    rp = rp_palloc(r->pool, sizeof(rp_http_upstream_random_peer_data_t));
    if (rp == NULL) {
        return RP_ERROR;
    }

    r->upstream->peer.data = &rp->rrp;

    if (rp_http_upstream_init_round_robin_peer(r, us) != RP_OK) {
        return RP_ERROR;
    }

    if (rcf->two) {
        r->upstream->peer.get = rp_http_upstream_get_random2_peer;

    } else {
        r->upstream->peer.get = rp_http_upstream_get_random_peer;
    }

    rp->conf = rcf;
    rp->tries = 0;

    rp_http_upstream_rr_peers_rlock(rp->rrp.peers);

#if (RP_HTTP_UPSTREAM_ZONE)
    if (rp->rrp.peers->shpool && rcf->ranges == NULL) {
        if (rp_http_upstream_update_random(NULL, us) != RP_OK) {
            rp_http_upstream_rr_peers_unlock(rp->rrp.peers);
            return RP_ERROR;
        }
    }
#endif

    rp_http_upstream_rr_peers_unlock(rp->rrp.peers);

    return RP_OK;
}


static rp_int_t
rp_http_upstream_get_random_peer(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_random_peer_data_t  *rp = data;

    time_t                             now;
    uintptr_t                          m;
    rp_uint_t                         i, n;
    rp_http_upstream_rr_peer_t       *peer;
    rp_http_upstream_rr_peers_t      *peers;
    rp_http_upstream_rr_peer_data_t  *rrp;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get random peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    rp_http_upstream_rr_peers_rlock(peers);

    if (rp->tries > 20 || peers->single) {
        rp_http_upstream_rr_peers_unlock(peers);
        return rp_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rp_time();

    for ( ;; ) {

        i = rp_http_upstream_peek_random_peer(peers, rp);

        peer = rp->conf->ranges[i].peer;

        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            goto next;
        }

        rp_http_upstream_rr_peer_lock(peers, peer);

        if (peer->down) {
            rp_http_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rp_http_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rp_http_upstream_rr_peer_unlock(peers, peer);
            goto next;
        }

        break;

    next:

        if (++rp->tries > 20) {
            rp_http_upstream_rr_peers_unlock(peers);
            return rp_http_upstream_get_round_robin_peer(pc, rrp);
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

    rp_http_upstream_rr_peer_unlock(peers, peer);
    rp_http_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_get_random2_peer(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_random_peer_data_t  *rp = data;

    time_t                             now;
    uintptr_t                          m;
    rp_uint_t                         i, n, p;
    rp_http_upstream_rr_peer_t       *peer, *prev;
    rp_http_upstream_rr_peers_t      *peers;
    rp_http_upstream_rr_peer_data_t  *rrp;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get random2 peer, try: %ui", pc->tries);

    rrp = &rp->rrp;
    peers = rrp->peers;

    rp_http_upstream_rr_peers_wlock(peers);

    if (rp->tries > 20 || peers->single) {
        rp_http_upstream_rr_peers_unlock(peers);
        return rp_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rp_time();

    prev = NULL;

#if (RP_SUPPRESS_WARN)
    p = 0;
#endif

    for ( ;; ) {

        i = rp_http_upstream_peek_random_peer(peers, rp);

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
            rp_http_upstream_rr_peers_unlock(peers);
            return rp_http_upstream_get_round_robin_peer(pc, rrp);
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

    rp_http_upstream_rr_peers_unlock(peers);

    rrp->tried[n] |= m;

    return RP_OK;
}


static rp_uint_t
rp_http_upstream_peek_random_peer(rp_http_upstream_rr_peers_t *peers,
    rp_http_upstream_random_peer_data_t *rp)
{
    rp_uint_t  i, j, k, x;

    x = rp_random() % peers->total_weight;

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
rp_http_upstream_random_create_conf(rp_conf_t *cf)
{
    rp_http_upstream_random_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_random_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->two = 0;
     */

    return conf;
}


static char *
rp_http_upstream_random(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_upstream_random_srv_conf_t  *rcf = conf;

    rp_str_t                     *value;
    rp_http_upstream_srv_conf_t  *uscf;

    uscf = rp_http_conf_get_module_srv_conf(cf, rp_http_upstream_module);

    if (uscf->peer.init_upstream) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rp_http_upstream_init_random;

    uscf->flags = RP_HTTP_UPSTREAM_CREATE
                  |RP_HTTP_UPSTREAM_WEIGHT
                  |RP_HTTP_UPSTREAM_MAX_CONNS
                  |RP_HTTP_UPSTREAM_MAX_FAILS
                  |RP_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |RP_HTTP_UPSTREAM_DOWN;

    if (cf->args->nelts == 1) {
        return RP_CONF_OK;
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "two") == 0) {
        rcf->two = 1;

    } else {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[2].data, "least_conn") != 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
