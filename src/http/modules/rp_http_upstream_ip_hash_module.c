
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    /* the round robin data must be first */
    rp_http_upstream_rr_peer_data_t   rrp;

    rp_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    rp_event_get_peer_pt              get_rr_peer;
} rp_http_upstream_ip_hash_peer_data_t;


static rp_int_t rp_http_upstream_init_ip_hash_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us);
static rp_int_t rp_http_upstream_get_ip_hash_peer(rp_peer_connection_t *pc,
    void *data);
static char *rp_http_upstream_ip_hash(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_upstream_ip_hash_commands[] = {

    { rp_string("ip_hash"),
      RP_HTTP_UPS_CONF|RP_CONF_NOARGS,
      rp_http_upstream_ip_hash,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_upstream_ip_hash_module = {
    RP_MODULE_V1,
    &rp_http_upstream_ip_hash_module_ctx, /* module context */
    rp_http_upstream_ip_hash_commands,    /* module directives */
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


static u_char rp_http_upstream_ip_hash_pseudo_addr[3];


static rp_int_t
rp_http_upstream_init_ip_hash(rp_conf_t *cf, rp_http_upstream_srv_conf_t *us)
{
    if (rp_http_upstream_init_round_robin(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    us->peer.init = rp_http_upstream_init_ip_hash_peer;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_init_ip_hash_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    rp_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = rp_palloc(r->pool, sizeof(rp_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return RP_ERROR;
    }

    r->upstream->peer.data = &iphp->rrp;

    if (rp_http_upstream_init_round_robin_peer(r, us) != RP_OK) {
        return RP_ERROR;
    }

    r->upstream->peer.get = rp_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (RP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = rp_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = rp_http_upstream_get_round_robin_peer;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_get_ip_hash_peer(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    rp_int_t                     w;
    uintptr_t                     m;
    rp_uint_t                    i, n, p, hash;
    rp_http_upstream_rr_peer_t  *peer;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    rp_http_upstream_rr_peers_rlock(iphp->rrp.peers);

    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        rp_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }

    now = rp_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash;

    for ( ;; ) {

        for (i = 0; i < (rp_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }

        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (iphp->rrp.tried[n] & m) {
            goto next;
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        rp_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);

        if (peer->down) {
            rp_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rp_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rp_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++iphp->tries > 20) {
            rp_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }

    iphp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    rp_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
    rp_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return RP_OK;
}


static char *
rp_http_upstream_ip_hash(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_upstream_srv_conf_t  *uscf;

    uscf = rp_http_conf_get_module_srv_conf(cf, rp_http_upstream_module);

    if (uscf->peer.init_upstream) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rp_http_upstream_init_ip_hash;

    uscf->flags = RP_HTTP_UPSTREAM_CREATE
                  |RP_HTTP_UPSTREAM_WEIGHT
                  |RP_HTTP_UPSTREAM_MAX_CONNS
                  |RP_HTTP_UPSTREAM_MAX_FAILS
                  |RP_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |RP_HTTP_UPSTREAM_DOWN;

    return RP_CONF_OK;
}
