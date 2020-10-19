
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    /* the round robin data must be first */
    rap_http_upstream_rr_peer_data_t   rrp;

    rap_uint_t                         hash;

    u_char                             addrlen;
    u_char                            *addr;

    u_char                             tries;

    rap_event_get_peer_pt              get_rr_peer;
} rap_http_upstream_ip_hash_peer_data_t;


static rap_int_t rap_http_upstream_init_ip_hash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_get_ip_hash_peer(rap_peer_connection_t *pc,
    void *data);
static char *rap_http_upstream_ip_hash(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_upstream_ip_hash_commands[] = {

    { rap_string("ip_hash"),
      RAP_HTTP_UPS_CONF|RAP_CONF_NOARGS,
      rap_http_upstream_ip_hash,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_ip_hash_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_ip_hash_module_ctx, /* module context */
    rap_http_upstream_ip_hash_commands,    /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static u_char rap_http_upstream_ip_hash_pseudo_addr[3];


static rap_int_t
rap_http_upstream_init_ip_hash(rap_conf_t *cf, rap_http_upstream_srv_conf_t *us)
{
    if (rap_http_upstream_init_round_robin(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    us->peer.init = rap_http_upstream_init_ip_hash_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_init_ip_hash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    rap_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = rap_palloc(r->pool, sizeof(rap_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return RAP_ERROR;
    }

    r->upstream->peer.data = &iphp->rrp;

    if (rap_http_upstream_init_round_robin_peer(r, us) != RAP_OK) {
        return RAP_ERROR;
    }

    r->upstream->peer.get = rap_http_upstream_get_ip_hash_peer;

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = rap_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = rap_http_upstream_get_round_robin_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_get_ip_hash_peer(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    rap_int_t                     w;
    uintptr_t                     m;
    rap_uint_t                    i, n, p, hash;
    rap_http_upstream_rr_peer_t  *peer;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    rap_http_upstream_rr_peers_rlock(iphp->rrp.peers);

    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        rap_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }

    now = rap_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash;

    for ( ;; ) {

        for (i = 0; i < (rap_uint_t) iphp->addrlen; i++) {
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

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        rap_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);

        if (peer->down) {
            rap_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rap_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rap_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++iphp->tries > 20) {
            rap_http_upstream_rr_peers_unlock(iphp->rrp.peers);
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

    rap_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
    rap_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return RAP_OK;
}


static char *
rap_http_upstream_ip_hash(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_upstream_srv_conf_t  *uscf;

    uscf = rap_http_conf_get_module_srv_conf(cf, rap_http_upstream_module);

    if (uscf->peer.init_upstream) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rap_http_upstream_init_ip_hash;

    uscf->flags = RAP_HTTP_UPSTREAM_CREATE
                  |RAP_HTTP_UPSTREAM_WEIGHT
                  |RAP_HTTP_UPSTREAM_MAX_CONNS
                  |RAP_HTTP_UPSTREAM_MAX_FAILS
                  |RAP_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |RAP_HTTP_UPSTREAM_DOWN;

    return RAP_CONF_OK;
}
