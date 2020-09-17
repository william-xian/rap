
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define rp_http_upstream_tries(p) ((p)->number                               \
                                    + ((p)->next ? (p)->next->number : 0))


static rp_http_upstream_rr_peer_t *rp_http_upstream_get_peer(
    rp_http_upstream_rr_peer_data_t *rrp);

#if (RP_HTTP_SSL)

static rp_int_t rp_http_upstream_empty_set_session(rp_peer_connection_t *pc,
    void *data);
static void rp_http_upstream_empty_save_session(rp_peer_connection_t *pc,
    void *data);

#endif


rp_int_t
rp_http_upstream_init_round_robin(rp_conf_t *cf,
    rp_http_upstream_srv_conf_t *us)
{
    rp_url_t                      u;
    rp_uint_t                     i, j, n, w;
    rp_http_upstream_server_t    *server;
    rp_http_upstream_rr_peer_t   *peer, **peerp;
    rp_http_upstream_rr_peers_t  *peers, *backup;

    us->peer.init = rp_http_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;
        w = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no servers in upstream \"%V\" in %s:%ui",
                          &us->host, us->file_name, us->line);
            return RP_ERROR;
        }

        peers = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peers_t));
        if (peers == NULL) {
            return RP_ERROR;
        }

        peer = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return RP_ERROR;
        }

        peers->single = (n == 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;
        peers->name = &us->host;

        n = 0;
        peerp = &peers->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        us->peer.data = peers;

        /* backup servers */

        n = 0;
        w = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
            w += server[i].naddrs * server[i].weight;
        }

        if (n == 0) {
            return RP_OK;
        }

        backup = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peers_t));
        if (backup == NULL) {
            return RP_ERROR;
        }

        peer = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peer_t) * n);
        if (peer == NULL) {
            return RP_ERROR;
        }

        peers->single = 0;
        backup->single = 0;
        backup->number = n;
        backup->weighted = (w != n);
        backup->total_weight = w;
        backup->name = &us->host;

        n = 0;
        peerp = &backup->peer;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            for (j = 0; j < server[i].naddrs; j++) {
                peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peer[n].socklen = server[i].addrs[j].socklen;
                peer[n].name = server[i].addrs[j].name;
                peer[n].weight = server[i].weight;
                peer[n].effective_weight = server[i].weight;
                peer[n].current_weight = 0;
                peer[n].max_conns = server[i].max_conns;
                peer[n].max_fails = server[i].max_fails;
                peer[n].fail_timeout = server[i].fail_timeout;
                peer[n].down = server[i].down;
                peer[n].server = server[i].name;

                *peerp = &peer[n];
                peerp = &peer[n].next;
                n++;
            }
        }

        peers->next = backup;

        return RP_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return RP_ERROR;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.host = us->host;
    u.port = us->port;

    if (rp_inet_resolve_host(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return RP_ERROR;
    }

    n = u.naddrs;

    peers = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return RP_ERROR;
    }

    peer = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_rr_peer_t) * n);
    if (peer == NULL) {
        return RP_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = 0;
    peers->total_weight = n;
    peers->name = &us->host;

    peerp = &peers->peer;

    for (i = 0; i < u.naddrs; i++) {
        peer[i].sockaddr = u.addrs[i].sockaddr;
        peer[i].socklen = u.addrs[i].socklen;
        peer[i].name = u.addrs[i].name;
        peer[i].weight = 1;
        peer[i].effective_weight = 1;
        peer[i].current_weight = 0;
        peer[i].max_conns = 0;
        peer[i].max_fails = 1;
        peer[i].fail_timeout = 10;
        *peerp = &peer[i];
        peerp = &peer[i].next;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return RP_OK;
}


rp_int_t
rp_http_upstream_init_round_robin_peer(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us)
{
    rp_uint_t                         n;
    rp_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = rp_palloc(r->pool, sizeof(rp_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return RP_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    rrp->peers = us->peer.data;
    rrp->current = NULL;
    rrp->config = 0;

    n = rrp->peers->number;

    if (rrp->peers->next && rrp->peers->next->number > n) {
        n = rrp->peers->next->number;
    }

    if (n <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (n + (8 * sizeof(uintptr_t) - 1)) / (8 * sizeof(uintptr_t));

        rrp->tried = rp_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return RP_ERROR;
        }
    }

    r->upstream->peer.get = rp_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = rp_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = rp_http_upstream_tries(rrp->peers);
#if (RP_HTTP_SSL)
    r->upstream->peer.set_session =
                               rp_http_upstream_set_round_robin_peer_session;
    r->upstream->peer.save_session =
                               rp_http_upstream_save_round_robin_peer_session;
#endif

    return RP_OK;
}


rp_int_t
rp_http_upstream_create_round_robin_peer(rp_http_request_t *r,
    rp_http_upstream_resolved_t *ur)
{
    u_char                            *p;
    size_t                             len;
    socklen_t                          socklen;
    rp_uint_t                         i, n;
    struct sockaddr                   *sockaddr;
    rp_http_upstream_rr_peer_t       *peer, **peerp;
    rp_http_upstream_rr_peers_t      *peers;
    rp_http_upstream_rr_peer_data_t  *rrp;

    rrp = r->upstream->peer.data;

    if (rrp == NULL) {
        rrp = rp_palloc(r->pool, sizeof(rp_http_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return RP_ERROR;
        }

        r->upstream->peer.data = rrp;
    }

    peers = rp_pcalloc(r->pool, sizeof(rp_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return RP_ERROR;
    }

    peer = rp_pcalloc(r->pool, sizeof(rp_http_upstream_rr_peer_t)
                                * ur->naddrs);
    if (peer == NULL) {
        return RP_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peer[0].sockaddr = ur->sockaddr;
        peer[0].socklen = ur->socklen;
        peer[0].name = ur->name.data ? ur->name : ur->host;
        peer[0].weight = 1;
        peer[0].effective_weight = 1;
        peer[0].current_weight = 0;
        peer[0].max_conns = 0;
        peer[0].max_fails = 1;
        peer[0].fail_timeout = 10;
        peers->peer = peer;

    } else {
        peerp = &peers->peer;

        for (i = 0; i < ur->naddrs; i++) {

            socklen = ur->addrs[i].socklen;

            sockaddr = rp_palloc(r->pool, socklen);
            if (sockaddr == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);
            rp_inet_set_port(sockaddr, ur->port);

            p = rp_pnalloc(r->pool, RP_SOCKADDR_STRLEN);
            if (p == NULL) {
                return RP_ERROR;
            }

            len = rp_sock_ntop(sockaddr, socklen, p, RP_SOCKADDR_STRLEN, 1);

            peer[i].sockaddr = sockaddr;
            peer[i].socklen = socklen;
            peer[i].name.len = len;
            peer[i].name.data = p;
            peer[i].weight = 1;
            peer[i].effective_weight = 1;
            peer[i].current_weight = 0;
            peer[i].max_conns = 0;
            peer[i].max_fails = 1;
            peer[i].fail_timeout = 10;
            *peerp = &peer[i];
            peerp = &peer[i].next;
        }
    }

    rrp->peers = peers;
    rrp->current = NULL;
    rrp->config = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        rrp->tried = rp_pcalloc(r->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return RP_ERROR;
        }
    }

    r->upstream->peer.get = rp_http_upstream_get_round_robin_peer;
    r->upstream->peer.free = rp_http_upstream_free_round_robin_peer;
    r->upstream->peer.tries = rp_http_upstream_tries(rrp->peers);
#if (RP_HTTP_SSL)
    r->upstream->peer.set_session = rp_http_upstream_empty_set_session;
    r->upstream->peer.save_session = rp_http_upstream_empty_save_session;
#endif

    return RP_OK;
}


rp_int_t
rp_http_upstream_get_round_robin_peer(rp_peer_connection_t *pc, void *data)
{
    rp_http_upstream_rr_peer_data_t  *rrp = data;

    rp_int_t                      rc;
    rp_uint_t                     i, n;
    rp_http_upstream_rr_peer_t   *peer;
    rp_http_upstream_rr_peers_t  *peers;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    pc->cached = 0;
    pc->connection = NULL;

    peers = rrp->peers;
    rp_http_upstream_rr_peers_wlock(peers);

    if (peers->single) {
        peer = peers->peer;

        if (peer->down) {
            goto failed;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto failed;
        }

        rrp->current = peer;

    } else {

        /* there are several peers */

        peer = rp_http_upstream_get_peer(rrp);

        if (peer == NULL) {
            goto failed;
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get rr peer, current: %p %i",
                       peer, peer->current_weight);
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    rp_http_upstream_rr_peers_unlock(peers);

    return RP_OK;

failed:

    if (peers->next) {

        rp_log_debug0(RP_LOG_DEBUG_HTTP, pc->log, 0, "backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        rp_http_upstream_rr_peers_unlock(peers);

        rc = rp_http_upstream_get_round_robin_peer(pc, rrp);

        if (rc != RP_BUSY) {
            return rc;
        }

        rp_http_upstream_rr_peers_wlock(peers);
    }

    rp_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return RP_BUSY;
}


static rp_http_upstream_rr_peer_t *
rp_http_upstream_get_peer(rp_http_upstream_rr_peer_data_t *rrp)
{
    time_t                        now;
    uintptr_t                     m;
    rp_int_t                     total;
    rp_uint_t                    i, n, p;
    rp_http_upstream_rr_peer_t  *peer, *best;

    now = rp_time();

    best = NULL;
    total = 0;

#if (RP_SUPPRESS_WARN)
    p = 0;
#endif

    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;

        if (peer->effective_weight < peer->weight) {
            peer->effective_weight++;
        }

        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
        return NULL;
    }

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


void
rp_http_upstream_free_round_robin_peer(rp_peer_connection_t *pc, void *data,
    rp_uint_t state)
{
    rp_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    rp_http_upstream_rr_peer_t  *peer;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    /* TODO: RP_PEER_KEEPALIVE */

    peer = rrp->current;

    rp_http_upstream_rr_peers_rlock(rrp->peers);
    rp_http_upstream_rr_peer_lock(rrp->peers, peer);

    if (rrp->peers->single) {

        peer->conns--;

        rp_http_upstream_rr_peer_unlock(rrp->peers, peer);
        rp_http_upstream_rr_peers_unlock(rrp->peers);

        pc->tries = 0;
        return;
    }

    if (state & RP_PEER_FAILED) {
        now = rp_time();

        peer->fails++;
        peer->accessed = now;
        peer->checked = now;

        if (peer->max_fails) {
            peer->effective_weight -= peer->weight / peer->max_fails;

            if (peer->fails >= peer->max_fails) {
                rp_log_error(RP_LOG_WARN, pc->log, 0,
                              "upstream server temporarily disabled");
            }
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "free rr peer failed: %p %i",
                       peer, peer->effective_weight);

        if (peer->effective_weight < 0) {
            peer->effective_weight = 0;
        }

    } else {

        /* mark peer live if check passed */

        if (peer->accessed < peer->checked) {
            peer->fails = 0;
        }
    }

    peer->conns--;

    rp_http_upstream_rr_peer_unlock(rrp->peers, peer);
    rp_http_upstream_rr_peers_unlock(rrp->peers);

    if (pc->tries) {
        pc->tries--;
    }
}


#if (RP_HTTP_SSL)

rp_int_t
rp_http_upstream_set_round_robin_peer_session(rp_peer_connection_t *pc,
    void *data)
{
    rp_http_upstream_rr_peer_data_t  *rrp = data;

    rp_int_t                      rc;
    rp_ssl_session_t             *ssl_session;
    rp_http_upstream_rr_peer_t   *peer;
#if (RP_HTTP_UPSTREAM_ZONE)
    int                            len;
    const u_char                  *p;
    rp_http_upstream_rr_peers_t  *peers;
    u_char                         buf[RP_SSL_MAX_SESSION_SIZE];
#endif

    peer = rrp->current;

#if (RP_HTTP_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {
        rp_http_upstream_rr_peers_rlock(peers);
        rp_http_upstream_rr_peer_lock(peers, peer);

        if (peer->ssl_session == NULL) {
            rp_http_upstream_rr_peer_unlock(peers, peer);
            rp_http_upstream_rr_peers_unlock(peers);
            return RP_OK;
        }

        len = peer->ssl_session_len;

        rp_memcpy(buf, peer->ssl_session, len);

        rp_http_upstream_rr_peer_unlock(peers, peer);
        rp_http_upstream_rr_peers_unlock(peers);

        p = buf;
        ssl_session = d2i_SSL_SESSION(NULL, &p, len);

        rc = rp_ssl_set_session(pc->connection, ssl_session);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "set session: %p", ssl_session);

        rp_ssl_free_session(ssl_session);

        return rc;
    }
#endif

    ssl_session = peer->ssl_session;

    rc = rp_ssl_set_session(pc->connection, ssl_session);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "set session: %p", ssl_session);

    return rc;
}


void
rp_http_upstream_save_round_robin_peer_session(rp_peer_connection_t *pc,
    void *data)
{
    rp_http_upstream_rr_peer_data_t  *rrp = data;

    rp_ssl_session_t             *old_ssl_session, *ssl_session;
    rp_http_upstream_rr_peer_t   *peer;
#if (RP_HTTP_UPSTREAM_ZONE)
    int                            len;
    u_char                        *p;
    rp_http_upstream_rr_peers_t  *peers;
    u_char                         buf[RP_SSL_MAX_SESSION_SIZE];
#endif

#if (RP_HTTP_UPSTREAM_ZONE)
    peers = rrp->peers;

    if (peers->shpool) {

        ssl_session = rp_ssl_get0_session(pc->connection);

        if (ssl_session == NULL) {
            return;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "save session: %p", ssl_session);

        len = i2d_SSL_SESSION(ssl_session, NULL);

        /* do not cache too big session */

        if (len > RP_SSL_MAX_SESSION_SIZE) {
            return;
        }

        p = buf;
        (void) i2d_SSL_SESSION(ssl_session, &p);

        peer = rrp->current;

        rp_http_upstream_rr_peers_rlock(peers);
        rp_http_upstream_rr_peer_lock(peers, peer);

        if (len > peer->ssl_session_len) {
            rp_shmtx_lock(&peers->shpool->mutex);

            if (peer->ssl_session) {
                rp_slab_free_locked(peers->shpool, peer->ssl_session);
            }

            peer->ssl_session = rp_slab_alloc_locked(peers->shpool, len);

            rp_shmtx_unlock(&peers->shpool->mutex);

            if (peer->ssl_session == NULL) {
                peer->ssl_session_len = 0;

                rp_http_upstream_rr_peer_unlock(peers, peer);
                rp_http_upstream_rr_peers_unlock(peers);
                return;
            }

            peer->ssl_session_len = len;
        }

        rp_memcpy(peer->ssl_session, buf, len);

        rp_http_upstream_rr_peer_unlock(peers, peer);
        rp_http_upstream_rr_peers_unlock(peers);

        return;
    }
#endif

    ssl_session = rp_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p", ssl_session);

    peer = rrp->current;

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    if (old_ssl_session) {

        rp_log_debug1(RP_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p", old_ssl_session);

        /* TODO: may block */

        rp_ssl_free_session(old_ssl_session);
    }
}


static rp_int_t
rp_http_upstream_empty_set_session(rp_peer_connection_t *pc, void *data)
{
    return RP_OK;
}


static void
rp_http_upstream_empty_save_session(rp_peer_connection_t *pc, void *data)
{
    return;
}

#endif
