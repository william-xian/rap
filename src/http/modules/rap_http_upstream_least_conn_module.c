
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_upstream_init_least_conn_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_get_least_conn_peer(
    rap_peer_connection_t *pc, void *data);
static char *rap_http_upstream_least_conn(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_upstream_least_conn_commands[] = {

    { rap_string("least_conn"),
      RAP_HTTP_UPS_CONF|RAP_CONF_NOARGS,
      rap_http_upstream_least_conn,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_least_conn_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_least_conn_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_least_conn_module_ctx, /* module context */
    rap_http_upstream_least_conn_commands, /* module directives */
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


static rap_int_t
rap_http_upstream_init_least_conn(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, cf->log, 0,
                   "init least conn");

    if (rap_http_upstream_init_round_robin(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    us->peer.init = rap_http_upstream_init_least_conn_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_init_least_conn_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init least conn peer");

    if (rap_http_upstream_init_round_robin_peer(r, us) != RAP_OK) {
        return RAP_ERROR;
    }

    r->upstream->peer.get = rap_http_upstream_get_least_conn_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_get_least_conn_peer(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_rr_peer_data_t  *rrp = data;

    time_t                         now;
    uintptr_t                      m;
    rap_int_t                      rc, total;
    rap_uint_t                     i, n, p, many;
    rap_http_upstream_rr_peer_t   *peer, *best;
    rap_http_upstream_rr_peers_t  *peers;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return rap_http_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rap_time();

    peers = rrp->peers;

    rap_http_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (RAP_SUPPRESS_WARN)
    many = 0;
    p = 0;
#endif

    for (peer = peers->peer, i = 0;
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

        /*
         * select peer with least number of connections; if there are
         * multiple peers with the same number of connections, select
         * based on round-robin
         */

        if (best == NULL
            || peer->conns * best->weight < best->conns * peer->weight)
        {
            best = peer;
            many = 0;
            p = i;

        } else if (peer->conns * best->weight == best->conns * peer->weight) {
            many = 1;
        }
    }

    if (best == NULL) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, many");

        for (peer = best, i = p;
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

            if (peer->conns * best->weight != best->conns * peer->weight) {
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

            if (peer->current_weight > best->current_weight) {
                best = peer;
                p = i;
            }
        }
    }

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    rap_http_upstream_rr_peers_unlock(peers);

    return RAP_OK;

failed:

    if (peers->next) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        rap_http_upstream_rr_peers_unlock(peers);

        rc = rap_http_upstream_get_least_conn_peer(pc, rrp);

        if (rc != RAP_BUSY) {
            return rc;
        }

        rap_http_upstream_rr_peers_wlock(peers);
    }

    rap_http_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return RAP_BUSY;
}


static char *
rap_http_upstream_least_conn(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_upstream_srv_conf_t  *uscf;

    uscf = rap_http_conf_get_module_srv_conf(cf, rap_http_upstream_module);

    if (uscf->peer.init_upstream) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rap_http_upstream_init_least_conn;

    uscf->flags = RAP_HTTP_UPSTREAM_CREATE
                  |RAP_HTTP_UPSTREAM_WEIGHT
                  |RAP_HTTP_UPSTREAM_MAX_CONNS
                  |RAP_HTTP_UPSTREAM_MAX_FAILS
                  |RAP_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |RAP_HTTP_UPSTREAM_DOWN
                  |RAP_HTTP_UPSTREAM_BACKUP;

    return RAP_CONF_OK;
}
