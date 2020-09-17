
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


static rp_int_t rp_stream_upstream_init_least_conn_peer(
    rp_stream_session_t *s, rp_stream_upstream_srv_conf_t *us);
static rp_int_t rp_stream_upstream_get_least_conn_peer(
    rp_peer_connection_t *pc, void *data);
static char *rp_stream_upstream_least_conn(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_stream_upstream_least_conn_commands[] = {

    { rp_string("least_conn"),
      RP_STREAM_UPS_CONF|RP_CONF_NOARGS,
      rp_stream_upstream_least_conn,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_upstream_least_conn_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL                                     /* merge server configuration */
};


rp_module_t  rp_stream_upstream_least_conn_module = {
    RP_MODULE_V1,
    &rp_stream_upstream_least_conn_module_ctx, /* module context */
    rp_stream_upstream_least_conn_commands, /* module directives */
    RP_STREAM_MODULE,                       /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_stream_upstream_init_least_conn(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us)
{
    rp_log_debug0(RP_LOG_DEBUG_STREAM, cf->log, 0,
                   "init least conn");

    if (rp_stream_upstream_init_round_robin(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    us->peer.init = rp_stream_upstream_init_least_conn_peer;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_init_least_conn_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us)
{
    rp_log_debug0(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "init least conn peer");

    if (rp_stream_upstream_init_round_robin_peer(s, us) != RP_OK) {
        return RP_ERROR;
    }

    s->upstream->peer.get = rp_stream_upstream_get_least_conn_peer;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_get_least_conn_peer(rp_peer_connection_t *pc, void *data)
{
    rp_stream_upstream_rr_peer_data_t *rrp = data;

    time_t                           now;
    uintptr_t                        m;
    rp_int_t                        rc, total;
    rp_uint_t                       i, n, p, many;
    rp_stream_upstream_rr_peer_t   *peer, *best;
    rp_stream_upstream_rr_peers_t  *peers;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, pc->log, 0,
                   "get least conn peer, try: %ui", pc->tries);

    if (rrp->peers->single) {
        return rp_stream_upstream_get_round_robin_peer(pc, rrp);
    }

    pc->connection = NULL;

    now = rp_time();

    peers = rrp->peers;

    rp_stream_upstream_rr_peers_wlock(peers);

    best = NULL;
    total = 0;

#if (RP_SUPPRESS_WARN)
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
        rp_log_debug0(RP_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, no peer found");

        goto failed;
    }

    if (many) {
        rp_log_debug0(RP_LOG_DEBUG_STREAM, pc->log, 0,
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

    rp_stream_upstream_rr_peers_unlock(peers);

    return RP_OK;

failed:

    if (peers->next) {
        rp_log_debug0(RP_LOG_DEBUG_STREAM, pc->log, 0,
                       "get least conn peer, backup servers");

        rrp->peers = peers->next;

        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
                / (8 * sizeof(uintptr_t));

        for (i = 0; i < n; i++) {
            rrp->tried[i] = 0;
        }

        rp_stream_upstream_rr_peers_unlock(peers);

        rc = rp_stream_upstream_get_least_conn_peer(pc, rrp);

        if (rc != RP_BUSY) {
            return rc;
        }

        rp_stream_upstream_rr_peers_wlock(peers);
    }

    rp_stream_upstream_rr_peers_unlock(peers);

    pc->name = peers->name;

    return RP_BUSY;
}


static char *
rp_stream_upstream_least_conn(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_upstream_srv_conf_t  *uscf;

    uscf = rp_stream_conf_get_module_srv_conf(cf, rp_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = rp_stream_upstream_init_least_conn;

    uscf->flags = RP_STREAM_UPSTREAM_CREATE
                  |RP_STREAM_UPSTREAM_WEIGHT
                  |RP_STREAM_UPSTREAM_MAX_CONNS
                  |RP_STREAM_UPSTREAM_MAX_FAILS
                  |RP_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |RP_STREAM_UPSTREAM_DOWN
                  |RP_STREAM_UPSTREAM_BACKUP;

    return RP_CONF_OK;
}
