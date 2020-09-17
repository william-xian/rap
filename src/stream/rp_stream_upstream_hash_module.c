
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    uint32_t                              hash;
    rp_str_t                            *server;
} rp_stream_upstream_chash_point_t;


typedef struct {
    rp_uint_t                            number;
    rp_stream_upstream_chash_point_t     point[1];
} rp_stream_upstream_chash_points_t;


typedef struct {
    rp_stream_complex_value_t            key;
    rp_stream_upstream_chash_points_t   *points;
} rp_stream_upstream_hash_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    rp_stream_upstream_rr_peer_data_t    rrp;
    rp_stream_upstream_hash_srv_conf_t  *conf;
    rp_str_t                             key;
    rp_uint_t                            tries;
    rp_uint_t                            rehash;
    uint32_t                              hash;
    rp_event_get_peer_pt                 get_rr_peer;
} rp_stream_upstream_hash_peer_data_t;


static rp_int_t rp_stream_upstream_init_hash(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us);
static rp_int_t rp_stream_upstream_init_hash_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us);
static rp_int_t rp_stream_upstream_get_hash_peer(rp_peer_connection_t *pc,
    void *data);

static rp_int_t rp_stream_upstream_init_chash(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us);
static int rp_libc_cdecl
    rp_stream_upstream_chash_cmp_points(const void *one, const void *two);
static rp_uint_t rp_stream_upstream_find_chash_point(
    rp_stream_upstream_chash_points_t *points, uint32_t hash);
static rp_int_t rp_stream_upstream_init_chash_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us);
static rp_int_t rp_stream_upstream_get_chash_peer(rp_peer_connection_t *pc,
    void *data);

static void *rp_stream_upstream_hash_create_conf(rp_conf_t *cf);
static char *rp_stream_upstream_hash(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_stream_upstream_hash_commands[] = {

    { rp_string("hash"),
      RP_STREAM_UPS_CONF|RP_CONF_TAKE12,
      rp_stream_upstream_hash,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_upstream_hash_create_conf,  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_upstream_hash_module = {
    RP_MODULE_V1,
    &rp_stream_upstream_hash_module_ctx,  /* module context */
    rp_stream_upstream_hash_commands,     /* module directives */
    RP_STREAM_MODULE,                     /* module type */
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
rp_stream_upstream_init_hash(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us)
{
    if (rp_stream_upstream_init_round_robin(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    us->peer.init = rp_stream_upstream_init_hash_peer;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_init_hash_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us)
{
    rp_stream_upstream_hash_srv_conf_t   *hcf;
    rp_stream_upstream_hash_peer_data_t  *hp;

    hp = rp_palloc(s->connection->pool,
                    sizeof(rp_stream_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return RP_ERROR;
    }

    s->upstream->peer.data = &hp->rrp;

    if (rp_stream_upstream_init_round_robin_peer(s, us) != RP_OK) {
        return RP_ERROR;
    }

    s->upstream->peer.get = rp_stream_upstream_get_hash_peer;

    hcf = rp_stream_conf_upstream_srv_conf(us,
                                            rp_stream_upstream_hash_module);

    if (rp_stream_complex_value(s, &hcf->key, &hp->key) != RP_OK) {
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream hash key:\"%V\"", &hp->key);

    hp->conf = hcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = rp_stream_upstream_get_round_robin_peer;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_get_hash_peer(rp_peer_connection_t *pc, void *data)
{
    rp_stream_upstream_hash_peer_data_t *hp = data;

    time_t                          now;
    u_char                          buf[RP_INT_T_LEN];
    size_t                          size;
    uint32_t                        hash;
    rp_int_t                       w;
    uintptr_t                       m;
    rp_uint_t                      n, p;
    rp_stream_upstream_rr_peer_t  *peer;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, pc->log, 0,
                   "get hash peer, try: %ui", pc->tries);

    rp_stream_upstream_rr_peers_rlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    now = rp_time();

    pc->connection = NULL;

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        rp_crc32_init(hash);

        if (hp->rehash > 0) {
            size = rp_sprintf(buf, "%ui", hp->rehash) - buf;
            rp_crc32_update(&hash, buf, size);
        }

        rp_crc32_update(&hash, hp->key.data, hp->key.len);
        rp_crc32_final(hash);

        hash = (hash >> 16) & 0x7fff;

        hp->hash += hash;
        hp->rehash++;

        w = hp->hash % hp->rrp.peers->total_weight;
        peer = hp->rrp.peers->peer;
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (hp->rrp.tried[n] & m) {
            goto next;
        }

        rp_stream_upstream_rr_peer_lock(hp->rrp.peers, peer);

        rp_log_debug2(RP_LOG_DEBUG_STREAM, pc->log, 0,
                       "get hash peer, value:%uD, peer:%ui", hp->hash, p);

        if (peer->down) {
            rp_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rp_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rp_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++hp->tries > 20) {
            rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    rp_stream_upstream_rr_peer_unlock(hp->rrp.peers, peer);
    rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_init_chash(rp_conf_t *cf,
    rp_stream_upstream_srv_conf_t *us)
{
    u_char                               *host, *port, c;
    size_t                                host_len, port_len, size;
    uint32_t                              hash, base_hash;
    rp_str_t                            *server;
    rp_uint_t                            npoints, i, j;
    rp_stream_upstream_rr_peer_t        *peer;
    rp_stream_upstream_rr_peers_t       *peers;
    rp_stream_upstream_chash_points_t   *points;
    rp_stream_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                          value;
        u_char                            byte[4];
    } prev_hash;

    if (rp_stream_upstream_init_round_robin(cf, us) != RP_OK) {
        return RP_ERROR;
    }

    us->peer.init = rp_stream_upstream_init_chash_peer;

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(rp_stream_upstream_chash_points_t)
           + sizeof(rp_stream_upstream_chash_point_t) * (npoints - 1);

    points = rp_palloc(cf->pool, size);
    if (points == NULL) {
        return RP_ERROR;
    }

    points->number = 0;

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && rp_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        rp_crc32_init(base_hash);
        rp_crc32_update(&base_hash, host, host_len);
        rp_crc32_update(&base_hash, (u_char *) "", 1);
        rp_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            rp_crc32_update(&hash, prev_hash.byte, 4);
            rp_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (RP_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    rp_qsort(points->point,
              points->number,
              sizeof(rp_stream_upstream_chash_point_t),
              rp_stream_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    hcf = rp_stream_conf_upstream_srv_conf(us,
                                            rp_stream_upstream_hash_module);
    hcf->points = points;

    return RP_OK;
}


static int rp_libc_cdecl
rp_stream_upstream_chash_cmp_points(const void *one, const void *two)
{
    rp_stream_upstream_chash_point_t *first =
                                     (rp_stream_upstream_chash_point_t *) one;
    rp_stream_upstream_chash_point_t *second =
                                     (rp_stream_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static rp_uint_t
rp_stream_upstream_find_chash_point(rp_stream_upstream_chash_points_t *points,
    uint32_t hash)
{
    rp_uint_t                          i, j, k;
    rp_stream_upstream_chash_point_t  *point;

    /* find first point >= hash */

    point = &points->point[0];

    i = 0;
    j = points->number;

    while (i < j) {
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;
        }
    }

    return i;
}


static rp_int_t
rp_stream_upstream_init_chash_peer(rp_stream_session_t *s,
    rp_stream_upstream_srv_conf_t *us)
{
    uint32_t                               hash;
    rp_stream_upstream_hash_srv_conf_t   *hcf;
    rp_stream_upstream_hash_peer_data_t  *hp;

    if (rp_stream_upstream_init_hash_peer(s, us) != RP_OK) {
        return RP_ERROR;
    }

    s->upstream->peer.get = rp_stream_upstream_get_chash_peer;

    hp = s->upstream->peer.data;
    hcf = rp_stream_conf_upstream_srv_conf(us,
                                            rp_stream_upstream_hash_module);

    hash = rp_crc32_long(hp->key.data, hp->key.len);

    rp_stream_upstream_rr_peers_rlock(hp->rrp.peers);

    hp->hash = rp_stream_upstream_find_chash_point(hcf->points, hash);

    rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_get_chash_peer(rp_peer_connection_t *pc, void *data)
{
    rp_stream_upstream_hash_peer_data_t *hp = data;

    time_t                                now;
    intptr_t                              m;
    rp_str_t                            *server;
    rp_int_t                             total;
    rp_uint_t                            i, n, best_i;
    rp_stream_upstream_rr_peer_t        *peer, *best;
    rp_stream_upstream_chash_point_t    *point;
    rp_stream_upstream_chash_points_t   *points;
    rp_stream_upstream_hash_srv_conf_t  *hcf;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, pc->log, 0,
                   "get consistent hash peer, try: %ui", pc->tries);

    rp_stream_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    pc->connection = NULL;

    now = rp_time();
    hcf = hp->conf;

    points = hcf->points;
    point = &points->point[0];

    for ( ;; ) {
        server = point[hp->hash % points->number].server;

        rp_log_debug2(RP_LOG_DEBUG_STREAM, pc->log, 0,
                       "consistent hash peer:%uD, server:\"%V\"",
                       hp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        for (peer = hp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {
            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (hp->rrp.tried[n] & m) {
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

            if (peer->server.len != server->len
                || rp_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        if (best) {
            best->current_weight -= total;
            break;
        }

        hp->hash++;
        hp->tries++;

        if (hp->tries > 20) {
            rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = best;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    rp_stream_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    hp->rrp.tried[n] |= m;

    return RP_OK;
}


static void *
rp_stream_upstream_hash_create_conf(rp_conf_t *cf)
{
    rp_stream_upstream_hash_srv_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_stream_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


static char *
rp_stream_upstream_hash(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_upstream_hash_srv_conf_t  *hcf = conf;

    rp_str_t                           *value;
    rp_stream_upstream_srv_conf_t      *uscf;
    rp_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hcf->key;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    uscf = rp_stream_conf_get_module_srv_conf(cf, rp_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = RP_STREAM_UPSTREAM_CREATE
                  |RP_STREAM_UPSTREAM_WEIGHT
                  |RP_STREAM_UPSTREAM_MAX_CONNS
                  |RP_STREAM_UPSTREAM_MAX_FAILS
                  |RP_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |RP_STREAM_UPSTREAM_DOWN;

    if (cf->args->nelts == 2) {
        uscf->peer.init_upstream = rp_stream_upstream_init_hash;

    } else if (rp_strcmp(value[2].data, "consistent") == 0) {
        uscf->peer.init_upstream = rp_stream_upstream_init_chash;

    } else {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
