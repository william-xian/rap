
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    uint32_t                            hash;
    rap_str_t                          *server;
} rap_http_upstream_chash_point_t;


typedef struct {
    rap_uint_t                          number;
    rap_http_upstream_chash_point_t     point[1];
} rap_http_upstream_chash_points_t;


typedef struct {
    rap_http_complex_value_t            key;
    rap_http_upstream_chash_points_t   *points;
} rap_http_upstream_hash_srv_conf_t;


typedef struct {
    /* the round robin data must be first */
    rap_http_upstream_rr_peer_data_t    rrp;
    rap_http_upstream_hash_srv_conf_t  *conf;
    rap_str_t                           key;
    rap_uint_t                          tries;
    rap_uint_t                          rehash;
    uint32_t                            hash;
    rap_event_get_peer_pt               get_rr_peer;
} rap_http_upstream_hash_peer_data_t;


static rap_int_t rap_http_upstream_init_hash(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_init_hash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_get_hash_peer(rap_peer_connection_t *pc,
    void *data);

static rap_int_t rap_http_upstream_init_chash(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us);
static int rap_libc_cdecl
    rap_http_upstream_chash_cmp_points(const void *one, const void *two);
static rap_uint_t rap_http_upstream_find_chash_point(
    rap_http_upstream_chash_points_t *points, uint32_t hash);
static rap_int_t rap_http_upstream_init_chash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);
static rap_int_t rap_http_upstream_get_chash_peer(rap_peer_connection_t *pc,
    void *data);

static void *rap_http_upstream_hash_create_conf(rap_conf_t *cf);
static char *rap_http_upstream_hash(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_upstream_hash_commands[] = {

    { rap_string("hash"),
      RAP_HTTP_UPS_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_hash,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_http_upstream_hash_create_conf,    /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_hash_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_hash_module_ctx,    /* module context */
    rap_http_upstream_hash_commands,       /* module directives */
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
rap_http_upstream_init_hash(rap_conf_t *cf, rap_http_upstream_srv_conf_t *us)
{
    if (rap_http_upstream_init_round_robin(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    us->peer.init = rap_http_upstream_init_hash_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_init_hash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us)
{
    rap_http_upstream_hash_srv_conf_t   *hcf;
    rap_http_upstream_hash_peer_data_t  *hp;

    hp = rap_palloc(r->pool, sizeof(rap_http_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return RAP_ERROR;
    }

    r->upstream->peer.data = &hp->rrp;

    if (rap_http_upstream_init_round_robin_peer(r, us) != RAP_OK) {
        return RAP_ERROR;
    }

    r->upstream->peer.get = rap_http_upstream_get_hash_peer;

    hcf = rap_http_conf_upstream_srv_conf(us, rap_http_upstream_hash_module);

    if (rap_http_complex_value(r, &hcf->key, &hp->key) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream hash key:\"%V\"", &hp->key);

    hp->conf = hcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = rap_http_upstream_get_round_robin_peer;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_get_hash_peer(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_hash_peer_data_t  *hp = data;

    time_t                        now;
    u_char                        buf[RAP_INT_T_LEN];
    size_t                        size;
    uint32_t                      hash;
    rap_int_t                     w;
    uintptr_t                     m;
    rap_uint_t                    n, p;
    rap_http_upstream_rr_peer_t  *peer;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get hash peer, try: %ui", pc->tries);

    rap_http_upstream_rr_peers_rlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        rap_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    now = rap_time();

    pc->cached = 0;
    pc->connection = NULL;

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        rap_crc32_init(hash);

        if (hp->rehash > 0) {
            size = rap_sprintf(buf, "%ui", hp->rehash) - buf;
            rap_crc32_update(&hash, buf, size);
        }

        rap_crc32_update(&hash, hp->key.data, hp->key.len);
        rap_crc32_final(hash);

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

        rap_http_upstream_rr_peer_lock(hp->rrp.peers, peer);

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                       "get hash peer, value:%uD, peer:%ui", hp->hash, p);

        if (peer->down) {
            rap_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            rap_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            rap_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        if (++hp->tries > 20) {
            rap_http_upstream_rr_peers_unlock(hp->rrp.peers);
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

    rap_http_upstream_rr_peer_unlock(hp->rrp.peers, peer);
    rap_http_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_init_chash(rap_conf_t *cf, rap_http_upstream_srv_conf_t *us)
{
    u_char                             *host, *port, c;
    size_t                              host_len, port_len, size;
    uint32_t                            hash, base_hash;
    rap_str_t                          *server;
    rap_uint_t                          npoints, i, j;
    rap_http_upstream_rr_peer_t        *peer;
    rap_http_upstream_rr_peers_t       *peers;
    rap_http_upstream_chash_points_t   *points;
    rap_http_upstream_hash_srv_conf_t  *hcf;
    union {
        uint32_t                        value;
        u_char                          byte[4];
    } prev_hash;

    if (rap_http_upstream_init_round_robin(cf, us) != RAP_OK) {
        return RAP_ERROR;
    }

    us->peer.init = rap_http_upstream_init_chash_peer;

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(rap_http_upstream_chash_points_t)
           + sizeof(rap_http_upstream_chash_point_t) * (npoints - 1);

    points = rap_palloc(cf->pool, size);
    if (points == NULL) {
        return RAP_ERROR;
    }

    points->number = 0;

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && rap_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
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

        rap_crc32_init(base_hash);
        rap_crc32_update(&base_hash, host, host_len);
        rap_crc32_update(&base_hash, (u_char *) "", 1);
        rap_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            rap_crc32_update(&hash, prev_hash.byte, 4);
            rap_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (RAP_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    rap_qsort(points->point,
              points->number,
              sizeof(rap_http_upstream_chash_point_t),
              rap_http_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    hcf = rap_http_conf_upstream_srv_conf(us, rap_http_upstream_hash_module);
    hcf->points = points;

    return RAP_OK;
}


static int rap_libc_cdecl
rap_http_upstream_chash_cmp_points(const void *one, const void *two)
{
    rap_http_upstream_chash_point_t *first =
                                       (rap_http_upstream_chash_point_t *) one;
    rap_http_upstream_chash_point_t *second =
                                       (rap_http_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static rap_uint_t
rap_http_upstream_find_chash_point(rap_http_upstream_chash_points_t *points,
    uint32_t hash)
{
    rap_uint_t                        i, j, k;
    rap_http_upstream_chash_point_t  *point;

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


static rap_int_t
rap_http_upstream_init_chash_peer(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us)
{
    uint32_t                             hash;
    rap_http_upstream_hash_srv_conf_t   *hcf;
    rap_http_upstream_hash_peer_data_t  *hp;

    if (rap_http_upstream_init_hash_peer(r, us) != RAP_OK) {
        return RAP_ERROR;
    }

    r->upstream->peer.get = rap_http_upstream_get_chash_peer;

    hp = r->upstream->peer.data;
    hcf = rap_http_conf_upstream_srv_conf(us, rap_http_upstream_hash_module);

    hash = rap_crc32_long(hp->key.data, hp->key.len);

    rap_http_upstream_rr_peers_rlock(hp->rrp.peers);

    hp->hash = rap_http_upstream_find_chash_point(hcf->points, hash);

    rap_http_upstream_rr_peers_unlock(hp->rrp.peers);

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_get_chash_peer(rap_peer_connection_t *pc, void *data)
{
    rap_http_upstream_hash_peer_data_t  *hp = data;

    time_t                              now;
    intptr_t                            m;
    rap_str_t                          *server;
    rap_int_t                           total;
    rap_uint_t                          i, n, best_i;
    rap_http_upstream_rr_peer_t        *peer, *best;
    rap_http_upstream_chash_point_t    *point;
    rap_http_upstream_chash_points_t   *points;
    rap_http_upstream_hash_srv_conf_t  *hcf;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pc->log, 0,
                   "get consistent hash peer, try: %ui", pc->tries);

    rap_http_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single || hp->key.len == 0) {
        rap_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    pc->cached = 0;
    pc->connection = NULL;

    now = rap_time();
    hcf = hp->conf;

    points = hcf->points;
    point = &points->point[0];

    for ( ;; ) {
        server = point[hp->hash % points->number].server;

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, pc->log, 0,
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
                || rap_strncmp(peer->server.data, server->data, server->len)
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
            goto found;
        }

        hp->hash++;
        hp->tries++;

        if (hp->tries > 20) {
            rap_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

found:

    hp->rrp.current = best;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    rap_http_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    hp->rrp.tried[n] |= m;

    return RAP_OK;
}


static void *
rap_http_upstream_hash_create_conf(rap_conf_t *cf)
{
    rap_http_upstream_hash_srv_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_upstream_hash_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->points = NULL;

    return conf;
}


static char *
rap_http_upstream_hash(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_upstream_hash_srv_conf_t  *hcf = conf;

    rap_str_t                         *value;
    rap_http_upstream_srv_conf_t      *uscf;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hcf->key;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    uscf = rap_http_conf_get_module_srv_conf(cf, rap_http_upstream_module);

    if (uscf->peer.init_upstream) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = RAP_HTTP_UPSTREAM_CREATE
                  |RAP_HTTP_UPSTREAM_WEIGHT
                  |RAP_HTTP_UPSTREAM_MAX_CONNS
                  |RAP_HTTP_UPSTREAM_MAX_FAILS
                  |RAP_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |RAP_HTTP_UPSTREAM_DOWN;

    if (cf->args->nelts == 2) {
        uscf->peer.init_upstream = rap_http_upstream_init_hash;

    } else if (rap_strcmp(value[2].data, "consistent") == 0) {
        uscf->peer.init_upstream = rap_http_upstream_init_chash;

    } else {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
