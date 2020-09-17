
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static char *rp_http_upstream_zone(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_upstream_init_zone(rp_shm_zone_t *shm_zone,
    void *data);
static rp_http_upstream_rr_peers_t *rp_http_upstream_zone_copy_peers(
    rp_slab_pool_t *shpool, rp_http_upstream_srv_conf_t *uscf);
static rp_http_upstream_rr_peer_t *rp_http_upstream_zone_copy_peer(
    rp_http_upstream_rr_peers_t *peers, rp_http_upstream_rr_peer_t *src);


static rp_command_t  rp_http_upstream_zone_commands[] = {

    { rp_string("zone"),
      RP_HTTP_UPS_CONF|RP_CONF_TAKE12,
      rp_http_upstream_zone,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_upstream_zone_module = {
    RP_MODULE_V1,
    &rp_http_upstream_zone_module_ctx,    /* module context */
    rp_http_upstream_zone_commands,       /* module directives */
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


static char *
rp_http_upstream_zone(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    ssize_t                         size;
    rp_str_t                      *value;
    rp_http_upstream_srv_conf_t   *uscf;
    rp_http_upstream_main_conf_t  *umcf;

    uscf = rp_http_conf_get_module_srv_conf(cf, rp_http_upstream_module);
    umcf = rp_http_conf_get_module_main_conf(cf, rp_http_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = rp_parse_size(&value[2]);

        if (size == RP_ERROR) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return RP_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * rp_pagesize)) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return RP_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = rp_shared_memory_add(cf, &value[1], size,
                                           &rp_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return RP_CONF_ERROR;
    }

    uscf->shm_zone->init = rp_http_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_upstream_init_zone(rp_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    rp_uint_t                      i;
    rp_slab_pool_t                *shpool;
    rp_http_upstream_rr_peers_t   *peers, **peersp;
    rp_http_upstream_srv_conf_t   *uscf, **uscfp;
    rp_http_upstream_main_conf_t  *umcf;

    shpool = (rp_slab_pool_t *) shm_zone->shm.addr;
    umcf = shm_zone->data;
    uscfp = umcf->upstreams.elts;

    if (shm_zone->shm.exists) {
        peers = shpool->data;

        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            if (uscf->shm_zone != shm_zone) {
                continue;
            }

            uscf->peer.data = peers;
            peers = peers->zone_next;
        }

        return RP_OK;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = rp_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return RP_ERROR;
    }

    rp_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    peersp = (rp_http_upstream_rr_peers_t **) (void *) &shpool->data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        peers = rp_http_upstream_zone_copy_peers(shpool, uscf);
        if (peers == NULL) {
            return RP_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return RP_OK;
}


static rp_http_upstream_rr_peers_t *
rp_http_upstream_zone_copy_peers(rp_slab_pool_t *shpool,
    rp_http_upstream_srv_conf_t *uscf)
{
    rp_str_t                     *name;
    rp_http_upstream_rr_peer_t   *peer, **peerp;
    rp_http_upstream_rr_peers_t  *peers, *backup;

    peers = rp_slab_alloc(shpool, sizeof(rp_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    rp_memcpy(peers, uscf->peer.data, sizeof(rp_http_upstream_rr_peers_t));

    name = rp_slab_alloc(shpool, sizeof(rp_str_t));
    if (name == NULL) {
        return NULL;
    }

    name->data = rp_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    rp_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    peers->shpool = shpool;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = rp_http_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = rp_slab_alloc(shpool, sizeof(rp_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    rp_memcpy(backup, peers->next, sizeof(rp_http_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = rp_http_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    peers->next = backup;

done:

    uscf->peer.data = peers;

    return peers;
}


static rp_http_upstream_rr_peer_t *
rp_http_upstream_zone_copy_peer(rp_http_upstream_rr_peers_t *peers,
    rp_http_upstream_rr_peer_t *src)
{
    rp_slab_pool_t              *pool;
    rp_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = rp_slab_calloc_locked(pool, sizeof(rp_http_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        rp_memcpy(dst, src, sizeof(rp_http_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
    }

    dst->sockaddr = rp_slab_calloc_locked(pool, sizeof(rp_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = rp_slab_calloc_locked(pool, RP_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        rp_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        rp_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = rp_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        rp_memcpy(dst->server.data, src->server.data, src->server.len);
    }

    return dst;

failed:

    if (dst->server.data) {
        rp_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        rp_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        rp_slab_free_locked(pool, dst->sockaddr);
    }

    rp_slab_free_locked(pool, dst);

    return NULL;
}
