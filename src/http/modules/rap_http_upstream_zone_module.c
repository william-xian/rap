
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static char *rap_http_upstream_zone(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_upstream_init_zone(rap_shm_zone_t *shm_zone,
    void *data);
static rap_http_upstream_rr_peers_t *rap_http_upstream_zone_copy_peers(
    rap_slab_pool_t *shpool, rap_http_upstream_srv_conf_t *uscf);
static rap_http_upstream_rr_peer_t *rap_http_upstream_zone_copy_peer(
    rap_http_upstream_rr_peers_t *peers, rap_http_upstream_rr_peer_t *src);


static rap_command_t  rap_http_upstream_zone_commands[] = {

    { rap_string("zone"),
      RAP_HTTP_UPS_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_zone,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_zone_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_zone_module_ctx,    /* module context */
    rap_http_upstream_zone_commands,       /* module directives */
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


static char *
rap_http_upstream_zone(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    ssize_t                         size;
    rap_str_t                      *value;
    rap_http_upstream_srv_conf_t   *uscf;
    rap_http_upstream_main_conf_t  *umcf;

    uscf = rap_http_conf_get_module_srv_conf(cf, rap_http_upstream_module);
    umcf = rap_http_conf_get_module_main_conf(cf, rap_http_upstream_module);

    value = cf->args->elts;

    if (!value[1].len) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        size = rap_parse_size(&value[2]);

        if (size == RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }

        if (size < (ssize_t) (8 * rap_pagesize)) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return RAP_CONF_ERROR;
        }

    } else {
        size = 0;
    }

    uscf->shm_zone = rap_shared_memory_add(cf, &value[1], size,
                                           &rap_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    uscf->shm_zone->init = rap_http_upstream_init_zone;
    uscf->shm_zone->data = umcf;

    uscf->shm_zone->noreuse = 1;

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_upstream_init_zone(rap_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    rap_uint_t                      i;
    rap_slab_pool_t                *shpool;
    rap_http_upstream_rr_peers_t   *peers, **peersp;
    rap_http_upstream_srv_conf_t   *uscf, **uscfp;
    rap_http_upstream_main_conf_t  *umcf;

    shpool = (rap_slab_pool_t *) shm_zone->shm.addr;
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

        return RAP_OK;
    }

    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = rap_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return RAP_ERROR;
    }

    rap_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    peersp = (rap_http_upstream_rr_peers_t **) (void *) &shpool->data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];

        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        peers = rap_http_upstream_zone_copy_peers(shpool, uscf);
        if (peers == NULL) {
            return RAP_ERROR;
        }

        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return RAP_OK;
}


static rap_http_upstream_rr_peers_t *
rap_http_upstream_zone_copy_peers(rap_slab_pool_t *shpool,
    rap_http_upstream_srv_conf_t *uscf)
{
    rap_str_t                     *name;
    rap_http_upstream_rr_peer_t   *peer, **peerp;
    rap_http_upstream_rr_peers_t  *peers, *backup;

    peers = rap_slab_alloc(shpool, sizeof(rap_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    rap_memcpy(peers, uscf->peer.data, sizeof(rap_http_upstream_rr_peers_t));

    name = rap_slab_alloc(shpool, sizeof(rap_str_t));
    if (name == NULL) {
        return NULL;
    }

    name->data = rap_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    rap_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    peers->shpool = shpool;

    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = rap_http_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    if (peers->next == NULL) {
        goto done;
    }

    backup = rap_slab_alloc(shpool, sizeof(rap_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    rap_memcpy(backup, peers->next, sizeof(rap_http_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;

    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = rap_http_upstream_zone_copy_peer(backup, *peerp);
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


static rap_http_upstream_rr_peer_t *
rap_http_upstream_zone_copy_peer(rap_http_upstream_rr_peers_t *peers,
    rap_http_upstream_rr_peer_t *src)
{
    rap_slab_pool_t              *pool;
    rap_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = rap_slab_calloc_locked(pool, sizeof(rap_http_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        rap_memcpy(dst, src, sizeof(rap_http_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
    }

    dst->sockaddr = rap_slab_calloc_locked(pool, sizeof(rap_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = rap_slab_calloc_locked(pool, RAP_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        rap_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        rap_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = rap_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        rap_memcpy(dst->server.data, src->server.data, src->server.len);
    }

    return dst;

failed:

    if (dst->server.data) {
        rap_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        rap_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        rap_slab_free_locked(pool, dst->sockaddr);
    }

    rap_slab_free_locked(pool, dst);

    return NULL;
}
