
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


#define RP_STREAM_LIMIT_CONN_PASSED            1
#define RP_STREAM_LIMIT_CONN_REJECTED          2
#define RP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN  3


typedef struct {
    u_char                          color;
    u_char                          len;
    u_short                         conn;
    u_char                          data[1];
} rp_stream_limit_conn_node_t;


typedef struct {
    rp_shm_zone_t                 *shm_zone;
    rp_rbtree_node_t              *node;
} rp_stream_limit_conn_cleanup_t;


typedef struct {
    rp_rbtree_t                    rbtree;
    rp_rbtree_node_t               sentinel;
} rp_stream_limit_conn_shctx_t;


typedef struct {
    rp_stream_limit_conn_shctx_t  *sh;
    rp_slab_pool_t                *shpool;
    rp_stream_complex_value_t      key;
} rp_stream_limit_conn_ctx_t;


typedef struct {
    rp_shm_zone_t                 *shm_zone;
    rp_uint_t                      conn;
} rp_stream_limit_conn_limit_t;


typedef struct {
    rp_array_t                     limits;
    rp_uint_t                      log_level;
    rp_flag_t                      dry_run;
} rp_stream_limit_conn_conf_t;


static rp_rbtree_node_t *rp_stream_limit_conn_lookup(rp_rbtree_t *rbtree,
    rp_str_t *key, uint32_t hash);
static void rp_stream_limit_conn_cleanup(void *data);
static rp_inline void rp_stream_limit_conn_cleanup_all(rp_pool_t *pool);

static rp_int_t rp_stream_limit_conn_status_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static void *rp_stream_limit_conn_create_conf(rp_conf_t *cf);
static char *rp_stream_limit_conn_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_stream_limit_conn_zone(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_limit_conn(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_stream_limit_conn_add_variables(rp_conf_t *cf);
static rp_int_t rp_stream_limit_conn_init(rp_conf_t *cf);


static rp_conf_enum_t  rp_stream_limit_conn_log_levels[] = {
    { rp_string("info"), RP_LOG_INFO },
    { rp_string("notice"), RP_LOG_NOTICE },
    { rp_string("warn"), RP_LOG_WARN },
    { rp_string("error"), RP_LOG_ERR },
    { rp_null_string, 0 }
};


static rp_command_t  rp_stream_limit_conn_commands[] = {

    { rp_string("limit_conn_zone"),
      RP_STREAM_MAIN_CONF|RP_CONF_TAKE2,
      rp_stream_limit_conn_zone,
      0,
      0,
      NULL },

    { rp_string("limit_conn"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE2,
      rp_stream_limit_conn,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("limit_conn_log_level"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_limit_conn_conf_t, log_level),
      &rp_stream_limit_conn_log_levels },

    { rp_string("limit_conn_dry_run"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_limit_conn_conf_t, dry_run),
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_limit_conn_module_ctx = {
    rp_stream_limit_conn_add_variables,   /* preconfiguration */
    rp_stream_limit_conn_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_limit_conn_create_conf,     /* create server configuration */
    rp_stream_limit_conn_merge_conf       /* merge server configuration */
};


rp_module_t  rp_stream_limit_conn_module = {
    RP_MODULE_V1,
    &rp_stream_limit_conn_module_ctx,     /* module context */
    rp_stream_limit_conn_commands,        /* module directives */
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


static rp_stream_variable_t  rp_stream_limit_conn_vars[] = {

    { rp_string("limit_conn_status"), NULL,
      rp_stream_limit_conn_status_variable, 0, RP_STREAM_VAR_NOCACHEABLE, 0 },

      rp_stream_null_variable
};


static rp_str_t  rp_stream_limit_conn_status[] = {
    rp_string("PASSED"),
    rp_string("REJECTED"),
    rp_string("REJECTED_DRY_RUN")
};


static rp_int_t
rp_stream_limit_conn_handler(rp_stream_session_t *s)
{
    size_t                            n;
    uint32_t                          hash;
    rp_str_t                         key;
    rp_uint_t                        i;
    rp_rbtree_node_t                *node;
    rp_pool_cleanup_t               *cln;
    rp_stream_limit_conn_ctx_t      *ctx;
    rp_stream_limit_conn_node_t     *lc;
    rp_stream_limit_conn_conf_t     *lccf;
    rp_stream_limit_conn_limit_t    *limits;
    rp_stream_limit_conn_cleanup_t  *lccln;

    lccf = rp_stream_get_module_srv_conf(s, rp_stream_limit_conn_module);
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        if (rp_stream_complex_value(s, &ctx->key, &key) != RP_OK) {
            return RP_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        s->limit_conn_status = RP_STREAM_LIMIT_CONN_PASSED;

        hash = rp_crc32_short(key.data, key.len);

        rp_shmtx_lock(&ctx->shpool->mutex);

        node = rp_stream_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL) {

            n = offsetof(rp_rbtree_node_t, color)
                + offsetof(rp_stream_limit_conn_node_t, data)
                + key.len;

            node = rp_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL) {
                rp_shmtx_unlock(&ctx->shpool->mutex);
                rp_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        RP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return RP_DECLINED;
                }

                s->limit_conn_status = RP_STREAM_LIMIT_CONN_REJECTED;

                return RP_STREAM_SERVICE_UNAVAILABLE;
            }

            lc = (rp_stream_limit_conn_node_t *) &node->color;

            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            rp_memcpy(lc->data, key.data, key.len);

            rp_rbtree_insert(&ctx->sh->rbtree, node);

        } else {

            lc = (rp_stream_limit_conn_node_t *) &node->color;

            if ((rp_uint_t) lc->conn >= limits[i].conn) {

                rp_shmtx_unlock(&ctx->shpool->mutex);

                rp_log_error(lccf->log_level, s->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                rp_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        RP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return RP_DECLINED;
                }

                s->limit_conn_status = RP_STREAM_LIMIT_CONN_REJECTED;

                return RP_STREAM_SERVICE_UNAVAILABLE;
            }

            lc->conn++;
        }

        rp_log_debug2(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        rp_shmtx_unlock(&ctx->shpool->mutex);

        cln = rp_pool_cleanup_add(s->connection->pool,
                                   sizeof(rp_stream_limit_conn_cleanup_t));
        if (cln == NULL) {
            return RP_ERROR;
        }

        cln->handler = rp_stream_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    return RP_DECLINED;
}


static void
rp_stream_limit_conn_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t             **p;
    rp_stream_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (rp_stream_limit_conn_node_t *) &node->color;
            lcnt = (rp_stream_limit_conn_node_t *) &temp->color;

            p = (rp_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    rp_rbt_red(node);
}


static rp_rbtree_node_t *
rp_stream_limit_conn_lookup(rp_rbtree_t *rbtree, rp_str_t *key,
    uint32_t hash)
{
    rp_int_t                      rc;
    rp_rbtree_node_t             *node, *sentinel;
    rp_stream_limit_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (rp_stream_limit_conn_node_t *) &node->color;

        rc = rp_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
rp_stream_limit_conn_cleanup(void *data)
{
    rp_stream_limit_conn_cleanup_t  *lccln = data;

    rp_rbtree_node_t             *node;
    rp_stream_limit_conn_ctx_t   *ctx;
    rp_stream_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    node = lccln->node;
    lc = (rp_stream_limit_conn_node_t *) &node->color;

    rp_shmtx_lock(&ctx->shpool->mutex);

    rp_log_debug2(RP_LOG_DEBUG_STREAM, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        rp_rbtree_delete(&ctx->sh->rbtree, node);
        rp_slab_free_locked(ctx->shpool, node);
    }

    rp_shmtx_unlock(&ctx->shpool->mutex);
}


static rp_inline void
rp_stream_limit_conn_cleanup_all(rp_pool_t *pool)
{
    rp_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == rp_stream_limit_conn_cleanup) {
        rp_stream_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static rp_int_t
rp_stream_limit_conn_init_zone(rp_shm_zone_t *shm_zone, void *data)
{
    rp_stream_limit_conn_ctx_t  *octx = data;

    size_t                        len;
    rp_stream_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || rp_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            rp_log_error(RP_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return RP_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return RP_OK;
    }

    ctx->shpool = (rp_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return RP_OK;
    }

    ctx->sh = rp_slab_alloc(ctx->shpool,
                             sizeof(rp_stream_limit_conn_shctx_t));
    if (ctx->sh == NULL) {
        return RP_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    rp_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    rp_stream_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = rp_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return RP_ERROR;
    }

    rp_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return RP_OK;
}


static rp_int_t
rp_stream_limit_conn_status_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    if (s->limit_conn_status == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rp_stream_limit_conn_status[s->limit_conn_status - 1].len;
    v->data = rp_stream_limit_conn_status[s->limit_conn_status - 1].data;

    return RP_OK;
}


static void *
rp_stream_limit_conn_create_conf(rp_conf_t *cf)
{
    rp_stream_limit_conn_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = RP_CONF_UNSET_UINT;
    conf->dry_run = RP_CONF_UNSET;

    return conf;
}


static char *
rp_stream_limit_conn_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_limit_conn_conf_t *prev = parent;
    rp_stream_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    rp_conf_merge_uint_value(conf->log_level, prev->log_level, RP_LOG_ERR);

    rp_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return RP_CONF_OK;
}


static char *
rp_stream_limit_conn_zone(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    u_char                              *p;
    ssize_t                              size;
    rp_str_t                           *value, name, s;
    rp_uint_t                           i;
    rp_shm_zone_t                      *shm_zone;
    rp_stream_limit_conn_ctx_t         *ctx;
    rp_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_stream_limit_conn_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ccv, sizeof(rp_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (rp_stream_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) rp_strchr(name.data, ':');

            if (p == NULL) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = rp_parse_size(&s);

            if (size == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * rp_pagesize)) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RP_CONF_ERROR;
    }

    if (name.len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return RP_CONF_ERROR;
    }

    shm_zone = rp_shared_memory_add(cf, &name, size,
                                     &rp_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return RP_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return RP_CONF_ERROR;
    }

    shm_zone->init = rp_stream_limit_conn_init_zone;
    shm_zone->data = ctx;

    return RP_CONF_OK;
}


static char *
rp_stream_limit_conn(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_shm_zone_t                 *shm_zone;
    rp_stream_limit_conn_conf_t   *lccf = conf;
    rp_stream_limit_conn_limit_t  *limit, *limits;

    rp_str_t   *value;
    rp_int_t    n;
    rp_uint_t   i;

    value = cf->args->elts;

    shm_zone = rp_shared_memory_add(cf, &value[1], 0,
                                     &rp_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return RP_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (rp_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(rp_stream_limit_conn_limit_t))
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = rp_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return RP_CONF_ERROR;
    }

    if (n > 65535) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return RP_CONF_ERROR;
    }

    limit = rp_array_push(&lccf->limits);
    if (limit == NULL) {
        return RP_CONF_ERROR;
    }

    limit->conn = n;
    limit->shm_zone = shm_zone;

    return RP_CONF_OK;
}


static rp_int_t
rp_stream_limit_conn_add_variables(rp_conf_t *cf)
{
    rp_stream_variable_t  *var, *v;

    for (v = rp_stream_limit_conn_vars; v->name.len; v++) {
        var = rp_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_limit_conn_init(rp_conf_t *cf)
{
    rp_stream_handler_pt        *h;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    h = rp_array_push(&cmcf->phases[RP_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_stream_limit_conn_handler;

    return RP_OK;
}
