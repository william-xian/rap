
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


#define RAP_STREAM_LIMIT_CONN_PASSED            1
#define RAP_STREAM_LIMIT_CONN_REJECTED          2
#define RAP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN  3


typedef struct {
    u_char                          color;
    u_char                          len;
    u_short                         conn;
    u_char                          data[1];
} rap_stream_limit_conn_node_t;


typedef struct {
    rap_shm_zone_t                 *shm_zone;
    rap_rbtree_node_t              *node;
} rap_stream_limit_conn_cleanup_t;


typedef struct {
    rap_rbtree_t                    rbtree;
    rap_rbtree_node_t               sentinel;
} rap_stream_limit_conn_shctx_t;


typedef struct {
    rap_stream_limit_conn_shctx_t  *sh;
    rap_slab_pool_t                *shpool;
    rap_stream_complex_value_t      key;
} rap_stream_limit_conn_ctx_t;


typedef struct {
    rap_shm_zone_t                 *shm_zone;
    rap_uint_t                      conn;
} rap_stream_limit_conn_limit_t;


typedef struct {
    rap_array_t                     limits;
    rap_uint_t                      log_level;
    rap_flag_t                      dry_run;
} rap_stream_limit_conn_conf_t;


static rap_rbtree_node_t *rap_stream_limit_conn_lookup(rap_rbtree_t *rbtree,
    rap_str_t *key, uint32_t hash);
static void rap_stream_limit_conn_cleanup(void *data);
static rap_inline void rap_stream_limit_conn_cleanup_all(rap_pool_t *pool);

static rap_int_t rap_stream_limit_conn_status_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static void *rap_stream_limit_conn_create_conf(rap_conf_t *cf);
static char *rap_stream_limit_conn_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_stream_limit_conn_zone(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_limit_conn(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_stream_limit_conn_add_variables(rap_conf_t *cf);
static rap_int_t rap_stream_limit_conn_init(rap_conf_t *cf);


static rap_conf_enum_t  rap_stream_limit_conn_log_levels[] = {
    { rap_string("info"), RAP_LOG_INFO },
    { rap_string("notice"), RAP_LOG_NOTICE },
    { rap_string("warn"), RAP_LOG_WARN },
    { rap_string("error"), RAP_LOG_ERR },
    { rap_null_string, 0 }
};


static rap_command_t  rap_stream_limit_conn_commands[] = {

    { rap_string("limit_conn_zone"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_TAKE2,
      rap_stream_limit_conn_zone,
      0,
      0,
      NULL },

    { rap_string("limit_conn"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE2,
      rap_stream_limit_conn,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("limit_conn_log_level"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_limit_conn_conf_t, log_level),
      &rap_stream_limit_conn_log_levels },

    { rap_string("limit_conn_dry_run"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_limit_conn_conf_t, dry_run),
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_limit_conn_module_ctx = {
    rap_stream_limit_conn_add_variables,   /* preconfiguration */
    rap_stream_limit_conn_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_stream_limit_conn_create_conf,     /* create server configuration */
    rap_stream_limit_conn_merge_conf       /* merge server configuration */
};


rap_module_t  rap_stream_limit_conn_module = {
    RAP_MODULE_V1,
    &rap_stream_limit_conn_module_ctx,     /* module context */
    rap_stream_limit_conn_commands,        /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_stream_variable_t  rap_stream_limit_conn_vars[] = {

    { rap_string("limit_conn_status"), NULL,
      rap_stream_limit_conn_status_variable, 0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

      rap_stream_null_variable
};


static rap_str_t  rap_stream_limit_conn_status[] = {
    rap_string("PASSED"),
    rap_string("REJECTED"),
    rap_string("REJECTED_DRY_RUN")
};


static rap_int_t
rap_stream_limit_conn_handler(rap_stream_session_t *s)
{
    size_t                            n;
    uint32_t                          hash;
    rap_str_t                         key;
    rap_uint_t                        i;
    rap_rbtree_node_t                *node;
    rap_pool_cleanup_t               *cln;
    rap_stream_limit_conn_ctx_t      *ctx;
    rap_stream_limit_conn_node_t     *lc;
    rap_stream_limit_conn_conf_t     *lccf;
    rap_stream_limit_conn_limit_t    *limits;
    rap_stream_limit_conn_cleanup_t  *lccln;

    lccf = rap_stream_get_module_srv_conf(s, rap_stream_limit_conn_module);
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        if (rap_stream_complex_value(s, &ctx->key, &key) != RAP_OK) {
            return RAP_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        s->limit_conn_status = RAP_STREAM_LIMIT_CONN_PASSED;

        hash = rap_crc32_short(key.data, key.len);

        rap_shmtx_lock(&ctx->shpool->mutex);

        node = rap_stream_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL) {

            n = offsetof(rap_rbtree_node_t, color)
                + offsetof(rap_stream_limit_conn_node_t, data)
                + key.len;

            node = rap_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL) {
                rap_shmtx_unlock(&ctx->shpool->mutex);
                rap_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        RAP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return RAP_DECLINED;
                }

                s->limit_conn_status = RAP_STREAM_LIMIT_CONN_REJECTED;

                return RAP_STREAM_SERVICE_UNAVAILABLE;
            }

            lc = (rap_stream_limit_conn_node_t *) &node->color;

            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            rap_memcpy(lc->data, key.data, key.len);

            rap_rbtree_insert(&ctx->sh->rbtree, node);

        } else {

            lc = (rap_stream_limit_conn_node_t *) &node->color;

            if ((rap_uint_t) lc->conn >= limits[i].conn) {

                rap_shmtx_unlock(&ctx->shpool->mutex);

                rap_log_error(lccf->log_level, s->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                rap_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        RAP_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return RAP_DECLINED;
                }

                s->limit_conn_status = RAP_STREAM_LIMIT_CONN_REJECTED;

                return RAP_STREAM_SERVICE_UNAVAILABLE;
            }

            lc->conn++;
        }

        rap_log_debug2(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        rap_shmtx_unlock(&ctx->shpool->mutex);

        cln = rap_pool_cleanup_add(s->connection->pool,
                                   sizeof(rap_stream_limit_conn_cleanup_t));
        if (cln == NULL) {
            return RAP_ERROR;
        }

        cln->handler = rap_stream_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    return RAP_DECLINED;
}


static void
rap_stream_limit_conn_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t             **p;
    rap_stream_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (rap_stream_limit_conn_node_t *) &node->color;
            lcnt = (rap_stream_limit_conn_node_t *) &temp->color;

            p = (rap_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
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
    rap_rbt_red(node);
}


static rap_rbtree_node_t *
rap_stream_limit_conn_lookup(rap_rbtree_t *rbtree, rap_str_t *key,
    uint32_t hash)
{
    rap_int_t                      rc;
    rap_rbtree_node_t             *node, *sentinel;
    rap_stream_limit_conn_node_t  *lcn;

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

        lcn = (rap_stream_limit_conn_node_t *) &node->color;

        rc = rap_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
rap_stream_limit_conn_cleanup(void *data)
{
    rap_stream_limit_conn_cleanup_t  *lccln = data;

    rap_rbtree_node_t             *node;
    rap_stream_limit_conn_ctx_t   *ctx;
    rap_stream_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    node = lccln->node;
    lc = (rap_stream_limit_conn_node_t *) &node->color;

    rap_shmtx_lock(&ctx->shpool->mutex);

    rap_log_debug2(RAP_LOG_DEBUG_STREAM, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        rap_rbtree_delete(&ctx->sh->rbtree, node);
        rap_slab_free_locked(ctx->shpool, node);
    }

    rap_shmtx_unlock(&ctx->shpool->mutex);
}


static rap_inline void
rap_stream_limit_conn_cleanup_all(rap_pool_t *pool)
{
    rap_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == rap_stream_limit_conn_cleanup) {
        rap_stream_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static rap_int_t
rap_stream_limit_conn_init_zone(rap_shm_zone_t *shm_zone, void *data)
{
    rap_stream_limit_conn_ctx_t  *octx = data;

    size_t                        len;
    rap_stream_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || rap_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            rap_log_error(RAP_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return RAP_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return RAP_OK;
    }

    ctx->shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return RAP_OK;
    }

    ctx->sh = rap_slab_alloc(ctx->shpool,
                             sizeof(rap_stream_limit_conn_shctx_t));
    if (ctx->sh == NULL) {
        return RAP_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    rap_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    rap_stream_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = rap_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return RAP_ERROR;
    }

    rap_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return RAP_OK;
}


static rap_int_t
rap_stream_limit_conn_status_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    if (s->limit_conn_status == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rap_stream_limit_conn_status[s->limit_conn_status - 1].len;
    v->data = rap_stream_limit_conn_status[s->limit_conn_status - 1].data;

    return RAP_OK;
}


static void *
rap_stream_limit_conn_create_conf(rap_conf_t *cf)
{
    rap_stream_limit_conn_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_stream_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = RAP_CONF_UNSET_UINT;
    conf->dry_run = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_stream_limit_conn_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_stream_limit_conn_conf_t *prev = parent;
    rap_stream_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    rap_conf_merge_uint_value(conf->log_level, prev->log_level, RAP_LOG_ERR);

    rap_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return RAP_CONF_OK;
}


static char *
rap_stream_limit_conn_zone(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    u_char                              *p;
    ssize_t                              size;
    rap_str_t                           *value, name, s;
    rap_uint_t                           i;
    rap_shm_zone_t                      *shm_zone;
    rap_stream_limit_conn_ctx_t         *ctx;
    rap_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_stream_limit_conn_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ccv, sizeof(rap_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (rap_stream_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) rap_strchr(name.data, ':');

            if (p == NULL) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = rap_parse_size(&s);

            if (size == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * rap_pagesize)) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (name.len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return RAP_CONF_ERROR;
    }

    shm_zone = rap_shared_memory_add(cf, &name, size,
                                     &rap_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return RAP_CONF_ERROR;
    }

    shm_zone->init = rap_stream_limit_conn_init_zone;
    shm_zone->data = ctx;

    return RAP_CONF_OK;
}


static char *
rap_stream_limit_conn(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_shm_zone_t                 *shm_zone;
    rap_stream_limit_conn_conf_t   *lccf = conf;
    rap_stream_limit_conn_limit_t  *limit, *limits;

    rap_str_t   *value;
    rap_int_t    n;
    rap_uint_t   i;

    value = cf->args->elts;

    shm_zone = rap_shared_memory_add(cf, &value[1], 0,
                                     &rap_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (rap_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(rap_stream_limit_conn_limit_t))
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = rap_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return RAP_CONF_ERROR;
    }

    if (n > 65535) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return RAP_CONF_ERROR;
    }

    limit = rap_array_push(&lccf->limits);
    if (limit == NULL) {
        return RAP_CONF_ERROR;
    }

    limit->conn = n;
    limit->shm_zone = shm_zone;

    return RAP_CONF_OK;
}


static rap_int_t
rap_stream_limit_conn_add_variables(rap_conf_t *cf)
{
    rap_stream_variable_t  *var, *v;

    for (v = rap_stream_limit_conn_vars; v->name.len; v++) {
        var = rap_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_limit_conn_init(rap_conf_t *cf)
{
    rap_stream_handler_pt        *h;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    h = rap_array_push(&cmcf->phases[RAP_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_stream_limit_conn_handler;

    return RAP_OK;
}
