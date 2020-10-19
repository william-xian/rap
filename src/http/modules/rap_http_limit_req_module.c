
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_LIMIT_REQ_PASSED            1
#define RAP_HTTP_LIMIT_REQ_DELAYED           2
#define RAP_HTTP_LIMIT_REQ_REJECTED          3
#define RAP_HTTP_LIMIT_REQ_DELAYED_DRY_RUN   4
#define RAP_HTTP_LIMIT_REQ_REJECTED_DRY_RUN  5


typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    rap_queue_t                  queue;
    rap_msec_t                   last;
    /* integer value, 1 corresponds to 0.001 r/s */
    rap_uint_t                   excess;
    rap_uint_t                   count;
    u_char                       data[1];
} rap_http_limit_req_node_t;


typedef struct {
    rap_rbtree_t                  rbtree;
    rap_rbtree_node_t             sentinel;
    rap_queue_t                   queue;
} rap_http_limit_req_shctx_t;


typedef struct {
    rap_http_limit_req_shctx_t  *sh;
    rap_slab_pool_t             *shpool;
    /* integer value, 1 corresponds to 0.001 r/s */
    rap_uint_t                   rate;
    rap_http_complex_value_t     key;
    rap_http_limit_req_node_t   *node;
} rap_http_limit_req_ctx_t;


typedef struct {
    rap_shm_zone_t              *shm_zone;
    /* integer value, 1 corresponds to 0.001 r/s */
    rap_uint_t                   burst;
    rap_uint_t                   delay;
} rap_http_limit_req_limit_t;


typedef struct {
    rap_array_t                  limits;
    rap_uint_t                   limit_log_level;
    rap_uint_t                   delay_log_level;
    rap_uint_t                   status_code;
    rap_flag_t                   dry_run;
} rap_http_limit_req_conf_t;


static void rap_http_limit_req_delay(rap_http_request_t *r);
static rap_int_t rap_http_limit_req_lookup(rap_http_limit_req_limit_t *limit,
    rap_uint_t hash, rap_str_t *key, rap_uint_t *ep, rap_uint_t account);
static rap_msec_t rap_http_limit_req_account(rap_http_limit_req_limit_t *limits,
    rap_uint_t n, rap_uint_t *ep, rap_http_limit_req_limit_t **limit);
static void rap_http_limit_req_expire(rap_http_limit_req_ctx_t *ctx,
    rap_uint_t n);

static rap_int_t rap_http_limit_req_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static void *rap_http_limit_req_create_conf(rap_conf_t *cf);
static char *rap_http_limit_req_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_limit_req_zone(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_limit_req(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_limit_req_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_limit_req_init(rap_conf_t *cf);


static rap_conf_enum_t  rap_http_limit_req_log_levels[] = {
    { rap_string("info"), RAP_LOG_INFO },
    { rap_string("notice"), RAP_LOG_NOTICE },
    { rap_string("warn"), RAP_LOG_WARN },
    { rap_string("error"), RAP_LOG_ERR },
    { rap_null_string, 0 }
};


static rap_conf_num_bounds_t  rap_http_limit_req_status_bounds = {
    rap_conf_check_num_bounds, 400, 599
};


static rap_command_t  rap_http_limit_req_commands[] = {

    { rap_string("limit_req_zone"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE3,
      rap_http_limit_req_zone,
      0,
      0,
      NULL },

    { rap_string("limit_req"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_http_limit_req,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("limit_req_log_level"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_limit_req_conf_t, limit_log_level),
      &rap_http_limit_req_log_levels },

    { rap_string("limit_req_status"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_limit_req_conf_t, status_code),
      &rap_http_limit_req_status_bounds },

    { rap_string("limit_req_dry_run"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_limit_req_conf_t, dry_run),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_limit_req_module_ctx = {
    rap_http_limit_req_add_variables,      /* preconfiguration */
    rap_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_limit_req_create_conf,        /* create location configuration */
    rap_http_limit_req_merge_conf          /* merge location configuration */
};


rap_module_t  rap_http_limit_req_module = {
    RAP_MODULE_V1,
    &rap_http_limit_req_module_ctx,        /* module context */
    rap_http_limit_req_commands,           /* module directives */
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


static rap_http_variable_t  rap_http_limit_req_vars[] = {

    { rap_string("limit_req_status"), NULL,
      rap_http_limit_req_status_variable, 0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

      rap_http_null_variable
};


static rap_str_t  rap_http_limit_req_status[] = {
    rap_string("PASSED"),
    rap_string("DELAYED"),
    rap_string("REJECTED"),
    rap_string("DELAYED_DRY_RUN"),
    rap_string("REJECTED_DRY_RUN")
};


static rap_int_t
rap_http_limit_req_handler(rap_http_request_t *r)
{
    uint32_t                     hash;
    rap_str_t                    key;
    rap_int_t                    rc;
    rap_uint_t                   n, excess;
    rap_msec_t                   delay;
    rap_http_limit_req_ctx_t    *ctx;
    rap_http_limit_req_conf_t   *lrcf;
    rap_http_limit_req_limit_t  *limit, *limits;

    if (r->main->limit_req_status) {
        return RAP_DECLINED;
    }

    lrcf = rap_http_get_module_loc_conf(r, rap_http_limit_req_module);
    limits = lrcf->limits.elts;

    excess = 0;

    rc = RAP_DECLINED;

#if (RAP_SUPPRESS_WARN)
    limit = NULL;
#endif

    for (n = 0; n < lrcf->limits.nelts; n++) {

        limit = &limits[n];

        ctx = limit->shm_zone->data;

        if (rap_http_complex_value(r, &ctx->key, &key) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        hash = rap_crc32_short(key.data, key.len);

        rap_shmtx_lock(&ctx->shpool->mutex);

        rc = rap_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));

        rap_shmtx_unlock(&ctx->shpool->mutex);

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        if (rc != RAP_AGAIN) {
            break;
        }
    }

    if (rc == RAP_DECLINED) {
        return RAP_DECLINED;
    }

    if (rc == RAP_BUSY || rc == RAP_ERROR) {

        if (rc == RAP_BUSY) {
            rap_log_error(lrcf->limit_log_level, r->connection->log, 0,
                        "limiting requests%s, excess: %ui.%03ui by zone \"%V\"",
                        lrcf->dry_run ? ", dry run" : "",
                        excess / 1000, excess % 1000,
                        &limit->shm_zone->shm.name);
        }

        while (n--) {
            ctx = limits[n].shm_zone->data;

            if (ctx->node == NULL) {
                continue;
            }

            rap_shmtx_lock(&ctx->shpool->mutex);

            ctx->node->count--;

            rap_shmtx_unlock(&ctx->shpool->mutex);

            ctx->node = NULL;
        }

        if (lrcf->dry_run) {
            r->main->limit_req_status = RAP_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
            return RAP_DECLINED;
        }

        r->main->limit_req_status = RAP_HTTP_LIMIT_REQ_REJECTED;

        return lrcf->status_code;
    }

    /* rc == RAP_AGAIN || rc == RAP_OK */

    if (rc == RAP_AGAIN) {
        excess = 0;
    }

    delay = rap_http_limit_req_account(limits, n, &excess, &limit);

    if (!delay) {
        r->main->limit_req_status = RAP_HTTP_LIMIT_REQ_PASSED;
        return RAP_DECLINED;
    }

    rap_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request%s, excess: %ui.%03ui, by zone \"%V\"",
                  lrcf->dry_run ? ", dry run" : "",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);

    if (lrcf->dry_run) {
        r->main->limit_req_status = RAP_HTTP_LIMIT_REQ_DELAYED_DRY_RUN;
        return RAP_DECLINED;
    }

    r->main->limit_req_status = RAP_HTTP_LIMIT_REQ_DELAYED;

    if (rap_handle_read_event(r->connection->read, 0) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = rap_http_test_reading;
    r->write_event_handler = rap_http_limit_req_delay;

    r->connection->write->delayed = 1;
    rap_add_timer(r->connection->write, delay);

    return RAP_AGAIN;
}


static void
rap_http_limit_req_delay(rap_http_request_t *r)
{
    rap_event_t  *wev;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rap_handle_write_event(wev, 0) != RAP_OK) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (rap_handle_read_event(r->connection->read, 0) != RAP_OK) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = rap_http_block_reading;
    r->write_event_handler = rap_http_core_run_phases;

    rap_http_core_run_phases(r);
}


static void
rap_http_limit_req_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t          **p;
    rap_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (rap_http_limit_req_node_t *) &node->color;
            lrnt = (rap_http_limit_req_node_t *) &temp->color;

            p = (rap_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
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


static rap_int_t
rap_http_limit_req_lookup(rap_http_limit_req_limit_t *limit, rap_uint_t hash,
    rap_str_t *key, rap_uint_t *ep, rap_uint_t account)
{
    size_t                      size;
    rap_int_t                   rc, excess;
    rap_msec_t                  now;
    rap_msec_int_t              ms;
    rap_rbtree_node_t          *node, *sentinel;
    rap_http_limit_req_ctx_t   *ctx;
    rap_http_limit_req_node_t  *lr;

    now = rap_current_msec;

    ctx = limit->shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

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

        lr = (rap_http_limit_req_node_t *) &node->color;

        rc = rap_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        if (rc == 0) {
            rap_queue_remove(&lr->queue);
            rap_queue_insert_head(&ctx->sh->queue, &lr->queue);

            ms = (rap_msec_int_t) (now - lr->last);

            if (ms < -60000) {
                ms = 1;

            } else if (ms < 0) {
                ms = 0;
            }

            excess = lr->excess - ctx->rate * ms / 1000 + 1000;

            if (excess < 0) {
                excess = 0;
            }

            *ep = excess;

            if ((rap_uint_t) excess > limit->burst) {
                return RAP_BUSY;
            }

            if (account) {
                lr->excess = excess;

                if (ms) {
                    lr->last = now;
                }

                return RAP_OK;
            }

            lr->count++;

            ctx->node = lr;

            return RAP_AGAIN;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *ep = 0;

    size = offsetof(rap_rbtree_node_t, color)
           + offsetof(rap_http_limit_req_node_t, data)
           + key->len;

    rap_http_limit_req_expire(ctx, 1);

    node = rap_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        rap_http_limit_req_expire(ctx, 0);

        node = rap_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return RAP_ERROR;
        }
    }

    node->key = hash;

    lr = (rap_http_limit_req_node_t *) &node->color;

    lr->len = (u_short) key->len;
    lr->excess = 0;

    rap_memcpy(lr->data, key->data, key->len);

    rap_rbtree_insert(&ctx->sh->rbtree, node);

    rap_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {
        lr->last = now;
        lr->count = 0;
        return RAP_OK;
    }

    lr->last = 0;
    lr->count = 1;

    ctx->node = lr;

    return RAP_AGAIN;
}


static rap_msec_t
rap_http_limit_req_account(rap_http_limit_req_limit_t *limits, rap_uint_t n,
    rap_uint_t *ep, rap_http_limit_req_limit_t **limit)
{
    rap_int_t                   excess;
    rap_msec_t                  now, delay, max_delay;
    rap_msec_int_t              ms;
    rap_http_limit_req_ctx_t   *ctx;
    rap_http_limit_req_node_t  *lr;

    excess = *ep;

    if ((rap_uint_t) excess <= (*limit)->delay) {
        max_delay = 0;

    } else {
        ctx = (*limit)->shm_zone->data;
        max_delay = (excess - (*limit)->delay) * 1000 / ctx->rate;
    }

    while (n--) {
        ctx = limits[n].shm_zone->data;
        lr = ctx->node;

        if (lr == NULL) {
            continue;
        }

        rap_shmtx_lock(&ctx->shpool->mutex);

        now = rap_current_msec;
        ms = (rap_msec_int_t) (now - lr->last);

        if (ms < -60000) {
            ms = 1;

        } else if (ms < 0) {
            ms = 0;
        }

        excess = lr->excess - ctx->rate * ms / 1000 + 1000;

        if (excess < 0) {
            excess = 0;
        }

        if (ms) {
            lr->last = now;
        }

        lr->excess = excess;
        lr->count--;

        rap_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;

        if ((rap_uint_t) excess <= limits[n].delay) {
            continue;
        }

        delay = (excess - limits[n].delay) * 1000 / ctx->rate;

        if (delay > max_delay) {
            max_delay = delay;
            *ep = excess;
            *limit = &limits[n];
        }
    }

    return max_delay;
}


static void
rap_http_limit_req_expire(rap_http_limit_req_ctx_t *ctx, rap_uint_t n)
{
    rap_int_t                   excess;
    rap_msec_t                  now;
    rap_queue_t                *q;
    rap_msec_int_t              ms;
    rap_rbtree_node_t          *node;
    rap_http_limit_req_node_t  *lr;

    now = rap_current_msec;

    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (rap_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = rap_queue_last(&ctx->sh->queue);

        lr = rap_queue_data(q, rap_http_limit_req_node_t, queue);

        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        if (n++ != 0) {

            ms = (rap_msec_int_t) (now - lr->last);
            ms = rap_abs(ms);

            if (ms < 60000) {
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;

            if (excess > 0) {
                return;
            }
        }

        rap_queue_remove(q);

        node = (rap_rbtree_node_t *)
                   ((u_char *) lr - offsetof(rap_rbtree_node_t, color));

        rap_rbtree_delete(&ctx->sh->rbtree, node);

        rap_slab_free_locked(ctx->shpool, node);
    }
}


static rap_int_t
rap_http_limit_req_init_zone(rap_shm_zone_t *shm_zone, void *data)
{
    rap_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    rap_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || rap_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            rap_log_error(RAP_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
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

    ctx->sh = rap_slab_alloc(ctx->shpool, sizeof(rap_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return RAP_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    rap_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    rap_http_limit_req_rbtree_insert_value);

    rap_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = rap_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return RAP_ERROR;
    }

    rap_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_limit_req_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_req_status == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rap_http_limit_req_status[r->main->limit_req_status - 1].len;
    v->data = rap_http_limit_req_status[r->main->limit_req_status - 1].data;

    return RAP_OK;
}


static void *
rap_http_limit_req_create_conf(rap_conf_t *cf)
{
    rap_http_limit_req_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = RAP_CONF_UNSET_UINT;
    conf->status_code = RAP_CONF_UNSET_UINT;
    conf->dry_run = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_limit_req_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_limit_req_conf_t *prev = parent;
    rap_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    rap_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              RAP_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == RAP_LOG_INFO) ?
                                RAP_LOG_INFO : conf->limit_log_level + 1;

    rap_conf_merge_uint_value(conf->status_code, prev->status_code,
                              RAP_HTTP_SERVICE_UNAVAILABLE);

    rap_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return RAP_CONF_OK;
}


static char *
rap_http_limit_req_zone(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    rap_str_t                         *value, name, s;
    rap_int_t                          rate, scale;
    rap_uint_t                         i;
    rap_shm_zone_t                    *shm_zone;
    rap_http_limit_req_ctx_t          *ctx;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
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

        if (rap_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (rap_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (rap_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = rap_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
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

    ctx->rate = rate * 1000 / scale;

    shm_zone = rap_shared_memory_add(cf, &name, size,
                                     &rap_http_limit_req_module);
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

    shm_zone->init = rap_http_limit_req_init_zone;
    shm_zone->data = ctx;

    return RAP_CONF_OK;
}


static char *
rap_http_limit_req(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_limit_req_conf_t  *lrcf = conf;

    rap_int_t                    burst, delay;
    rap_str_t                   *value, s;
    rap_uint_t                   i;
    rap_shm_zone_t              *shm_zone;
    rap_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    delay = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = rap_shared_memory_add(cf, &s, 0,
                                             &rap_http_limit_req_module);
            if (shm_zone == NULL) {
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = rap_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid burst value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "delay=", 6) == 0) {

            delay = rap_atoi(value[i].data + 6, value[i].len - 6);
            if (delay <= 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid delay value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strcmp(value[i].data, "nodelay") == 0) {
            delay = RAP_MAX_INT_T_VALUE / 1000;
            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return RAP_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (rap_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(rap_http_limit_req_limit_t))
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = rap_array_push(&lrcf->limits);
    if (limit == NULL) {
        return RAP_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->burst = burst * 1000;
    limit->delay = delay * 1000;

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_limit_req_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_limit_req_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_limit_req_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_limit_req_handler;

    return RAP_OK;
}
