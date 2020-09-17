
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_LIMIT_REQ_PASSED            1
#define RP_HTTP_LIMIT_REQ_DELAYED           2
#define RP_HTTP_LIMIT_REQ_REJECTED          3
#define RP_HTTP_LIMIT_REQ_DELAYED_DRY_RUN   4
#define RP_HTTP_LIMIT_REQ_REJECTED_DRY_RUN  5


typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    rp_queue_t                  queue;
    rp_msec_t                   last;
    /* integer value, 1 corresponds to 0.001 r/s */
    rp_uint_t                   excess;
    rp_uint_t                   count;
    u_char                       data[1];
} rp_http_limit_req_node_t;


typedef struct {
    rp_rbtree_t                  rbtree;
    rp_rbtree_node_t             sentinel;
    rp_queue_t                   queue;
} rp_http_limit_req_shctx_t;


typedef struct {
    rp_http_limit_req_shctx_t  *sh;
    rp_slab_pool_t             *shpool;
    /* integer value, 1 corresponds to 0.001 r/s */
    rp_uint_t                   rate;
    rp_http_complex_value_t     key;
    rp_http_limit_req_node_t   *node;
} rp_http_limit_req_ctx_t;


typedef struct {
    rp_shm_zone_t              *shm_zone;
    /* integer value, 1 corresponds to 0.001 r/s */
    rp_uint_t                   burst;
    rp_uint_t                   delay;
} rp_http_limit_req_limit_t;


typedef struct {
    rp_array_t                  limits;
    rp_uint_t                   limit_log_level;
    rp_uint_t                   delay_log_level;
    rp_uint_t                   status_code;
    rp_flag_t                   dry_run;
} rp_http_limit_req_conf_t;


static void rp_http_limit_req_delay(rp_http_request_t *r);
static rp_int_t rp_http_limit_req_lookup(rp_http_limit_req_limit_t *limit,
    rp_uint_t hash, rp_str_t *key, rp_uint_t *ep, rp_uint_t account);
static rp_msec_t rp_http_limit_req_account(rp_http_limit_req_limit_t *limits,
    rp_uint_t n, rp_uint_t *ep, rp_http_limit_req_limit_t **limit);
static void rp_http_limit_req_expire(rp_http_limit_req_ctx_t *ctx,
    rp_uint_t n);

static rp_int_t rp_http_limit_req_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static void *rp_http_limit_req_create_conf(rp_conf_t *cf);
static char *rp_http_limit_req_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_limit_req_zone(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_limit_req(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_limit_req_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_limit_req_init(rp_conf_t *cf);


static rp_conf_enum_t  rp_http_limit_req_log_levels[] = {
    { rp_string("info"), RP_LOG_INFO },
    { rp_string("notice"), RP_LOG_NOTICE },
    { rp_string("warn"), RP_LOG_WARN },
    { rp_string("error"), RP_LOG_ERR },
    { rp_null_string, 0 }
};


static rp_conf_num_bounds_t  rp_http_limit_req_status_bounds = {
    rp_conf_check_num_bounds, 400, 599
};


static rp_command_t  rp_http_limit_req_commands[] = {

    { rp_string("limit_req_zone"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE3,
      rp_http_limit_req_zone,
      0,
      0,
      NULL },

    { rp_string("limit_req"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE123,
      rp_http_limit_req,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("limit_req_log_level"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_limit_req_conf_t, limit_log_level),
      &rp_http_limit_req_log_levels },

    { rp_string("limit_req_status"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_limit_req_conf_t, status_code),
      &rp_http_limit_req_status_bounds },

    { rp_string("limit_req_dry_run"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_limit_req_conf_t, dry_run),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_limit_req_module_ctx = {
    rp_http_limit_req_add_variables,      /* preconfiguration */
    rp_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_limit_req_create_conf,        /* create location configuration */
    rp_http_limit_req_merge_conf          /* merge location configuration */
};


rp_module_t  rp_http_limit_req_module = {
    RP_MODULE_V1,
    &rp_http_limit_req_module_ctx,        /* module context */
    rp_http_limit_req_commands,           /* module directives */
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


static rp_http_variable_t  rp_http_limit_req_vars[] = {

    { rp_string("limit_req_status"), NULL,
      rp_http_limit_req_status_variable, 0, RP_HTTP_VAR_NOCACHEABLE, 0 },

      rp_http_null_variable
};


static rp_str_t  rp_http_limit_req_status[] = {
    rp_string("PASSED"),
    rp_string("DELAYED"),
    rp_string("REJECTED"),
    rp_string("DELAYED_DRY_RUN"),
    rp_string("REJECTED_DRY_RUN")
};


static rp_int_t
rp_http_limit_req_handler(rp_http_request_t *r)
{
    uint32_t                     hash;
    rp_str_t                    key;
    rp_int_t                    rc;
    rp_uint_t                   n, excess;
    rp_msec_t                   delay;
    rp_http_limit_req_ctx_t    *ctx;
    rp_http_limit_req_conf_t   *lrcf;
    rp_http_limit_req_limit_t  *limit, *limits;

    if (r->main->limit_req_status) {
        return RP_DECLINED;
    }

    lrcf = rp_http_get_module_loc_conf(r, rp_http_limit_req_module);
    limits = lrcf->limits.elts;

    excess = 0;

    rc = RP_DECLINED;

#if (RP_SUPPRESS_WARN)
    limit = NULL;
#endif

    for (n = 0; n < lrcf->limits.nelts; n++) {

        limit = &limits[n];

        ctx = limit->shm_zone->data;

        if (rp_http_complex_value(r, &ctx->key, &key) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        hash = rp_crc32_short(key.data, key.len);

        rp_shmtx_lock(&ctx->shpool->mutex);

        rc = rp_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));

        rp_shmtx_unlock(&ctx->shpool->mutex);

        rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        if (rc != RP_AGAIN) {
            break;
        }
    }

    if (rc == RP_DECLINED) {
        return RP_DECLINED;
    }

    if (rc == RP_BUSY || rc == RP_ERROR) {

        if (rc == RP_BUSY) {
            rp_log_error(lrcf->limit_log_level, r->connection->log, 0,
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

            rp_shmtx_lock(&ctx->shpool->mutex);

            ctx->node->count--;

            rp_shmtx_unlock(&ctx->shpool->mutex);

            ctx->node = NULL;
        }

        if (lrcf->dry_run) {
            r->main->limit_req_status = RP_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
            return RP_DECLINED;
        }

        r->main->limit_req_status = RP_HTTP_LIMIT_REQ_REJECTED;

        return lrcf->status_code;
    }

    /* rc == RP_AGAIN || rc == RP_OK */

    if (rc == RP_AGAIN) {
        excess = 0;
    }

    delay = rp_http_limit_req_account(limits, n, &excess, &limit);

    if (!delay) {
        r->main->limit_req_status = RP_HTTP_LIMIT_REQ_PASSED;
        return RP_DECLINED;
    }

    rp_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request%s, excess: %ui.%03ui, by zone \"%V\"",
                  lrcf->dry_run ? ", dry run" : "",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);

    if (lrcf->dry_run) {
        r->main->limit_req_status = RP_HTTP_LIMIT_REQ_DELAYED_DRY_RUN;
        return RP_DECLINED;
    }

    r->main->limit_req_status = RP_HTTP_LIMIT_REQ_DELAYED;

    if (rp_handle_read_event(r->connection->read, 0) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = rp_http_test_reading;
    r->write_event_handler = rp_http_limit_req_delay;

    r->connection->write->delayed = 1;
    rp_add_timer(r->connection->write, delay);

    return RP_AGAIN;
}


static void
rp_http_limit_req_delay(rp_http_request_t *r)
{
    rp_event_t  *wev;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rp_handle_write_event(wev, 0) != RP_OK) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (rp_handle_read_event(r->connection->read, 0) != RP_OK) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = rp_http_block_reading;
    r->write_event_handler = rp_http_core_run_phases;

    rp_http_core_run_phases(r);
}


static void
rp_http_limit_req_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t          **p;
    rp_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (rp_http_limit_req_node_t *) &node->color;
            lrnt = (rp_http_limit_req_node_t *) &temp->color;

            p = (rp_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
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


static rp_int_t
rp_http_limit_req_lookup(rp_http_limit_req_limit_t *limit, rp_uint_t hash,
    rp_str_t *key, rp_uint_t *ep, rp_uint_t account)
{
    size_t                      size;
    rp_int_t                   rc, excess;
    rp_msec_t                  now;
    rp_msec_int_t              ms;
    rp_rbtree_node_t          *node, *sentinel;
    rp_http_limit_req_ctx_t   *ctx;
    rp_http_limit_req_node_t  *lr;

    now = rp_current_msec;

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

        lr = (rp_http_limit_req_node_t *) &node->color;

        rc = rp_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        if (rc == 0) {
            rp_queue_remove(&lr->queue);
            rp_queue_insert_head(&ctx->sh->queue, &lr->queue);

            ms = (rp_msec_int_t) (now - lr->last);

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

            if ((rp_uint_t) excess > limit->burst) {
                return RP_BUSY;
            }

            if (account) {
                lr->excess = excess;

                if (ms) {
                    lr->last = now;
                }

                return RP_OK;
            }

            lr->count++;

            ctx->node = lr;

            return RP_AGAIN;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *ep = 0;

    size = offsetof(rp_rbtree_node_t, color)
           + offsetof(rp_http_limit_req_node_t, data)
           + key->len;

    rp_http_limit_req_expire(ctx, 1);

    node = rp_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        rp_http_limit_req_expire(ctx, 0);

        node = rp_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return RP_ERROR;
        }
    }

    node->key = hash;

    lr = (rp_http_limit_req_node_t *) &node->color;

    lr->len = (u_short) key->len;
    lr->excess = 0;

    rp_memcpy(lr->data, key->data, key->len);

    rp_rbtree_insert(&ctx->sh->rbtree, node);

    rp_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {
        lr->last = now;
        lr->count = 0;
        return RP_OK;
    }

    lr->last = 0;
    lr->count = 1;

    ctx->node = lr;

    return RP_AGAIN;
}


static rp_msec_t
rp_http_limit_req_account(rp_http_limit_req_limit_t *limits, rp_uint_t n,
    rp_uint_t *ep, rp_http_limit_req_limit_t **limit)
{
    rp_int_t                   excess;
    rp_msec_t                  now, delay, max_delay;
    rp_msec_int_t              ms;
    rp_http_limit_req_ctx_t   *ctx;
    rp_http_limit_req_node_t  *lr;

    excess = *ep;

    if ((rp_uint_t) excess <= (*limit)->delay) {
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

        rp_shmtx_lock(&ctx->shpool->mutex);

        now = rp_current_msec;
        ms = (rp_msec_int_t) (now - lr->last);

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

        rp_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;

        if ((rp_uint_t) excess <= limits[n].delay) {
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
rp_http_limit_req_expire(rp_http_limit_req_ctx_t *ctx, rp_uint_t n)
{
    rp_int_t                   excess;
    rp_msec_t                  now;
    rp_queue_t                *q;
    rp_msec_int_t              ms;
    rp_rbtree_node_t          *node;
    rp_http_limit_req_node_t  *lr;

    now = rp_current_msec;

    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (rp_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = rp_queue_last(&ctx->sh->queue);

        lr = rp_queue_data(q, rp_http_limit_req_node_t, queue);

        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        if (n++ != 0) {

            ms = (rp_msec_int_t) (now - lr->last);
            ms = rp_abs(ms);

            if (ms < 60000) {
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;

            if (excess > 0) {
                return;
            }
        }

        rp_queue_remove(q);

        node = (rp_rbtree_node_t *)
                   ((u_char *) lr - offsetof(rp_rbtree_node_t, color));

        rp_rbtree_delete(&ctx->sh->rbtree, node);

        rp_slab_free_locked(ctx->shpool, node);
    }
}


static rp_int_t
rp_http_limit_req_init_zone(rp_shm_zone_t *shm_zone, void *data)
{
    rp_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    rp_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || rp_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            rp_log_error(RP_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
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

    ctx->sh = rp_slab_alloc(ctx->shpool, sizeof(rp_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return RP_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    rp_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    rp_http_limit_req_rbtree_insert_value);

    rp_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = rp_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return RP_ERROR;
    }

    rp_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return RP_OK;
}


static rp_int_t
rp_http_limit_req_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_req_status == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rp_http_limit_req_status[r->main->limit_req_status - 1].len;
    v->data = rp_http_limit_req_status[r->main->limit_req_status - 1].data;

    return RP_OK;
}


static void *
rp_http_limit_req_create_conf(rp_conf_t *cf)
{
    rp_http_limit_req_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = RP_CONF_UNSET_UINT;
    conf->status_code = RP_CONF_UNSET_UINT;
    conf->dry_run = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_limit_req_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_limit_req_conf_t *prev = parent;
    rp_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    rp_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              RP_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == RP_LOG_INFO) ?
                                RP_LOG_INFO : conf->limit_log_level + 1;

    rp_conf_merge_uint_value(conf->status_code, prev->status_code,
                              RP_HTTP_SERVICE_UNAVAILABLE);

    rp_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return RP_CONF_OK;
}


static char *
rp_http_limit_req_zone(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    rp_str_t                         *value, name, s;
    rp_int_t                          rate, scale;
    rp_uint_t                         i;
    rp_shm_zone_t                    *shm_zone;
    rp_http_limit_req_ctx_t          *ctx;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
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

        if (rp_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (rp_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (rp_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = rp_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
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

    ctx->rate = rate * 1000 / scale;

    shm_zone = rp_shared_memory_add(cf, &name, size,
                                     &rp_http_limit_req_module);
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

    shm_zone->init = rp_http_limit_req_init_zone;
    shm_zone->data = ctx;

    return RP_CONF_OK;
}


static char *
rp_http_limit_req(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_limit_req_conf_t  *lrcf = conf;

    rp_int_t                    burst, delay;
    rp_str_t                   *value, s;
    rp_uint_t                   i;
    rp_shm_zone_t              *shm_zone;
    rp_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    delay = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = rp_shared_memory_add(cf, &s, 0,
                                             &rp_http_limit_req_module);
            if (shm_zone == NULL) {
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = rp_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid burst value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "delay=", 6) == 0) {

            delay = rp_atoi(value[i].data + 6, value[i].len - 6);
            if (delay <= 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid delay value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strcmp(value[i].data, "nodelay") == 0) {
            delay = RP_MAX_INT_T_VALUE / 1000;
            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RP_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return RP_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (rp_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(rp_http_limit_req_limit_t))
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = rp_array_push(&lrcf->limits);
    if (limit == NULL) {
        return RP_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->burst = burst * 1000;
    limit->delay = delay * 1000;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_limit_req_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_limit_req_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_limit_req_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_limit_req_handler;

    return RP_OK;
}
