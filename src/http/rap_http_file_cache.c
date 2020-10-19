
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_md5.h>


static rap_int_t rap_http_file_cache_lock(rap_http_request_t *r,
    rap_http_cache_t *c);
static void rap_http_file_cache_lock_wait_handler(rap_event_t *ev);
static void rap_http_file_cache_lock_wait(rap_http_request_t *r,
    rap_http_cache_t *c);
static rap_int_t rap_http_file_cache_read(rap_http_request_t *r,
    rap_http_cache_t *c);
static ssize_t rap_http_file_cache_aio_read(rap_http_request_t *r,
    rap_http_cache_t *c);
#if (RAP_HAVE_FILE_AIO)
static void rap_http_cache_aio_event_handler(rap_event_t *ev);
#endif
#if (RAP_THREADS)
static rap_int_t rap_http_cache_thread_handler(rap_thread_task_t *task,
    rap_file_t *file);
static void rap_http_cache_thread_event_handler(rap_event_t *ev);
#endif
static rap_int_t rap_http_file_cache_exists(rap_http_file_cache_t *cache,
    rap_http_cache_t *c);
static rap_int_t rap_http_file_cache_name(rap_http_request_t *r,
    rap_path_t *path);
static rap_http_file_cache_node_t *
    rap_http_file_cache_lookup(rap_http_file_cache_t *cache, u_char *key);
static void rap_http_file_cache_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);
static void rap_http_file_cache_vary(rap_http_request_t *r, u_char *vary,
    size_t len, u_char *hash);
static void rap_http_file_cache_vary_header(rap_http_request_t *r,
    rap_md5_t *md5, rap_str_t *name);
static rap_int_t rap_http_file_cache_reopen(rap_http_request_t *r,
    rap_http_cache_t *c);
static rap_int_t rap_http_file_cache_update_variant(rap_http_request_t *r,
    rap_http_cache_t *c);
static void rap_http_file_cache_cleanup(void *data);
static time_t rap_http_file_cache_forced_expire(rap_http_file_cache_t *cache);
static time_t rap_http_file_cache_expire(rap_http_file_cache_t *cache);
static void rap_http_file_cache_delete(rap_http_file_cache_t *cache,
    rap_queue_t *q, u_char *name);
static void rap_http_file_cache_loader_sleep(rap_http_file_cache_t *cache);
static rap_int_t rap_http_file_cache_noop(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static rap_int_t rap_http_file_cache_manage_file(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static rap_int_t rap_http_file_cache_manage_directory(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static rap_int_t rap_http_file_cache_add_file(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static rap_int_t rap_http_file_cache_add(rap_http_file_cache_t *cache,
    rap_http_cache_t *c);
static rap_int_t rap_http_file_cache_delete_file(rap_tree_ctx_t *ctx,
    rap_str_t *path);
static void rap_http_file_cache_set_watermark(rap_http_file_cache_t *cache);


rap_str_t  rap_http_cache_status[] = {
    rap_string("MISS"),
    rap_string("BYPASS"),
    rap_string("EXPIRED"),
    rap_string("STALE"),
    rap_string("UPDATING"),
    rap_string("REVALIDATED"),
    rap_string("HIT")
};


static u_char  rap_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };


static rap_int_t
rap_http_file_cache_init(rap_shm_zone_t *shm_zone, void *data)
{
    rap_http_file_cache_t  *ocache = data;

    size_t                  len;
    rap_uint_t              n;
    rap_http_file_cache_t  *cache;

    cache = shm_zone->data;

    if (ocache) {
        if (rap_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
            rap_log_error(RAP_LOG_EMERG, shm_zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &cache->path->name,
                          &ocache->path->name);

            return RAP_ERROR;
        }

        for (n = 0; n < RAP_MAX_PATH_LEVEL; n++) {
            if (cache->path->level[n] != ocache->path->level[n]) {
                rap_log_error(RAP_LOG_EMERG, shm_zone->shm.log, 0,
                              "cache \"%V\" had previously different levels",
                              &shm_zone->shm.name);
                return RAP_ERROR;
            }
        }

        cache->sh = ocache->sh;

        cache->shpool = ocache->shpool;
        cache->bsize = ocache->bsize;

        cache->max_size /= cache->bsize;

        if (!cache->sh->cold || cache->sh->loading) {
            cache->path->loader = NULL;
        }

        return RAP_OK;
    }

    cache->shpool = (rap_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cache->sh = cache->shpool->data;
        cache->bsize = rap_fs_bsize(cache->path->name.data);
        cache->max_size /= cache->bsize;

        return RAP_OK;
    }

    cache->sh = rap_slab_alloc(cache->shpool, sizeof(rap_http_file_cache_sh_t));
    if (cache->sh == NULL) {
        return RAP_ERROR;
    }

    cache->shpool->data = cache->sh;

    rap_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
                    rap_http_file_cache_rbtree_insert_value);

    rap_queue_init(&cache->sh->queue);

    cache->sh->cold = 1;
    cache->sh->loading = 0;
    cache->sh->size = 0;
    cache->sh->count = 0;
    cache->sh->watermark = (rap_uint_t) -1;

    cache->bsize = rap_fs_bsize(cache->path->name.data);

    cache->max_size /= cache->bsize;

    len = sizeof(" in cache keys zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = rap_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return RAP_ERROR;
    }

    rap_sprintf(cache->shpool->log_ctx, " in cache keys zone \"%V\"%Z",
                &shm_zone->shm.name);

    cache->shpool->log_nomem = 0;

    return RAP_OK;
}


rap_int_t
rap_http_file_cache_new(rap_http_request_t *r)
{
    rap_http_cache_t  *c;

    c = rap_pcalloc(r->pool, sizeof(rap_http_cache_t));
    if (c == NULL) {
        return RAP_ERROR;
    }

    if (rap_array_init(&c->keys, r->pool, 4, sizeof(rap_str_t)) != RAP_OK) {
        return RAP_ERROR;
    }

    r->cache = c;
    c->file.log = r->connection->log;
    c->file.fd = RAP_INVALID_FILE;

    return RAP_OK;
}


rap_int_t
rap_http_file_cache_create(rap_http_request_t *r)
{
    rap_http_cache_t       *c;
    rap_pool_cleanup_t     *cln;
    rap_http_file_cache_t  *cache;

    c = r->cache;
    cache = c->file_cache;

    cln = rap_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->handler = rap_http_file_cache_cleanup;
    cln->data = c;

    if (rap_http_file_cache_exists(cache, c) == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rap_http_file_cache_name(r, cache->path) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_http_file_cache_create_key(rap_http_request_t *r)
{
    size_t             len;
    rap_str_t         *key;
    rap_uint_t         i;
    rap_md5_t          md5;
    rap_http_cache_t  *c;

    c = r->cache;

    len = 0;

    rap_crc32_init(c->crc32);
    rap_md5_init(&md5);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cache key: \"%V\"", &key[i]);

        len += key[i].len;

        rap_crc32_update(&c->crc32, key[i].data, key[i].len);
        rap_md5_update(&md5, key[i].data, key[i].len);
    }

    c->header_start = sizeof(rap_http_file_cache_header_t)
                      + sizeof(rap_http_file_cache_key) + len + 1;

    rap_crc32_final(c->crc32);
    rap_md5_final(c->key, &md5);

    rap_memcpy(c->main, c->key, RAP_HTTP_CACHE_KEY_LEN);
}


rap_int_t
rap_http_file_cache_open(rap_http_request_t *r)
{
    rap_int_t                  rc, rv;
    rap_uint_t                 test;
    rap_http_cache_t          *c;
    rap_pool_cleanup_t        *cln;
    rap_open_file_info_t       of;
    rap_http_file_cache_t     *cache;
    rap_http_core_loc_conf_t  *clcf;

    c = r->cache;

    if (c->waiting) {
        return RAP_AGAIN;
    }

    if (c->reading) {
        return rap_http_file_cache_read(r, c);
    }

    cache = c->file_cache;

    if (c->node == NULL) {
        cln = rap_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return RAP_ERROR;
        }

        cln->handler = rap_http_file_cache_cleanup;
        cln->data = c;
    }

    rc = rap_http_file_cache_exists(cache, c);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache exists: %i e:%d", rc, c->exists);

    if (rc == RAP_ERROR) {
        return rc;
    }

    if (rc == RAP_AGAIN) {
        return RAP_HTTP_CACHE_SCARCE;
    }

    if (rc == RAP_OK) {

        if (c->error) {
            return c->error;
        }

        c->temp_file = 1;
        test = c->exists ? 1 : 0;
        rv = RAP_DECLINED;

    } else { /* rc == RAP_DECLINED */

        test = cache->sh->cold ? 1 : 0;

        if (c->min_uses > 1) {

            if (!test) {
                return RAP_HTTP_CACHE_SCARCE;
            }

            rv = RAP_HTTP_CACHE_SCARCE;

        } else {
            c->temp_file = 1;
            rv = RAP_DECLINED;
        }
    }

    if (rap_http_file_cache_name(r, cache->path) != RAP_OK) {
        return RAP_ERROR;
    }

    if (!test) {
        goto done;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_memzero(&of, sizeof(rap_open_file_info_t));

    of.uniq = c->uniq;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.events = clcf->open_file_cache_events;
    of.directio = RAP_OPEN_FILE_DIRECTIO_OFF;
    of.read_ahead = clcf->read_ahead;

    if (rap_open_cached_file(clcf->open_file_cache, &c->file.name, &of, r->pool)
        != RAP_OK)
    {
        switch (of.err) {

        case 0:
            return RAP_ERROR;

        case RAP_ENOENT:
        case RAP_ENOTDIR:
            goto done;

        default:
            rap_log_error(RAP_LOG_CRIT, r->connection->log, of.err,
                          rap_open_file_n " \"%s\" failed", c->file.name.data);
            return RAP_ERROR;
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache fd: %d", of.fd);

    c->file.fd = of.fd;
    c->file.log = r->connection->log;
    c->uniq = of.uniq;
    c->length = of.size;
    c->fs_size = (of.fs_size + cache->bsize - 1) / cache->bsize;

    c->buf = rap_create_temp_buf(r->pool, c->body_start);
    if (c->buf == NULL) {
        return RAP_ERROR;
    }

    return rap_http_file_cache_read(r, c);

done:

    if (rv == RAP_DECLINED) {
        return rap_http_file_cache_lock(r, c);
    }

    return rv;
}


static rap_int_t
rap_http_file_cache_lock(rap_http_request_t *r, rap_http_cache_t *c)
{
    rap_msec_t                 now, timer;
    rap_http_file_cache_t     *cache;

    if (!c->lock) {
        return RAP_DECLINED;
    }

    now = rap_current_msec;

    cache = c->file_cache;

    rap_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (!c->node->updating || (rap_msec_int_t) timer <= 0) {
        c->node->updating = 1;
        c->node->lock_time = now + c->lock_age;
        c->updating = 1;
        c->lock_time = c->node->lock_time;
    }

    rap_shmtx_unlock(&cache->shpool->mutex);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache lock u:%d wt:%M",
                   c->updating, c->wait_time);

    if (c->updating) {
        return RAP_DECLINED;
    }

    if (c->lock_timeout == 0) {
        return RAP_HTTP_CACHE_SCARCE;
    }

    c->waiting = 1;

    if (c->wait_time == 0) {
        c->wait_time = now + c->lock_timeout;

        c->wait_event.handler = rap_http_file_cache_lock_wait_handler;
        c->wait_event.data = r;
        c->wait_event.log = r->connection->log;
    }

    timer = c->wait_time - now;

    rap_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);

    r->main->blocked++;

    return RAP_AGAIN;
}


static void
rap_http_file_cache_lock_wait_handler(rap_event_t *ev)
{
    rap_connection_t    *c;
    rap_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache wait: \"%V?%V\"", &r->uri, &r->args);

    rap_http_file_cache_lock_wait(r, r->cache);

    rap_http_run_posted_requests(c);
}


static void
rap_http_file_cache_lock_wait(rap_http_request_t *r, rap_http_cache_t *c)
{
    rap_uint_t              wait;
    rap_msec_t              now, timer;
    rap_http_file_cache_t  *cache;

    now = rap_current_msec;

    timer = c->wait_time - now;

    if ((rap_msec_int_t) timer <= 0) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "cache lock timeout");
        c->lock_timeout = 0;
        goto wakeup;
    }

    cache = c->file_cache;
    wait = 0;

    rap_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (c->node->updating && (rap_msec_int_t) timer > 0) {
        wait = 1;
    }

    rap_shmtx_unlock(&cache->shpool->mutex);

    if (wait) {
        rap_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
        return;
    }

wakeup:

    c->waiting = 0;
    r->main->blocked--;
    r->write_event_handler(r);
}


static rap_int_t
rap_http_file_cache_read(rap_http_request_t *r, rap_http_cache_t *c)
{
    u_char                        *p;
    time_t                         now;
    ssize_t                        n;
    rap_str_t                     *key;
    rap_int_t                      rc;
    rap_uint_t                     i;
    rap_http_file_cache_t         *cache;
    rap_http_file_cache_header_t  *h;

    n = rap_http_file_cache_aio_read(r, c);

    if (n < 0) {
        return n;
    }

    if ((size_t) n < c->header_start) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is too small", c->file.name.data);
        return RAP_DECLINED;
    }

    h = (rap_http_file_cache_header_t *) c->buf->pos;

    if (h->version != RAP_HTTP_CACHE_VERSION) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "cache file \"%s\" version mismatch", c->file.name.data);
        return RAP_DECLINED;
    }

    if (h->crc32 != c->crc32 || (size_t) h->header_start != c->header_start) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has md5 collision", c->file.name.data);
        return RAP_DECLINED;
    }

    p = c->buf->pos + sizeof(rap_http_file_cache_header_t)
        + sizeof(rap_http_file_cache_key);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        if (rap_memcmp(p, key[i].data, key[i].len) != 0) {
            rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                          "cache file \"%s\" has md5 collision",
                          c->file.name.data);
            return RAP_DECLINED;
        }

        p += key[i].len;
    }

    if ((size_t) h->body_start > c->body_start) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has too long header",
                      c->file.name.data);
        return RAP_DECLINED;
    }

    if (h->vary_len > RAP_HTTP_CACHE_VARY_LEN) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary length",
                      c->file.name.data);
        return RAP_DECLINED;
    }

    if (h->vary_len) {
        rap_http_file_cache_vary(r, h->vary, h->vary_len, c->variant);

        if (rap_memcmp(c->variant, h->variant, RAP_HTTP_CACHE_KEY_LEN) != 0) {
            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache vary mismatch");
            return rap_http_file_cache_reopen(r, c);
        }
    }

    c->buf->last += n;

    c->valid_sec = h->valid_sec;
    c->updating_sec = h->updating_sec;
    c->error_sec = h->error_sec;
    c->last_modified = h->last_modified;
    c->date = h->date;
    c->valid_msec = h->valid_msec;
    c->body_start = h->body_start;
    c->etag.len = h->etag_len;
    c->etag.data = h->etag;

    r->cached = 1;

    cache = c->file_cache;

    if (cache->sh->cold) {

        rap_shmtx_lock(&cache->shpool->mutex);

        if (!c->node->exists) {
            c->node->uses = 1;
            c->node->body_start = c->body_start;
            c->node->exists = 1;
            c->node->uniq = c->uniq;
            c->node->fs_size = c->fs_size;

            cache->sh->size += c->fs_size;
        }

        rap_shmtx_unlock(&cache->shpool->mutex);
    }

    now = rap_time();

    if (c->valid_sec < now) {
        c->stale_updating = c->valid_sec + c->updating_sec >= now;
        c->stale_error = c->valid_sec + c->error_sec >= now;

        rap_shmtx_lock(&cache->shpool->mutex);

        if (c->node->updating) {
            rc = RAP_HTTP_CACHE_UPDATING;

        } else {
            c->node->updating = 1;
            c->updating = 1;
            c->lock_time = c->node->lock_time;
            rc = RAP_HTTP_CACHE_STALE;
        }

        rap_shmtx_unlock(&cache->shpool->mutex);

        rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache expired: %i %T %T",
                       rc, c->valid_sec, now);

        return rc;
    }

    return RAP_OK;
}


static ssize_t
rap_http_file_cache_aio_read(rap_http_request_t *r, rap_http_cache_t *c)
{
#if (RAP_HAVE_FILE_AIO || RAP_THREADS)
    ssize_t                    n;
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
#endif

#if (RAP_HAVE_FILE_AIO)

    if (clcf->aio == RAP_HTTP_AIO_ON && rap_file_aio) {
        n = rap_file_aio_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        if (n != RAP_AGAIN) {
            c->reading = 0;
            return n;
        }

        c->reading = 1;

        c->file.aio->data = r;
        c->file.aio->handler = rap_http_cache_aio_event_handler;

        r->main->blocked++;
        r->aio = 1;

        return RAP_AGAIN;
    }

#endif

#if (RAP_THREADS)

    if (clcf->aio == RAP_HTTP_AIO_THREADS) {
        c->file.thread_task = c->thread_task;
        c->file.thread_handler = rap_http_cache_thread_handler;
        c->file.thread_ctx = r;

        n = rap_thread_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        c->thread_task = c->file.thread_task;
        c->reading = (n == RAP_AGAIN);

        return n;
    }

#endif

    return rap_read_file(&c->file, c->buf->pos, c->body_start, 0);
}


#if (RAP_HAVE_FILE_AIO)

static void
rap_http_cache_aio_event_handler(rap_event_t *ev)
{
    rap_event_aio_t     *aio;
    rap_connection_t    *c;
    rap_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rap_http_run_posted_requests(c);
}

#endif


#if (RAP_THREADS)

static rap_int_t
rap_http_cache_thread_handler(rap_thread_task_t *task, rap_file_t *file)
{
    rap_str_t                  name;
    rap_thread_pool_t         *tp;
    rap_http_request_t        *r;
    rap_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rap_http_complex_value(r, clcf->thread_pool_value, &name)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        tp = rap_thread_pool_get((rap_cycle_t *) rap_cycle, &name);

        if (tp == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RAP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rap_http_cache_thread_event_handler;

    if (rap_thread_task_post(tp, task) != RAP_OK) {
        return RAP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    return RAP_OK;
}


static void
rap_http_cache_thread_event_handler(rap_event_t *ev)
{
    rap_connection_t    *c;
    rap_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rap_http_run_posted_requests(c);
}

#endif


static rap_int_t
rap_http_file_cache_exists(rap_http_file_cache_t *cache, rap_http_cache_t *c)
{
    rap_int_t                    rc;
    rap_http_file_cache_node_t  *fcn;

    rap_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;

    if (fcn == NULL) {
        fcn = rap_http_file_cache_lookup(cache, c->key);
    }

    if (fcn) {
        rap_queue_remove(&fcn->queue);

        if (c->node == NULL) {
            fcn->uses++;
            fcn->count++;
        }

        if (fcn->error) {

            if (fcn->valid_sec < rap_time()) {
                goto renew;
            }

            rc = RAP_OK;

            goto done;
        }

        if (fcn->exists || fcn->uses >= c->min_uses) {

            c->exists = fcn->exists;
            if (fcn->body_start) {
                c->body_start = fcn->body_start;
            }

            rc = RAP_OK;

            goto done;
        }

        rc = RAP_AGAIN;

        goto done;
    }

    fcn = rap_slab_calloc_locked(cache->shpool,
                                 sizeof(rap_http_file_cache_node_t));
    if (fcn == NULL) {
        rap_http_file_cache_set_watermark(cache);

        rap_shmtx_unlock(&cache->shpool->mutex);

        (void) rap_http_file_cache_forced_expire(cache);

        rap_shmtx_lock(&cache->shpool->mutex);

        fcn = rap_slab_calloc_locked(cache->shpool,
                                     sizeof(rap_http_file_cache_node_t));
        if (fcn == NULL) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                          "could not allocate node%s", cache->shpool->log_ctx);
            rc = RAP_ERROR;
            goto failed;
        }
    }

    cache->sh->count++;

    rap_memcpy((u_char *) &fcn->node.key, c->key, sizeof(rap_rbtree_key_t));

    rap_memcpy(fcn->key, &c->key[sizeof(rap_rbtree_key_t)],
               RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t));

    rap_rbtree_insert(&cache->sh->rbtree, &fcn->node);

    fcn->uses = 1;
    fcn->count = 1;

renew:

    rc = RAP_DECLINED;

    fcn->valid_msec = 0;
    fcn->error = 0;
    fcn->exists = 0;
    fcn->valid_sec = 0;
    fcn->uniq = 0;
    fcn->body_start = 0;
    fcn->fs_size = 0;

done:

    fcn->expire = rap_time() + cache->inactive;

    rap_queue_insert_head(&cache->sh->queue, &fcn->queue);

    c->uniq = fcn->uniq;
    c->error = fcn->error;
    c->node = fcn;

failed:

    rap_shmtx_unlock(&cache->shpool->mutex);

    return rc;
}


static rap_int_t
rap_http_file_cache_name(rap_http_request_t *r, rap_path_t *path)
{
    u_char            *p;
    rap_http_cache_t  *c;

    c = r->cache;

    if (c->file.name.len) {
        return RAP_OK;
    }

    c->file.name.len = path->name.len + 1 + path->len
                       + 2 * RAP_HTTP_CACHE_KEY_LEN;

    c->file.name.data = rap_pnalloc(r->pool, c->file.name.len + 1);
    if (c->file.name.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(c->file.name.data, path->name.data, path->name.len);

    p = c->file.name.data + path->name.len + 1 + path->len;
    p = rap_hex_dump(p, c->key, RAP_HTTP_CACHE_KEY_LEN);
    *p = '\0';

    rap_create_hashed_filename(path, c->file.name.data, c->file.name.len);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache file: \"%s\"", c->file.name.data);

    return RAP_OK;
}


static rap_http_file_cache_node_t *
rap_http_file_cache_lookup(rap_http_file_cache_t *cache, u_char *key)
{
    rap_int_t                    rc;
    rap_rbtree_key_t             node_key;
    rap_rbtree_node_t           *node, *sentinel;
    rap_http_file_cache_node_t  *fcn;

    rap_memcpy((u_char *) &node_key, key, sizeof(rap_rbtree_key_t));

    node = cache->sh->rbtree.root;
    sentinel = cache->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (node_key < node->key) {
            node = node->left;
            continue;
        }

        if (node_key > node->key) {
            node = node->right;
            continue;
        }

        /* node_key == node->key */

        fcn = (rap_http_file_cache_node_t *) node;

        rc = rap_memcmp(&key[sizeof(rap_rbtree_key_t)], fcn->key,
                        RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t));

        if (rc == 0) {
            return fcn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
rap_http_file_cache_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t           **p;
    rap_http_file_cache_node_t   *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (rap_http_file_cache_node_t *) node;
            cnt = (rap_http_file_cache_node_t *) temp;

            p = (rap_memcmp(cn->key, cnt->key,
                            RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t))
                 < 0)
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


static void
rap_http_file_cache_vary(rap_http_request_t *r, u_char *vary, size_t len,
    u_char *hash)
{
    u_char     *p, *last;
    rap_str_t   name;
    rap_md5_t   md5;
    u_char      buf[RAP_HTTP_CACHE_VARY_LEN];

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache vary: \"%*s\"", len, vary);

    rap_md5_init(&md5);
    rap_md5_update(&md5, r->cache->main, RAP_HTTP_CACHE_KEY_LEN);

    rap_strlow(buf, vary, len);

    p = buf;
    last = buf + len;

    while (p < last) {

        while (p < last && (*p == ' ' || *p == ',')) { p++; }

        name.data = p;

        while (p < last && *p != ',' && *p != ' ') { p++; }

        name.len = p - name.data;

        if (name.len == 0) {
            break;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache vary: %V", &name);

        rap_md5_update(&md5, name.data, name.len);
        rap_md5_update(&md5, (u_char *) ":", sizeof(":") - 1);

        rap_http_file_cache_vary_header(r, &md5, &name);

        rap_md5_update(&md5, (u_char *) CRLF, sizeof(CRLF) - 1);
    }

    rap_md5_final(hash, &md5);
}


static void
rap_http_file_cache_vary_header(rap_http_request_t *r, rap_md5_t *md5,
    rap_str_t *name)
{
    size_t            len;
    u_char           *p, *start, *last;
    rap_uint_t        i, multiple, normalize;
    rap_list_part_t  *part;
    rap_table_elt_t  *header;

    multiple = 0;
    normalize = 0;

    if (name->len == sizeof("Accept-Charset") - 1
        && rap_strncasecmp(name->data, (u_char *) "Accept-Charset",
                           sizeof("Accept-Charset") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Encoding") - 1
        && rap_strncasecmp(name->data, (u_char *) "Accept-Encoding",
                           sizeof("Accept-Encoding") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Language") - 1
        && rap_strncasecmp(name->data, (u_char *) "Accept-Language",
                           sizeof("Accept-Language") - 1) == 0)
    {
        normalize = 1;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if (header[i].key.len != name->len) {
            continue;
        }

        if (rap_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
            continue;
        }

        if (!normalize) {

            if (multiple) {
                rap_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            rap_md5_update(md5, header[i].value.data, header[i].value.len);

            multiple = 1;

            continue;
        }

        /* normalize spaces */

        p = header[i].value.data;
        last = p + header[i].value.len;

        while (p < last) {

            while (p < last && (*p == ' ' || *p == ',')) { p++; }

            start = p;

            while (p < last && *p != ',' && *p != ' ') { p++; }

            len = p - start;

            if (len == 0) {
                break;
            }

            if (multiple) {
                rap_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            rap_md5_update(md5, start, len);

            multiple = 1;
        }
    }
}


static rap_int_t
rap_http_file_cache_reopen(rap_http_request_t *r, rap_http_cache_t *c)
{
    rap_http_file_cache_t  *cache;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache reopen");

    if (c->secondary) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary hash",
                      c->file.name.data);
        return RAP_DECLINED;
    }

    cache = c->file_cache;

    rap_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node = NULL;

    rap_shmtx_unlock(&cache->shpool->mutex);

    c->secondary = 1;
    c->file.name.len = 0;
    c->body_start = c->buf->end - c->buf->start;

    rap_memcpy(c->key, c->variant, RAP_HTTP_CACHE_KEY_LEN);

    return rap_http_file_cache_open(r);
}


rap_int_t
rap_http_file_cache_set_header(rap_http_request_t *r, u_char *buf)
{
    rap_http_file_cache_header_t  *h = (rap_http_file_cache_header_t *) buf;

    u_char            *p;
    rap_str_t         *key;
    rap_uint_t         i;
    rap_http_cache_t  *c;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache set header");

    c = r->cache;

    rap_memzero(h, sizeof(rap_http_file_cache_header_t));

    h->version = RAP_HTTP_CACHE_VERSION;
    h->valid_sec = c->valid_sec;
    h->updating_sec = c->updating_sec;
    h->error_sec = c->error_sec;
    h->last_modified = c->last_modified;
    h->date = c->date;
    h->crc32 = c->crc32;
    h->valid_msec = (u_short) c->valid_msec;
    h->header_start = (u_short) c->header_start;
    h->body_start = (u_short) c->body_start;

    if (c->etag.len <= RAP_HTTP_CACHE_ETAG_LEN) {
        h->etag_len = (u_char) c->etag.len;
        rap_memcpy(h->etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > RAP_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = RAP_HTTP_CACHE_VARY_LEN;
        }

        h->vary_len = (u_char) c->vary.len;
        rap_memcpy(h->vary, c->vary.data, c->vary.len);

        rap_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        rap_memcpy(h->variant, c->variant, RAP_HTTP_CACHE_KEY_LEN);
    }

    if (rap_http_file_cache_update_variant(r, c) != RAP_OK) {
        return RAP_ERROR;
    }

    p = buf + sizeof(rap_http_file_cache_header_t);

    p = rap_cpymem(p, rap_http_file_cache_key, sizeof(rap_http_file_cache_key));

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        p = rap_copy(p, key[i].data, key[i].len);
    }

    *p = LF;

    return RAP_OK;
}


static rap_int_t
rap_http_file_cache_update_variant(rap_http_request_t *r, rap_http_cache_t *c)
{
    rap_http_file_cache_t  *cache;

    if (!c->secondary) {
        return RAP_OK;
    }

    if (c->vary.len
        && rap_memcmp(c->variant, c->key, RAP_HTTP_CACHE_KEY_LEN) == 0)
    {
        return RAP_OK;
    }

    /*
     * if the variant hash doesn't match one we used as a secondary
     * cache key, switch back to the original key
     */

    cache = c->file_cache;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache main key");

    rap_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->updating = 0;
    c->node = NULL;

    rap_shmtx_unlock(&cache->shpool->mutex);

    c->file.name.len = 0;

    rap_memcpy(c->key, c->main, RAP_HTTP_CACHE_KEY_LEN);

    if (rap_http_file_cache_exists(cache, c) == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rap_http_file_cache_name(r, cache->path) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_http_file_cache_update(rap_http_request_t *r, rap_temp_file_t *tf)
{
    off_t                   fs_size;
    rap_int_t               rc;
    rap_file_uniq_t         uniq;
    rap_file_info_t         fi;
    rap_http_cache_t        *c;
    rap_ext_rename_file_t   ext;
    rap_http_file_cache_t  *cache;

    c = r->cache;

    if (c->updated) {
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update");

    cache = c->file_cache;

    c->updated = 1;
    c->updating = 0;

    uniq = 0;
    fs_size = 0;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache rename: \"%s\" to \"%s\"",
                   tf->file.name.data, c->file.name.data);

    ext.access = RAP_FILE_OWNER_ACCESS;
    ext.path_access = RAP_FILE_OWNER_ACCESS;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    rc = rap_ext_rename_file(&tf->file.name, &c->file.name, &ext);

    if (rc == RAP_OK) {

        if (rap_fd_info(tf->file.fd, &fi) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                          rap_fd_info_n " \"%s\" failed", tf->file.name.data);

            rc = RAP_ERROR;

        } else {
            uniq = rap_file_uniq(&fi);
            fs_size = (rap_file_fs_size(&fi) + cache->bsize - 1) / cache->bsize;
        }
    }

    rap_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->error = 0;
    c->node->uniq = uniq;
    c->node->body_start = c->body_start;

    cache->sh->size += fs_size - c->node->fs_size;
    c->node->fs_size = fs_size;

    if (rc == RAP_OK) {
        c->node->exists = 1;
    }

    c->node->updating = 0;

    rap_shmtx_unlock(&cache->shpool->mutex);
}


void
rap_http_file_cache_update_header(rap_http_request_t *r)
{
    ssize_t                        n;
    rap_err_t                      err;
    rap_file_t                     file;
    rap_file_info_t                fi;
    rap_http_cache_t              *c;
    rap_http_file_cache_header_t   h;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update header");

    c = r->cache;

    rap_memzero(&file, sizeof(rap_file_t));

    file.name = c->file.name;
    file.log = r->connection->log;
    file.fd = rap_open_file(file.name.data, RAP_FILE_RDWR, RAP_FILE_OPEN, 0);

    if (file.fd == RAP_INVALID_FILE) {
        err = rap_errno;

        /* cache file may have been deleted */

        if (err == RAP_ENOENT) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache \"%s\" not found",
                           file.name.data);
            return;
        }

        rap_log_error(RAP_LOG_CRIT, r->connection->log, err,
                      rap_open_file_n " \"%s\" failed", file.name.data);
        return;
    }

    /*
     * make sure cache file wasn't replaced;
     * if it was, do nothing
     */

    if (rap_fd_info(file.fd, &fi) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                      rap_fd_info_n " \"%s\" failed", file.name.data);
        goto done;
    }

    if (c->uniq != rap_file_uniq(&fi)
        || c->length != rap_file_size(&fi))
    {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" changed",
                       file.name.data);
        goto done;
    }

    n = rap_read_file(&file, (u_char *) &h,
                      sizeof(rap_http_file_cache_header_t), 0);

    if (n == RAP_ERROR) {
        goto done;
    }

    if ((size_t) n != sizeof(rap_http_file_cache_header_t)) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                      rap_read_file_n " read only %z of %z from \"%s\"",
                      n, sizeof(rap_http_file_cache_header_t), file.name.data);
        goto done;
    }

    if (h.version != RAP_HTTP_CACHE_VERSION
        || h.last_modified != c->last_modified
        || h.crc32 != c->crc32
        || (size_t) h.header_start != c->header_start
        || (size_t) h.body_start != c->body_start)
    {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" content changed",
                       file.name.data);
        goto done;
    }

    /*
     * update cache file header with new data,
     * notably h.valid_sec and h.date
     */

    rap_memzero(&h, sizeof(rap_http_file_cache_header_t));

    h.version = RAP_HTTP_CACHE_VERSION;
    h.valid_sec = c->valid_sec;
    h.updating_sec = c->updating_sec;
    h.error_sec = c->error_sec;
    h.last_modified = c->last_modified;
    h.date = c->date;
    h.crc32 = c->crc32;
    h.valid_msec = (u_short) c->valid_msec;
    h.header_start = (u_short) c->header_start;
    h.body_start = (u_short) c->body_start;

    if (c->etag.len <= RAP_HTTP_CACHE_ETAG_LEN) {
        h.etag_len = (u_char) c->etag.len;
        rap_memcpy(h.etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > RAP_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = RAP_HTTP_CACHE_VARY_LEN;
        }

        h.vary_len = (u_char) c->vary.len;
        rap_memcpy(h.vary, c->vary.data, c->vary.len);

        rap_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        rap_memcpy(h.variant, c->variant, RAP_HTTP_CACHE_KEY_LEN);
    }

    (void) rap_write_file(&file, (u_char *) &h,
                          sizeof(rap_http_file_cache_header_t), 0);

done:

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", file.name.data);
    }
}


rap_int_t
rap_http_cache_send(rap_http_request_t *r)
{
    rap_int_t          rc;
    rap_buf_t         *b;
    rap_chain_t        out;
    rap_http_cache_t  *c;

    c = r->cache;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache send: %s", c->file.name.data);

    if (r != r->main && c->length - c->body_start == 0) {
        return rap_http_send_header(r);
    }

    /* we need to allocate all before the header would be sent */

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rap_pcalloc(r->pool, sizeof(rap_file_t));
    if (b->file == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return rc;
    }

    b->file_pos = c->body_start;
    b->file_last = c->length;

    b->in_file = (c->length - c->body_start) ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = c->file.fd;
    b->file->name = c->file.name;
    b->file->log = r->connection->log;

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}


void
rap_http_file_cache_free(rap_http_cache_t *c, rap_temp_file_t *tf)
{
    rap_http_file_cache_t       *cache;
    rap_http_file_cache_node_t  *fcn;

    if (c->updated || c->node == NULL) {
        return;
    }

    cache = c->file_cache;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache free, fd: %d", c->file.fd);

    rap_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;
    fcn->count--;

    if (c->updating && fcn->lock_time == c->lock_time) {
        fcn->updating = 0;
    }

    if (c->error) {
        fcn->error = c->error;

        if (c->valid_sec) {
            fcn->valid_sec = c->valid_sec;
            fcn->valid_msec = c->valid_msec;
        }

    } else if (!fcn->exists && fcn->count == 0 && c->min_uses == 1) {
        rap_queue_remove(&fcn->queue);
        rap_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        rap_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
        c->node = NULL;
    }

    rap_shmtx_unlock(&cache->shpool->mutex);

    c->updated = 1;
    c->updating = 0;

    if (c->temp_file) {
        if (tf && tf->file.fd != RAP_INVALID_FILE) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->file.log, 0,
                           "http file cache incomplete: \"%s\"",
                           tf->file.name.data);

            if (rap_delete_file(tf->file.name.data) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_CRIT, c->file.log, rap_errno,
                              rap_delete_file_n " \"%s\" failed",
                              tf->file.name.data);
            }
        }
    }

    if (c->wait_event.timer_set) {
        rap_del_timer(&c->wait_event);
    }
}


static void
rap_http_file_cache_cleanup(void *data)
{
    rap_http_cache_t  *c = data;

    if (c->updated) {
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache cleanup");

    if (c->updating && !c->background) {
        rap_log_error(RAP_LOG_ALERT, c->file.log, 0,
                      "stalled cache updating, error:%ui", c->error);
    }

    rap_http_file_cache_free(c, NULL);
}


static time_t
rap_http_file_cache_forced_expire(rap_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       wait;
    rap_uint_t                   tries;
    rap_path_t                  *path;
    rap_queue_t                 *q, *sentinel;
    rap_http_file_cache_node_t  *fcn;
    u_char                       key[2 * RAP_HTTP_CACHE_KEY_LEN];

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                   "http file cache forced expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * RAP_HTTP_CACHE_KEY_LEN;

    name = rap_alloc(len + 1, rap_cycle->log);
    if (name == NULL) {
        return 10;
    }

    rap_memcpy(name, path->name.data, path->name.len);

    wait = 10;
    tries = 20;
    sentinel = NULL;

    rap_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {
        if (rap_queue_empty(&cache->sh->queue)) {
            break;
        }

        q = rap_queue_last(&cache->sh->queue);

        if (q == sentinel) {
            break;
        }

        fcn = rap_queue_data(q, rap_http_file_cache_node_t, queue);

        rap_log_debug6(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                  "http file cache forced expire: #%d %d %02xd%02xd%02xd%02xd",
                  fcn->count, fcn->exists,
                  fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            rap_http_file_cache_delete(cache, q, name);
            wait = 0;
            break;
        }

        p = rap_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(rap_rbtree_key_t));
        len = RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t);
        (void) rap_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        rap_queue_remove(q);
        fcn->expire = rap_time() + cache->inactive;
        rap_queue_insert_head(&cache->sh->queue, &fcn->queue);

        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * RAP_HTTP_CACHE_KEY_LEN, key, fcn->count);

        if (sentinel == NULL) {
            sentinel = q;
        }

        if (--tries) {
            continue;
        }

        wait = 1;
        break;
    }

    rap_shmtx_unlock(&cache->shpool->mutex);

    rap_free(name);

    return wait;
}


static time_t
rap_http_file_cache_expire(rap_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       now, wait;
    rap_path_t                  *path;
    rap_msec_t                   elapsed;
    rap_queue_t                 *q;
    rap_http_file_cache_node_t  *fcn;
    u_char                       key[2 * RAP_HTTP_CACHE_KEY_LEN];

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                   "http file cache expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * RAP_HTTP_CACHE_KEY_LEN;

    name = rap_alloc(len + 1, rap_cycle->log);
    if (name == NULL) {
        return 10;
    }

    rap_memcpy(name, path->name.data, path->name.len);

    now = rap_time();

    rap_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {

        if (rap_quit || rap_terminate) {
            wait = 1;
            break;
        }

        if (rap_queue_empty(&cache->sh->queue)) {
            wait = 10;
            break;
        }

        q = rap_queue_last(&cache->sh->queue);

        fcn = rap_queue_data(q, rap_http_file_cache_node_t, queue);

        wait = fcn->expire - now;

        if (wait > 0) {
            wait = wait > 10 ? 10 : wait;
            break;
        }

        rap_log_debug6(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                       "http file cache expire: #%d %d %02xd%02xd%02xd%02xd",
                       fcn->count, fcn->exists,
                       fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            rap_http_file_cache_delete(cache, q, name);
            goto next;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = rap_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(rap_rbtree_key_t));
        len = RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t);
        (void) rap_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        rap_queue_remove(q);
        fcn->expire = rap_time() + cache->inactive;
        rap_queue_insert_head(&cache->sh->queue, &fcn->queue);

        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * RAP_HTTP_CACHE_KEY_LEN, key, fcn->count);

next:

        if (++cache->files >= cache->manager_files) {
            wait = 0;
            break;
        }

        rap_time_update();

        elapsed = rap_abs((rap_msec_int_t) (rap_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            wait = 0;
            break;
        }
    }

    rap_shmtx_unlock(&cache->shpool->mutex);

    rap_free(name);

    return wait;
}


static void
rap_http_file_cache_delete(rap_http_file_cache_t *cache, rap_queue_t *q,
    u_char *name)
{
    u_char                      *p;
    size_t                       len;
    rap_path_t                  *path;
    rap_http_file_cache_node_t  *fcn;

    fcn = rap_queue_data(q, rap_http_file_cache_node_t, queue);

    if (fcn->exists) {
        cache->sh->size -= fcn->fs_size;

        path = cache->path;
        p = name + path->name.len + 1 + path->len;
        p = rap_hex_dump(p, (u_char *) &fcn->node.key,
                         sizeof(rap_rbtree_key_t));
        len = RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t);
        p = rap_hex_dump(p, fcn->key, len);
        *p = '\0';

        fcn->count++;
        fcn->deleting = 1;
        rap_shmtx_unlock(&cache->shpool->mutex);

        len = path->name.len + 1 + path->len + 2 * RAP_HTTP_CACHE_KEY_LEN;
        rap_create_hashed_filename(path, name, len);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                       "http file cache expire: \"%s\"", name);

        if (rap_delete_file(name) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_CRIT, rap_cycle->log, rap_errno,
                          rap_delete_file_n " \"%s\" failed", name);
        }

        rap_shmtx_lock(&cache->shpool->mutex);
        fcn->count--;
        fcn->deleting = 0;
    }

    if (fcn->count == 0) {
        rap_queue_remove(q);
        rap_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        rap_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
    }
}


static rap_msec_t
rap_http_file_cache_manager(void *data)
{
    rap_http_file_cache_t  *cache = data;

    off_t       size;
    time_t      wait;
    rap_msec_t  elapsed, next;
    rap_uint_t  count, watermark;

    cache->last = rap_current_msec;
    cache->files = 0;

    next = (rap_msec_t) rap_http_file_cache_expire(cache) * 1000;

    if (next == 0) {
        next = cache->manager_sleep;
        goto done;
    }

    for ( ;; ) {
        rap_shmtx_lock(&cache->shpool->mutex);

        size = cache->sh->size;
        count = cache->sh->count;
        watermark = cache->sh->watermark;

        rap_shmtx_unlock(&cache->shpool->mutex);

        rap_log_debug3(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                       "http file cache size: %O c:%ui w:%i",
                       size, count, (rap_int_t) watermark);

        if (size < cache->max_size && count < watermark) {
            break;
        }

        wait = rap_http_file_cache_forced_expire(cache);

        if (wait > 0) {
            next = (rap_msec_t) wait * 1000;
            break;
        }

        if (rap_quit || rap_terminate) {
            break;
        }

        if (++cache->files >= cache->manager_files) {
            next = cache->manager_sleep;
            break;
        }

        rap_time_update();

        elapsed = rap_abs((rap_msec_int_t) (rap_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            next = cache->manager_sleep;
            break;
        }
    }

done:

    elapsed = rap_abs((rap_msec_int_t) (rap_current_msec - cache->last));

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                   "http file cache manager: %ui e:%M n:%M",
                   cache->files, elapsed, next);

    return next;
}


static void
rap_http_file_cache_loader(void *data)
{
    rap_http_file_cache_t  *cache = data;

    rap_tree_ctx_t  tree;

    if (!cache->sh->cold || cache->sh->loading) {
        return;
    }

    if (!rap_atomic_cmp_set(&cache->sh->loading, 0, rap_pid)) {
        return;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                   "http file cache loader");

    tree.init_handler = NULL;
    tree.file_handler = rap_http_file_cache_manage_file;
    tree.pre_tree_handler = rap_http_file_cache_manage_directory;
    tree.post_tree_handler = rap_http_file_cache_noop;
    tree.spec_handler = rap_http_file_cache_delete_file;
    tree.data = cache;
    tree.alloc = 0;
    tree.log = rap_cycle->log;

    cache->last = rap_current_msec;
    cache->files = 0;

    if (rap_walk_tree(&tree, &cache->path->name) == RAP_ABORT) {
        cache->sh->loading = 0;
        return;
    }

    cache->sh->cold = 0;
    cache->sh->loading = 0;

    rap_log_error(RAP_LOG_NOTICE, rap_cycle->log, 0,
                  "http file cache: %V %.3fM, bsize: %uz",
                  &cache->path->name,
                  ((double) cache->sh->size * cache->bsize) / (1024 * 1024),
                  cache->bsize);
}


static rap_int_t
rap_http_file_cache_noop(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    return RAP_OK;
}


static rap_int_t
rap_http_file_cache_manage_file(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    rap_msec_t              elapsed;
    rap_http_file_cache_t  *cache;

    cache = ctx->data;

    if (rap_http_file_cache_add_file(ctx, path) != RAP_OK) {
        (void) rap_http_file_cache_delete_file(ctx, path);
    }

    if (++cache->files >= cache->loader_files) {
        rap_http_file_cache_loader_sleep(cache);

    } else {
        rap_time_update();

        elapsed = rap_abs((rap_msec_int_t) (rap_current_msec - cache->last));

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                       "http file cache loader time elapsed: %M", elapsed);

        if (elapsed >= cache->loader_threshold) {
            rap_http_file_cache_loader_sleep(cache);
        }
    }

    return (rap_quit || rap_terminate) ? RAP_ABORT : RAP_OK;
}


static rap_int_t
rap_http_file_cache_manage_directory(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    if (path->len >= 5
        && rap_strncmp(path->data + path->len - 5, "/temp", 5) == 0)
    {
        return RAP_DECLINED;
    }

    return RAP_OK;
}


static void
rap_http_file_cache_loader_sleep(rap_http_file_cache_t *cache)
{
    rap_msleep(cache->loader_sleep);

    rap_time_update();

    cache->last = rap_current_msec;
    cache->files = 0;
}


static rap_int_t
rap_http_file_cache_add_file(rap_tree_ctx_t *ctx, rap_str_t *name)
{
    u_char                 *p;
    rap_int_t               n;
    rap_uint_t              i;
    rap_http_cache_t        c;
    rap_http_file_cache_t  *cache;

    if (name->len < 2 * RAP_HTTP_CACHE_KEY_LEN) {
        return RAP_ERROR;
    }

    /*
     * Temporary files in cache have a suffix consisting of a dot
     * followed by 10 digits.
     */

    if (name->len >= 2 * RAP_HTTP_CACHE_KEY_LEN + 1 + 10
        && name->data[name->len - 10 - 1] == '.')
    {
        return RAP_OK;
    }

    if (ctx->size < (off_t) sizeof(rap_http_file_cache_header_t)) {
        rap_log_error(RAP_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", name->data);
        return RAP_ERROR;
    }

    rap_memzero(&c, sizeof(rap_http_cache_t));
    cache = ctx->data;

    c.length = ctx->size;
    c.fs_size = (ctx->fs_size + cache->bsize - 1) / cache->bsize;

    p = &name->data[name->len - 2 * RAP_HTTP_CACHE_KEY_LEN];

    for (i = 0; i < RAP_HTTP_CACHE_KEY_LEN; i++) {
        n = rap_hextoi(p, 2);

        if (n == RAP_ERROR) {
            return RAP_ERROR;
        }

        p += 2;

        c.key[i] = (u_char) n;
    }

    return rap_http_file_cache_add(cache, &c);
}


static rap_int_t
rap_http_file_cache_add(rap_http_file_cache_t *cache, rap_http_cache_t *c)
{
    rap_http_file_cache_node_t  *fcn;

    rap_shmtx_lock(&cache->shpool->mutex);

    fcn = rap_http_file_cache_lookup(cache, c->key);

    if (fcn == NULL) {

        fcn = rap_slab_calloc_locked(cache->shpool,
                                     sizeof(rap_http_file_cache_node_t));
        if (fcn == NULL) {
            rap_http_file_cache_set_watermark(cache);

            if (cache->fail_time != rap_time()) {
                cache->fail_time = rap_time();
                rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                           "could not allocate node%s", cache->shpool->log_ctx);
            }

            rap_shmtx_unlock(&cache->shpool->mutex);
            return RAP_ERROR;
        }

        cache->sh->count++;

        rap_memcpy((u_char *) &fcn->node.key, c->key, sizeof(rap_rbtree_key_t));

        rap_memcpy(fcn->key, &c->key[sizeof(rap_rbtree_key_t)],
                   RAP_HTTP_CACHE_KEY_LEN - sizeof(rap_rbtree_key_t));

        rap_rbtree_insert(&cache->sh->rbtree, &fcn->node);

        fcn->uses = 1;
        fcn->exists = 1;
        fcn->fs_size = c->fs_size;

        cache->sh->size += c->fs_size;

    } else {
        rap_queue_remove(&fcn->queue);
    }

    fcn->expire = rap_time() + cache->inactive;

    rap_queue_insert_head(&cache->sh->queue, &fcn->queue);

    rap_shmtx_unlock(&cache->shpool->mutex);

    return RAP_OK;
}


static rap_int_t
rap_http_file_cache_delete_file(rap_tree_ctx_t *ctx, rap_str_t *path)
{
    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http file cache delete: \"%s\"", path->data);

    if (rap_delete_file(path->data) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_CRIT, ctx->log, rap_errno,
                      rap_delete_file_n " \"%s\" failed", path->data);
    }

    return RAP_OK;
}


static void
rap_http_file_cache_set_watermark(rap_http_file_cache_t *cache)
{
    cache->sh->watermark = cache->sh->count - cache->sh->count / 8;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0,
                   "http file cache watermark: %ui", cache->sh->watermark);
}


time_t
rap_http_file_cache_valid(rap_array_t *cache_valid, rap_uint_t status)
{
    rap_uint_t               i;
    rap_http_cache_valid_t  *valid;

    if (cache_valid == NULL) {
        return 0;
    }

    valid = cache_valid->elts;
    for (i = 0; i < cache_valid->nelts; i++) {

        if (valid[i].status == 0) {
            return valid[i].valid;
        }

        if (valid[i].status == status) {
            return valid[i].valid;
        }
    }

    return 0;
}


char *
rap_http_file_cache_set_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *confp = conf;

    off_t                   max_size;
    u_char                 *last, *p;
    time_t                  inactive;
    ssize_t                 size;
    rap_str_t               s, name, *value;
    rap_int_t               loader_files, manager_files;
    rap_msec_t              loader_sleep, manager_sleep, loader_threshold,
                            manager_threshold;
    rap_uint_t              i, n, use_temp_path;
    rap_array_t            *caches;
    rap_http_file_cache_t  *cache, **ce;

    cache = rap_pcalloc(cf->pool, sizeof(rap_http_file_cache_t));
    if (cache == NULL) {
        return RAP_CONF_ERROR;
    }

    cache->path = rap_pcalloc(cf->pool, sizeof(rap_path_t));
    if (cache->path == NULL) {
        return RAP_CONF_ERROR;
    }

    use_temp_path = 1;

    inactive = 600;

    loader_files = 100;
    loader_sleep = 50;
    loader_threshold = 200;

    manager_files = 100;
    manager_sleep = 50;
    manager_threshold = 200;

    name.len = 0;
    size = 0;
    max_size = RAP_MAX_OFF_T_VALUE;

    value = cf->args->elts;

    cache->path->name = value[1];

    if (cache->path->name.data[cache->path->name.len - 1] == '/') {
        cache->path->name.len--;
    }

    if (rap_conf_full_name(cf->cycle, &cache->path->name, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "levels=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            for (n = 0; n < RAP_MAX_PATH_LEVEL && p < last; n++) {

                if (*p > '0' && *p < '3') {

                    cache->path->level[n] = *p++ - '0';
                    cache->path->len += cache->path->level[n] + 1;

                    if (p == last) {
                        break;
                    }

                    if (*p++ == ':' && n < RAP_MAX_PATH_LEVEL - 1 && p < last) {
                        continue;
                    }

                    goto invalid_levels;
                }

                goto invalid_levels;
            }

            if (cache->path->len < 10 + RAP_MAX_PATH_LEVEL) {
                continue;
            }

        invalid_levels:

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid \"levels\" \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }

        if (rap_strncmp(value[i].data, "use_temp_path=", 14) == 0) {

            if (rap_strcmp(&value[i].data[14], "on") == 0) {
                use_temp_path = 1;

            } else if (rap_strcmp(&value[i].data[14], "off") == 0) {
                use_temp_path = 0;

            } else {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid use_temp_path value \"%V\", "
                                   "it must be \"on\" or \"off\"",
                                   &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            name.data = value[i].data + 10;

            p = (u_char *) rap_strchr(name.data, ':');

            if (p == NULL) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = rap_parse_size(&s);

            if (size == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            if (size < (ssize_t) (2 * rap_pagesize)) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "keys zone \"%V\" is too small", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rap_parse_time(&s, 1);
            if (inactive == (time_t) RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid inactive value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = rap_parse_offset(&s);
            if (max_size < 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid max_size value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "loader_files=", 13) == 0) {

            loader_files = rap_atoi(value[i].data + 13, value[i].len - 13);
            if (loader_files == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid loader_files value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "loader_sleep=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            loader_sleep = rap_parse_time(&s, 0);
            if (loader_sleep == (rap_msec_t) RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid loader_sleep value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "loader_threshold=", 17) == 0) {

            s.len = value[i].len - 17;
            s.data = value[i].data + 17;

            loader_threshold = rap_parse_time(&s, 0);
            if (loader_threshold == (rap_msec_t) RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid loader_threshold value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "manager_files=", 14) == 0) {

            manager_files = rap_atoi(value[i].data + 14, value[i].len - 14);
            if (manager_files == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid manager_files value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "manager_sleep=", 14) == 0) {

            s.len = value[i].len - 14;
            s.data = value[i].data + 14;

            manager_sleep = rap_parse_time(&s, 0);
            if (manager_sleep == (rap_msec_t) RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid manager_sleep value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "manager_threshold=", 18) == 0) {

            s.len = value[i].len - 18;
            s.data = value[i].data + 18;

            manager_threshold = rap_parse_time(&s, 0);
            if (manager_threshold == (rap_msec_t) RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid manager_threshold value \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return RAP_CONF_ERROR;
    }

    cache->path->manager = rap_http_file_cache_manager;
    cache->path->loader = rap_http_file_cache_loader;
    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;
    cache->loader_files = loader_files;
    cache->loader_sleep = loader_sleep;
    cache->loader_threshold = loader_threshold;
    cache->manager_files = manager_files;
    cache->manager_sleep = manager_sleep;
    cache->manager_threshold = manager_threshold;

    if (rap_add_path(cf, &cache->path) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    cache->shm_zone = rap_shared_memory_add(cf, &name, size, cmd->post);
    if (cache->shm_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    if (cache->shm_zone->data) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return RAP_CONF_ERROR;
    }


    cache->shm_zone->init = rap_http_file_cache_init;
    cache->shm_zone->data = cache;

    cache->use_temp_path = use_temp_path;

    cache->inactive = inactive;
    cache->max_size = max_size;

    caches = (rap_array_t *) (confp + cmd->offset);

    ce = rap_array_push(caches);
    if (ce == NULL) {
        return RAP_CONF_ERROR;
    }

    *ce = cache;

    return RAP_CONF_OK;
}


char *
rap_http_file_cache_valid_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    time_t                    valid;
    rap_str_t                *value;
    rap_int_t                 status;
    rap_uint_t                i, n;
    rap_array_t             **a;
    rap_http_cache_valid_t   *v;
    static rap_uint_t         statuses[] = { 200, 301, 302 };

    a = (rap_array_t **) (p + cmd->offset);

    if (*a == RAP_CONF_UNSET_PTR) {
        *a = rap_array_create(cf->pool, 1, sizeof(rap_http_cache_valid_t));
        if (*a == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    n = cf->args->nelts - 1;

    valid = rap_parse_time(&value[n], 1);
    if (valid == (time_t) RAP_ERROR) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid time value \"%V\"", &value[n]);
        return RAP_CONF_ERROR;
    }

    if (n == 1) {

        for (i = 0; i < 3; i++) {
            v = rap_array_push(*a);
            if (v == NULL) {
                return RAP_CONF_ERROR;
            }

            v->status = statuses[i];
            v->valid = valid;
        }

        return RAP_CONF_OK;
    }

    for (i = 1; i < n; i++) {

        if (rap_strcmp(value[i].data, "any") == 0) {

            status = 0;

        } else {

            status = rap_atoi(value[i].data, value[i].len);
            if (status < 100 || status > 599) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid status \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }
        }

        v = rap_array_push(*a);
        if (v == NULL) {
            return RAP_CONF_ERROR;
        }

        v->status = status;
        v->valid = valid;
    }

    return RAP_CONF_OK;
}
