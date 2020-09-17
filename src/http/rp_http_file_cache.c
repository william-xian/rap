
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_md5.h>


static rp_int_t rp_http_file_cache_lock(rp_http_request_t *r,
    rp_http_cache_t *c);
static void rp_http_file_cache_lock_wait_handler(rp_event_t *ev);
static void rp_http_file_cache_lock_wait(rp_http_request_t *r,
    rp_http_cache_t *c);
static rp_int_t rp_http_file_cache_read(rp_http_request_t *r,
    rp_http_cache_t *c);
static ssize_t rp_http_file_cache_aio_read(rp_http_request_t *r,
    rp_http_cache_t *c);
#if (RP_HAVE_FILE_AIO)
static void rp_http_cache_aio_event_handler(rp_event_t *ev);
#endif
#if (RP_THREADS)
static rp_int_t rp_http_cache_thread_handler(rp_thread_task_t *task,
    rp_file_t *file);
static void rp_http_cache_thread_event_handler(rp_event_t *ev);
#endif
static rp_int_t rp_http_file_cache_exists(rp_http_file_cache_t *cache,
    rp_http_cache_t *c);
static rp_int_t rp_http_file_cache_name(rp_http_request_t *r,
    rp_path_t *path);
static rp_http_file_cache_node_t *
    rp_http_file_cache_lookup(rp_http_file_cache_t *cache, u_char *key);
static void rp_http_file_cache_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
static void rp_http_file_cache_vary(rp_http_request_t *r, u_char *vary,
    size_t len, u_char *hash);
static void rp_http_file_cache_vary_header(rp_http_request_t *r,
    rp_md5_t *md5, rp_str_t *name);
static rp_int_t rp_http_file_cache_reopen(rp_http_request_t *r,
    rp_http_cache_t *c);
static rp_int_t rp_http_file_cache_update_variant(rp_http_request_t *r,
    rp_http_cache_t *c);
static void rp_http_file_cache_cleanup(void *data);
static time_t rp_http_file_cache_forced_expire(rp_http_file_cache_t *cache);
static time_t rp_http_file_cache_expire(rp_http_file_cache_t *cache);
static void rp_http_file_cache_delete(rp_http_file_cache_t *cache,
    rp_queue_t *q, u_char *name);
static void rp_http_file_cache_loader_sleep(rp_http_file_cache_t *cache);
static rp_int_t rp_http_file_cache_noop(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static rp_int_t rp_http_file_cache_manage_file(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static rp_int_t rp_http_file_cache_manage_directory(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static rp_int_t rp_http_file_cache_add_file(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static rp_int_t rp_http_file_cache_add(rp_http_file_cache_t *cache,
    rp_http_cache_t *c);
static rp_int_t rp_http_file_cache_delete_file(rp_tree_ctx_t *ctx,
    rp_str_t *path);
static void rp_http_file_cache_set_watermark(rp_http_file_cache_t *cache);


rp_str_t  rp_http_cache_status[] = {
    rp_string("MISS"),
    rp_string("BYPASS"),
    rp_string("EXPIRED"),
    rp_string("STALE"),
    rp_string("UPDATING"),
    rp_string("REVALIDATED"),
    rp_string("HIT")
};


static u_char  rp_http_file_cache_key[] = { LF, 'K', 'E', 'Y', ':', ' ' };


static rp_int_t
rp_http_file_cache_init(rp_shm_zone_t *shm_zone, void *data)
{
    rp_http_file_cache_t  *ocache = data;

    size_t                  len;
    rp_uint_t              n;
    rp_http_file_cache_t  *cache;

    cache = shm_zone->data;

    if (ocache) {
        if (rp_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
            rp_log_error(RP_LOG_EMERG, shm_zone->shm.log, 0,
                          "cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &cache->path->name,
                          &ocache->path->name);

            return RP_ERROR;
        }

        for (n = 0; n < RP_MAX_PATH_LEVEL; n++) {
            if (cache->path->level[n] != ocache->path->level[n]) {
                rp_log_error(RP_LOG_EMERG, shm_zone->shm.log, 0,
                              "cache \"%V\" had previously different levels",
                              &shm_zone->shm.name);
                return RP_ERROR;
            }
        }

        cache->sh = ocache->sh;

        cache->shpool = ocache->shpool;
        cache->bsize = ocache->bsize;

        cache->max_size /= cache->bsize;

        if (!cache->sh->cold || cache->sh->loading) {
            cache->path->loader = NULL;
        }

        return RP_OK;
    }

    cache->shpool = (rp_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        cache->sh = cache->shpool->data;
        cache->bsize = rp_fs_bsize(cache->path->name.data);
        cache->max_size /= cache->bsize;

        return RP_OK;
    }

    cache->sh = rp_slab_alloc(cache->shpool, sizeof(rp_http_file_cache_sh_t));
    if (cache->sh == NULL) {
        return RP_ERROR;
    }

    cache->shpool->data = cache->sh;

    rp_rbtree_init(&cache->sh->rbtree, &cache->sh->sentinel,
                    rp_http_file_cache_rbtree_insert_value);

    rp_queue_init(&cache->sh->queue);

    cache->sh->cold = 1;
    cache->sh->loading = 0;
    cache->sh->size = 0;
    cache->sh->count = 0;
    cache->sh->watermark = (rp_uint_t) -1;

    cache->bsize = rp_fs_bsize(cache->path->name.data);

    cache->max_size /= cache->bsize;

    len = sizeof(" in cache keys zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = rp_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return RP_ERROR;
    }

    rp_sprintf(cache->shpool->log_ctx, " in cache keys zone \"%V\"%Z",
                &shm_zone->shm.name);

    cache->shpool->log_nomem = 0;

    return RP_OK;
}


rp_int_t
rp_http_file_cache_new(rp_http_request_t *r)
{
    rp_http_cache_t  *c;

    c = rp_pcalloc(r->pool, sizeof(rp_http_cache_t));
    if (c == NULL) {
        return RP_ERROR;
    }

    if (rp_array_init(&c->keys, r->pool, 4, sizeof(rp_str_t)) != RP_OK) {
        return RP_ERROR;
    }

    r->cache = c;
    c->file.log = r->connection->log;
    c->file.fd = RP_INVALID_FILE;

    return RP_OK;
}


rp_int_t
rp_http_file_cache_create(rp_http_request_t *r)
{
    rp_http_cache_t       *c;
    rp_pool_cleanup_t     *cln;
    rp_http_file_cache_t  *cache;

    c = r->cache;
    cache = c->file_cache;

    cln = rp_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return RP_ERROR;
    }

    cln->handler = rp_http_file_cache_cleanup;
    cln->data = c;

    if (rp_http_file_cache_exists(cache, c) == RP_ERROR) {
        return RP_ERROR;
    }

    if (rp_http_file_cache_name(r, cache->path) != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_http_file_cache_create_key(rp_http_request_t *r)
{
    size_t             len;
    rp_str_t         *key;
    rp_uint_t         i;
    rp_md5_t          md5;
    rp_http_cache_t  *c;

    c = r->cache;

    len = 0;

    rp_crc32_init(c->crc32);
    rp_md5_init(&md5);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http cache key: \"%V\"", &key[i]);

        len += key[i].len;

        rp_crc32_update(&c->crc32, key[i].data, key[i].len);
        rp_md5_update(&md5, key[i].data, key[i].len);
    }

    c->header_start = sizeof(rp_http_file_cache_header_t)
                      + sizeof(rp_http_file_cache_key) + len + 1;

    rp_crc32_final(c->crc32);
    rp_md5_final(c->key, &md5);

    rp_memcpy(c->main, c->key, RP_HTTP_CACHE_KEY_LEN);
}


rp_int_t
rp_http_file_cache_open(rp_http_request_t *r)
{
    rp_int_t                  rc, rv;
    rp_uint_t                 test;
    rp_http_cache_t          *c;
    rp_pool_cleanup_t        *cln;
    rp_open_file_info_t       of;
    rp_http_file_cache_t     *cache;
    rp_http_core_loc_conf_t  *clcf;

    c = r->cache;

    if (c->waiting) {
        return RP_AGAIN;
    }

    if (c->reading) {
        return rp_http_file_cache_read(r, c);
    }

    cache = c->file_cache;

    if (c->node == NULL) {
        cln = rp_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return RP_ERROR;
        }

        cln->handler = rp_http_file_cache_cleanup;
        cln->data = c;
    }

    rc = rp_http_file_cache_exists(cache, c);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache exists: %i e:%d", rc, c->exists);

    if (rc == RP_ERROR) {
        return rc;
    }

    if (rc == RP_AGAIN) {
        return RP_HTTP_CACHE_SCARCE;
    }

    if (rc == RP_OK) {

        if (c->error) {
            return c->error;
        }

        c->temp_file = 1;
        test = c->exists ? 1 : 0;
        rv = RP_DECLINED;

    } else { /* rc == RP_DECLINED */

        test = cache->sh->cold ? 1 : 0;

        if (c->min_uses > 1) {

            if (!test) {
                return RP_HTTP_CACHE_SCARCE;
            }

            rv = RP_HTTP_CACHE_SCARCE;

        } else {
            c->temp_file = 1;
            rv = RP_DECLINED;
        }
    }

    if (rp_http_file_cache_name(r, cache->path) != RP_OK) {
        return RP_ERROR;
    }

    if (!test) {
        goto done;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.uniq = c->uniq;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.events = clcf->open_file_cache_events;
    of.directio = RP_OPEN_FILE_DIRECTIO_OFF;
    of.read_ahead = clcf->read_ahead;

    if (rp_open_cached_file(clcf->open_file_cache, &c->file.name, &of, r->pool)
        != RP_OK)
    {
        switch (of.err) {

        case 0:
            return RP_ERROR;

        case RP_ENOENT:
        case RP_ENOTDIR:
            goto done;

        default:
            rp_log_error(RP_LOG_CRIT, r->connection->log, of.err,
                          rp_open_file_n " \"%s\" failed", c->file.name.data);
            return RP_ERROR;
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache fd: %d", of.fd);

    c->file.fd = of.fd;
    c->file.log = r->connection->log;
    c->uniq = of.uniq;
    c->length = of.size;
    c->fs_size = (of.fs_size + cache->bsize - 1) / cache->bsize;

    c->buf = rp_create_temp_buf(r->pool, c->body_start);
    if (c->buf == NULL) {
        return RP_ERROR;
    }

    return rp_http_file_cache_read(r, c);

done:

    if (rv == RP_DECLINED) {
        return rp_http_file_cache_lock(r, c);
    }

    return rv;
}


static rp_int_t
rp_http_file_cache_lock(rp_http_request_t *r, rp_http_cache_t *c)
{
    rp_msec_t                 now, timer;
    rp_http_file_cache_t     *cache;

    if (!c->lock) {
        return RP_DECLINED;
    }

    now = rp_current_msec;

    cache = c->file_cache;

    rp_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (!c->node->updating || (rp_msec_int_t) timer <= 0) {
        c->node->updating = 1;
        c->node->lock_time = now + c->lock_age;
        c->updating = 1;
        c->lock_time = c->node->lock_time;
    }

    rp_shmtx_unlock(&cache->shpool->mutex);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache lock u:%d wt:%M",
                   c->updating, c->wait_time);

    if (c->updating) {
        return RP_DECLINED;
    }

    if (c->lock_timeout == 0) {
        return RP_HTTP_CACHE_SCARCE;
    }

    c->waiting = 1;

    if (c->wait_time == 0) {
        c->wait_time = now + c->lock_timeout;

        c->wait_event.handler = rp_http_file_cache_lock_wait_handler;
        c->wait_event.data = r;
        c->wait_event.log = r->connection->log;
    }

    timer = c->wait_time - now;

    rp_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);

    r->main->blocked++;

    return RP_AGAIN;
}


static void
rp_http_file_cache_lock_wait_handler(rp_event_t *ev)
{
    rp_connection_t    *c;
    rp_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache wait: \"%V?%V\"", &r->uri, &r->args);

    rp_http_file_cache_lock_wait(r, r->cache);

    rp_http_run_posted_requests(c);
}


static void
rp_http_file_cache_lock_wait(rp_http_request_t *r, rp_http_cache_t *c)
{
    rp_uint_t              wait;
    rp_msec_t              now, timer;
    rp_http_file_cache_t  *cache;

    now = rp_current_msec;

    timer = c->wait_time - now;

    if ((rp_msec_int_t) timer <= 0) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "cache lock timeout");
        c->lock_timeout = 0;
        goto wakeup;
    }

    cache = c->file_cache;
    wait = 0;

    rp_shmtx_lock(&cache->shpool->mutex);

    timer = c->node->lock_time - now;

    if (c->node->updating && (rp_msec_int_t) timer > 0) {
        wait = 1;
    }

    rp_shmtx_unlock(&cache->shpool->mutex);

    if (wait) {
        rp_add_timer(&c->wait_event, (timer > 500) ? 500 : timer);
        return;
    }

wakeup:

    c->waiting = 0;
    r->main->blocked--;
    r->write_event_handler(r);
}


static rp_int_t
rp_http_file_cache_read(rp_http_request_t *r, rp_http_cache_t *c)
{
    u_char                        *p;
    time_t                         now;
    ssize_t                        n;
    rp_str_t                     *key;
    rp_int_t                      rc;
    rp_uint_t                     i;
    rp_http_file_cache_t         *cache;
    rp_http_file_cache_header_t  *h;

    n = rp_http_file_cache_aio_read(r, c);

    if (n < 0) {
        return n;
    }

    if ((size_t) n < c->header_start) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" is too small", c->file.name.data);
        return RP_DECLINED;
    }

    h = (rp_http_file_cache_header_t *) c->buf->pos;

    if (h->version != RP_HTTP_CACHE_VERSION) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "cache file \"%s\" version mismatch", c->file.name.data);
        return RP_DECLINED;
    }

    if (h->crc32 != c->crc32 || (size_t) h->header_start != c->header_start) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has md5 collision", c->file.name.data);
        return RP_DECLINED;
    }

    p = c->buf->pos + sizeof(rp_http_file_cache_header_t)
        + sizeof(rp_http_file_cache_key);

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        if (rp_memcmp(p, key[i].data, key[i].len) != 0) {
            rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                          "cache file \"%s\" has md5 collision",
                          c->file.name.data);
            return RP_DECLINED;
        }

        p += key[i].len;
    }

    if ((size_t) h->body_start > c->body_start) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has too long header",
                      c->file.name.data);
        return RP_DECLINED;
    }

    if (h->vary_len > RP_HTTP_CACHE_VARY_LEN) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary length",
                      c->file.name.data);
        return RP_DECLINED;
    }

    if (h->vary_len) {
        rp_http_file_cache_vary(r, h->vary, h->vary_len, c->variant);

        if (rp_memcmp(c->variant, h->variant, RP_HTTP_CACHE_KEY_LEN) != 0) {
            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache vary mismatch");
            return rp_http_file_cache_reopen(r, c);
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

        rp_shmtx_lock(&cache->shpool->mutex);

        if (!c->node->exists) {
            c->node->uses = 1;
            c->node->body_start = c->body_start;
            c->node->exists = 1;
            c->node->uniq = c->uniq;
            c->node->fs_size = c->fs_size;

            cache->sh->size += c->fs_size;
        }

        rp_shmtx_unlock(&cache->shpool->mutex);
    }

    now = rp_time();

    if (c->valid_sec < now) {
        c->stale_updating = c->valid_sec + c->updating_sec >= now;
        c->stale_error = c->valid_sec + c->error_sec >= now;

        rp_shmtx_lock(&cache->shpool->mutex);

        if (c->node->updating) {
            rc = RP_HTTP_CACHE_UPDATING;

        } else {
            c->node->updating = 1;
            c->updating = 1;
            c->lock_time = c->node->lock_time;
            rc = RP_HTTP_CACHE_STALE;
        }

        rp_shmtx_unlock(&cache->shpool->mutex);

        rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache expired: %i %T %T",
                       rc, c->valid_sec, now);

        return rc;
    }

    return RP_OK;
}


static ssize_t
rp_http_file_cache_aio_read(rp_http_request_t *r, rp_http_cache_t *c)
{
#if (RP_HAVE_FILE_AIO || RP_THREADS)
    ssize_t                    n;
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
#endif

#if (RP_HAVE_FILE_AIO)

    if (clcf->aio == RP_HTTP_AIO_ON && rp_file_aio) {
        n = rp_file_aio_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        if (n != RP_AGAIN) {
            c->reading = 0;
            return n;
        }

        c->reading = 1;

        c->file.aio->data = r;
        c->file.aio->handler = rp_http_cache_aio_event_handler;

        r->main->blocked++;
        r->aio = 1;

        return RP_AGAIN;
    }

#endif

#if (RP_THREADS)

    if (clcf->aio == RP_HTTP_AIO_THREADS) {
        c->file.thread_task = c->thread_task;
        c->file.thread_handler = rp_http_cache_thread_handler;
        c->file.thread_ctx = r;

        n = rp_thread_read(&c->file, c->buf->pos, c->body_start, 0, r->pool);

        c->thread_task = c->file.thread_task;
        c->reading = (n == RP_AGAIN);

        return n;
    }

#endif

    return rp_read_file(&c->file, c->buf->pos, c->body_start, 0);
}


#if (RP_HAVE_FILE_AIO)

static void
rp_http_cache_aio_event_handler(rp_event_t *ev)
{
    rp_event_aio_t     *aio;
    rp_connection_t    *c;
    rp_http_request_t  *r;

    aio = ev->data;
    r = aio->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache aio: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rp_http_run_posted_requests(c);
}

#endif


#if (RP_THREADS)

static rp_int_t
rp_http_cache_thread_handler(rp_thread_task_t *task, rp_file_t *file)
{
    rp_str_t                  name;
    rp_thread_pool_t         *tp;
    rp_http_request_t        *r;
    rp_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rp_http_complex_value(r, clcf->thread_pool_value, &name)
            != RP_OK)
        {
            return RP_ERROR;
        }

        tp = rp_thread_pool_get((rp_cycle_t *) rp_cycle, &name);

        if (tp == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rp_http_cache_thread_event_handler;

    if (rp_thread_task_post(tp, task) != RP_OK) {
        return RP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;

    return RP_OK;
}


static void
rp_http_cache_thread_event_handler(rp_event_t *ev)
{
    rp_connection_t    *c;
    rp_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http file cache thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);

    rp_http_run_posted_requests(c);
}

#endif


static rp_int_t
rp_http_file_cache_exists(rp_http_file_cache_t *cache, rp_http_cache_t *c)
{
    rp_int_t                    rc;
    rp_http_file_cache_node_t  *fcn;

    rp_shmtx_lock(&cache->shpool->mutex);

    fcn = c->node;

    if (fcn == NULL) {
        fcn = rp_http_file_cache_lookup(cache, c->key);
    }

    if (fcn) {
        rp_queue_remove(&fcn->queue);

        if (c->node == NULL) {
            fcn->uses++;
            fcn->count++;
        }

        if (fcn->error) {

            if (fcn->valid_sec < rp_time()) {
                goto renew;
            }

            rc = RP_OK;

            goto done;
        }

        if (fcn->exists || fcn->uses >= c->min_uses) {

            c->exists = fcn->exists;
            if (fcn->body_start) {
                c->body_start = fcn->body_start;
            }

            rc = RP_OK;

            goto done;
        }

        rc = RP_AGAIN;

        goto done;
    }

    fcn = rp_slab_calloc_locked(cache->shpool,
                                 sizeof(rp_http_file_cache_node_t));
    if (fcn == NULL) {
        rp_http_file_cache_set_watermark(cache);

        rp_shmtx_unlock(&cache->shpool->mutex);

        (void) rp_http_file_cache_forced_expire(cache);

        rp_shmtx_lock(&cache->shpool->mutex);

        fcn = rp_slab_calloc_locked(cache->shpool,
                                     sizeof(rp_http_file_cache_node_t));
        if (fcn == NULL) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                          "could not allocate node%s", cache->shpool->log_ctx);
            rc = RP_ERROR;
            goto failed;
        }
    }

    cache->sh->count++;

    rp_memcpy((u_char *) &fcn->node.key, c->key, sizeof(rp_rbtree_key_t));

    rp_memcpy(fcn->key, &c->key[sizeof(rp_rbtree_key_t)],
               RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t));

    rp_rbtree_insert(&cache->sh->rbtree, &fcn->node);

    fcn->uses = 1;
    fcn->count = 1;

renew:

    rc = RP_DECLINED;

    fcn->valid_msec = 0;
    fcn->error = 0;
    fcn->exists = 0;
    fcn->valid_sec = 0;
    fcn->uniq = 0;
    fcn->body_start = 0;
    fcn->fs_size = 0;

done:

    fcn->expire = rp_time() + cache->inactive;

    rp_queue_insert_head(&cache->sh->queue, &fcn->queue);

    c->uniq = fcn->uniq;
    c->error = fcn->error;
    c->node = fcn;

failed:

    rp_shmtx_unlock(&cache->shpool->mutex);

    return rc;
}


static rp_int_t
rp_http_file_cache_name(rp_http_request_t *r, rp_path_t *path)
{
    u_char            *p;
    rp_http_cache_t  *c;

    c = r->cache;

    if (c->file.name.len) {
        return RP_OK;
    }

    c->file.name.len = path->name.len + 1 + path->len
                       + 2 * RP_HTTP_CACHE_KEY_LEN;

    c->file.name.data = rp_pnalloc(r->pool, c->file.name.len + 1);
    if (c->file.name.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(c->file.name.data, path->name.data, path->name.len);

    p = c->file.name.data + path->name.len + 1 + path->len;
    p = rp_hex_dump(p, c->key, RP_HTTP_CACHE_KEY_LEN);
    *p = '\0';

    rp_create_hashed_filename(path, c->file.name.data, c->file.name.len);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache file: \"%s\"", c->file.name.data);

    return RP_OK;
}


static rp_http_file_cache_node_t *
rp_http_file_cache_lookup(rp_http_file_cache_t *cache, u_char *key)
{
    rp_int_t                    rc;
    rp_rbtree_key_t             node_key;
    rp_rbtree_node_t           *node, *sentinel;
    rp_http_file_cache_node_t  *fcn;

    rp_memcpy((u_char *) &node_key, key, sizeof(rp_rbtree_key_t));

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

        fcn = (rp_http_file_cache_node_t *) node;

        rc = rp_memcmp(&key[sizeof(rp_rbtree_key_t)], fcn->key,
                        RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t));

        if (rc == 0) {
            return fcn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static void
rp_http_file_cache_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t           **p;
    rp_http_file_cache_node_t   *cn, *cnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            cn = (rp_http_file_cache_node_t *) node;
            cnt = (rp_http_file_cache_node_t *) temp;

            p = (rp_memcmp(cn->key, cnt->key,
                            RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t))
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
    rp_rbt_red(node);
}


static void
rp_http_file_cache_vary(rp_http_request_t *r, u_char *vary, size_t len,
    u_char *hash)
{
    u_char     *p, *last;
    rp_str_t   name;
    rp_md5_t   md5;
    u_char      buf[RP_HTTP_CACHE_VARY_LEN];

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache vary: \"%*s\"", len, vary);

    rp_md5_init(&md5);
    rp_md5_update(&md5, r->cache->main, RP_HTTP_CACHE_KEY_LEN);

    rp_strlow(buf, vary, len);

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

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache vary: %V", &name);

        rp_md5_update(&md5, name.data, name.len);
        rp_md5_update(&md5, (u_char *) ":", sizeof(":") - 1);

        rp_http_file_cache_vary_header(r, &md5, &name);

        rp_md5_update(&md5, (u_char *) CRLF, sizeof(CRLF) - 1);
    }

    rp_md5_final(hash, &md5);
}


static void
rp_http_file_cache_vary_header(rp_http_request_t *r, rp_md5_t *md5,
    rp_str_t *name)
{
    size_t            len;
    u_char           *p, *start, *last;
    rp_uint_t        i, multiple, normalize;
    rp_list_part_t  *part;
    rp_table_elt_t  *header;

    multiple = 0;
    normalize = 0;

    if (name->len == sizeof("Accept-Charset") - 1
        && rp_strncasecmp(name->data, (u_char *) "Accept-Charset",
                           sizeof("Accept-Charset") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Encoding") - 1
        && rp_strncasecmp(name->data, (u_char *) "Accept-Encoding",
                           sizeof("Accept-Encoding") - 1) == 0)
    {
        normalize = 1;

    } else if (name->len == sizeof("Accept-Language") - 1
        && rp_strncasecmp(name->data, (u_char *) "Accept-Language",
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

        if (rp_strncasecmp(header[i].key.data, name->data, name->len) != 0) {
            continue;
        }

        if (!normalize) {

            if (multiple) {
                rp_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            rp_md5_update(md5, header[i].value.data, header[i].value.len);

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
                rp_md5_update(md5, (u_char *) ",", sizeof(",") - 1);
            }

            rp_md5_update(md5, start, len);

            multiple = 1;
        }
    }
}


static rp_int_t
rp_http_file_cache_reopen(rp_http_request_t *r, rp_http_cache_t *c)
{
    rp_http_file_cache_t  *cache;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache reopen");

    if (c->secondary) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      "cache file \"%s\" has incorrect vary hash",
                      c->file.name.data);
        return RP_DECLINED;
    }

    cache = c->file_cache;

    rp_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node = NULL;

    rp_shmtx_unlock(&cache->shpool->mutex);

    c->secondary = 1;
    c->file.name.len = 0;
    c->body_start = c->buf->end - c->buf->start;

    rp_memcpy(c->key, c->variant, RP_HTTP_CACHE_KEY_LEN);

    return rp_http_file_cache_open(r);
}


rp_int_t
rp_http_file_cache_set_header(rp_http_request_t *r, u_char *buf)
{
    rp_http_file_cache_header_t  *h = (rp_http_file_cache_header_t *) buf;

    u_char            *p;
    rp_str_t         *key;
    rp_uint_t         i;
    rp_http_cache_t  *c;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache set header");

    c = r->cache;

    rp_memzero(h, sizeof(rp_http_file_cache_header_t));

    h->version = RP_HTTP_CACHE_VERSION;
    h->valid_sec = c->valid_sec;
    h->updating_sec = c->updating_sec;
    h->error_sec = c->error_sec;
    h->last_modified = c->last_modified;
    h->date = c->date;
    h->crc32 = c->crc32;
    h->valid_msec = (u_short) c->valid_msec;
    h->header_start = (u_short) c->header_start;
    h->body_start = (u_short) c->body_start;

    if (c->etag.len <= RP_HTTP_CACHE_ETAG_LEN) {
        h->etag_len = (u_char) c->etag.len;
        rp_memcpy(h->etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > RP_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = RP_HTTP_CACHE_VARY_LEN;
        }

        h->vary_len = (u_char) c->vary.len;
        rp_memcpy(h->vary, c->vary.data, c->vary.len);

        rp_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        rp_memcpy(h->variant, c->variant, RP_HTTP_CACHE_KEY_LEN);
    }

    if (rp_http_file_cache_update_variant(r, c) != RP_OK) {
        return RP_ERROR;
    }

    p = buf + sizeof(rp_http_file_cache_header_t);

    p = rp_cpymem(p, rp_http_file_cache_key, sizeof(rp_http_file_cache_key));

    key = c->keys.elts;
    for (i = 0; i < c->keys.nelts; i++) {
        p = rp_copy(p, key[i].data, key[i].len);
    }

    *p = LF;

    return RP_OK;
}


static rp_int_t
rp_http_file_cache_update_variant(rp_http_request_t *r, rp_http_cache_t *c)
{
    rp_http_file_cache_t  *cache;

    if (!c->secondary) {
        return RP_OK;
    }

    if (c->vary.len
        && rp_memcmp(c->variant, c->key, RP_HTTP_CACHE_KEY_LEN) == 0)
    {
        return RP_OK;
    }

    /*
     * if the variant hash doesn't match one we used as a secondary
     * cache key, switch back to the original key
     */

    cache = c->file_cache;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache main key");

    rp_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->updating = 0;
    c->node = NULL;

    rp_shmtx_unlock(&cache->shpool->mutex);

    c->file.name.len = 0;

    rp_memcpy(c->key, c->main, RP_HTTP_CACHE_KEY_LEN);

    if (rp_http_file_cache_exists(cache, c) == RP_ERROR) {
        return RP_ERROR;
    }

    if (rp_http_file_cache_name(r, cache->path) != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_http_file_cache_update(rp_http_request_t *r, rp_temp_file_t *tf)
{
    off_t                   fs_size;
    rp_int_t               rc;
    rp_file_uniq_t         uniq;
    rp_file_info_t         fi;
    rp_http_cache_t        *c;
    rp_ext_rename_file_t   ext;
    rp_http_file_cache_t  *cache;

    c = r->cache;

    if (c->updated) {
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update");

    cache = c->file_cache;

    c->updated = 1;
    c->updating = 0;

    uniq = 0;
    fs_size = 0;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache rename: \"%s\" to \"%s\"",
                   tf->file.name.data, c->file.name.data);

    ext.access = RP_FILE_OWNER_ACCESS;
    ext.path_access = RP_FILE_OWNER_ACCESS;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    rc = rp_ext_rename_file(&tf->file.name, &c->file.name, &ext);

    if (rc == RP_OK) {

        if (rp_fd_info(tf->file.fd, &fi) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                          rp_fd_info_n " \"%s\" failed", tf->file.name.data);

            rc = RP_ERROR;

        } else {
            uniq = rp_file_uniq(&fi);
            fs_size = (rp_file_fs_size(&fi) + cache->bsize - 1) / cache->bsize;
        }
    }

    rp_shmtx_lock(&cache->shpool->mutex);

    c->node->count--;
    c->node->error = 0;
    c->node->uniq = uniq;
    c->node->body_start = c->body_start;

    cache->sh->size += fs_size - c->node->fs_size;
    c->node->fs_size = fs_size;

    if (rc == RP_OK) {
        c->node->exists = 1;
    }

    c->node->updating = 0;

    rp_shmtx_unlock(&cache->shpool->mutex);
}


void
rp_http_file_cache_update_header(rp_http_request_t *r)
{
    ssize_t                        n;
    rp_err_t                      err;
    rp_file_t                     file;
    rp_file_info_t                fi;
    rp_http_cache_t              *c;
    rp_http_file_cache_header_t   h;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache update header");

    c = r->cache;

    rp_memzero(&file, sizeof(rp_file_t));

    file.name = c->file.name;
    file.log = r->connection->log;
    file.fd = rp_open_file(file.name.data, RP_FILE_RDWR, RP_FILE_OPEN, 0);

    if (file.fd == RP_INVALID_FILE) {
        err = rp_errno;

        /* cache file may have been deleted */

        if (err == RP_ENOENT) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http file cache \"%s\" not found",
                           file.name.data);
            return;
        }

        rp_log_error(RP_LOG_CRIT, r->connection->log, err,
                      rp_open_file_n " \"%s\" failed", file.name.data);
        return;
    }

    /*
     * make sure cache file wasn't replaced;
     * if it was, do nothing
     */

    if (rp_fd_info(file.fd, &fi) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                      rp_fd_info_n " \"%s\" failed", file.name.data);
        goto done;
    }

    if (c->uniq != rp_file_uniq(&fi)
        || c->length != rp_file_size(&fi))
    {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" changed",
                       file.name.data);
        goto done;
    }

    n = rp_read_file(&file, (u_char *) &h,
                      sizeof(rp_http_file_cache_header_t), 0);

    if (n == RP_ERROR) {
        goto done;
    }

    if ((size_t) n != sizeof(rp_http_file_cache_header_t)) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                      rp_read_file_n " read only %z of %z from \"%s\"",
                      n, sizeof(rp_http_file_cache_header_t), file.name.data);
        goto done;
    }

    if (h.version != RP_HTTP_CACHE_VERSION
        || h.last_modified != c->last_modified
        || h.crc32 != c->crc32
        || (size_t) h.header_start != c->header_start
        || (size_t) h.body_start != c->body_start)
    {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http file cache \"%s\" content changed",
                       file.name.data);
        goto done;
    }

    /*
     * update cache file header with new data,
     * notably h.valid_sec and h.date
     */

    rp_memzero(&h, sizeof(rp_http_file_cache_header_t));

    h.version = RP_HTTP_CACHE_VERSION;
    h.valid_sec = c->valid_sec;
    h.updating_sec = c->updating_sec;
    h.error_sec = c->error_sec;
    h.last_modified = c->last_modified;
    h.date = c->date;
    h.crc32 = c->crc32;
    h.valid_msec = (u_short) c->valid_msec;
    h.header_start = (u_short) c->header_start;
    h.body_start = (u_short) c->body_start;

    if (c->etag.len <= RP_HTTP_CACHE_ETAG_LEN) {
        h.etag_len = (u_char) c->etag.len;
        rp_memcpy(h.etag, c->etag.data, c->etag.len);
    }

    if (c->vary.len) {
        if (c->vary.len > RP_HTTP_CACHE_VARY_LEN) {
            /* should not happen */
            c->vary.len = RP_HTTP_CACHE_VARY_LEN;
        }

        h.vary_len = (u_char) c->vary.len;
        rp_memcpy(h.vary, c->vary.data, c->vary.len);

        rp_http_file_cache_vary(r, c->vary.data, c->vary.len, c->variant);
        rp_memcpy(h.variant, c->variant, RP_HTTP_CACHE_KEY_LEN);
    }

    (void) rp_write_file(&file, (u_char *) &h,
                          sizeof(rp_http_file_cache_header_t), 0);

done:

    if (rp_close_file(file.fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", file.name.data);
    }
}


rp_int_t
rp_http_cache_send(rp_http_request_t *r)
{
    rp_int_t          rc;
    rp_buf_t         *b;
    rp_chain_t        out;
    rp_http_cache_t  *c;

    c = r->cache;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http file cache send: %s", c->file.name.data);

    if (r != r->main && c->length - c->body_start == 0) {
        return rp_http_send_header(r);
    }

    /* we need to allocate all before the header would be sent */

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rp_pcalloc(r->pool, sizeof(rp_file_t));
    if (b->file == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
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

    return rp_http_output_filter(r, &out);
}


void
rp_http_file_cache_free(rp_http_cache_t *c, rp_temp_file_t *tf)
{
    rp_http_file_cache_t       *cache;
    rp_http_file_cache_node_t  *fcn;

    if (c->updated || c->node == NULL) {
        return;
    }

    cache = c->file_cache;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache free, fd: %d", c->file.fd);

    rp_shmtx_lock(&cache->shpool->mutex);

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
        rp_queue_remove(&fcn->queue);
        rp_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        rp_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
        c->node = NULL;
    }

    rp_shmtx_unlock(&cache->shpool->mutex);

    c->updated = 1;
    c->updating = 0;

    if (c->temp_file) {
        if (tf && tf->file.fd != RP_INVALID_FILE) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, c->file.log, 0,
                           "http file cache incomplete: \"%s\"",
                           tf->file.name.data);

            if (rp_delete_file(tf->file.name.data) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_CRIT, c->file.log, rp_errno,
                              rp_delete_file_n " \"%s\" failed",
                              tf->file.name.data);
            }
        }
    }

    if (c->wait_event.timer_set) {
        rp_del_timer(&c->wait_event);
    }
}


static void
rp_http_file_cache_cleanup(void *data)
{
    rp_http_cache_t  *c = data;

    if (c->updated) {
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->file.log, 0,
                   "http file cache cleanup");

    if (c->updating && !c->background) {
        rp_log_error(RP_LOG_ALERT, c->file.log, 0,
                      "stalled cache updating, error:%ui", c->error);
    }

    rp_http_file_cache_free(c, NULL);
}


static time_t
rp_http_file_cache_forced_expire(rp_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       wait;
    rp_uint_t                   tries;
    rp_path_t                  *path;
    rp_queue_t                 *q, *sentinel;
    rp_http_file_cache_node_t  *fcn;
    u_char                       key[2 * RP_HTTP_CACHE_KEY_LEN];

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                   "http file cache forced expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * RP_HTTP_CACHE_KEY_LEN;

    name = rp_alloc(len + 1, rp_cycle->log);
    if (name == NULL) {
        return 10;
    }

    rp_memcpy(name, path->name.data, path->name.len);

    wait = 10;
    tries = 20;
    sentinel = NULL;

    rp_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {
        if (rp_queue_empty(&cache->sh->queue)) {
            break;
        }

        q = rp_queue_last(&cache->sh->queue);

        if (q == sentinel) {
            break;
        }

        fcn = rp_queue_data(q, rp_http_file_cache_node_t, queue);

        rp_log_debug6(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                  "http file cache forced expire: #%d %d %02xd%02xd%02xd%02xd",
                  fcn->count, fcn->exists,
                  fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            rp_http_file_cache_delete(cache, q, name);
            wait = 0;
            break;
        }

        p = rp_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(rp_rbtree_key_t));
        len = RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t);
        (void) rp_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        rp_queue_remove(q);
        fcn->expire = rp_time() + cache->inactive;
        rp_queue_insert_head(&cache->sh->queue, &fcn->queue);

        rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * RP_HTTP_CACHE_KEY_LEN, key, fcn->count);

        if (sentinel == NULL) {
            sentinel = q;
        }

        if (--tries) {
            continue;
        }

        wait = 1;
        break;
    }

    rp_shmtx_unlock(&cache->shpool->mutex);

    rp_free(name);

    return wait;
}


static time_t
rp_http_file_cache_expire(rp_http_file_cache_t *cache)
{
    u_char                      *name, *p;
    size_t                       len;
    time_t                       now, wait;
    rp_path_t                  *path;
    rp_msec_t                   elapsed;
    rp_queue_t                 *q;
    rp_http_file_cache_node_t  *fcn;
    u_char                       key[2 * RP_HTTP_CACHE_KEY_LEN];

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                   "http file cache expire");

    path = cache->path;
    len = path->name.len + 1 + path->len + 2 * RP_HTTP_CACHE_KEY_LEN;

    name = rp_alloc(len + 1, rp_cycle->log);
    if (name == NULL) {
        return 10;
    }

    rp_memcpy(name, path->name.data, path->name.len);

    now = rp_time();

    rp_shmtx_lock(&cache->shpool->mutex);

    for ( ;; ) {

        if (rp_quit || rp_terminate) {
            wait = 1;
            break;
        }

        if (rp_queue_empty(&cache->sh->queue)) {
            wait = 10;
            break;
        }

        q = rp_queue_last(&cache->sh->queue);

        fcn = rp_queue_data(q, rp_http_file_cache_node_t, queue);

        wait = fcn->expire - now;

        if (wait > 0) {
            wait = wait > 10 ? 10 : wait;
            break;
        }

        rp_log_debug6(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                       "http file cache expire: #%d %d %02xd%02xd%02xd%02xd",
                       fcn->count, fcn->exists,
                       fcn->key[0], fcn->key[1], fcn->key[2], fcn->key[3]);

        if (fcn->count == 0) {
            rp_http_file_cache_delete(cache, q, name);
            goto next;
        }

        if (fcn->deleting) {
            wait = 1;
            break;
        }

        p = rp_hex_dump(key, (u_char *) &fcn->node.key,
                         sizeof(rp_rbtree_key_t));
        len = RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t);
        (void) rp_hex_dump(p, fcn->key, len);

        /*
         * abnormally exited workers may leave locked cache entries,
         * and although it may be safe to remove them completely,
         * we prefer to just move them to the top of the inactive queue
         */

        rp_queue_remove(q);
        fcn->expire = rp_time() + cache->inactive;
        rp_queue_insert_head(&cache->sh->queue, &fcn->queue);

        rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                      "ignore long locked inactive cache entry %*s, count:%d",
                      (size_t) 2 * RP_HTTP_CACHE_KEY_LEN, key, fcn->count);

next:

        if (++cache->files >= cache->manager_files) {
            wait = 0;
            break;
        }

        rp_time_update();

        elapsed = rp_abs((rp_msec_int_t) (rp_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            wait = 0;
            break;
        }
    }

    rp_shmtx_unlock(&cache->shpool->mutex);

    rp_free(name);

    return wait;
}


static void
rp_http_file_cache_delete(rp_http_file_cache_t *cache, rp_queue_t *q,
    u_char *name)
{
    u_char                      *p;
    size_t                       len;
    rp_path_t                  *path;
    rp_http_file_cache_node_t  *fcn;

    fcn = rp_queue_data(q, rp_http_file_cache_node_t, queue);

    if (fcn->exists) {
        cache->sh->size -= fcn->fs_size;

        path = cache->path;
        p = name + path->name.len + 1 + path->len;
        p = rp_hex_dump(p, (u_char *) &fcn->node.key,
                         sizeof(rp_rbtree_key_t));
        len = RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t);
        p = rp_hex_dump(p, fcn->key, len);
        *p = '\0';

        fcn->count++;
        fcn->deleting = 1;
        rp_shmtx_unlock(&cache->shpool->mutex);

        len = path->name.len + 1 + path->len + 2 * RP_HTTP_CACHE_KEY_LEN;
        rp_create_hashed_filename(path, name, len);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                       "http file cache expire: \"%s\"", name);

        if (rp_delete_file(name) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_CRIT, rp_cycle->log, rp_errno,
                          rp_delete_file_n " \"%s\" failed", name);
        }

        rp_shmtx_lock(&cache->shpool->mutex);
        fcn->count--;
        fcn->deleting = 0;
    }

    if (fcn->count == 0) {
        rp_queue_remove(q);
        rp_rbtree_delete(&cache->sh->rbtree, &fcn->node);
        rp_slab_free_locked(cache->shpool, fcn);
        cache->sh->count--;
    }
}


static rp_msec_t
rp_http_file_cache_manager(void *data)
{
    rp_http_file_cache_t  *cache = data;

    off_t       size;
    time_t      wait;
    rp_msec_t  elapsed, next;
    rp_uint_t  count, watermark;

    cache->last = rp_current_msec;
    cache->files = 0;

    next = (rp_msec_t) rp_http_file_cache_expire(cache) * 1000;

    if (next == 0) {
        next = cache->manager_sleep;
        goto done;
    }

    for ( ;; ) {
        rp_shmtx_lock(&cache->shpool->mutex);

        size = cache->sh->size;
        count = cache->sh->count;
        watermark = cache->sh->watermark;

        rp_shmtx_unlock(&cache->shpool->mutex);

        rp_log_debug3(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                       "http file cache size: %O c:%ui w:%i",
                       size, count, (rp_int_t) watermark);

        if (size < cache->max_size && count < watermark) {
            break;
        }

        wait = rp_http_file_cache_forced_expire(cache);

        if (wait > 0) {
            next = (rp_msec_t) wait * 1000;
            break;
        }

        if (rp_quit || rp_terminate) {
            break;
        }

        if (++cache->files >= cache->manager_files) {
            next = cache->manager_sleep;
            break;
        }

        rp_time_update();

        elapsed = rp_abs((rp_msec_int_t) (rp_current_msec - cache->last));

        if (elapsed >= cache->manager_threshold) {
            next = cache->manager_sleep;
            break;
        }
    }

done:

    elapsed = rp_abs((rp_msec_int_t) (rp_current_msec - cache->last));

    rp_log_debug3(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                   "http file cache manager: %ui e:%M n:%M",
                   cache->files, elapsed, next);

    return next;
}


static void
rp_http_file_cache_loader(void *data)
{
    rp_http_file_cache_t  *cache = data;

    rp_tree_ctx_t  tree;

    if (!cache->sh->cold || cache->sh->loading) {
        return;
    }

    if (!rp_atomic_cmp_set(&cache->sh->loading, 0, rp_pid)) {
        return;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                   "http file cache loader");

    tree.init_handler = NULL;
    tree.file_handler = rp_http_file_cache_manage_file;
    tree.pre_tree_handler = rp_http_file_cache_manage_directory;
    tree.post_tree_handler = rp_http_file_cache_noop;
    tree.spec_handler = rp_http_file_cache_delete_file;
    tree.data = cache;
    tree.alloc = 0;
    tree.log = rp_cycle->log;

    cache->last = rp_current_msec;
    cache->files = 0;

    if (rp_walk_tree(&tree, &cache->path->name) == RP_ABORT) {
        cache->sh->loading = 0;
        return;
    }

    cache->sh->cold = 0;
    cache->sh->loading = 0;

    rp_log_error(RP_LOG_NOTICE, rp_cycle->log, 0,
                  "http file cache: %V %.3fM, bsize: %uz",
                  &cache->path->name,
                  ((double) cache->sh->size * cache->bsize) / (1024 * 1024),
                  cache->bsize);
}


static rp_int_t
rp_http_file_cache_noop(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    return RP_OK;
}


static rp_int_t
rp_http_file_cache_manage_file(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    rp_msec_t              elapsed;
    rp_http_file_cache_t  *cache;

    cache = ctx->data;

    if (rp_http_file_cache_add_file(ctx, path) != RP_OK) {
        (void) rp_http_file_cache_delete_file(ctx, path);
    }

    if (++cache->files >= cache->loader_files) {
        rp_http_file_cache_loader_sleep(cache);

    } else {
        rp_time_update();

        elapsed = rp_abs((rp_msec_int_t) (rp_current_msec - cache->last));

        rp_log_debug1(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                       "http file cache loader time elapsed: %M", elapsed);

        if (elapsed >= cache->loader_threshold) {
            rp_http_file_cache_loader_sleep(cache);
        }
    }

    return (rp_quit || rp_terminate) ? RP_ABORT : RP_OK;
}


static rp_int_t
rp_http_file_cache_manage_directory(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    if (path->len >= 5
        && rp_strncmp(path->data + path->len - 5, "/temp", 5) == 0)
    {
        return RP_DECLINED;
    }

    return RP_OK;
}


static void
rp_http_file_cache_loader_sleep(rp_http_file_cache_t *cache)
{
    rp_msleep(cache->loader_sleep);

    rp_time_update();

    cache->last = rp_current_msec;
    cache->files = 0;
}


static rp_int_t
rp_http_file_cache_add_file(rp_tree_ctx_t *ctx, rp_str_t *name)
{
    u_char                 *p;
    rp_int_t               n;
    rp_uint_t              i;
    rp_http_cache_t        c;
    rp_http_file_cache_t  *cache;

    if (name->len < 2 * RP_HTTP_CACHE_KEY_LEN) {
        return RP_ERROR;
    }

    /*
     * Temporary files in cache have a suffix consisting of a dot
     * followed by 10 digits.
     */

    if (name->len >= 2 * RP_HTTP_CACHE_KEY_LEN + 1 + 10
        && name->data[name->len - 10 - 1] == '.')
    {
        return RP_OK;
    }

    if (ctx->size < (off_t) sizeof(rp_http_file_cache_header_t)) {
        rp_log_error(RP_LOG_CRIT, ctx->log, 0,
                      "cache file \"%s\" is too small", name->data);
        return RP_ERROR;
    }

    rp_memzero(&c, sizeof(rp_http_cache_t));
    cache = ctx->data;

    c.length = ctx->size;
    c.fs_size = (ctx->fs_size + cache->bsize - 1) / cache->bsize;

    p = &name->data[name->len - 2 * RP_HTTP_CACHE_KEY_LEN];

    for (i = 0; i < RP_HTTP_CACHE_KEY_LEN; i++) {
        n = rp_hextoi(p, 2);

        if (n == RP_ERROR) {
            return RP_ERROR;
        }

        p += 2;

        c.key[i] = (u_char) n;
    }

    return rp_http_file_cache_add(cache, &c);
}


static rp_int_t
rp_http_file_cache_add(rp_http_file_cache_t *cache, rp_http_cache_t *c)
{
    rp_http_file_cache_node_t  *fcn;

    rp_shmtx_lock(&cache->shpool->mutex);

    fcn = rp_http_file_cache_lookup(cache, c->key);

    if (fcn == NULL) {

        fcn = rp_slab_calloc_locked(cache->shpool,
                                     sizeof(rp_http_file_cache_node_t));
        if (fcn == NULL) {
            rp_http_file_cache_set_watermark(cache);

            if (cache->fail_time != rp_time()) {
                cache->fail_time = rp_time();
                rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                           "could not allocate node%s", cache->shpool->log_ctx);
            }

            rp_shmtx_unlock(&cache->shpool->mutex);
            return RP_ERROR;
        }

        cache->sh->count++;

        rp_memcpy((u_char *) &fcn->node.key, c->key, sizeof(rp_rbtree_key_t));

        rp_memcpy(fcn->key, &c->key[sizeof(rp_rbtree_key_t)],
                   RP_HTTP_CACHE_KEY_LEN - sizeof(rp_rbtree_key_t));

        rp_rbtree_insert(&cache->sh->rbtree, &fcn->node);

        fcn->uses = 1;
        fcn->exists = 1;
        fcn->fs_size = c->fs_size;

        cache->sh->size += c->fs_size;

    } else {
        rp_queue_remove(&fcn->queue);
    }

    fcn->expire = rp_time() + cache->inactive;

    rp_queue_insert_head(&cache->sh->queue, &fcn->queue);

    rp_shmtx_unlock(&cache->shpool->mutex);

    return RP_OK;
}


static rp_int_t
rp_http_file_cache_delete_file(rp_tree_ctx_t *ctx, rp_str_t *path)
{
    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http file cache delete: \"%s\"", path->data);

    if (rp_delete_file(path->data) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_CRIT, ctx->log, rp_errno,
                      rp_delete_file_n " \"%s\" failed", path->data);
    }

    return RP_OK;
}


static void
rp_http_file_cache_set_watermark(rp_http_file_cache_t *cache)
{
    cache->sh->watermark = cache->sh->count - cache->sh->count / 8;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0,
                   "http file cache watermark: %ui", cache->sh->watermark);
}


time_t
rp_http_file_cache_valid(rp_array_t *cache_valid, rp_uint_t status)
{
    rp_uint_t               i;
    rp_http_cache_valid_t  *valid;

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
rp_http_file_cache_set_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *confp = conf;

    off_t                   max_size;
    u_char                 *last, *p;
    time_t                  inactive;
    ssize_t                 size;
    rp_str_t               s, name, *value;
    rp_int_t               loader_files, manager_files;
    rp_msec_t              loader_sleep, manager_sleep, loader_threshold,
                            manager_threshold;
    rp_uint_t              i, n, use_temp_path;
    rp_array_t            *caches;
    rp_http_file_cache_t  *cache, **ce;

    cache = rp_pcalloc(cf->pool, sizeof(rp_http_file_cache_t));
    if (cache == NULL) {
        return RP_CONF_ERROR;
    }

    cache->path = rp_pcalloc(cf->pool, sizeof(rp_path_t));
    if (cache->path == NULL) {
        return RP_CONF_ERROR;
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
    max_size = RP_MAX_OFF_T_VALUE;

    value = cf->args->elts;

    cache->path->name = value[1];

    if (cache->path->name.data[cache->path->name.len - 1] == '/') {
        cache->path->name.len--;
    }

    if (rp_conf_full_name(cf->cycle, &cache->path->name, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "levels=", 7) == 0) {

            p = value[i].data + 7;
            last = value[i].data + value[i].len;

            for (n = 0; n < RP_MAX_PATH_LEVEL && p < last; n++) {

                if (*p > '0' && *p < '3') {

                    cache->path->level[n] = *p++ - '0';
                    cache->path->len += cache->path->level[n] + 1;

                    if (p == last) {
                        break;
                    }

                    if (*p++ == ':' && n < RP_MAX_PATH_LEVEL - 1 && p < last) {
                        continue;
                    }

                    goto invalid_levels;
                }

                goto invalid_levels;
            }

            if (cache->path->len < 10 + RP_MAX_PATH_LEVEL) {
                continue;
            }

        invalid_levels:

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid \"levels\" \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }

        if (rp_strncmp(value[i].data, "use_temp_path=", 14) == 0) {

            if (rp_strcmp(&value[i].data[14], "on") == 0) {
                use_temp_path = 1;

            } else if (rp_strcmp(&value[i].data[14], "off") == 0) {
                use_temp_path = 0;

            } else {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid use_temp_path value \"%V\", "
                                   "it must be \"on\" or \"off\"",
                                   &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "keys_zone=", 10) == 0) {

            name.data = value[i].data + 10;

            p = (u_char *) rp_strchr(name.data, ':');

            if (p == NULL) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = rp_parse_size(&s);

            if (size == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid keys zone size \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            if (size < (ssize_t) (2 * rp_pagesize)) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "keys zone \"%V\" is too small", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = rp_parse_time(&s, 1);
            if (inactive == (time_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid inactive value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = rp_parse_offset(&s);
            if (max_size < 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid max_size value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "loader_files=", 13) == 0) {

            loader_files = rp_atoi(value[i].data + 13, value[i].len - 13);
            if (loader_files == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid loader_files value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "loader_sleep=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            loader_sleep = rp_parse_time(&s, 0);
            if (loader_sleep == (rp_msec_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid loader_sleep value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "loader_threshold=", 17) == 0) {

            s.len = value[i].len - 17;
            s.data = value[i].data + 17;

            loader_threshold = rp_parse_time(&s, 0);
            if (loader_threshold == (rp_msec_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid loader_threshold value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "manager_files=", 14) == 0) {

            manager_files = rp_atoi(value[i].data + 14, value[i].len - 14);
            if (manager_files == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid manager_files value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "manager_sleep=", 14) == 0) {

            s.len = value[i].len - 14;
            s.data = value[i].data + 14;

            manager_sleep = rp_parse_time(&s, 0);
            if (manager_sleep == (rp_msec_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid manager_sleep value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "manager_threshold=", 18) == 0) {

            s.len = value[i].len - 18;
            s.data = value[i].data + 18;

            manager_threshold = rp_parse_time(&s, 0);
            if (manager_threshold == (rp_msec_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid manager_threshold value \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return RP_CONF_ERROR;
    }

    if (name.len == 0 || size == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"keys_zone\" parameter",
                           &cmd->name);
        return RP_CONF_ERROR;
    }

    cache->path->manager = rp_http_file_cache_manager;
    cache->path->loader = rp_http_file_cache_loader;
    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;
    cache->loader_files = loader_files;
    cache->loader_sleep = loader_sleep;
    cache->loader_threshold = loader_threshold;
    cache->manager_files = manager_files;
    cache->manager_sleep = manager_sleep;
    cache->manager_threshold = manager_threshold;

    if (rp_add_path(cf, &cache->path) != RP_OK) {
        return RP_CONF_ERROR;
    }

    cache->shm_zone = rp_shared_memory_add(cf, &name, size, cmd->post);
    if (cache->shm_zone == NULL) {
        return RP_CONF_ERROR;
    }

    if (cache->shm_zone->data) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &name);
        return RP_CONF_ERROR;
    }


    cache->shm_zone->init = rp_http_file_cache_init;
    cache->shm_zone->data = cache;

    cache->use_temp_path = use_temp_path;

    cache->inactive = inactive;
    cache->max_size = max_size;

    caches = (rp_array_t *) (confp + cmd->offset);

    ce = rp_array_push(caches);
    if (ce == NULL) {
        return RP_CONF_ERROR;
    }

    *ce = cache;

    return RP_CONF_OK;
}


char *
rp_http_file_cache_valid_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    time_t                    valid;
    rp_str_t                *value;
    rp_int_t                 status;
    rp_uint_t                i, n;
    rp_array_t             **a;
    rp_http_cache_valid_t   *v;
    static rp_uint_t         statuses[] = { 200, 301, 302 };

    a = (rp_array_t **) (p + cmd->offset);

    if (*a == RP_CONF_UNSET_PTR) {
        *a = rp_array_create(cf->pool, 1, sizeof(rp_http_cache_valid_t));
        if (*a == NULL) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    n = cf->args->nelts - 1;

    valid = rp_parse_time(&value[n], 1);
    if (valid == (time_t) RP_ERROR) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid time value \"%V\"", &value[n]);
        return RP_CONF_ERROR;
    }

    if (n == 1) {

        for (i = 0; i < 3; i++) {
            v = rp_array_push(*a);
            if (v == NULL) {
                return RP_CONF_ERROR;
            }

            v->status = statuses[i];
            v->valid = valid;
        }

        return RP_CONF_OK;
    }

    for (i = 1; i < n; i++) {

        if (rp_strcmp(value[i].data, "any") == 0) {

            status = 0;

        } else {

            status = rp_atoi(value[i].data, value[i].len);
            if (status < 100 || status > 599) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid status \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }
        }

        v = rp_array_push(*a);
        if (v == NULL) {
            return RP_CONF_ERROR;
        }

        v->status = status;
        v->valid = valid;
    }

    return RP_CONF_OK;
}
