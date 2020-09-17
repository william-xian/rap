
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


/*
 * open file cache caches
 *    open file handles with stat() info;
 *    directories stat() info;
 *    files and directories errors: not found, access denied, etc.
 */


#define RP_MIN_READ_AHEAD  (128 * 1024)


static void rp_open_file_cache_cleanup(void *data);
#if (RP_HAVE_OPENAT)
static rp_fd_t rp_openat_file_owner(rp_fd_t at_fd, const u_char *name,
    rp_int_t mode, rp_int_t create, rp_int_t access, rp_log_t *log);
#if (RP_HAVE_O_PATH)
static rp_int_t rp_file_o_path_info(rp_fd_t fd, rp_file_info_t *fi,
    rp_log_t *log);
#endif
#endif
static rp_fd_t rp_open_file_wrapper(rp_str_t *name,
    rp_open_file_info_t *of, rp_int_t mode, rp_int_t create,
    rp_int_t access, rp_log_t *log);
static rp_int_t rp_file_info_wrapper(rp_str_t *name,
    rp_open_file_info_t *of, rp_file_info_t *fi, rp_log_t *log);
static rp_int_t rp_open_and_stat_file(rp_str_t *name,
    rp_open_file_info_t *of, rp_log_t *log);
static void rp_open_file_add_event(rp_open_file_cache_t *cache,
    rp_cached_open_file_t *file, rp_open_file_info_t *of, rp_log_t *log);
static void rp_open_file_cleanup(void *data);
static void rp_close_cached_file(rp_open_file_cache_t *cache,
    rp_cached_open_file_t *file, rp_uint_t min_uses, rp_log_t *log);
static void rp_open_file_del_event(rp_cached_open_file_t *file);
static void rp_expire_old_cached_files(rp_open_file_cache_t *cache,
    rp_uint_t n, rp_log_t *log);
static void rp_open_file_cache_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
static rp_cached_open_file_t *
    rp_open_file_lookup(rp_open_file_cache_t *cache, rp_str_t *name,
    uint32_t hash);
static void rp_open_file_cache_remove(rp_event_t *ev);


rp_open_file_cache_t *
rp_open_file_cache_init(rp_pool_t *pool, rp_uint_t max, time_t inactive)
{
    rp_pool_cleanup_t     *cln;
    rp_open_file_cache_t  *cache;

    cache = rp_palloc(pool, sizeof(rp_open_file_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    rp_rbtree_init(&cache->rbtree, &cache->sentinel,
                    rp_open_file_cache_rbtree_insert_value);

    rp_queue_init(&cache->expire_queue);

    cache->current = 0;
    cache->max = max;
    cache->inactive = inactive;

    cln = rp_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rp_open_file_cache_cleanup;
    cln->data = cache;

    return cache;
}


static void
rp_open_file_cache_cleanup(void *data)
{
    rp_open_file_cache_t  *cache = data;

    rp_queue_t             *q;
    rp_cached_open_file_t  *file;

    rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                   "open file cache cleanup");

    for ( ;; ) {

        if (rp_queue_empty(&cache->expire_queue)) {
            break;
        }

        q = rp_queue_last(&cache->expire_queue);

        file = rp_queue_data(q, rp_cached_open_file_t, queue);

        rp_queue_remove(q);

        rp_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        rp_log_debug1(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                       "delete cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            file->count = 0;
            rp_close_cached_file(cache, file, 0, rp_cycle->log);

        } else {
            rp_free(file->name);
            rp_free(file);
        }
    }

    if (cache->current) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                      "%ui items still left in open file cache",
                      cache->current);
    }

    if (cache->rbtree.root != cache->rbtree.sentinel) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                      "rbtree still is not empty in open file cache");

    }
}


rp_int_t
rp_open_cached_file(rp_open_file_cache_t *cache, rp_str_t *name,
    rp_open_file_info_t *of, rp_pool_t *pool)
{
    time_t                          now;
    uint32_t                        hash;
    rp_int_t                       rc;
    rp_file_info_t                 fi;
    rp_pool_cleanup_t             *cln;
    rp_cached_open_file_t         *file;
    rp_pool_cleanup_file_t        *clnf;
    rp_open_file_cache_cleanup_t  *ofcln;

    of->fd = RP_INVALID_FILE;
    of->err = 0;

    if (cache == NULL) {

        if (of->test_only) {

            if (rp_file_info_wrapper(name, of, &fi, pool->log)
                == RP_FILE_ERROR)
            {
                return RP_ERROR;
            }

            of->uniq = rp_file_uniq(&fi);
            of->mtime = rp_file_mtime(&fi);
            of->size = rp_file_size(&fi);
            of->fs_size = rp_file_fs_size(&fi);
            of->is_dir = rp_is_dir(&fi);
            of->is_file = rp_is_file(&fi);
            of->is_link = rp_is_link(&fi);
            of->is_exec = rp_is_exec(&fi);

            return RP_OK;
        }

        cln = rp_pool_cleanup_add(pool, sizeof(rp_pool_cleanup_file_t));
        if (cln == NULL) {
            return RP_ERROR;
        }

        rc = rp_open_and_stat_file(name, of, pool->log);

        if (rc == RP_OK && !of->is_dir) {
            cln->handler = rp_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = of->fd;
            clnf->name = name->data;
            clnf->log = pool->log;
        }

        return rc;
    }

    cln = rp_pool_cleanup_add(pool, sizeof(rp_open_file_cache_cleanup_t));
    if (cln == NULL) {
        return RP_ERROR;
    }

    now = rp_time();

    hash = rp_crc32_long(name->data, name->len);

    file = rp_open_file_lookup(cache, name, hash);

    if (file) {

        file->uses++;

        rp_queue_remove(&file->queue);

        if (file->fd == RP_INVALID_FILE && file->err == 0 && !file->is_dir) {

            /* file was not used often enough to keep open */

            rc = rp_open_and_stat_file(name, of, pool->log);

            if (rc != RP_OK && (of->err == 0 || !of->errors)) {
                goto failed;
            }

            goto add_event;
        }

        if (file->use_event
            || (file->event == NULL
                && (of->uniq == 0 || of->uniq == file->uniq)
                && now - file->created < of->valid
#if (RP_HAVE_OPENAT)
                && of->disable_symlinks == file->disable_symlinks
                && of->disable_symlinks_from == file->disable_symlinks_from
#endif
            ))
        {
            if (file->err == 0) {

                of->fd = file->fd;
                of->uniq = file->uniq;
                of->mtime = file->mtime;
                of->size = file->size;

                of->is_dir = file->is_dir;
                of->is_file = file->is_file;
                of->is_link = file->is_link;
                of->is_exec = file->is_exec;
                of->is_directio = file->is_directio;

                if (!file->is_dir) {
                    file->count++;
                    rp_open_file_add_event(cache, file, of, pool->log);
                }

            } else {
                of->err = file->err;
#if (RP_HAVE_OPENAT)
                of->failed = file->disable_symlinks ? rp_openat_file_n
                                                    : rp_open_file_n;
#else
                of->failed = rp_open_file_n;
#endif
            }

            goto found;
        }

        rp_log_debug4(RP_LOG_DEBUG_CORE, pool->log, 0,
                       "retest open file: %s, fd:%d, c:%d, e:%d",
                       file->name, file->fd, file->count, file->err);

        if (file->is_dir) {

            /*
             * chances that directory became file are very small
             * so test_dir flag allows to use a single syscall
             * in rp_file_info() instead of three syscalls
             */

            of->test_dir = 1;
        }

        of->fd = file->fd;
        of->uniq = file->uniq;

        rc = rp_open_and_stat_file(name, of, pool->log);

        if (rc != RP_OK && (of->err == 0 || !of->errors)) {
            goto failed;
        }

        if (of->is_dir) {

            if (file->is_dir || file->err) {
                goto update;
            }

            /* file became directory */

        } else if (of->err == 0) {  /* file */

            if (file->is_dir || file->err) {
                goto add_event;
            }

            if (of->uniq == file->uniq) {

                if (file->event) {
                    file->use_event = 1;
                }

                of->is_directio = file->is_directio;

                goto update;
            }

            /* file was changed */

        } else { /* error to cache */

            if (file->err || file->is_dir) {
                goto update;
            }

            /* file was removed, etc. */
        }

        if (file->count == 0) {

            rp_open_file_del_event(file);

            if (rp_close_file(file->fd) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_ALERT, pool->log, rp_errno,
                              rp_close_file_n " \"%V\" failed", name);
            }

            goto add_event;
        }

        rp_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        file->close = 1;

        goto create;
    }

    /* not found */

    rc = rp_open_and_stat_file(name, of, pool->log);

    if (rc != RP_OK && (of->err == 0 || !of->errors)) {
        goto failed;
    }

create:

    if (cache->current >= cache->max) {
        rp_expire_old_cached_files(cache, 0, pool->log);
    }

    file = rp_alloc(sizeof(rp_cached_open_file_t), pool->log);

    if (file == NULL) {
        goto failed;
    }

    file->name = rp_alloc(name->len + 1, pool->log);

    if (file->name == NULL) {
        rp_free(file);
        file = NULL;
        goto failed;
    }

    rp_cpystrn(file->name, name->data, name->len + 1);

    file->node.key = hash;

    rp_rbtree_insert(&cache->rbtree, &file->node);

    cache->current++;

    file->uses = 1;
    file->count = 0;
    file->use_event = 0;
    file->event = NULL;

add_event:

    rp_open_file_add_event(cache, file, of, pool->log);

update:

    file->fd = of->fd;
    file->err = of->err;
#if (RP_HAVE_OPENAT)
    file->disable_symlinks = of->disable_symlinks;
    file->disable_symlinks_from = of->disable_symlinks_from;
#endif

    if (of->err == 0) {
        file->uniq = of->uniq;
        file->mtime = of->mtime;
        file->size = of->size;

        file->close = 0;

        file->is_dir = of->is_dir;
        file->is_file = of->is_file;
        file->is_link = of->is_link;
        file->is_exec = of->is_exec;
        file->is_directio = of->is_directio;

        if (!of->is_dir) {
            file->count++;
        }
    }

    file->created = now;

found:

    file->accessed = now;

    rp_queue_insert_head(&cache->expire_queue, &file->queue);

    rp_log_debug5(RP_LOG_DEBUG_CORE, pool->log, 0,
                   "cached open file: %s, fd:%d, c:%d, e:%d, u:%d",
                   file->name, file->fd, file->count, file->err, file->uses);

    if (of->err == 0) {

        if (!of->is_dir) {
            cln->handler = rp_open_file_cleanup;
            ofcln = cln->data;

            ofcln->cache = cache;
            ofcln->file = file;
            ofcln->min_uses = of->min_uses;
            ofcln->log = pool->log;
        }

        return RP_OK;
    }

    return RP_ERROR;

failed:

    if (file) {
        rp_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        if (file->count == 0) {

            if (file->fd != RP_INVALID_FILE) {
                if (rp_close_file(file->fd) == RP_FILE_ERROR) {
                    rp_log_error(RP_LOG_ALERT, pool->log, rp_errno,
                                  rp_close_file_n " \"%s\" failed",
                                  file->name);
                }
            }

            rp_free(file->name);
            rp_free(file);

        } else {
            file->close = 1;
        }
    }

    if (of->fd != RP_INVALID_FILE) {
        if (rp_close_file(of->fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, pool->log, rp_errno,
                          rp_close_file_n " \"%V\" failed", name);
        }
    }

    return RP_ERROR;
}


#if (RP_HAVE_OPENAT)

static rp_fd_t
rp_openat_file_owner(rp_fd_t at_fd, const u_char *name,
    rp_int_t mode, rp_int_t create, rp_int_t access, rp_log_t *log)
{
    rp_fd_t         fd;
    rp_err_t        err;
    rp_file_info_t  fi, atfi;

    /*
     * To allow symlinks with the same owner, use openat() (followed
     * by fstat()) and fstatat(AT_SYMLINK_NOFOLLOW), and then compare
     * uids between fstat() and fstatat().
     *
     * As there is a race between openat() and fstatat() we don't
     * know if openat() in fact opened symlink or not.  Therefore,
     * we have to compare uids even if fstatat() reports the opened
     * component isn't a symlink (as we don't know whether it was
     * symlink during openat() or not).
     */

    fd = rp_openat_file(at_fd, name, mode, create, access);

    if (fd == RP_INVALID_FILE) {
        return RP_INVALID_FILE;
    }

    if (rp_file_at_info(at_fd, name, &atfi, AT_SYMLINK_NOFOLLOW)
        == RP_FILE_ERROR)
    {
        err = rp_errno;
        goto failed;
    }

#if (RP_HAVE_O_PATH)
    if (rp_file_o_path_info(fd, &fi, log) == RP_ERROR) {
        err = rp_errno;
        goto failed;
    }
#else
    if (rp_fd_info(fd, &fi) == RP_FILE_ERROR) {
        err = rp_errno;
        goto failed;
    }
#endif

    if (fi.st_uid != atfi.st_uid) {
        err = RP_ELOOP;
        goto failed;
    }

    return fd;

failed:

    if (rp_close_file(fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_close_file_n " \"%s\" failed", name);
    }

    rp_set_errno(err);

    return RP_INVALID_FILE;
}


#if (RP_HAVE_O_PATH)

static rp_int_t
rp_file_o_path_info(rp_fd_t fd, rp_file_info_t *fi, rp_log_t *log)
{
    static rp_uint_t  use_fstat = 1;

    /*
     * In Linux 2.6.39 the O_PATH flag was introduced that allows to obtain
     * a descriptor without actually opening file or directory.  It requires
     * less permissions for path components, but till Linux 3.6 fstat() returns
     * EBADF on such descriptors, and fstatat() with the AT_EMPTY_PATH flag
     * should be used instead.
     *
     * Three scenarios are handled in this function:
     *
     * 1) The kernel is newer than 3.6 or fstat() with O_PATH support was
     *    backported by vendor.  Then fstat() is used.
     *
     * 2) The kernel is newer than 2.6.39 but older than 3.6.  In this case
     *    the first call of fstat() returns EBADF and we fallback to fstatat()
     *    with AT_EMPTY_PATH which was introduced at the same time as O_PATH.
     *
     * 3) The kernel is older than 2.6.39 but rap was build with O_PATH
     *    support.  Since descriptors are opened with O_PATH|O_RDONLY flags
     *    and O_PATH is ignored by the kernel then the O_RDONLY flag is
     *    actually used.  In this case fstat() just works.
     */

    if (use_fstat) {
        if (rp_fd_info(fd, fi) != RP_FILE_ERROR) {
            return RP_OK;
        }

        if (rp_errno != RP_EBADF) {
            return RP_ERROR;
        }

        rp_log_error(RP_LOG_NOTICE, log, 0,
                      "fstat(O_PATH) failed with EBADF, "
                      "switching to fstatat(AT_EMPTY_PATH)");

        use_fstat = 0;
    }

    if (rp_file_at_info(fd, "", fi, AT_EMPTY_PATH) != RP_FILE_ERROR) {
        return RP_OK;
    }

    return RP_ERROR;
}

#endif

#endif /* RP_HAVE_OPENAT */


static rp_fd_t
rp_open_file_wrapper(rp_str_t *name, rp_open_file_info_t *of,
    rp_int_t mode, rp_int_t create, rp_int_t access, rp_log_t *log)
{
    rp_fd_t  fd;

#if !(RP_HAVE_OPENAT)

    fd = rp_open_file(name->data, mode, create, access);

    if (fd == RP_INVALID_FILE) {
        of->err = rp_errno;
        of->failed = rp_open_file_n;
        return RP_INVALID_FILE;
    }

    return fd;

#else

    u_char           *p, *cp, *end;
    rp_fd_t          at_fd;
    rp_str_t         at_name;

    if (of->disable_symlinks == RP_DISABLE_SYMLINKS_OFF) {
        fd = rp_open_file(name->data, mode, create, access);

        if (fd == RP_INVALID_FILE) {
            of->err = rp_errno;
            of->failed = rp_open_file_n;
            return RP_INVALID_FILE;
        }

        return fd;
    }

    p = name->data;
    end = p + name->len;

    at_name = *name;

    if (of->disable_symlinks_from) {

        cp = p + of->disable_symlinks_from;

        *cp = '\0';

        at_fd = rp_open_file(p, RP_FILE_SEARCH|RP_FILE_NONBLOCK,
                              RP_FILE_OPEN, 0);

        *cp = '/';

        if (at_fd == RP_INVALID_FILE) {
            of->err = rp_errno;
            of->failed = rp_open_file_n;
            return RP_INVALID_FILE;
        }

        at_name.len = of->disable_symlinks_from;
        p = cp + 1;

    } else if (*p == '/') {

        at_fd = rp_open_file("/",
                              RP_FILE_SEARCH|RP_FILE_NONBLOCK,
                              RP_FILE_OPEN, 0);

        if (at_fd == RP_INVALID_FILE) {
            of->err = rp_errno;
            of->failed = rp_openat_file_n;
            return RP_INVALID_FILE;
        }

        at_name.len = 1;
        p++;

    } else {
        at_fd = RP_AT_FDCWD;
    }

    for ( ;; ) {
        cp = rp_strlchr(p, end, '/');
        if (cp == NULL) {
            break;
        }

        if (cp == p) {
            p++;
            continue;
        }

        *cp = '\0';

        if (of->disable_symlinks == RP_DISABLE_SYMLINKS_NOTOWNER) {
            fd = rp_openat_file_owner(at_fd, p,
                                       RP_FILE_SEARCH|RP_FILE_NONBLOCK,
                                       RP_FILE_OPEN, 0, log);

        } else {
            fd = rp_openat_file(at_fd, p,
                           RP_FILE_SEARCH|RP_FILE_NONBLOCK|RP_FILE_NOFOLLOW,
                           RP_FILE_OPEN, 0);
        }

        *cp = '/';

        if (fd == RP_INVALID_FILE) {
            of->err = rp_errno;
            of->failed = rp_openat_file_n;
            goto failed;
        }

        if (at_fd != RP_AT_FDCWD && rp_close_file(at_fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%V\" failed", &at_name);
        }

        p = cp + 1;
        at_fd = fd;
        at_name.len = cp - at_name.data;
    }

    if (p == end) {

        /*
         * If pathname ends with a trailing slash, assume the last path
         * component is a directory and reopen it with requested flags;
         * if not, fail with ENOTDIR as per POSIX.
         *
         * We cannot rely on O_DIRECTORY in the loop above to check
         * that the last path component is a directory because
         * O_DIRECTORY doesn't work on FreeBSD 8.  Fortunately, by
         * reopening a directory, we don't depend on it at all.
         */

        fd = rp_openat_file(at_fd, ".", mode, create, access);
        goto done;
    }

    if (of->disable_symlinks == RP_DISABLE_SYMLINKS_NOTOWNER
        && !(create & (RP_FILE_CREATE_OR_OPEN|RP_FILE_TRUNCATE)))
    {
        fd = rp_openat_file_owner(at_fd, p, mode, create, access, log);

    } else {
        fd = rp_openat_file(at_fd, p, mode|RP_FILE_NOFOLLOW, create, access);
    }

done:

    if (fd == RP_INVALID_FILE) {
        of->err = rp_errno;
        of->failed = rp_openat_file_n;
    }

failed:

    if (at_fd != RP_AT_FDCWD && rp_close_file(at_fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_close_file_n " \"%V\" failed", &at_name);
    }

    return fd;
#endif
}


static rp_int_t
rp_file_info_wrapper(rp_str_t *name, rp_open_file_info_t *of,
    rp_file_info_t *fi, rp_log_t *log)
{
    rp_int_t  rc;

#if !(RP_HAVE_OPENAT)

    rc = rp_file_info(name->data, fi);

    if (rc == RP_FILE_ERROR) {
        of->err = rp_errno;
        of->failed = rp_file_info_n;
        return RP_FILE_ERROR;
    }

    return rc;

#else

    rp_fd_t  fd;

    if (of->disable_symlinks == RP_DISABLE_SYMLINKS_OFF) {

        rc = rp_file_info(name->data, fi);

        if (rc == RP_FILE_ERROR) {
            of->err = rp_errno;
            of->failed = rp_file_info_n;
            return RP_FILE_ERROR;
        }

        return rc;
    }

    fd = rp_open_file_wrapper(name, of, RP_FILE_RDONLY|RP_FILE_NONBLOCK,
                               RP_FILE_OPEN, 0, log);

    if (fd == RP_INVALID_FILE) {
        return RP_FILE_ERROR;
    }

    rc = rp_fd_info(fd, fi);

    if (rc == RP_FILE_ERROR) {
        of->err = rp_errno;
        of->failed = rp_fd_info_n;
    }

    if (rp_close_file(fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_close_file_n " \"%V\" failed", name);
    }

    return rc;
#endif
}


static rp_int_t
rp_open_and_stat_file(rp_str_t *name, rp_open_file_info_t *of,
    rp_log_t *log)
{
    rp_fd_t         fd;
    rp_file_info_t  fi;

    if (of->fd != RP_INVALID_FILE) {

        if (rp_file_info_wrapper(name, of, &fi, log) == RP_FILE_ERROR) {
            of->fd = RP_INVALID_FILE;
            return RP_ERROR;
        }

        if (of->uniq == rp_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (rp_file_info_wrapper(name, of, &fi, log) == RP_FILE_ERROR) {
            of->fd = RP_INVALID_FILE;
            return RP_ERROR;
        }

        if (rp_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = rp_open_file_wrapper(name, of, RP_FILE_RDONLY|RP_FILE_NONBLOCK,
                                   RP_FILE_OPEN, 0, log);

    } else {
        fd = rp_open_file_wrapper(name, of, RP_FILE_APPEND,
                                   RP_FILE_CREATE_OR_OPEN,
                                   RP_FILE_DEFAULT_ACCESS, log);
    }

    if (fd == RP_INVALID_FILE) {
        of->fd = RP_INVALID_FILE;
        return RP_ERROR;
    }

    if (rp_fd_info(fd, &fi) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_CRIT, log, rp_errno,
                      rp_fd_info_n " \"%V\" failed", name);

        if (rp_close_file(fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%V\" failed", name);
        }

        of->fd = RP_INVALID_FILE;

        return RP_ERROR;
    }

    if (rp_is_dir(&fi)) {
        if (rp_close_file(fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%V\" failed", name);
        }

        of->fd = RP_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->read_ahead && rp_file_size(&fi) > RP_MIN_READ_AHEAD) {
            if (rp_read_ahead(fd, of->read_ahead) == RP_ERROR) {
                rp_log_error(RP_LOG_ALERT, log, rp_errno,
                              rp_read_ahead_n " \"%V\" failed", name);
            }
        }

        if (of->directio <= rp_file_size(&fi)) {
            if (rp_directio_on(fd) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_ALERT, log, rp_errno,
                              rp_directio_on_n " \"%V\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = rp_file_uniq(&fi);
    of->mtime = rp_file_mtime(&fi);
    of->size = rp_file_size(&fi);
    of->fs_size = rp_file_fs_size(&fi);
    of->is_dir = rp_is_dir(&fi);
    of->is_file = rp_is_file(&fi);
    of->is_link = rp_is_link(&fi);
    of->is_exec = rp_is_exec(&fi);

    return RP_OK;
}


/*
 * we ignore any possible event setting error and
 * fallback to usual periodic file retests
 */

static void
rp_open_file_add_event(rp_open_file_cache_t *cache,
    rp_cached_open_file_t *file, rp_open_file_info_t *of, rp_log_t *log)
{
    rp_open_file_cache_event_t  *fev;

    if (!(rp_event_flags & RP_USE_VNODE_EVENT)
        || !of->events
        || file->event
        || of->fd == RP_INVALID_FILE
        || file->uses < of->min_uses)
    {
        return;
    }

    file->use_event = 0;

    file->event = rp_calloc(sizeof(rp_event_t), log);
    if (file->event== NULL) {
        return;
    }

    fev = rp_alloc(sizeof(rp_open_file_cache_event_t), log);
    if (fev == NULL) {
        rp_free(file->event);
        file->event = NULL;
        return;
    }

    fev->fd = of->fd;
    fev->file = file;
    fev->cache = cache;

    file->event->handler = rp_open_file_cache_remove;
    file->event->data = fev;

    /*
     * although vnode event may be called while rp_cycle->poll
     * destruction, however, cleanup procedures are run before any
     * memory freeing and events will be canceled.
     */

    file->event->log = rp_cycle->log;

    if (rp_add_event(file->event, RP_VNODE_EVENT, RP_ONESHOT_EVENT)
        != RP_OK)
    {
        rp_free(file->event->data);
        rp_free(file->event);
        file->event = NULL;
        return;
    }

    /*
     * we do not set file->use_event here because there may be a race
     * condition: a file may be deleted between opening the file and
     * adding event, so we rely upon event notification only after
     * one file revalidation on next file access
     */

    return;
}


static void
rp_open_file_cleanup(void *data)
{
    rp_open_file_cache_cleanup_t  *c = data;

    c->file->count--;

    rp_close_cached_file(c->cache, c->file, c->min_uses, c->log);

    /* drop one or two expired open files */
    rp_expire_old_cached_files(c->cache, 1, c->log);
}


static void
rp_close_cached_file(rp_open_file_cache_t *cache,
    rp_cached_open_file_t *file, rp_uint_t min_uses, rp_log_t *log)
{
    rp_log_debug5(RP_LOG_DEBUG_CORE, log, 0,
                   "close cached open file: %s, fd:%d, c:%d, u:%d, %d",
                   file->name, file->fd, file->count, file->uses, file->close);

    if (!file->close) {

        file->accessed = rp_time();

        rp_queue_remove(&file->queue);

        rp_queue_insert_head(&cache->expire_queue, &file->queue);

        if (file->uses >= min_uses || file->count) {
            return;
        }
    }

    rp_open_file_del_event(file);

    if (file->count) {
        return;
    }

    if (file->fd != RP_INVALID_FILE) {

        if (rp_close_file(file->fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%s\" failed", file->name);
        }

        file->fd = RP_INVALID_FILE;
    }

    if (!file->close) {
        return;
    }

    rp_free(file->name);
    rp_free(file);
}


static void
rp_open_file_del_event(rp_cached_open_file_t *file)
{
    if (file->event == NULL) {
        return;
    }

    (void) rp_del_event(file->event, RP_VNODE_EVENT,
                         file->count ? RP_FLUSH_EVENT : RP_CLOSE_EVENT);

    rp_free(file->event->data);
    rp_free(file->event);
    file->event = NULL;
    file->use_event = 0;
}


static void
rp_expire_old_cached_files(rp_open_file_cache_t *cache, rp_uint_t n,
    rp_log_t *log)
{
    time_t                   now;
    rp_queue_t             *q;
    rp_cached_open_file_t  *file;

    now = rp_time();

    /*
     * n == 1 deletes one or two inactive files
     * n == 0 deletes least recently used file by force
     *        and one or two inactive files
     */

    while (n < 3) {

        if (rp_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = rp_queue_last(&cache->expire_queue);

        file = rp_queue_data(q, rp_cached_open_file_t, queue);

        if (n++ != 0 && now - file->accessed <= cache->inactive) {
            return;
        }

        rp_queue_remove(q);

        rp_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        rp_log_debug1(RP_LOG_DEBUG_CORE, log, 0,
                       "expire cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            rp_close_cached_file(cache, file, 0, log);

        } else {
            rp_free(file->name);
            rp_free(file);
        }
    }
}


static void
rp_open_file_cache_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t       **p;
    rp_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (rp_cached_open_file_t *) node;
            file_temp = (rp_cached_open_file_t *) temp;

            p = (rp_strcmp(file->name, file_temp->name) < 0)
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


static rp_cached_open_file_t *
rp_open_file_lookup(rp_open_file_cache_t *cache, rp_str_t *name,
    uint32_t hash)
{
    rp_int_t                rc;
    rp_rbtree_node_t       *node, *sentinel;
    rp_cached_open_file_t  *file;

    node = cache->rbtree.root;
    sentinel = cache->rbtree.sentinel;

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

        file = (rp_cached_open_file_t *) node;

        rc = rp_strcmp(name->data, file->name);

        if (rc == 0) {
            return file;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
rp_open_file_cache_remove(rp_event_t *ev)
{
    rp_cached_open_file_t       *file;
    rp_open_file_cache_event_t  *fev;

    fev = ev->data;
    file = fev->file;

    rp_queue_remove(&file->queue);

    rp_rbtree_delete(&fev->cache->rbtree, &file->node);

    fev->cache->current--;

    /* RP_ONESHOT_EVENT was already deleted */
    file->event = NULL;
    file->use_event = 0;

    file->close = 1;

    rp_close_cached_file(fev->cache, file, 0, ev->log);

    /* free memory only when fev->cache and fev->file are already not needed */

    rp_free(ev->data);
    rp_free(ev);
}
