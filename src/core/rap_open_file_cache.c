
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


/*
 * open file cache caches
 *    open file handles with stat() info;
 *    directories stat() info;
 *    files and directories errors: not found, access denied, etc.
 */


#define RAP_MIN_READ_AHEAD  (128 * 1024)


static void rap_open_file_cache_cleanup(void *data);
#if (RAP_HAVE_OPENAT)
static rap_fd_t rap_openat_file_owner(rap_fd_t at_fd, const u_char *name,
    rap_int_t mode, rap_int_t create, rap_int_t access, rap_log_t *log);
#if (RAP_HAVE_O_PATH)
static rap_int_t rap_file_o_path_info(rap_fd_t fd, rap_file_info_t *fi,
    rap_log_t *log);
#endif
#endif
static rap_fd_t rap_open_file_wrapper(rap_str_t *name,
    rap_open_file_info_t *of, rap_int_t mode, rap_int_t create,
    rap_int_t access, rap_log_t *log);
static rap_int_t rap_file_info_wrapper(rap_str_t *name,
    rap_open_file_info_t *of, rap_file_info_t *fi, rap_log_t *log);
static rap_int_t rap_open_and_stat_file(rap_str_t *name,
    rap_open_file_info_t *of, rap_log_t *log);
static void rap_open_file_add_event(rap_open_file_cache_t *cache,
    rap_cached_open_file_t *file, rap_open_file_info_t *of, rap_log_t *log);
static void rap_open_file_cleanup(void *data);
static void rap_close_cached_file(rap_open_file_cache_t *cache,
    rap_cached_open_file_t *file, rap_uint_t min_uses, rap_log_t *log);
static void rap_open_file_del_event(rap_cached_open_file_t *file);
static void rap_expire_old_cached_files(rap_open_file_cache_t *cache,
    rap_uint_t n, rap_log_t *log);
static void rap_open_file_cache_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);
static rap_cached_open_file_t *
    rap_open_file_lookup(rap_open_file_cache_t *cache, rap_str_t *name,
    uint32_t hash);
static void rap_open_file_cache_remove(rap_event_t *ev);


rap_open_file_cache_t *
rap_open_file_cache_init(rap_pool_t *pool, rap_uint_t max, time_t inactive)
{
    rap_pool_cleanup_t     *cln;
    rap_open_file_cache_t  *cache;

    cache = rap_palloc(pool, sizeof(rap_open_file_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    rap_rbtree_init(&cache->rbtree, &cache->sentinel,
                    rap_open_file_cache_rbtree_insert_value);

    rap_queue_init(&cache->expire_queue);

    cache->current = 0;
    cache->max = max;
    cache->inactive = inactive;

    cln = rap_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rap_open_file_cache_cleanup;
    cln->data = cache;

    return cache;
}


static void
rap_open_file_cache_cleanup(void *data)
{
    rap_open_file_cache_t  *cache = data;

    rap_queue_t             *q;
    rap_cached_open_file_t  *file;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                   "open file cache cleanup");

    for ( ;; ) {

        if (rap_queue_empty(&cache->expire_queue)) {
            break;
        }

        q = rap_queue_last(&cache->expire_queue);

        file = rap_queue_data(q, rap_cached_open_file_t, queue);

        rap_queue_remove(q);

        rap_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        rap_log_debug1(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                       "delete cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            file->count = 0;
            rap_close_cached_file(cache, file, 0, rap_cycle->log);

        } else {
            rap_free(file->name);
            rap_free(file);
        }
    }

    if (cache->current) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      "%ui items still left in open file cache",
                      cache->current);
    }

    if (cache->rbtree.root != cache->rbtree.sentinel) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      "rbtree still is not empty in open file cache");

    }
}


rap_int_t
rap_open_cached_file(rap_open_file_cache_t *cache, rap_str_t *name,
    rap_open_file_info_t *of, rap_pool_t *pool)
{
    time_t                          now;
    uint32_t                        hash;
    rap_int_t                       rc;
    rap_file_info_t                 fi;
    rap_pool_cleanup_t             *cln;
    rap_cached_open_file_t         *file;
    rap_pool_cleanup_file_t        *clnf;
    rap_open_file_cache_cleanup_t  *ofcln;

    of->fd = RAP_INVALID_FILE;
    of->err = 0;

    if (cache == NULL) {

        if (of->test_only) {

            if (rap_file_info_wrapper(name, of, &fi, pool->log)
                == RAP_FILE_ERROR)
            {
                return RAP_ERROR;
            }

            of->uniq = rap_file_uniq(&fi);
            of->mtime = rap_file_mtime(&fi);
            of->size = rap_file_size(&fi);
            of->fs_size = rap_file_fs_size(&fi);
            of->is_dir = rap_is_dir(&fi);
            of->is_file = rap_is_file(&fi);
            of->is_link = rap_is_link(&fi);
            of->is_exec = rap_is_exec(&fi);

            return RAP_OK;
        }

        cln = rap_pool_cleanup_add(pool, sizeof(rap_pool_cleanup_file_t));
        if (cln == NULL) {
            return RAP_ERROR;
        }

        rc = rap_open_and_stat_file(name, of, pool->log);

        if (rc == RAP_OK && !of->is_dir) {
            cln->handler = rap_pool_cleanup_file;
            clnf = cln->data;

            clnf->fd = of->fd;
            clnf->name = name->data;
            clnf->log = pool->log;
        }

        return rc;
    }

    cln = rap_pool_cleanup_add(pool, sizeof(rap_open_file_cache_cleanup_t));
    if (cln == NULL) {
        return RAP_ERROR;
    }

    now = rap_time();

    hash = rap_crc32_long(name->data, name->len);

    file = rap_open_file_lookup(cache, name, hash);

    if (file) {

        file->uses++;

        rap_queue_remove(&file->queue);

        if (file->fd == RAP_INVALID_FILE && file->err == 0 && !file->is_dir) {

            /* file was not used often enough to keep open */

            rc = rap_open_and_stat_file(name, of, pool->log);

            if (rc != RAP_OK && (of->err == 0 || !of->errors)) {
                goto failed;
            }

            goto add_event;
        }

        if (file->use_event
            || (file->event == NULL
                && (of->uniq == 0 || of->uniq == file->uniq)
                && now - file->created < of->valid
#if (RAP_HAVE_OPENAT)
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
                    rap_open_file_add_event(cache, file, of, pool->log);
                }

            } else {
                of->err = file->err;
#if (RAP_HAVE_OPENAT)
                of->failed = file->disable_symlinks ? rap_openat_file_n
                                                    : rap_open_file_n;
#else
                of->failed = rap_open_file_n;
#endif
            }

            goto found;
        }

        rap_log_debug4(RAP_LOG_DEBUG_CORE, pool->log, 0,
                       "retest open file: %s, fd:%d, c:%d, e:%d",
                       file->name, file->fd, file->count, file->err);

        if (file->is_dir) {

            /*
             * chances that directory became file are very small
             * so test_dir flag allows to use a single syscall
             * in rap_file_info() instead of three syscalls
             */

            of->test_dir = 1;
        }

        of->fd = file->fd;
        of->uniq = file->uniq;

        rc = rap_open_and_stat_file(name, of, pool->log);

        if (rc != RAP_OK && (of->err == 0 || !of->errors)) {
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

            rap_open_file_del_event(file);

            if (rap_close_file(file->fd) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_ALERT, pool->log, rap_errno,
                              rap_close_file_n " \"%V\" failed", name);
            }

            goto add_event;
        }

        rap_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        file->close = 1;

        goto create;
    }

    /* not found */

    rc = rap_open_and_stat_file(name, of, pool->log);

    if (rc != RAP_OK && (of->err == 0 || !of->errors)) {
        goto failed;
    }

create:

    if (cache->current >= cache->max) {
        rap_expire_old_cached_files(cache, 0, pool->log);
    }

    file = rap_alloc(sizeof(rap_cached_open_file_t), pool->log);

    if (file == NULL) {
        goto failed;
    }

    file->name = rap_alloc(name->len + 1, pool->log);

    if (file->name == NULL) {
        rap_free(file);
        file = NULL;
        goto failed;
    }

    rap_cpystrn(file->name, name->data, name->len + 1);

    file->node.key = hash;

    rap_rbtree_insert(&cache->rbtree, &file->node);

    cache->current++;

    file->uses = 1;
    file->count = 0;
    file->use_event = 0;
    file->event = NULL;

add_event:

    rap_open_file_add_event(cache, file, of, pool->log);

update:

    file->fd = of->fd;
    file->err = of->err;
#if (RAP_HAVE_OPENAT)
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

    rap_queue_insert_head(&cache->expire_queue, &file->queue);

    rap_log_debug5(RAP_LOG_DEBUG_CORE, pool->log, 0,
                   "cached open file: %s, fd:%d, c:%d, e:%d, u:%d",
                   file->name, file->fd, file->count, file->err, file->uses);

    if (of->err == 0) {

        if (!of->is_dir) {
            cln->handler = rap_open_file_cleanup;
            ofcln = cln->data;

            ofcln->cache = cache;
            ofcln->file = file;
            ofcln->min_uses = of->min_uses;
            ofcln->log = pool->log;
        }

        return RAP_OK;
    }

    return RAP_ERROR;

failed:

    if (file) {
        rap_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        if (file->count == 0) {

            if (file->fd != RAP_INVALID_FILE) {
                if (rap_close_file(file->fd) == RAP_FILE_ERROR) {
                    rap_log_error(RAP_LOG_ALERT, pool->log, rap_errno,
                                  rap_close_file_n " \"%s\" failed",
                                  file->name);
                }
            }

            rap_free(file->name);
            rap_free(file);

        } else {
            file->close = 1;
        }
    }

    if (of->fd != RAP_INVALID_FILE) {
        if (rap_close_file(of->fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, pool->log, rap_errno,
                          rap_close_file_n " \"%V\" failed", name);
        }
    }

    return RAP_ERROR;
}


#if (RAP_HAVE_OPENAT)

static rap_fd_t
rap_openat_file_owner(rap_fd_t at_fd, const u_char *name,
    rap_int_t mode, rap_int_t create, rap_int_t access, rap_log_t *log)
{
    rap_fd_t         fd;
    rap_err_t        err;
    rap_file_info_t  fi, atfi;

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

    fd = rap_openat_file(at_fd, name, mode, create, access);

    if (fd == RAP_INVALID_FILE) {
        return RAP_INVALID_FILE;
    }

    if (rap_file_at_info(at_fd, name, &atfi, AT_SYMLINK_NOFOLLOW)
        == RAP_FILE_ERROR)
    {
        err = rap_errno;
        goto failed;
    }

#if (RAP_HAVE_O_PATH)
    if (rap_file_o_path_info(fd, &fi, log) == RAP_ERROR) {
        err = rap_errno;
        goto failed;
    }
#else
    if (rap_fd_info(fd, &fi) == RAP_FILE_ERROR) {
        err = rap_errno;
        goto failed;
    }
#endif

    if (fi.st_uid != atfi.st_uid) {
        err = RAP_ELOOP;
        goto failed;
    }

    return fd;

failed:

    if (rap_close_file(fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_close_file_n " \"%s\" failed", name);
    }

    rap_set_errno(err);

    return RAP_INVALID_FILE;
}


#if (RAP_HAVE_O_PATH)

static rap_int_t
rap_file_o_path_info(rap_fd_t fd, rap_file_info_t *fi, rap_log_t *log)
{
    static rap_uint_t  use_fstat = 1;

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
        if (rap_fd_info(fd, fi) != RAP_FILE_ERROR) {
            return RAP_OK;
        }

        if (rap_errno != RAP_EBADF) {
            return RAP_ERROR;
        }

        rap_log_error(RAP_LOG_NOTICE, log, 0,
                      "fstat(O_PATH) failed with EBADF, "
                      "switching to fstatat(AT_EMPTY_PATH)");

        use_fstat = 0;
    }

    if (rap_file_at_info(fd, "", fi, AT_EMPTY_PATH) != RAP_FILE_ERROR) {
        return RAP_OK;
    }

    return RAP_ERROR;
}

#endif

#endif /* RAP_HAVE_OPENAT */


static rap_fd_t
rap_open_file_wrapper(rap_str_t *name, rap_open_file_info_t *of,
    rap_int_t mode, rap_int_t create, rap_int_t access, rap_log_t *log)
{
    rap_fd_t  fd;

#if !(RAP_HAVE_OPENAT)

    fd = rap_open_file(name->data, mode, create, access);

    if (fd == RAP_INVALID_FILE) {
        of->err = rap_errno;
        of->failed = rap_open_file_n;
        return RAP_INVALID_FILE;
    }

    return fd;

#else

    u_char           *p, *cp, *end;
    rap_fd_t          at_fd;
    rap_str_t         at_name;

    if (of->disable_symlinks == RAP_DISABLE_SYMLINKS_OFF) {
        fd = rap_open_file(name->data, mode, create, access);

        if (fd == RAP_INVALID_FILE) {
            of->err = rap_errno;
            of->failed = rap_open_file_n;
            return RAP_INVALID_FILE;
        }

        return fd;
    }

    p = name->data;
    end = p + name->len;

    at_name = *name;

    if (of->disable_symlinks_from) {

        cp = p + of->disable_symlinks_from;

        *cp = '\0';

        at_fd = rap_open_file(p, RAP_FILE_SEARCH|RAP_FILE_NONBLOCK,
                              RAP_FILE_OPEN, 0);

        *cp = '/';

        if (at_fd == RAP_INVALID_FILE) {
            of->err = rap_errno;
            of->failed = rap_open_file_n;
            return RAP_INVALID_FILE;
        }

        at_name.len = of->disable_symlinks_from;
        p = cp + 1;

    } else if (*p == '/') {

        at_fd = rap_open_file("/",
                              RAP_FILE_SEARCH|RAP_FILE_NONBLOCK,
                              RAP_FILE_OPEN, 0);

        if (at_fd == RAP_INVALID_FILE) {
            of->err = rap_errno;
            of->failed = rap_openat_file_n;
            return RAP_INVALID_FILE;
        }

        at_name.len = 1;
        p++;

    } else {
        at_fd = RAP_AT_FDCWD;
    }

    for ( ;; ) {
        cp = rap_strlchr(p, end, '/');
        if (cp == NULL) {
            break;
        }

        if (cp == p) {
            p++;
            continue;
        }

        *cp = '\0';

        if (of->disable_symlinks == RAP_DISABLE_SYMLINKS_NOTOWNER) {
            fd = rap_openat_file_owner(at_fd, p,
                                       RAP_FILE_SEARCH|RAP_FILE_NONBLOCK,
                                       RAP_FILE_OPEN, 0, log);

        } else {
            fd = rap_openat_file(at_fd, p,
                           RAP_FILE_SEARCH|RAP_FILE_NONBLOCK|RAP_FILE_NOFOLLOW,
                           RAP_FILE_OPEN, 0);
        }

        *cp = '/';

        if (fd == RAP_INVALID_FILE) {
            of->err = rap_errno;
            of->failed = rap_openat_file_n;
            goto failed;
        }

        if (at_fd != RAP_AT_FDCWD && rap_close_file(at_fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          rap_close_file_n " \"%V\" failed", &at_name);
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

        fd = rap_openat_file(at_fd, ".", mode, create, access);
        goto done;
    }

    if (of->disable_symlinks == RAP_DISABLE_SYMLINKS_NOTOWNER
        && !(create & (RAP_FILE_CREATE_OR_OPEN|RAP_FILE_TRUNCATE)))
    {
        fd = rap_openat_file_owner(at_fd, p, mode, create, access, log);

    } else {
        fd = rap_openat_file(at_fd, p, mode|RAP_FILE_NOFOLLOW, create, access);
    }

done:

    if (fd == RAP_INVALID_FILE) {
        of->err = rap_errno;
        of->failed = rap_openat_file_n;
    }

failed:

    if (at_fd != RAP_AT_FDCWD && rap_close_file(at_fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_close_file_n " \"%V\" failed", &at_name);
    }

    return fd;
#endif
}


static rap_int_t
rap_file_info_wrapper(rap_str_t *name, rap_open_file_info_t *of,
    rap_file_info_t *fi, rap_log_t *log)
{
    rap_int_t  rc;

#if !(RAP_HAVE_OPENAT)

    rc = rap_file_info(name->data, fi);

    if (rc == RAP_FILE_ERROR) {
        of->err = rap_errno;
        of->failed = rap_file_info_n;
        return RAP_FILE_ERROR;
    }

    return rc;

#else

    rap_fd_t  fd;

    if (of->disable_symlinks == RAP_DISABLE_SYMLINKS_OFF) {

        rc = rap_file_info(name->data, fi);

        if (rc == RAP_FILE_ERROR) {
            of->err = rap_errno;
            of->failed = rap_file_info_n;
            return RAP_FILE_ERROR;
        }

        return rc;
    }

    fd = rap_open_file_wrapper(name, of, RAP_FILE_RDONLY|RAP_FILE_NONBLOCK,
                               RAP_FILE_OPEN, 0, log);

    if (fd == RAP_INVALID_FILE) {
        return RAP_FILE_ERROR;
    }

    rc = rap_fd_info(fd, fi);

    if (rc == RAP_FILE_ERROR) {
        of->err = rap_errno;
        of->failed = rap_fd_info_n;
    }

    if (rap_close_file(fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_close_file_n " \"%V\" failed", name);
    }

    return rc;
#endif
}


static rap_int_t
rap_open_and_stat_file(rap_str_t *name, rap_open_file_info_t *of,
    rap_log_t *log)
{
    rap_fd_t         fd;
    rap_file_info_t  fi;

    if (of->fd != RAP_INVALID_FILE) {

        if (rap_file_info_wrapper(name, of, &fi, log) == RAP_FILE_ERROR) {
            of->fd = RAP_INVALID_FILE;
            return RAP_ERROR;
        }

        if (of->uniq == rap_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (rap_file_info_wrapper(name, of, &fi, log) == RAP_FILE_ERROR) {
            of->fd = RAP_INVALID_FILE;
            return RAP_ERROR;
        }

        if (rap_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = rap_open_file_wrapper(name, of, RAP_FILE_RDONLY|RAP_FILE_NONBLOCK,
                                   RAP_FILE_OPEN, 0, log);

    } else {
        fd = rap_open_file_wrapper(name, of, RAP_FILE_APPEND,
                                   RAP_FILE_CREATE_OR_OPEN,
                                   RAP_FILE_DEFAULT_ACCESS, log);
    }

    if (fd == RAP_INVALID_FILE) {
        of->fd = RAP_INVALID_FILE;
        return RAP_ERROR;
    }

    if (rap_fd_info(fd, &fi) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_CRIT, log, rap_errno,
                      rap_fd_info_n " \"%V\" failed", name);

        if (rap_close_file(fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          rap_close_file_n " \"%V\" failed", name);
        }

        of->fd = RAP_INVALID_FILE;

        return RAP_ERROR;
    }

    if (rap_is_dir(&fi)) {
        if (rap_close_file(fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          rap_close_file_n " \"%V\" failed", name);
        }

        of->fd = RAP_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->read_ahead && rap_file_size(&fi) > RAP_MIN_READ_AHEAD) {
            if (rap_read_ahead(fd, of->read_ahead) == RAP_ERROR) {
                rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                              rap_read_ahead_n " \"%V\" failed", name);
            }
        }

        if (of->directio <= rap_file_size(&fi)) {
            if (rap_directio_on(fd) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                              rap_directio_on_n " \"%V\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = rap_file_uniq(&fi);
    of->mtime = rap_file_mtime(&fi);
    of->size = rap_file_size(&fi);
    of->fs_size = rap_file_fs_size(&fi);
    of->is_dir = rap_is_dir(&fi);
    of->is_file = rap_is_file(&fi);
    of->is_link = rap_is_link(&fi);
    of->is_exec = rap_is_exec(&fi);

    return RAP_OK;
}


/*
 * we ignore any possible event setting error and
 * fallback to usual periodic file retests
 */

static void
rap_open_file_add_event(rap_open_file_cache_t *cache,
    rap_cached_open_file_t *file, rap_open_file_info_t *of, rap_log_t *log)
{
    rap_open_file_cache_event_t  *fev;

    if (!(rap_event_flags & RAP_USE_VNODE_EVENT)
        || !of->events
        || file->event
        || of->fd == RAP_INVALID_FILE
        || file->uses < of->min_uses)
    {
        return;
    }

    file->use_event = 0;

    file->event = rap_calloc(sizeof(rap_event_t), log);
    if (file->event== NULL) {
        return;
    }

    fev = rap_alloc(sizeof(rap_open_file_cache_event_t), log);
    if (fev == NULL) {
        rap_free(file->event);
        file->event = NULL;
        return;
    }

    fev->fd = of->fd;
    fev->file = file;
    fev->cache = cache;

    file->event->handler = rap_open_file_cache_remove;
    file->event->data = fev;

    /*
     * although vnode event may be called while rap_cycle->poll
     * destruction, however, cleanup procedures are run before any
     * memory freeing and events will be canceled.
     */

    file->event->log = rap_cycle->log;

    if (rap_add_event(file->event, RAP_VNODE_EVENT, RAP_ONESHOT_EVENT)
        != RAP_OK)
    {
        rap_free(file->event->data);
        rap_free(file->event);
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
rap_open_file_cleanup(void *data)
{
    rap_open_file_cache_cleanup_t  *c = data;

    c->file->count--;

    rap_close_cached_file(c->cache, c->file, c->min_uses, c->log);

    /* drop one or two expired open files */
    rap_expire_old_cached_files(c->cache, 1, c->log);
}


static void
rap_close_cached_file(rap_open_file_cache_t *cache,
    rap_cached_open_file_t *file, rap_uint_t min_uses, rap_log_t *log)
{
    rap_log_debug5(RAP_LOG_DEBUG_CORE, log, 0,
                   "close cached open file: %s, fd:%d, c:%d, u:%d, %d",
                   file->name, file->fd, file->count, file->uses, file->close);

    if (!file->close) {

        file->accessed = rap_time();

        rap_queue_remove(&file->queue);

        rap_queue_insert_head(&cache->expire_queue, &file->queue);

        if (file->uses >= min_uses || file->count) {
            return;
        }
    }

    rap_open_file_del_event(file);

    if (file->count) {
        return;
    }

    if (file->fd != RAP_INVALID_FILE) {

        if (rap_close_file(file->fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          rap_close_file_n " \"%s\" failed", file->name);
        }

        file->fd = RAP_INVALID_FILE;
    }

    if (!file->close) {
        return;
    }

    rap_free(file->name);
    rap_free(file);
}


static void
rap_open_file_del_event(rap_cached_open_file_t *file)
{
    if (file->event == NULL) {
        return;
    }

    (void) rap_del_event(file->event, RAP_VNODE_EVENT,
                         file->count ? RAP_FLUSH_EVENT : RAP_CLOSE_EVENT);

    rap_free(file->event->data);
    rap_free(file->event);
    file->event = NULL;
    file->use_event = 0;
}


static void
rap_expire_old_cached_files(rap_open_file_cache_t *cache, rap_uint_t n,
    rap_log_t *log)
{
    time_t                   now;
    rap_queue_t             *q;
    rap_cached_open_file_t  *file;

    now = rap_time();

    /*
     * n == 1 deletes one or two inactive files
     * n == 0 deletes least recently used file by force
     *        and one or two inactive files
     */

    while (n < 3) {

        if (rap_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = rap_queue_last(&cache->expire_queue);

        file = rap_queue_data(q, rap_cached_open_file_t, queue);

        if (n++ != 0 && now - file->accessed <= cache->inactive) {
            return;
        }

        rap_queue_remove(q);

        rap_rbtree_delete(&cache->rbtree, &file->node);

        cache->current--;

        rap_log_debug1(RAP_LOG_DEBUG_CORE, log, 0,
                       "expire cached open file: %s", file->name);

        if (!file->err && !file->is_dir) {
            file->close = 1;
            rap_close_cached_file(cache, file, 0, log);

        } else {
            rap_free(file->name);
            rap_free(file);
        }
    }
}


static void
rap_open_file_cache_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t       **p;
    rap_cached_open_file_t    *file, *file_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            file = (rap_cached_open_file_t *) node;
            file_temp = (rap_cached_open_file_t *) temp;

            p = (rap_strcmp(file->name, file_temp->name) < 0)
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


static rap_cached_open_file_t *
rap_open_file_lookup(rap_open_file_cache_t *cache, rap_str_t *name,
    uint32_t hash)
{
    rap_int_t                rc;
    rap_rbtree_node_t       *node, *sentinel;
    rap_cached_open_file_t  *file;

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

        file = (rap_cached_open_file_t *) node;

        rc = rap_strcmp(name->data, file->name);

        if (rc == 0) {
            return file;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
rap_open_file_cache_remove(rap_event_t *ev)
{
    rap_cached_open_file_t       *file;
    rap_open_file_cache_event_t  *fev;

    fev = ev->data;
    file = fev->file;

    rap_queue_remove(&file->queue);

    rap_rbtree_delete(&fev->cache->rbtree, &file->node);

    fev->cache->current--;

    /* RAP_ONESHOT_EVENT was already deleted */
    file->event = NULL;
    file->use_event = 0;

    file->close = 1;

    rap_close_cached_file(fev->cache, file, 0, ev->log);

    /* free memory only when fev->cache and fev->file are already not needed */

    rap_free(ev->data);
    rap_free(ev);
}
