
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_THREADS)
#include <rap_thread_pool.h>
static void rap_thread_read_handler(void *data, rap_log_t *log);
static void rap_thread_write_chain_to_file_handler(void *data, rap_log_t *log);
#endif

static rap_chain_t *rap_chain_to_iovec(rap_iovec_t *vec, rap_chain_t *cl);
static ssize_t rap_writev_file(rap_file_t *file, rap_iovec_t *vec,
    off_t offset);


#if (RAP_HAVE_FILE_AIO)

rap_uint_t  rap_file_aio = 1;

#endif


ssize_t
rap_read_file(rap_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;

    rap_log_debug4(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "read: %d, %p, %uz, %O", file->fd, buf, size, offset);

#if (RAP_HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                      "pread() \"%s\" failed", file->name.data);
        return RAP_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                      "read() \"%s\" failed", file->name.data);
        return RAP_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (RAP_THREADS)

typedef struct {
    rap_fd_t       fd;
    rap_uint_t     write;   /* unsigned  write:1; */

    u_char        *buf;
    size_t         size;
    rap_chain_t   *chain;
    off_t          offset;

    size_t         nbytes;
    rap_err_t      err;
} rap_thread_file_ctx_t;


ssize_t
rap_thread_read(rap_file_t *file, u_char *buf, size_t size, off_t offset,
    rap_pool_t *pool)
{
    rap_thread_task_t      *task;
    rap_thread_file_ctx_t  *ctx;

    rap_log_debug4(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "thread read: %d, %p, %uz, %O",
                   file->fd, buf, size, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = rap_thread_task_alloc(pool, sizeof(rap_thread_file_ctx_t));
        if (task == NULL) {
            return RAP_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->write) {
            rap_log_error(RAP_LOG_ALERT, file->log, 0,
                          "invalid thread call, read instead of write");
            return RAP_ERROR;
        }

        if (ctx->err) {
            rap_log_error(RAP_LOG_CRIT, file->log, ctx->err,
                          "pread() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        return ctx->nbytes;
    }

    task->handler = rap_thread_read_handler;

    ctx->write = 0;

    ctx->fd = file->fd;
    ctx->buf = buf;
    ctx->size = size;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_AGAIN;
}


#if (RAP_HAVE_PREAD)

static void
rap_thread_read_handler(void *data, rap_log_t *log)
{
    rap_thread_file_ctx_t *ctx = data;

    ssize_t  n;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, log, 0, "thread read handler");

    n = pread(ctx->fd, ctx->buf, ctx->size, ctx->offset);

    if (n == -1) {
        ctx->err = rap_errno;

    } else {
        ctx->nbytes = n;
        ctx->err = 0;
    }

#if 0
    rap_time_update();
#endif

    rap_log_debug4(RAP_LOG_DEBUG_CORE, log, 0,
                   "pread: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, ctx->offset);
}

#else

#error pread() is required!

#endif

#endif /* RAP_THREADS */


ssize_t
rap_write_file(rap_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t    n, written;
    rap_err_t  err;

    rap_log_debug4(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

    written = 0;

#if (RAP_HAVE_PWRITE)

    for ( ;; ) {
        n = pwrite(file->fd, buf + written, size, offset);

        if (n == -1) {
            err = rap_errno;

            if (err == RAP_EINTR) {
                rap_log_debug0(RAP_LOG_DEBUG_CORE, file->log, err,
                               "pwrite() was interrupted");
                continue;
            }

            rap_log_error(RAP_LOG_CRIT, file->log, err,
                          "pwrite() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        offset += n;
        size -= n;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->sys_offset = offset;
    }

    for ( ;; ) {
        n = write(file->fd, buf + written, size);

        if (n == -1) {
            err = rap_errno;

            if (err == RAP_EINTR) {
                rap_log_debug0(RAP_LOG_DEBUG_CORE, file->log, err,
                               "write() was interrupted");
                continue;
            }

            rap_log_error(RAP_LOG_CRIT, file->log, err,
                          "write() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->sys_offset += n;
        file->offset += n;
        written += n;

        if ((size_t) n == size) {
            return written;
        }

        size -= n;
    }
#endif
}


rap_fd_t
rap_open_tempfile(u_char *name, rap_uint_t persistent, rap_uint_t access)
{
    rap_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
              access ? access : 0600);

    if (fd != -1 && !persistent) {
        (void) unlink((const char *) name);
    }

    return fd;
}


ssize_t
rap_write_chain_to_file(rap_file_t *file, rap_chain_t *cl, off_t offset,
    rap_pool_t *pool)
{
    ssize_t        total, n;
    rap_iovec_t    vec;
    struct iovec   iovs[RAP_IOVS_PREALLOCATE];

    /* use pwrite() if there is the only buf in a chain */

    if (cl->next == NULL) {
        return rap_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    total = 0;

    vec.iovs = iovs;
    vec.nalloc = RAP_IOVS_PREALLOCATE;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = rap_chain_to_iovec(&vec, cl);

        /* use pwrite() if there is the only iovec buffer */

        if (vec.count == 1) {
            n = rap_write_file(file, (u_char *) iovs[0].iov_base,
                               iovs[0].iov_len, offset);

            if (n == RAP_ERROR) {
                return n;
            }

            return total + n;
        }

        n = rap_writev_file(file, &vec, offset);

        if (n == RAP_ERROR) {
            return n;
        }

        offset += n;
        total += n;

    } while (cl);

    return total;
}


static rap_chain_t *
rap_chain_to_iovec(rap_iovec_t *vec, rap_chain_t *cl)
{
    size_t         total, size;
    u_char        *prev;
    rap_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; cl; cl = cl->next) {

        if (rap_buf_special(cl->buf)) {
            continue;
        }

        size = cl->buf->last - cl->buf->pos;

        if (prev == cl->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) cl->buf->pos;
            iov->iov_len = size;
        }

        prev = cl->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return cl;
}


static ssize_t
rap_writev_file(rap_file_t *file, rap_iovec_t *vec, off_t offset)
{
    ssize_t    n;
    rap_err_t  err;

    rap_log_debug3(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "writev: %d, %uz, %O", file->fd, vec->size, offset);

#if (RAP_HAVE_PWRITEV)

eintr:

    n = pwritev(file->fd, vec->iovs, vec->count, offset);

    if (n == -1) {
        err = rap_errno;

        if (err == RAP_EINTR) {
            rap_log_debug0(RAP_LOG_DEBUG_CORE, file->log, err,
                           "pwritev() was interrupted");
            goto eintr;
        }

        rap_log_error(RAP_LOG_CRIT, file->log, err,
                      "pwritev() \"%s\" failed", file->name.data);
        return RAP_ERROR;
    }

    if ((size_t) n != vec->size) {
        rap_log_error(RAP_LOG_CRIT, file->log, 0,
                      "pwritev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return RAP_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->sys_offset = offset;
    }

eintr:

    n = writev(file->fd, vec->iovs, vec->count);

    if (n == -1) {
        err = rap_errno;

        if (err == RAP_EINTR) {
            rap_log_debug0(RAP_LOG_DEBUG_CORE, file->log, err,
                           "writev() was interrupted");
            goto eintr;
        }

        rap_log_error(RAP_LOG_CRIT, file->log, err,
                      "writev() \"%s\" failed", file->name.data);
        return RAP_ERROR;
    }

    if ((size_t) n != vec->size) {
        rap_log_error(RAP_LOG_CRIT, file->log, 0,
                      "writev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return RAP_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (RAP_THREADS)

ssize_t
rap_thread_write_chain_to_file(rap_file_t *file, rap_chain_t *cl, off_t offset,
    rap_pool_t *pool)
{
    rap_thread_task_t      *task;
    rap_thread_file_ctx_t  *ctx;

    rap_log_debug3(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "thread write chain: %d, %p, %O",
                   file->fd, cl, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = rap_thread_task_alloc(pool,
                                     sizeof(rap_thread_file_ctx_t));
        if (task == NULL) {
            return RAP_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (!ctx->write) {
            rap_log_error(RAP_LOG_ALERT, file->log, 0,
                          "invalid thread call, write instead of read");
            return RAP_ERROR;
        }

        if (ctx->err || ctx->nbytes == 0) {
            rap_log_error(RAP_LOG_CRIT, file->log, ctx->err,
                          "pwritev() \"%s\" failed", file->name.data);
            return RAP_ERROR;
        }

        file->offset += ctx->nbytes;
        return ctx->nbytes;
    }

    task->handler = rap_thread_write_chain_to_file_handler;

    ctx->write = 1;

    ctx->fd = file->fd;
    ctx->chain = cl;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_AGAIN;
}


static void
rap_thread_write_chain_to_file_handler(void *data, rap_log_t *log)
{
    rap_thread_file_ctx_t *ctx = data;

#if (RAP_HAVE_PWRITEV)

    off_t          offset;
    ssize_t        n;
    rap_err_t      err;
    rap_chain_t   *cl;
    rap_iovec_t    vec;
    struct iovec   iovs[RAP_IOVS_PREALLOCATE];

    vec.iovs = iovs;
    vec.nalloc = RAP_IOVS_PREALLOCATE;

    cl = ctx->chain;
    offset = ctx->offset;

    ctx->nbytes = 0;
    ctx->err = 0;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = rap_chain_to_iovec(&vec, cl);

eintr:

        n = pwritev(ctx->fd, iovs, vec.count, offset);

        if (n == -1) {
            err = rap_errno;

            if (err == RAP_EINTR) {
                rap_log_debug0(RAP_LOG_DEBUG_CORE, log, err,
                               "pwritev() was interrupted");
                goto eintr;
            }

            ctx->err = err;
            return;
        }

        if ((size_t) n != vec.size) {
            ctx->nbytes = 0;
            return;
        }

        ctx->nbytes += n;
        offset += n;
    } while (cl);

#else

    ctx->err = RAP_ENOSYS;
    return;

#endif
}

#endif /* RAP_THREADS */


rap_int_t
rap_set_file_time(u_char *name, rap_fd_t fd, time_t s)
{
    struct timeval  tv[2];

    tv[0].tv_sec = rap_time();
    tv[0].tv_usec = 0;
    tv[1].tv_sec = s;
    tv[1].tv_usec = 0;

    if (utimes((char *) name, tv) != -1) {
        return RAP_OK;
    }

    return RAP_ERROR;
}


rap_int_t
rap_create_file_mapping(rap_file_mapping_t *fm)
{
    fm->fd = rap_open_file(fm->name, RAP_FILE_RDWR, RAP_FILE_TRUNCATE,
                           RAP_FILE_DEFAULT_ACCESS);

    if (fm->fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_CRIT, fm->log, rap_errno,
                      rap_open_file_n " \"%s\" failed", fm->name);
        return RAP_ERROR;
    }

    if (ftruncate(fm->fd, fm->size) == -1) {
        rap_log_error(RAP_LOG_CRIT, fm->log, rap_errno,
                      "ftruncate() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    fm->fd, 0);
    if (fm->addr != MAP_FAILED) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_CRIT, fm->log, rap_errno,
                  "mmap(%uz) \"%s\" failed", fm->size, fm->name);

failed:

    if (rap_close_file(fm->fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, fm->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", fm->name);
    }

    return RAP_ERROR;
}


void
rap_close_file_mapping(rap_file_mapping_t *fm)
{
    if (munmap(fm->addr, fm->size) == -1) {
        rap_log_error(RAP_LOG_CRIT, fm->log, rap_errno,
                      "munmap(%uz) \"%s\" failed", fm->size, fm->name);
    }

    if (rap_close_file(fm->fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, fm->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", fm->name);
    }
}


rap_int_t
rap_open_dir(rap_str_t *name, rap_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return RAP_ERROR;
    }

    dir->valid_info = 0;

    return RAP_OK;
}


rap_int_t
rap_read_dir(rap_dir_t *dir)
{
    dir->de = readdir(dir->dir);

    if (dir->de) {
#if (RAP_HAVE_D_TYPE)
        dir->type = dir->de->d_type;
#else
        dir->type = 0;
#endif
        return RAP_OK;
    }

    return RAP_ERROR;
}


rap_int_t
rap_open_glob(rap_glob_t *gl)
{
    int  n;

    n = glob((char *) gl->pattern, 0, NULL, &gl->pglob);

    if (n == 0) {
        return RAP_OK;
    }

#ifdef GLOB_NOMATCH

    if (n == GLOB_NOMATCH && gl->test) {
        return RAP_OK;
    }

#endif

    return RAP_ERROR;
}


rap_int_t
rap_read_glob(rap_glob_t *gl, rap_str_t *name)
{
    size_t  count;

#ifdef GLOB_NOMATCH
    count = (size_t) gl->pglob.gl_pathc;
#else
    count = (size_t) gl->pglob.gl_matchc;
#endif

    if (gl->n < count) {

        name->len = (size_t) rap_strlen(gl->pglob.gl_pathv[gl->n]);
        name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
        gl->n++;

        return RAP_OK;
    }

    return RAP_DONE;
}


void
rap_close_glob(rap_glob_t *gl)
{
    globfree(&gl->pglob);
}


rap_err_t
rap_trylock_fd(rap_fd_t fd)
{
    struct flock  fl;

    rap_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return rap_errno;
    }

    return 0;
}


rap_err_t
rap_lock_fd(rap_fd_t fd)
{
    struct flock  fl;

    rap_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        return rap_errno;
    }

    return 0;
}


rap_err_t
rap_unlock_fd(rap_fd_t fd)
{
    struct flock  fl;

    rap_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return  rap_errno;
    }

    return 0;
}


#if (RAP_HAVE_POSIX_FADVISE) && !(RAP_HAVE_F_READAHEAD)

rap_int_t
rap_read_ahead(rap_fd_t fd, size_t n)
{
    int  err;

    err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    if (err == 0) {
        return 0;
    }

    rap_set_errno(err);
    return RAP_FILE_ERROR;
}

#endif


#if (RAP_HAVE_O_DIRECT)

rap_int_t
rap_directio_on(rap_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return RAP_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags | O_DIRECT);
}


rap_int_t
rap_directio_off(rap_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return RAP_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
}

#endif


#if (RAP_HAVE_STATFS)

size_t
rap_fs_bsize(u_char *name)
{
    struct statfs  fs;

    if (statfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_bsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_bsize;
}

#elif (RAP_HAVE_STATVFS)

size_t
rap_fs_bsize(u_char *name)
{
    struct statvfs  fs;

    if (statvfs((char *) name, &fs) == -1) {
        return 512;
    }

    if ((fs.f_frsize % 512) != 0) {
        return 512;
    }

    return (size_t) fs.f_frsize;
}

#else

size_t
rap_fs_bsize(u_char *name)
{
    return 512;
}

#endif
