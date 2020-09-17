
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_THREADS)
#include <rp_thread_pool.h>
static void rp_thread_read_handler(void *data, rp_log_t *log);
static void rp_thread_write_chain_to_file_handler(void *data, rp_log_t *log);
#endif

static rp_chain_t *rp_chain_to_iovec(rp_iovec_t *vec, rp_chain_t *cl);
static ssize_t rp_writev_file(rp_file_t *file, rp_iovec_t *vec,
    off_t offset);


#if (RP_HAVE_FILE_AIO)

rp_uint_t  rp_file_aio = 1;

#endif


ssize_t
rp_read_file(rp_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t  n;

    rp_log_debug4(RP_LOG_DEBUG_CORE, file->log, 0,
                   "read: %d, %p, %uz, %O", file->fd, buf, size, offset);

#if (RP_HAVE_PREAD)

    n = pread(file->fd, buf, size, offset);

    if (n == -1) {
        rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                      "pread() \"%s\" failed", file->name.data);
        return RP_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RP_ERROR;
        }

        file->sys_offset = offset;
    }

    n = read(file->fd, buf, size);

    if (n == -1) {
        rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                      "read() \"%s\" failed", file->name.data);
        return RP_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (RP_THREADS)

typedef struct {
    rp_fd_t       fd;
    rp_uint_t     write;   /* unsigned  write:1; */

    u_char        *buf;
    size_t         size;
    rp_chain_t   *chain;
    off_t          offset;

    size_t         nbytes;
    rp_err_t      err;
} rp_thread_file_ctx_t;


ssize_t
rp_thread_read(rp_file_t *file, u_char *buf, size_t size, off_t offset,
    rp_pool_t *pool)
{
    rp_thread_task_t      *task;
    rp_thread_file_ctx_t  *ctx;

    rp_log_debug4(RP_LOG_DEBUG_CORE, file->log, 0,
                   "thread read: %d, %p, %uz, %O",
                   file->fd, buf, size, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = rp_thread_task_alloc(pool, sizeof(rp_thread_file_ctx_t));
        if (task == NULL) {
            return RP_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->write) {
            rp_log_error(RP_LOG_ALERT, file->log, 0,
                          "invalid thread call, read instead of write");
            return RP_ERROR;
        }

        if (ctx->err) {
            rp_log_error(RP_LOG_CRIT, file->log, ctx->err,
                          "pread() \"%s\" failed", file->name.data);
            return RP_ERROR;
        }

        return ctx->nbytes;
    }

    task->handler = rp_thread_read_handler;

    ctx->write = 0;

    ctx->fd = file->fd;
    ctx->buf = buf;
    ctx->size = size;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != RP_OK) {
        return RP_ERROR;
    }

    return RP_AGAIN;
}


#if (RP_HAVE_PREAD)

static void
rp_thread_read_handler(void *data, rp_log_t *log)
{
    rp_thread_file_ctx_t *ctx = data;

    ssize_t  n;

    rp_log_debug0(RP_LOG_DEBUG_CORE, log, 0, "thread read handler");

    n = pread(ctx->fd, ctx->buf, ctx->size, ctx->offset);

    if (n == -1) {
        ctx->err = rp_errno;

    } else {
        ctx->nbytes = n;
        ctx->err = 0;
    }

#if 0
    rp_time_update();
#endif

    rp_log_debug4(RP_LOG_DEBUG_CORE, log, 0,
                   "pread: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, ctx->offset);
}

#else

#error pread() is required!

#endif

#endif /* RP_THREADS */


ssize_t
rp_write_file(rp_file_t *file, u_char *buf, size_t size, off_t offset)
{
    ssize_t    n, written;
    rp_err_t  err;

    rp_log_debug4(RP_LOG_DEBUG_CORE, file->log, 0,
                   "write: %d, %p, %uz, %O", file->fd, buf, size, offset);

    written = 0;

#if (RP_HAVE_PWRITE)

    for ( ;; ) {
        n = pwrite(file->fd, buf + written, size, offset);

        if (n == -1) {
            err = rp_errno;

            if (err == RP_EINTR) {
                rp_log_debug0(RP_LOG_DEBUG_CORE, file->log, err,
                               "pwrite() was interrupted");
                continue;
            }

            rp_log_error(RP_LOG_CRIT, file->log, err,
                          "pwrite() \"%s\" failed", file->name.data);
            return RP_ERROR;
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
            rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RP_ERROR;
        }

        file->sys_offset = offset;
    }

    for ( ;; ) {
        n = write(file->fd, buf + written, size);

        if (n == -1) {
            err = rp_errno;

            if (err == RP_EINTR) {
                rp_log_debug0(RP_LOG_DEBUG_CORE, file->log, err,
                               "write() was interrupted");
                continue;
            }

            rp_log_error(RP_LOG_CRIT, file->log, err,
                          "write() \"%s\" failed", file->name.data);
            return RP_ERROR;
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


rp_fd_t
rp_open_tempfile(u_char *name, rp_uint_t persistent, rp_uint_t access)
{
    rp_fd_t  fd;

    fd = open((const char *) name, O_CREAT|O_EXCL|O_RDWR,
              access ? access : 0600);

    if (fd != -1 && !persistent) {
        (void) unlink((const char *) name);
    }

    return fd;
}


ssize_t
rp_write_chain_to_file(rp_file_t *file, rp_chain_t *cl, off_t offset,
    rp_pool_t *pool)
{
    ssize_t        total, n;
    rp_iovec_t    vec;
    struct iovec   iovs[RP_IOVS_PREALLOCATE];

    /* use pwrite() if there is the only buf in a chain */

    if (cl->next == NULL) {
        return rp_write_file(file, cl->buf->pos,
                              (size_t) (cl->buf->last - cl->buf->pos),
                              offset);
    }

    total = 0;

    vec.iovs = iovs;
    vec.nalloc = RP_IOVS_PREALLOCATE;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = rp_chain_to_iovec(&vec, cl);

        /* use pwrite() if there is the only iovec buffer */

        if (vec.count == 1) {
            n = rp_write_file(file, (u_char *) iovs[0].iov_base,
                               iovs[0].iov_len, offset);

            if (n == RP_ERROR) {
                return n;
            }

            return total + n;
        }

        n = rp_writev_file(file, &vec, offset);

        if (n == RP_ERROR) {
            return n;
        }

        offset += n;
        total += n;

    } while (cl);

    return total;
}


static rp_chain_t *
rp_chain_to_iovec(rp_iovec_t *vec, rp_chain_t *cl)
{
    size_t         total, size;
    u_char        *prev;
    rp_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; cl; cl = cl->next) {

        if (rp_buf_special(cl->buf)) {
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
rp_writev_file(rp_file_t *file, rp_iovec_t *vec, off_t offset)
{
    ssize_t    n;
    rp_err_t  err;

    rp_log_debug3(RP_LOG_DEBUG_CORE, file->log, 0,
                   "writev: %d, %uz, %O", file->fd, vec->size, offset);

#if (RP_HAVE_PWRITEV)

eintr:

    n = pwritev(file->fd, vec->iovs, vec->count, offset);

    if (n == -1) {
        err = rp_errno;

        if (err == RP_EINTR) {
            rp_log_debug0(RP_LOG_DEBUG_CORE, file->log, err,
                           "pwritev() was interrupted");
            goto eintr;
        }

        rp_log_error(RP_LOG_CRIT, file->log, err,
                      "pwritev() \"%s\" failed", file->name.data);
        return RP_ERROR;
    }

    if ((size_t) n != vec->size) {
        rp_log_error(RP_LOG_CRIT, file->log, 0,
                      "pwritev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return RP_ERROR;
    }

#else

    if (file->sys_offset != offset) {
        if (lseek(file->fd, offset, SEEK_SET) == -1) {
            rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                          "lseek() \"%s\" failed", file->name.data);
            return RP_ERROR;
        }

        file->sys_offset = offset;
    }

eintr:

    n = writev(file->fd, vec->iovs, vec->count);

    if (n == -1) {
        err = rp_errno;

        if (err == RP_EINTR) {
            rp_log_debug0(RP_LOG_DEBUG_CORE, file->log, err,
                           "writev() was interrupted");
            goto eintr;
        }

        rp_log_error(RP_LOG_CRIT, file->log, err,
                      "writev() \"%s\" failed", file->name.data);
        return RP_ERROR;
    }

    if ((size_t) n != vec->size) {
        rp_log_error(RP_LOG_CRIT, file->log, 0,
                      "writev() \"%s\" has written only %z of %uz",
                      file->name.data, n, vec->size);
        return RP_ERROR;
    }

    file->sys_offset += n;

#endif

    file->offset += n;

    return n;
}


#if (RP_THREADS)

ssize_t
rp_thread_write_chain_to_file(rp_file_t *file, rp_chain_t *cl, off_t offset,
    rp_pool_t *pool)
{
    rp_thread_task_t      *task;
    rp_thread_file_ctx_t  *ctx;

    rp_log_debug3(RP_LOG_DEBUG_CORE, file->log, 0,
                   "thread write chain: %d, %p, %O",
                   file->fd, cl, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = rp_thread_task_alloc(pool,
                                     sizeof(rp_thread_file_ctx_t));
        if (task == NULL) {
            return RP_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (!ctx->write) {
            rp_log_error(RP_LOG_ALERT, file->log, 0,
                          "invalid thread call, write instead of read");
            return RP_ERROR;
        }

        if (ctx->err || ctx->nbytes == 0) {
            rp_log_error(RP_LOG_CRIT, file->log, ctx->err,
                          "pwritev() \"%s\" failed", file->name.data);
            return RP_ERROR;
        }

        file->offset += ctx->nbytes;
        return ctx->nbytes;
    }

    task->handler = rp_thread_write_chain_to_file_handler;

    ctx->write = 1;

    ctx->fd = file->fd;
    ctx->chain = cl;
    ctx->offset = offset;

    if (file->thread_handler(task, file) != RP_OK) {
        return RP_ERROR;
    }

    return RP_AGAIN;
}


static void
rp_thread_write_chain_to_file_handler(void *data, rp_log_t *log)
{
    rp_thread_file_ctx_t *ctx = data;

#if (RP_HAVE_PWRITEV)

    off_t          offset;
    ssize_t        n;
    rp_err_t      err;
    rp_chain_t   *cl;
    rp_iovec_t    vec;
    struct iovec   iovs[RP_IOVS_PREALLOCATE];

    vec.iovs = iovs;
    vec.nalloc = RP_IOVS_PREALLOCATE;

    cl = ctx->chain;
    offset = ctx->offset;

    ctx->nbytes = 0;
    ctx->err = 0;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = rp_chain_to_iovec(&vec, cl);

eintr:

        n = pwritev(ctx->fd, iovs, vec.count, offset);

        if (n == -1) {
            err = rp_errno;

            if (err == RP_EINTR) {
                rp_log_debug0(RP_LOG_DEBUG_CORE, log, err,
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

    ctx->err = RP_ENOSYS;
    return;

#endif
}

#endif /* RP_THREADS */


rp_int_t
rp_set_file_time(u_char *name, rp_fd_t fd, time_t s)
{
    struct timeval  tv[2];

    tv[0].tv_sec = rp_time();
    tv[0].tv_usec = 0;
    tv[1].tv_sec = s;
    tv[1].tv_usec = 0;

    if (utimes((char *) name, tv) != -1) {
        return RP_OK;
    }

    return RP_ERROR;
}


rp_int_t
rp_create_file_mapping(rp_file_mapping_t *fm)
{
    fm->fd = rp_open_file(fm->name, RP_FILE_RDWR, RP_FILE_TRUNCATE,
                           RP_FILE_DEFAULT_ACCESS);

    if (fm->fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_CRIT, fm->log, rp_errno,
                      rp_open_file_n " \"%s\" failed", fm->name);
        return RP_ERROR;
    }

    if (ftruncate(fm->fd, fm->size) == -1) {
        rp_log_error(RP_LOG_CRIT, fm->log, rp_errno,
                      "ftruncate() \"%s\" failed", fm->name);
        goto failed;
    }

    fm->addr = mmap(NULL, fm->size, PROT_READ|PROT_WRITE, MAP_SHARED,
                    fm->fd, 0);
    if (fm->addr != MAP_FAILED) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_CRIT, fm->log, rp_errno,
                  "mmap(%uz) \"%s\" failed", fm->size, fm->name);

failed:

    if (rp_close_file(fm->fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, fm->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", fm->name);
    }

    return RP_ERROR;
}


void
rp_close_file_mapping(rp_file_mapping_t *fm)
{
    if (munmap(fm->addr, fm->size) == -1) {
        rp_log_error(RP_LOG_CRIT, fm->log, rp_errno,
                      "munmap(%uz) \"%s\" failed", fm->size, fm->name);
    }

    if (rp_close_file(fm->fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, fm->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", fm->name);
    }
}


rp_int_t
rp_open_dir(rp_str_t *name, rp_dir_t *dir)
{
    dir->dir = opendir((const char *) name->data);

    if (dir->dir == NULL) {
        return RP_ERROR;
    }

    dir->valid_info = 0;

    return RP_OK;
}


rp_int_t
rp_read_dir(rp_dir_t *dir)
{
    dir->de = readdir(dir->dir);

    if (dir->de) {
#if (RP_HAVE_D_TYPE)
        dir->type = dir->de->d_type;
#else
        dir->type = 0;
#endif
        return RP_OK;
    }

    return RP_ERROR;
}


rp_int_t
rp_open_glob(rp_glob_t *gl)
{
    int  n;

    n = glob((char *) gl->pattern, 0, NULL, &gl->pglob);

    if (n == 0) {
        return RP_OK;
    }

#ifdef GLOB_NOMATCH

    if (n == GLOB_NOMATCH && gl->test) {
        return RP_OK;
    }

#endif

    return RP_ERROR;
}


rp_int_t
rp_read_glob(rp_glob_t *gl, rp_str_t *name)
{
    size_t  count;

#ifdef GLOB_NOMATCH
    count = (size_t) gl->pglob.gl_pathc;
#else
    count = (size_t) gl->pglob.gl_matchc;
#endif

    if (gl->n < count) {

        name->len = (size_t) rp_strlen(gl->pglob.gl_pathv[gl->n]);
        name->data = (u_char *) gl->pglob.gl_pathv[gl->n];
        gl->n++;

        return RP_OK;
    }

    return RP_DONE;
}


void
rp_close_glob(rp_glob_t *gl)
{
    globfree(&gl->pglob);
}


rp_err_t
rp_trylock_fd(rp_fd_t fd)
{
    struct flock  fl;

    rp_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return rp_errno;
    }

    return 0;
}


rp_err_t
rp_lock_fd(rp_fd_t fd)
{
    struct flock  fl;

    rp_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        return rp_errno;
    }

    return 0;
}


rp_err_t
rp_unlock_fd(rp_fd_t fd)
{
    struct flock  fl;

    rp_memzero(&fl, sizeof(struct flock));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        return  rp_errno;
    }

    return 0;
}


#if (RP_HAVE_POSIX_FADVISE) && !(RP_HAVE_F_READAHEAD)

rp_int_t
rp_read_ahead(rp_fd_t fd, size_t n)
{
    int  err;

    err = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

    if (err == 0) {
        return 0;
    }

    rp_set_errno(err);
    return RP_FILE_ERROR;
}

#endif


#if (RP_HAVE_O_DIRECT)

rp_int_t
rp_directio_on(rp_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return RP_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags | O_DIRECT);
}


rp_int_t
rp_directio_off(rp_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (flags == -1) {
        return RP_FILE_ERROR;
    }

    return fcntl(fd, F_SETFL, flags & ~O_DIRECT);
}

#endif


#if (RP_HAVE_STATFS)

size_t
rp_fs_bsize(u_char *name)
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

#elif (RP_HAVE_STATVFS)

size_t
rp_fs_bsize(u_char *name)
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
rp_fs_bsize(u_char *name)
{
    return 512;
}

#endif
