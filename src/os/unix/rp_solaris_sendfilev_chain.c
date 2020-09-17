
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if (RP_TEST_BUILD_SOLARIS_SENDFILEV)

/* Solaris declarations */

typedef struct sendfilevec {
    int     sfv_fd;
    u_int   sfv_flag;
    off_t   sfv_off;
    size_t  sfv_len;
} sendfilevec_t;

#define SFV_FD_SELF  -2

static ssize_t sendfilev(int fd, const struct sendfilevec *vec,
    int sfvcnt, size_t *xferred)
{
    return -1;
}

rp_chain_t *rp_solaris_sendfilev_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);

#endif


#define RP_SENDFILEVECS  RP_IOVS_PREALLOCATE


rp_chain_t *
rp_solaris_sendfilev_chain(rp_connection_t *c, rp_chain_t *in, off_t limit)
{
    int             fd;
    u_char         *prev;
    off_t           size, send, prev_send, aligned, fprev;
    size_t          sent;
    ssize_t         n;
    rp_int_t       eintr;
    rp_err_t       err;
    rp_buf_t      *file;
    rp_uint_t      nsfv;
    sendfilevec_t  *sfv, sfvs[RP_SENDFILEVECS];
    rp_event_t    *wev;
    rp_chain_t    *cl;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    if (!c->sendfile) {
        return rp_writev_chain(c, in, limit);
    }


    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (RP_MAX_SIZE_T_VALUE - rp_pagesize)) {
        limit = RP_MAX_SIZE_T_VALUE - rp_pagesize;
    }


    send = 0;

    for ( ;; ) {
        fd = SFV_FD_SELF;
        prev = NULL;
        fprev = 0;
        file = NULL;
        sfv = NULL;
        eintr = 0;
        sent = 0;
        prev_send = send;

        nsfv = 0;

        /* create the sendfilevec and coalesce the neighbouring bufs */

        for (cl = in; cl && send < limit; cl = cl->next) {

            if (rp_buf_special(cl->buf)) {
                continue;
            }

            if (rp_buf_in_memory_only(cl->buf)) {
                fd = SFV_FD_SELF;

                size = cl->buf->last - cl->buf->pos;

                if (send + size > limit) {
                    size = limit - send;
                }

                if (prev == cl->buf->pos) {
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (nsfv == RP_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
                    sfv->sfv_len = (size_t) size;
                }

                prev = cl->buf->pos + (size_t) size;
                send += size;

            } else {
                prev = NULL;

                size = cl->buf->file_last - cl->buf->file_pos;

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + rp_pagesize - 1)
                               & ~((off_t) rp_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (nsfv == RP_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = (size_t) size;
                }

                file = cl->buf;
                fprev = cl->buf->file_pos + size;
                send += size;
            }
        }

        n = sendfilev(c->fd, sfvs, nsfv, &sent);

        if (n == -1) {
            err = rp_errno;

            switch (err) {
            case RP_EAGAIN:
                break;

            case RP_EINTR:
                eintr = 1;
                break;

            default:
                wev->error = 1;
                rp_connection_error(c, err, "sendfilev() failed");
                return RP_CHAIN_ERROR;
            }

            rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, err,
                          "sendfilev() sent only %uz bytes", sent);

        } else if (n == 0 && sent == 0) {

            /*
             * sendfilev() is documented to return -1 with errno
             * set to EINVAL if svf_len is greater than the file size,
             * but at least Solaris 11 returns 0 instead
             */

            if (file) {
                rp_log_error(RP_LOG_ALERT, c->log, 0,
                        "sendfilev() reported that \"%s\" was truncated at %O",
                        file->file->name.data, file->file_pos);

            } else {
                rp_log_error(RP_LOG_ALERT, c->log, 0,
                              "sendfilev() returned 0 with memory buffers");
            }

            return RP_CHAIN_ERROR;
        }

        rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "sendfilev: %z %z", n, sent);

        c->sent += sent;

        in = rp_chain_update_sent(in, sent);

        if (eintr) {
            send = prev_send + sent;
            continue;
        }

        if (send - prev_send != (off_t) sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
