
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static rap_chain_t *rap_udp_output_chain_to_iovec(rap_iovec_t *vec,
    rap_chain_t *in, rap_log_t *log);
static ssize_t rap_sendmsg(rap_connection_t *c, rap_iovec_t *vec);


rap_chain_t *
rap_udp_unix_sendmsg_chain(rap_connection_t *c, rap_chain_t *in, off_t limit)
{
    ssize_t        n;
    off_t          send;
    rap_chain_t   *cl;
    rap_event_t   *wev;
    rap_iovec_t    vec;
    struct iovec   iovs[RAP_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (RAP_HAVE_KQUEUE)

    if ((rap_event_flags & RAP_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) rap_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return RAP_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (RAP_MAX_SIZE_T_VALUE - rap_pagesize)) {
        limit = RAP_MAX_SIZE_T_VALUE - rap_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = RAP_IOVS_PREALLOCATE;

    for ( ;; ) {

        /* create the iovec and coalesce the neighbouring bufs */

        cl = rap_udp_output_chain_to_iovec(&vec, in, c->log);

        if (cl == RAP_CHAIN_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "file buf in sendmsg "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();

            return RAP_CHAIN_ERROR;
        }

        if (cl == in) {
            return in;
        }

        send += vec.size;

        n = rap_sendmsg(c, &vec);

        if (n == RAP_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        if (n == RAP_AGAIN) {
            wev->ready = 0;
            return in;
        }

        c->sent += n;

        in = rap_chain_update_sent(in, n);

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static rap_chain_t *
rap_udp_output_chain_to_iovec(rap_iovec_t *vec, rap_chain_t *in, rap_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    rap_uint_t     n, flush;
    rap_chain_t   *cl;
    struct iovec  *iov;

    cl = in;
    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;
    flush = 0;

    for ( /* void */ ; in && !flush; in = in->next) {

        if (in->buf->flush || in->buf->last_buf) {
            flush = 1;
        }

        if (rap_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!rap_buf_in_memory(in->buf)) {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            rap_debug_point();

            return RAP_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                rap_log_error(RAP_LOG_ALERT, log, 0,
                              "too many parts in a datagram");
                return RAP_CHAIN_ERROR;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    if (!flush) {
#if (RAP_SUPPRESS_WARN)
        vec->size = 0;
        vec->count = 0;
#endif
        return cl;
    }

    vec->count = n;
    vec->size = total;

    return in;
}


static ssize_t
rap_sendmsg(rap_connection_t *c, rap_iovec_t *vec)
{
    ssize_t        n;
    rap_err_t      err;
    struct msghdr  msg;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

#if (RAP_HAVE_IP_SENDSRCADDR)
    u_char         msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (RAP_HAVE_IP_PKTINFO)
    u_char         msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)
    u_char         msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

#endif

    rap_memzero(&msg, sizeof(struct msghdr));

    if (c->socklen) {
        msg.msg_name = c->sockaddr;
        msg.msg_namelen = c->socklen;
    }

    msg.msg_iov = vec->iovs;
    msg.msg_iovlen = vec->count;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

    if (c->listening && c->listening->wildcard && c->local_sockaddr) {

#if (RAP_HAVE_IP_SENDSRCADDR)

        if (c->local_sockaddr->sa_family == AF_INET) {
            struct cmsghdr      *cmsg;
            struct in_addr      *addr;
            struct sockaddr_in  *sin;

            msg.msg_control = &msg_control;
            msg.msg_controllen = sizeof(msg_control);

            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_SENDSRCADDR;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));

            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = (struct in_addr *) CMSG_DATA(cmsg);
            *addr = sin->sin_addr;
        }

#elif (RAP_HAVE_IP_PKTINFO)

        if (c->local_sockaddr->sa_family == AF_INET) {
            struct cmsghdr      *cmsg;
            struct in_pktinfo   *pkt;
            struct sockaddr_in  *sin;

            msg.msg_control = &msg_control;
            msg.msg_controllen = sizeof(msg_control);

            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

            sin = (struct sockaddr_in *) c->local_sockaddr;

            pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
            rap_memzero(pkt, sizeof(struct in_pktinfo));
            pkt->ipi_spec_dst = sin->sin_addr;
        }

#endif

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)

        if (c->local_sockaddr->sa_family == AF_INET6) {
            struct cmsghdr       *cmsg;
            struct in6_pktinfo   *pkt6;
            struct sockaddr_in6  *sin6;

            msg.msg_control = &msg_control6;
            msg.msg_controllen = sizeof(msg_control6);

            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            rap_memzero(pkt6, sizeof(struct in6_pktinfo));
            pkt6->ipi6_addr = sin6->sin6_addr;
        }

#endif
    }

#endif

eintr:

    n = sendmsg(c->fd, &msg, 0);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "sendmsg: %z of %uz", n, vec->size);

    if (n == -1) {
        err = rap_errno;

        switch (err) {
        case RAP_EAGAIN:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() not ready");
            return RAP_AGAIN;

        case RAP_EINTR:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            rap_connection_error(c, err, "sendmsg() failed");
            return RAP_ERROR;
        }
    }

    return n;
}
