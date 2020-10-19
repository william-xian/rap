
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_channel.h>


rap_int_t
rap_write_channel(rap_socket_t s, rap_channel_t *ch, size_t size,
    rap_log_t *log)
{
    ssize_t             n;
    rap_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    if (ch->fd == -1) {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

    } else {
        msg.msg_control = (caddr_t) &cmsg;
        msg.msg_controllen = sizeof(cmsg);

        rap_memzero(&cmsg, sizeof(cmsg));

        cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
        cmsg.cm.cmsg_level = SOL_SOCKET;
        cmsg.cm.cmsg_type = SCM_RIGHTS;

        /*
         * We have to use rap_memcpy() instead of simple
         *   *(int *) CMSG_DATA(&cmsg.cm) = ch->fd;
         * because some gcc 4.4 with -O2/3/s optimization issues the warning:
         *   dereferencing type-punned pointer will break strict-aliasing rules
         *
         * Fortunately, gcc with -O1 compiles this rap_memcpy()
         * in the same simple assignment as in the code above
         */

        rap_memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
    }

    msg.msg_flags = 0;

#else

    if (ch->fd == -1) {
        msg.msg_accrights = NULL;
        msg.msg_accrightslen = 0;

    } else {
        msg.msg_accrights = (caddr_t) &ch->fd;
        msg.msg_accrightslen = sizeof(int);
    }

#endif

    iov[0].iov_base = (char *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    n = sendmsg(s, &msg, 0);

    if (n == -1) {
        err = rap_errno;
        if (err == RAP_EAGAIN) {
            return RAP_AGAIN;
        }

        rap_log_error(RAP_LOG_ALERT, log, err, "sendmsg() failed");
        return RAP_ERROR;
    }

    return RAP_OK;
}


rap_int_t
rap_read_channel(rap_socket_t s, rap_channel_t *ch, size_t size, rap_log_t *log)
{
    ssize_t             n;
    rap_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)
    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;
#else
    int                 fd;
#endif

    iov[0].iov_base = (char *) ch;
    iov[0].iov_len = size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)
    msg.msg_control = (caddr_t) &cmsg;
    msg.msg_controllen = sizeof(cmsg);
#else
    msg.msg_accrights = (caddr_t) &fd;
    msg.msg_accrightslen = sizeof(int);
#endif

    n = recvmsg(s, &msg, 0);

    if (n == -1) {
        err = rap_errno;
        if (err == RAP_EAGAIN) {
            return RAP_AGAIN;
        }

        rap_log_error(RAP_LOG_ALERT, log, err, "recvmsg() failed");
        return RAP_ERROR;
    }

    if (n == 0) {
        rap_log_debug0(RAP_LOG_DEBUG_CORE, log, 0, "recvmsg() returned zero");
        return RAP_ERROR;
    }

    if ((size_t) n < sizeof(rap_channel_t)) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "recvmsg() returned not enough data: %z", n);
        return RAP_ERROR;
    }

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

    if (ch->command == RAP_CMD_OPEN_CHANNEL) {

        if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          "recvmsg() returned too small ancillary data");
            return RAP_ERROR;
        }

        if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS)
        {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          "recvmsg() returned invalid ancillary data "
                          "level %d or type %d",
                          cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
            return RAP_ERROR;
        }

        /* ch->fd = *(int *) CMSG_DATA(&cmsg.cm); */

        rap_memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
    }

    if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "recvmsg() truncated data");
    }

#else

    if (ch->command == RAP_CMD_OPEN_CHANNEL) {
        if (msg.msg_accrightslen != sizeof(int)) {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          "recvmsg() returned no ancillary data");
            return RAP_ERROR;
        }

        ch->fd = fd;
    }

#endif

    return n;
}


rap_int_t
rap_add_channel_event(rap_cycle_t *cycle, rap_fd_t fd, rap_int_t event,
    rap_event_handler_pt handler)
{
    rap_event_t       *ev, *rev, *wev;
    rap_connection_t  *c;

    c = rap_get_connection(fd, cycle->log);

    if (c == NULL) {
        return RAP_ERROR;
    }

    c->pool = cycle->pool;

    rev = c->read;
    wev = c->write;

    rev->log = cycle->log;
    wev->log = cycle->log;

    rev->channel = 1;
    wev->channel = 1;

    ev = (event == RAP_READ_EVENT) ? rev : wev;

    ev->handler = handler;

    if (rap_add_conn && (rap_event_flags & RAP_USE_EPOLL_EVENT) == 0) {
        if (rap_add_conn(c) == RAP_ERROR) {
            rap_free_connection(c);
            return RAP_ERROR;
        }

    } else {
        if (rap_add_event(ev, event, 0) == RAP_ERROR) {
            rap_free_connection(c);
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


void
rap_close_channel(rap_fd_t *fd, rap_log_t *log)
{
    if (close(fd[0]) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno, "close() channel failed");
    }

    if (close(fd[1]) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno, "close() channel failed");
    }
}
