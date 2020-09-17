
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_channel.h>


rp_int_t
rp_write_channel(rp_socket_t s, rp_channel_t *ch, size_t size,
    rp_log_t *log)
{
    ssize_t             n;
    rp_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (RP_HAVE_MSGHDR_MSG_CONTROL)

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

        rp_memzero(&cmsg, sizeof(cmsg));

        cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
        cmsg.cm.cmsg_level = SOL_SOCKET;
        cmsg.cm.cmsg_type = SCM_RIGHTS;

        /*
         * We have to use rp_memcpy() instead of simple
         *   *(int *) CMSG_DATA(&cmsg.cm) = ch->fd;
         * because some gcc 4.4 with -O2/3/s optimization issues the warning:
         *   dereferencing type-punned pointer will break strict-aliasing rules
         *
         * Fortunately, gcc with -O1 compiles this rp_memcpy()
         * in the same simple assignment as in the code above
         */

        rp_memcpy(CMSG_DATA(&cmsg.cm), &ch->fd, sizeof(int));
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
        err = rp_errno;
        if (err == RP_EAGAIN) {
            return RP_AGAIN;
        }

        rp_log_error(RP_LOG_ALERT, log, err, "sendmsg() failed");
        return RP_ERROR;
    }

    return RP_OK;
}


rp_int_t
rp_read_channel(rp_socket_t s, rp_channel_t *ch, size_t size, rp_log_t *log)
{
    ssize_t             n;
    rp_err_t           err;
    struct iovec        iov[1];
    struct msghdr       msg;

#if (RP_HAVE_MSGHDR_MSG_CONTROL)
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

#if (RP_HAVE_MSGHDR_MSG_CONTROL)
    msg.msg_control = (caddr_t) &cmsg;
    msg.msg_controllen = sizeof(cmsg);
#else
    msg.msg_accrights = (caddr_t) &fd;
    msg.msg_accrightslen = sizeof(int);
#endif

    n = recvmsg(s, &msg, 0);

    if (n == -1) {
        err = rp_errno;
        if (err == RP_EAGAIN) {
            return RP_AGAIN;
        }

        rp_log_error(RP_LOG_ALERT, log, err, "recvmsg() failed");
        return RP_ERROR;
    }

    if (n == 0) {
        rp_log_debug0(RP_LOG_DEBUG_CORE, log, 0, "recvmsg() returned zero");
        return RP_ERROR;
    }

    if ((size_t) n < sizeof(rp_channel_t)) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "recvmsg() returned not enough data: %z", n);
        return RP_ERROR;
    }

#if (RP_HAVE_MSGHDR_MSG_CONTROL)

    if (ch->command == RP_CMD_OPEN_CHANNEL) {

        if (cmsg.cm.cmsg_len < (socklen_t) CMSG_LEN(sizeof(int))) {
            rp_log_error(RP_LOG_ALERT, log, 0,
                          "recvmsg() returned too small ancillary data");
            return RP_ERROR;
        }

        if (cmsg.cm.cmsg_level != SOL_SOCKET || cmsg.cm.cmsg_type != SCM_RIGHTS)
        {
            rp_log_error(RP_LOG_ALERT, log, 0,
                          "recvmsg() returned invalid ancillary data "
                          "level %d or type %d",
                          cmsg.cm.cmsg_level, cmsg.cm.cmsg_type);
            return RP_ERROR;
        }

        /* ch->fd = *(int *) CMSG_DATA(&cmsg.cm); */

        rp_memcpy(&ch->fd, CMSG_DATA(&cmsg.cm), sizeof(int));
    }

    if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "recvmsg() truncated data");
    }

#else

    if (ch->command == RP_CMD_OPEN_CHANNEL) {
        if (msg.msg_accrightslen != sizeof(int)) {
            rp_log_error(RP_LOG_ALERT, log, 0,
                          "recvmsg() returned no ancillary data");
            return RP_ERROR;
        }

        ch->fd = fd;
    }

#endif

    return n;
}


rp_int_t
rp_add_channel_event(rp_cycle_t *cycle, rp_fd_t fd, rp_int_t event,
    rp_event_handler_pt handler)
{
    rp_event_t       *ev, *rev, *wev;
    rp_connection_t  *c;

    c = rp_get_connection(fd, cycle->log);

    if (c == NULL) {
        return RP_ERROR;
    }

    c->pool = cycle->pool;

    rev = c->read;
    wev = c->write;

    rev->log = cycle->log;
    wev->log = cycle->log;

    rev->channel = 1;
    wev->channel = 1;

    ev = (event == RP_READ_EVENT) ? rev : wev;

    ev->handler = handler;

    if (rp_add_conn && (rp_event_flags & RP_USE_EPOLL_EVENT) == 0) {
        if (rp_add_conn(c) == RP_ERROR) {
            rp_free_connection(c);
            return RP_ERROR;
        }

    } else {
        if (rp_add_event(ev, event, 0) == RP_ERROR) {
            rp_free_connection(c);
            return RP_ERROR;
        }
    }

    return RP_OK;
}


void
rp_close_channel(rp_fd_t *fd, rp_log_t *log)
{
    if (close(fd[0]) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno, "close() channel failed");
    }

    if (close(fd[1]) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno, "close() channel failed");
    }
}
