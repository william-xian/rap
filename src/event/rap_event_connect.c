
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_connect.h>


#if (RAP_HAVE_TRANSPARENT_PROXY)
static rap_int_t rap_event_connect_set_transparent(rap_peer_connection_t *pc,
    rap_socket_t s);
#endif


rap_int_t
rap_event_connect_peer(rap_peer_connection_t *pc)
{
    int                rc, type, value;
#if (RAP_HAVE_IP_BIND_ADDRESS_NO_PORT || RAP_LINUX)
    in_port_t          port;
#endif
    rap_int_t          event;
    rap_err_t          err;
    rap_uint_t         level;
    rap_socket_t       s;
    rap_event_t       *rev, *wev;
    rap_connection_t  *c;

    rc = pc->get(pc, pc->data);
    if (rc != RAP_OK) {
        return rc;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

    s = rap_socket(pc->sockaddr->sa_family, type, 0);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (rap_socket_t) -1) {
        rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                      rap_socket_n " failed");
        return RAP_ERROR;
    }


    c = rap_get_connection(s, pc->log);

    if (c == NULL) {
        if (rap_close_socket(s) == -1) {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          rap_close_socket_n " failed");
        }

        return RAP_ERROR;
    }

    c->type = type;

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");
            goto failed;
        }
    }

    if (pc->so_keepalive) {
        value = 1;

        if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    if (rap_nonblocking(s) == -1) {
        rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                      rap_nonblocking_n " failed");

        goto failed;
    }

    if (pc->local) {

#if (RAP_HAVE_TRANSPARENT_PROXY)
        if (pc->transparent) {
            if (rap_event_connect_set_transparent(pc, s) != RAP_OK) {
                goto failed;
            }
        }
#endif

#if (RAP_HAVE_IP_BIND_ADDRESS_NO_PORT || RAP_LINUX)
        port = rap_inet_get_port(pc->local->sockaddr);
#endif

#if (RAP_HAVE_IP_BIND_ADDRESS_NO_PORT)

        if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
            static int  bind_address_no_port = 1;

            if (bind_address_no_port) {
                if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                               (const void *) &bind_address_no_port,
                               sizeof(int)) == -1)
                {
                    err = rap_socket_errno;

                    if (err != RAP_EOPNOTSUPP && err != RAP_ENOPROTOOPT) {
                        rap_log_error(RAP_LOG_ALERT, pc->log, err,
                                      "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
                                      "failed, ignored");

                    } else {
                        bind_address_no_port = 0;
                    }
                }
            }
        }

#endif

#if (RAP_LINUX)

        if (pc->type == SOCK_DGRAM && port != 0) {
            int  reuse_addr = 1;

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuse_addr, sizeof(int))
                 == -1)
            {
                rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                              "setsockopt(SO_REUSEADDR) failed");
                goto failed;
            }
        }

#endif

        if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
            rap_log_error(RAP_LOG_CRIT, pc->log, rap_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto failed;
        }
    }

    if (type == SOCK_STREAM) {
        c->recv = rap_recv;
        c->send = rap_send;
        c->recv_chain = rap_recv_chain;
        c->send_chain = rap_send_chain;

        c->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = RAP_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = RAP_TCP_NODELAY_DISABLED;

#if (RAP_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        c->recv = rap_udp_recv;
        c->send = rap_send;
        c->send_chain = rap_udp_send_chain;
    }

    c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

    c->number = rap_atomic_fetch_add(rap_connection_counter, 1);

    if (rap_add_conn) {
        if (rap_add_conn(c) == RAP_ERROR) {
            goto failed;
        }
    }

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%uA", pc->name, s, c->number);

    rc = connect(s, pc->sockaddr, pc->socklen);

    if (rc == -1) {
        err = rap_socket_errno;


        if (err != RAP_EINPROGRESS
#if (RAP_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (RAP_EAGAIN) */
            && err != RAP_EAGAIN
#endif
            )
        {
            if (err == RAP_ECONNREFUSED
#if (RAP_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == RAP_EAGAIN
#endif
                || err == RAP_ECONNRESET
                || err == RAP_ENETDOWN
                || err == RAP_ENETUNREACH
                || err == RAP_EHOSTDOWN
                || err == RAP_EHOSTUNREACH)
            {
                level = RAP_LOG_ERR;

            } else {
                level = RAP_LOG_CRIT;
            }

            rap_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            rap_close_connection(c);
            pc->connection = NULL;

            return RAP_DECLINED;
        }
    }

    if (rap_add_conn) {
        if (rc == -1) {

            /* RAP_EINPROGRESS */

            return RAP_AGAIN;
        }

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return RAP_OK;
    }

    if (rap_event_flags & RAP_USE_IOCP_EVENT) {

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, pc->log, rap_socket_errno,
                       "connect(): %d", rc);

        if (rap_blocking(s) == -1) {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          rap_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use RAP_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return RAP_OK;
    }

    if (rap_event_flags & RAP_USE_CLEAR_EVENT) {

        /* kqueue */

        event = RAP_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = RAP_LEVEL_EVENT;
    }

    if (rap_add_event(rev, RAP_READ_EVENT, event) != RAP_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* RAP_EINPROGRESS */

        if (rap_add_event(wev, RAP_WRITE_EVENT, event) != RAP_OK) {
            goto failed;
        }

        return RAP_AGAIN;
    }

    rap_log_debug0(RAP_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return RAP_OK;

failed:

    rap_close_connection(c);
    pc->connection = NULL;

    return RAP_ERROR;
}


#if (RAP_HAVE_TRANSPARENT_PROXY)

static rap_int_t
rap_event_connect_set_transparent(rap_peer_connection_t *pc, rap_socket_t s)
{
    int  value;

    value = 1;

#if defined(SO_BINDANY)

    if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
                   (const void *) &value, sizeof(int)) == -1)
    {
        rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                      "setsockopt(SO_BINDANY) failed");
        return RAP_ERROR;
    }

#else

    switch (pc->local->sockaddr->sa_family) {

    case AF_INET:

#if defined(IP_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(IP_TRANSPARENT) failed");
            return RAP_ERROR;
        }

#elif defined(IP_BINDANY)

        if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(IP_BINDANY) failed");
            return RAP_ERROR;
        }

#endif

        break;

#if (RAP_HAVE_INET6)

    case AF_INET6:

#if defined(IPV6_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(IPV6_TRANSPARENT) failed");
            return RAP_ERROR;
        }

#elif defined(IPV6_BINDANY)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rap_log_error(RAP_LOG_ALERT, pc->log, rap_socket_errno,
                          "setsockopt(IPV6_BINDANY) failed");
            return RAP_ERROR;
        }

#else

        rap_log_error(RAP_LOG_ALERT, pc->log, 0,
                      "could not enable transparent proxying for IPv6 "
                      "on this platform");

        return RAP_ERROR;

#endif

        break;

#endif /* RAP_HAVE_INET6 */

    }

#endif /* SO_BINDANY */

    return RAP_OK;
}

#endif


rap_int_t
rap_event_get_peer(rap_peer_connection_t *pc, void *data)
{
    return RAP_OK;
}
