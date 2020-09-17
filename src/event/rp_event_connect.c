
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_event_connect.h>


#if (RP_HAVE_TRANSPARENT_PROXY)
static rp_int_t rp_event_connect_set_transparent(rp_peer_connection_t *pc,
    rp_socket_t s);
#endif


rp_int_t
rp_event_connect_peer(rp_peer_connection_t *pc)
{
    int                rc, type, value;
#if (RP_HAVE_IP_BIND_ADDRESS_NO_PORT || RP_LINUX)
    in_port_t          port;
#endif
    rp_int_t          event;
    rp_err_t          err;
    rp_uint_t         level;
    rp_socket_t       s;
    rp_event_t       *rev, *wev;
    rp_connection_t  *c;

    rc = pc->get(pc, pc->data);
    if (rc != RP_OK) {
        return rc;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

    s = rp_socket(pc->sockaddr->sa_family, type, 0);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (rp_socket_t) -1) {
        rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                      rp_socket_n " failed");
        return RP_ERROR;
    }


    c = rp_get_connection(s, pc->log);

    if (c == NULL) {
        if (rp_close_socket(s) == -1) {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          rp_close_socket_n " failed");
        }

        return RP_ERROR;
    }

    c->type = type;

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
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
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    if (rp_nonblocking(s) == -1) {
        rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                      rp_nonblocking_n " failed");

        goto failed;
    }

    if (pc->local) {

#if (RP_HAVE_TRANSPARENT_PROXY)
        if (pc->transparent) {
            if (rp_event_connect_set_transparent(pc, s) != RP_OK) {
                goto failed;
            }
        }
#endif

#if (RP_HAVE_IP_BIND_ADDRESS_NO_PORT || RP_LINUX)
        port = rp_inet_get_port(pc->local->sockaddr);
#endif

#if (RP_HAVE_IP_BIND_ADDRESS_NO_PORT)

        if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
            static int  bind_address_no_port = 1;

            if (bind_address_no_port) {
                if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                               (const void *) &bind_address_no_port,
                               sizeof(int)) == -1)
                {
                    err = rp_socket_errno;

                    if (err != RP_EOPNOTSUPP && err != RP_ENOPROTOOPT) {
                        rp_log_error(RP_LOG_ALERT, pc->log, err,
                                      "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
                                      "failed, ignored");

                    } else {
                        bind_address_no_port = 0;
                    }
                }
            }
        }

#endif

#if (RP_LINUX)

        if (pc->type == SOCK_DGRAM && port != 0) {
            int  reuse_addr = 1;

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuse_addr, sizeof(int))
                 == -1)
            {
                rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                              "setsockopt(SO_REUSEADDR) failed");
                goto failed;
            }
        }

#endif

        if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
            rp_log_error(RP_LOG_CRIT, pc->log, rp_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto failed;
        }
    }

    if (type == SOCK_STREAM) {
        c->recv = rp_recv;
        c->send = rp_send;
        c->recv_chain = rp_recv_chain;
        c->send_chain = rp_send_chain;

        c->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = RP_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = RP_TCP_NODELAY_DISABLED;

#if (RP_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        c->recv = rp_udp_recv;
        c->send = rp_send;
        c->send_chain = rp_udp_send_chain;
    }

    c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

    c->number = rp_atomic_fetch_add(rp_connection_counter, 1);

    if (rp_add_conn) {
        if (rp_add_conn(c) == RP_ERROR) {
            goto failed;
        }
    }

    rp_log_debug3(RP_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%uA", pc->name, s, c->number);

    rc = connect(s, pc->sockaddr, pc->socklen);

    if (rc == -1) {
        err = rp_socket_errno;


        if (err != RP_EINPROGRESS
#if (RP_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (RP_EAGAIN) */
            && err != RP_EAGAIN
#endif
            )
        {
            if (err == RP_ECONNREFUSED
#if (RP_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == RP_EAGAIN
#endif
                || err == RP_ECONNRESET
                || err == RP_ENETDOWN
                || err == RP_ENETUNREACH
                || err == RP_EHOSTDOWN
                || err == RP_EHOSTUNREACH)
            {
                level = RP_LOG_ERR;

            } else {
                level = RP_LOG_CRIT;
            }

            rp_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            rp_close_connection(c);
            pc->connection = NULL;

            return RP_DECLINED;
        }
    }

    if (rp_add_conn) {
        if (rc == -1) {

            /* RP_EINPROGRESS */

            return RP_AGAIN;
        }

        rp_log_debug0(RP_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return RP_OK;
    }

    if (rp_event_flags & RP_USE_IOCP_EVENT) {

        rp_log_debug1(RP_LOG_DEBUG_EVENT, pc->log, rp_socket_errno,
                       "connect(): %d", rc);

        if (rp_blocking(s) == -1) {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          rp_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use RP_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return RP_OK;
    }

    if (rp_event_flags & RP_USE_CLEAR_EVENT) {

        /* kqueue */

        event = RP_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = RP_LEVEL_EVENT;
    }

    if (rp_add_event(rev, RP_READ_EVENT, event) != RP_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* RP_EINPROGRESS */

        if (rp_add_event(wev, RP_WRITE_EVENT, event) != RP_OK) {
            goto failed;
        }

        return RP_AGAIN;
    }

    rp_log_debug0(RP_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return RP_OK;

failed:

    rp_close_connection(c);
    pc->connection = NULL;

    return RP_ERROR;
}


#if (RP_HAVE_TRANSPARENT_PROXY)

static rp_int_t
rp_event_connect_set_transparent(rp_peer_connection_t *pc, rp_socket_t s)
{
    int  value;

    value = 1;

#if defined(SO_BINDANY)

    if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
                   (const void *) &value, sizeof(int)) == -1)
    {
        rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                      "setsockopt(SO_BINDANY) failed");
        return RP_ERROR;
    }

#else

    switch (pc->local->sockaddr->sa_family) {

    case AF_INET:

#if defined(IP_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          "setsockopt(IP_TRANSPARENT) failed");
            return RP_ERROR;
        }

#elif defined(IP_BINDANY)

        if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          "setsockopt(IP_BINDANY) failed");
            return RP_ERROR;
        }

#endif

        break;

#if (RP_HAVE_INET6)

    case AF_INET6:

#if defined(IPV6_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          "setsockopt(IPV6_TRANSPARENT) failed");
            return RP_ERROR;
        }

#elif defined(IPV6_BINDANY)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            rp_log_error(RP_LOG_ALERT, pc->log, rp_socket_errno,
                          "setsockopt(IPV6_BINDANY) failed");
            return RP_ERROR;
        }

#else

        rp_log_error(RP_LOG_ALERT, pc->log, 0,
                      "could not enable transparent proxying for IPv6 "
                      "on this platform");

        return RP_ERROR;

#endif

        break;

#endif /* RP_HAVE_INET6 */

    }

#endif /* SO_BINDANY */

    return RP_OK;
}

#endif


rp_int_t
rp_event_get_peer(rp_peer_connection_t *pc, void *data)
{
    return RP_OK;
}
