
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


rp_os_io_t  rp_io;


static void rp_drain_connections(rp_cycle_t *cycle);


rp_listening_t *
rp_create_listening(rp_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    size_t            len;
    rp_listening_t  *ls;
    struct sockaddr  *sa;
    u_char            text[RP_SOCKADDR_STRLEN];

    ls = rp_array_push(&cf->cycle->listening);
    if (ls == NULL) {
        return NULL;
    }

    rp_memzero(ls, sizeof(rp_listening_t));

    sa = rp_palloc(cf->pool, socklen);
    if (sa == NULL) {
        return NULL;
    }

    rp_memcpy(sa, sockaddr, socklen);

    ls->sockaddr = sa;
    ls->socklen = socklen;

    len = rp_sock_ntop(sa, socklen, text, RP_SOCKADDR_STRLEN, 1);
    ls->addr_text.len = len;

    switch (ls->sockaddr->sa_family) {
#if (RP_HAVE_INET6)
    case AF_INET6:
        ls->addr_text_max_len = RP_INET6_ADDRSTRLEN;
        break;
#endif
#if (RP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        ls->addr_text_max_len = RP_UNIX_ADDRSTRLEN;
        len++;
        break;
#endif
    case AF_INET:
        ls->addr_text_max_len = RP_INET_ADDRSTRLEN;
        break;
    default:
        ls->addr_text_max_len = RP_SOCKADDR_STRLEN;
        break;
    }

    ls->addr_text.data = rp_pnalloc(cf->pool, len);
    if (ls->addr_text.data == NULL) {
        return NULL;
    }

    rp_memcpy(ls->addr_text.data, text, len);

#if !(RP_WIN32)
    rp_rbtree_init(&ls->rbtree, &ls->sentinel, rp_udp_rbtree_insert_value);
#endif

    ls->fd = (rp_socket_t) -1;
    ls->type = SOCK_STREAM;

    ls->backlog = RP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

#if (RP_HAVE_SETFIB)
    ls->setfib = -1;
#endif

#if (RP_HAVE_TCP_FASTOPEN)
    ls->fastopen = -1;
#endif

    return ls;
}


rp_int_t
rp_clone_listening(rp_cycle_t *cycle, rp_listening_t *ls)
{
#if (RP_HAVE_REUSEPORT)

    rp_int_t         n;
    rp_core_conf_t  *ccf;
    rp_listening_t   ols;

    if (!ls->reuseport || ls->worker != 0) {
        return RP_OK;
    }

    ols = *ls;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    for (n = 1; n < ccf->worker_processes; n++) {

        /* create a socket for each worker process */

        ls = rp_array_push(&cycle->listening);
        if (ls == NULL) {
            return RP_ERROR;
        }

        *ls = ols;
        ls->worker = n;
    }

#endif

    return RP_OK;
}


rp_int_t
rp_set_inherited_sockets(rp_cycle_t *cycle)
{
    size_t                     len;
    rp_uint_t                 i;
    rp_listening_t           *ls;
    socklen_t                  olen;
#if (RP_HAVE_DEFERRED_ACCEPT || RP_HAVE_TCP_FASTOPEN)
    rp_err_t                  err;
#endif
#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    struct accept_filter_arg   af;
#endif
#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    int                        timeout;
#endif
#if (RP_HAVE_REUSEPORT)
    int                        reuseport;
#endif

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        ls[i].sockaddr = rp_palloc(cycle->pool, sizeof(rp_sockaddr_t));
        if (ls[i].sockaddr == NULL) {
            return RP_ERROR;
        }

        ls[i].socklen = sizeof(rp_sockaddr_t);
        if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
            rp_log_error(RP_LOG_CRIT, cycle->log, rp_socket_errno,
                          "getsockname() of the inherited "
                          "socket #%d failed", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        if (ls[i].socklen > (socklen_t) sizeof(rp_sockaddr_t)) {
            ls[i].socklen = sizeof(rp_sockaddr_t);
        }

        switch (ls[i].sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            ls[i].addr_text_max_len = RP_INET6_ADDRSTRLEN;
            len = RP_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;
            break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            ls[i].addr_text_max_len = RP_UNIX_ADDRSTRLEN;
            len = RP_UNIX_ADDRSTRLEN;
            break;
#endif

        case AF_INET:
            ls[i].addr_text_max_len = RP_INET_ADDRSTRLEN;
            len = RP_INET_ADDRSTRLEN + sizeof(":65535") - 1;
            break;

        default:
            rp_log_error(RP_LOG_CRIT, cycle->log, rp_socket_errno,
                          "the inherited socket #%d has "
                          "an unsupported protocol family", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        ls[i].addr_text.data = rp_pnalloc(cycle->pool, len);
        if (ls[i].addr_text.data == NULL) {
            return RP_ERROR;
        }

        len = rp_sock_ntop(ls[i].sockaddr, ls[i].socklen,
                            ls[i].addr_text.data, len, 1);
        if (len == 0) {
            return RP_ERROR;
        }

        ls[i].addr_text.len = len;

        ls[i].backlog = RP_LISTEN_BACKLOG;

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_TYPE, (void *) &ls[i].type,
                       &olen)
            == -1)
        {
            rp_log_error(RP_LOG_CRIT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_TYPE) %V failed", &ls[i].addr_text);
            ls[i].ignore = 1;
            continue;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF, (void *) &ls[i].rcvbuf,
                       &olen)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_RCVBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].rcvbuf = -1;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF, (void *) &ls[i].sndbuf,
                       &olen)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_SNDBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].sndbuf = -1;
        }

#if 0
        /* SO_SETFIB is currently a set only option */

#if (RP_HAVE_SETFIB)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                       (void *) &ls[i].setfib, &olen)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_SETFIB) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].setfib = -1;
        }

#endif
#endif

#if (RP_HAVE_REUSEPORT)

        reuseport = 0;
        olen = sizeof(int);

#ifdef SO_REUSEPORT_LB

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
                       (void *) &reuseport, &olen)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_REUSEPORT_LB) %V failed, ignored",
                          &ls[i].addr_text);

        } else {
            ls[i].reuseport = reuseport ? 1 : 0;
        }

#else

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
                       (void *) &reuseport, &olen)
            == -1)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                          "getsockopt(SO_REUSEPORT) %V failed, ignored",
                          &ls[i].addr_text);

        } else {
            ls[i].reuseport = reuseport ? 1 : 0;
        }
#endif

#endif

        if (ls[i].type != SOCK_STREAM) {
            continue;
        }

#if (RP_HAVE_TCP_FASTOPEN)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                       (void *) &ls[i].fastopen, &olen)
            == -1)
        {
            err = rp_socket_errno;

            if (err != RP_EOPNOTSUPP && err != RP_ENOPROTOOPT
                && err != RP_EINVAL)
            {
                rp_log_error(RP_LOG_NOTICE, cycle->log, err,
                              "getsockopt(TCP_FASTOPEN) %V failed, ignored",
                              &ls[i].addr_text);
            }

            ls[i].fastopen = -1;
        }

#endif

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

        rp_memzero(&af, sizeof(struct accept_filter_arg));
        olen = sizeof(struct accept_filter_arg);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &olen)
            == -1)
        {
            err = rp_socket_errno;

            if (err == RP_EINVAL) {
                continue;
            }

            rp_log_error(RP_LOG_NOTICE, cycle->log, err,
                          "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (olen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
            continue;
        }

        ls[i].accept_filter = rp_palloc(cycle->pool, 16);
        if (ls[i].accept_filter == NULL) {
            return RP_ERROR;
        }

        (void) rp_cpystrn((u_char *) ls[i].accept_filter,
                           (u_char *) af.af_name, 16);
#endif

#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

        timeout = 0;
        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &olen)
            == -1)
        {
            err = rp_socket_errno;

            if (err == RP_EOPNOTSUPP) {
                continue;
            }

            rp_log_error(RP_LOG_NOTICE, cycle->log, err,
                          "getsockopt(TCP_DEFER_ACCEPT) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (olen < sizeof(int) || timeout == 0) {
            continue;
        }

        ls[i].deferred_accept = 1;
#endif
    }

    return RP_OK;
}


rp_int_t
rp_open_listening_sockets(rp_cycle_t *cycle)
{
    int               reuseaddr;
    rp_uint_t        i, tries, failed;
    rp_err_t         err;
    rp_log_t        *log;
    rp_socket_t      s;
    rp_listening_t  *ls;

    reuseaddr = 1;
#if (RP_SUPPRESS_WARN)
    failed = 0;
#endif

    log = cycle->log;

    /* TODO: configurable try number */

    for (tries = 5; tries; tries--) {
        failed = 0;

        /* for each listening socket */

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].ignore) {
                continue;
            }

#if (RP_HAVE_REUSEPORT)

            if (ls[i].add_reuseport) {

                /*
                 * to allow transition from a socket without SO_REUSEPORT
                 * to multiple sockets with SO_REUSEPORT, we have to set
                 * SO_REUSEPORT on the old socket before opening new ones
                 */

                int  reuseport = 1;

#ifdef SO_REUSEPORT_LB

                if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed, "
                                  "ignored",
                                  &ls[i].addr_text);
                }

#else

                if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed, ignored",
                                  &ls[i].addr_text);
                }
#endif

                ls[i].add_reuseport = 0;
            }
#endif

            if (ls[i].fd != (rp_socket_t) -1) {
                continue;
            }

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                continue;
            }

            s = rp_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);

            if (s == (rp_socket_t) -1) {
                rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                              rp_socket_n " %V failed", &ls[i].addr_text);
                return RP_ERROR;
            }

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                              "setsockopt(SO_REUSEADDR) %V failed",
                              &ls[i].addr_text);

                if (rp_close_socket(s) == -1) {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  rp_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                return RP_ERROR;
            }

#if (RP_HAVE_REUSEPORT)

            if (ls[i].reuseport && !rp_test_config) {
                int  reuseport;

                reuseport = 1;

#ifdef SO_REUSEPORT_LB

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed",
                                  &ls[i].addr_text);

                    if (rp_close_socket(s) == -1) {
                        rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                      rp_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RP_ERROR;
                }

#else

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed",
                                  &ls[i].addr_text);

                    if (rp_close_socket(s) == -1) {
                        rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                      rp_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RP_ERROR;
                }
#endif
            }
#endif

#if (RP_HAVE_INET6 && defined IPV6_V6ONLY)

            if (ls[i].sockaddr->sa_family == AF_INET6) {
                int  ipv6only;

                ipv6only = ls[i].ipv6only;

                if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                               (const void *) &ipv6only, sizeof(int))
                    == -1)
                {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  "setsockopt(IPV6_V6ONLY) %V failed, ignored",
                                  &ls[i].addr_text);
                }
            }
#endif
            /* TODO: close on exit */

            if (!(rp_event_flags & RP_USE_IOCP_EVENT)) {
                if (rp_nonblocking(s) == -1) {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  rp_nonblocking_n " %V failed",
                                  &ls[i].addr_text);

                    if (rp_close_socket(s) == -1) {
                        rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                      rp_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RP_ERROR;
                }
            }

            rp_log_debug2(RP_LOG_DEBUG_CORE, log, 0,
                           "bind() %V #%d ", &ls[i].addr_text, s);

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = rp_socket_errno;

                if (err != RP_EADDRINUSE || !rp_test_config) {
                    rp_log_error(RP_LOG_EMERG, log, err,
                                  "bind() to %V failed", &ls[i].addr_text);
                }

                if (rp_close_socket(s) == -1) {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  rp_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != RP_EADDRINUSE) {
                    return RP_ERROR;
                }

                if (!rp_test_config) {
                    failed = 1;
                }

                continue;
            }

#if (RP_HAVE_UNIX_DOMAIN)

            if (ls[i].sockaddr->sa_family == AF_UNIX) {
                mode_t   mode;
                u_char  *name;

                name = ls[i].addr_text.data + sizeof("unix:") - 1;
                mode = (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

                if (chmod((char *) name, mode) == -1) {
                    rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                  "chmod() \"%s\" failed", name);
                }

                if (rp_test_config) {
                    if (rp_delete_file(name) == RP_FILE_ERROR) {
                        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                      rp_delete_file_n " %s failed", name);
                    }
                }
            }
#endif

            if (ls[i].type != SOCK_STREAM) {
                ls[i].fd = s;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                err = rp_socket_errno;

                /*
                 * on OpenVZ after suspend/resume EADDRINUSE
                 * may be returned by listen() instead of bind(), see
                 * https://bugzilla.openvz.org/show_bug.cgi?id=2470
                 */

                if (err != RP_EADDRINUSE || !rp_test_config) {
                    rp_log_error(RP_LOG_EMERG, log, err,
                                  "listen() to %V, backlog %d failed",
                                  &ls[i].addr_text, ls[i].backlog);
                }

                if (rp_close_socket(s) == -1) {
                    rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                                  rp_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != RP_EADDRINUSE) {
                    return RP_ERROR;
                }

                if (!rp_test_config) {
                    failed = 1;
                }

                continue;
            }

            ls[i].listen = 1;

            ls[i].fd = s;
        }

        if (!failed) {
            break;
        }

        /* TODO: delay configurable */

        rp_log_error(RP_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");

        rp_msleep(500);
    }

    if (failed) {
        rp_log_error(RP_LOG_EMERG, log, 0, "still could not bind()");
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_configure_listening_sockets(rp_cycle_t *cycle)
{
    int                        value;
    rp_uint_t                 i;
    rp_listening_t           *ls;

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    struct accept_filter_arg   af;
#endif

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        ls[i].log = *ls[i].logp;

        if (ls[i].rcvbuf != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF,
                           (const void *) &ls[i].rcvbuf, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_RCVBUF, %d) %V failed, ignored",
                              ls[i].rcvbuf, &ls[i].addr_text);
            }
        }

        if (ls[i].sndbuf != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF,
                           (const void *) &ls[i].sndbuf, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_SNDBUF, %d) %V failed, ignored",
                              ls[i].sndbuf, &ls[i].addr_text);
            }
        }

        if (ls[i].keepalive) {
            value = (ls[i].keepalive == 1) ? 1 : 0;

            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_KEEPALIVE,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_KEEPALIVE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

#if (RP_HAVE_KEEPALIVE_TUNABLE)

        if (ls[i].keepidle) {
            value = ls[i].keepidle;

#if (RP_KEEPALIVE_FACTOR)
            value *= RP_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPIDLE,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(TCP_KEEPIDLE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepintvl) {
            value = ls[i].keepintvl;

#if (RP_KEEPALIVE_FACTOR)
            value *= RP_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPINTVL,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                             "setsockopt(TCP_KEEPINTVL, %d) %V failed, ignored",
                             value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepcnt) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPCNT,
                           (const void *) &ls[i].keepcnt, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(TCP_KEEPCNT, %d) %V failed, ignored",
                              ls[i].keepcnt, &ls[i].addr_text);
            }
        }

#endif

#if (RP_HAVE_SETFIB)
        if (ls[i].setfib != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                           (const void *) &ls[i].setfib, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_SETFIB, %d) %V failed, ignored",
                              ls[i].setfib, &ls[i].addr_text);
            }
        }
#endif

#if (RP_HAVE_TCP_FASTOPEN)
        if (ls[i].fastopen != -1) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                           (const void *) &ls[i].fastopen, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(TCP_FASTOPEN, %d) %V failed, ignored",
                              ls[i].fastopen, &ls[i].addr_text);
            }
        }
#endif

#if 0
        if (1) {
            int tcp_nodelay = 1;

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(TCP_NODELAY) %V failed, ignored",
                              &ls[i].addr_text);
            }
        }
#endif

        if (ls[i].listen) {

            /* change backlog via listen() */

            if (listen(ls[i].fd, ls[i].backlog) == -1) {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "listen() to %V, backlog %d failed, ignored",
                              &ls[i].addr_text, ls[i].backlog);
            }
        }

        /*
         * setting deferred mode should be last operation on socket,
         * because code may prematurely continue cycle on failure
         */

#if (RP_HAVE_DEFERRED_ACCEPT)

#ifdef SO_ACCEPTFILTER

        if (ls[i].delete_deferred) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, NULL, 0)
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_ACCEPTFILTER, NULL) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);

                if (ls[i].accept_filter) {
                    rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                                  "could not change the accept filter "
                                  "to \"%s\" for %V, ignored",
                                  ls[i].accept_filter, &ls[i].addr_text);
                }

                continue;
            }

            ls[i].deferred_accept = 0;
        }

        if (ls[i].add_deferred) {
            rp_memzero(&af, sizeof(struct accept_filter_arg));
            (void) rp_cpystrn((u_char *) af.af_name,
                               (u_char *) ls[i].accept_filter, 16);

            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER,
                           &af, sizeof(struct accept_filter_arg))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(SO_ACCEPTFILTER, \"%s\") "
                              "for %V failed, ignored",
                              ls[i].accept_filter, &ls[i].addr_text);
                continue;
            }

            ls[i].deferred_accept = 1;
        }

#endif

#ifdef TCP_DEFER_ACCEPT

        if (ls[i].add_deferred || ls[i].delete_deferred) {

            if (ls[i].add_deferred) {
                /*
                 * There is no way to find out how long a connection was
                 * in queue (and a connection may bypass deferred queue at all
                 * if syncookies were used), hence we use 1 second timeout
                 * here.
                 */
                value = 1;

            } else {
                value = 0;
            }

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                           &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(TCP_DEFER_ACCEPT, %d) for %V failed, "
                              "ignored",
                              value, &ls[i].addr_text);

                continue;
            }
        }

        if (ls[i].add_deferred) {
            ls[i].deferred_accept = 1;
        }

#endif

#endif /* RP_HAVE_DEFERRED_ACCEPT */

#if (RP_HAVE_IP_RECVDSTADDR)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_RECVDSTADDR,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(IP_RECVDSTADDR) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#elif (RP_HAVE_IP_PKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_PKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(IP_PKTINFO) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#if (RP_HAVE_INET6 && RP_HAVE_IPV6_RECVPKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET6)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rp_log_error(RP_LOG_ALERT, cycle->log, rp_socket_errno,
                              "setsockopt(IPV6_RECVPKTINFO) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif
    }

    return;
}


void
rp_close_listening_sockets(rp_cycle_t *cycle)
{
    rp_uint_t         i;
    rp_listening_t   *ls;
    rp_connection_t  *c;

    if (rp_event_flags & RP_USE_IOCP_EVENT) {
        return;
    }

    rp_accept_mutex_held = 0;
    rp_use_accept_mutex = 0;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c) {
            if (c->read->active) {
                if (rp_event_flags & RP_USE_EPOLL_EVENT) {

                    /*
                     * it seems that Linux-2.6.x OpenVZ sends events
                     * for closed shared listening sockets unless
                     * the events was explicitly deleted
                     */

                    rp_del_event(c->read, RP_READ_EVENT, 0);

                } else {
                    rp_del_event(c->read, RP_READ_EVENT, RP_CLOSE_EVENT);
                }
            }

            rp_free_connection(c);

            c->fd = (rp_socket_t) -1;
        }

        rp_log_debug2(RP_LOG_DEBUG_CORE, cycle->log, 0,
                       "close listening %V #%d ", &ls[i].addr_text, ls[i].fd);

        if (rp_close_socket(ls[i].fd) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_socket_errno,
                          rp_close_socket_n " %V failed", &ls[i].addr_text);
        }

#if (RP_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX
            && rp_process <= RP_PROCESS_MASTER
            && rp_new_binary == 0)
        {
            u_char *name = ls[i].addr_text.data + sizeof("unix:") - 1;

            if (rp_delete_file(name) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_socket_errno,
                              rp_delete_file_n " %s failed", name);
            }
        }

#endif

        ls[i].fd = (rp_socket_t) -1;
    }

    cycle->listening.nelts = 0;
}


rp_connection_t *
rp_get_connection(rp_socket_t s, rp_log_t *log)
{
    rp_uint_t         instance;
    rp_event_t       *rev, *wev;
    rp_connection_t  *c;

    /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

    if (rp_cycle->files && (rp_uint_t) s >= rp_cycle->files_n) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "the new socket has number %d, "
                      "but only %ui files are available",
                      s, rp_cycle->files_n);
        return NULL;
    }

    c = rp_cycle->free_connections;

    if (c == NULL) {
        rp_drain_connections((rp_cycle_t *) rp_cycle);
        c = rp_cycle->free_connections;
    }

    if (c == NULL) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "%ui worker_connections are not enough",
                      rp_cycle->connection_n);

        return NULL;
    }

    rp_cycle->free_connections = c->data;
    rp_cycle->free_connection_n--;

    if (rp_cycle->files && rp_cycle->files[s] == NULL) {
        rp_cycle->files[s] = c;
    }

    rev = c->read;
    wev = c->write;

    rp_memzero(c, sizeof(rp_connection_t));

    c->read = rev;
    c->write = wev;
    c->fd = s;
    c->log = log;

    instance = rev->instance;

    rp_memzero(rev, sizeof(rp_event_t));
    rp_memzero(wev, sizeof(rp_event_t));

    rev->instance = !instance;
    wev->instance = !instance;

    rev->index = RP_INVALID_INDEX;
    wev->index = RP_INVALID_INDEX;

    rev->data = c;
    wev->data = c;

    wev->write = 1;

    return c;
}


void
rp_free_connection(rp_connection_t *c)
{
    c->data = rp_cycle->free_connections;
    rp_cycle->free_connections = c;
    rp_cycle->free_connection_n++;

    if (rp_cycle->files && rp_cycle->files[c->fd] == c) {
        rp_cycle->files[c->fd] = NULL;
    }
}


void
rp_close_connection(rp_connection_t *c)
{
    rp_err_t     err;
    rp_uint_t    log_error, level;
    rp_socket_t  fd;

    if (c->fd == (rp_socket_t) -1) {
        rp_log_error(RP_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    if (c->write->timer_set) {
        rp_del_timer(c->write);
    }

    if (!c->shared) {
        if (rp_del_conn) {
            rp_del_conn(c, RP_CLOSE_EVENT);

        } else {
            if (c->read->active || c->read->disabled) {
                rp_del_event(c->read, RP_READ_EVENT, RP_CLOSE_EVENT);
            }

            if (c->write->active || c->write->disabled) {
                rp_del_event(c->write, RP_WRITE_EVENT, RP_CLOSE_EVENT);
            }
        }
    }

    if (c->read->posted) {
        rp_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        rp_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    rp_reusable_connection(c, 0);

    log_error = c->log_error;

    rp_free_connection(c);

    fd = c->fd;
    c->fd = (rp_socket_t) -1;

    if (c->shared) {
        return;
    }

    if (rp_close_socket(fd) == -1) {

        err = rp_socket_errno;

        if (err == RP_ECONNRESET || err == RP_ENOTCONN) {

            switch (log_error) {

            case RP_ERROR_INFO:
                level = RP_LOG_INFO;
                break;

            case RP_ERROR_ERR:
                level = RP_LOG_ERR;
                break;

            default:
                level = RP_LOG_CRIT;
            }

        } else {
            level = RP_LOG_CRIT;
        }

        rp_log_error(level, c->log, err, rp_close_socket_n " %d failed", fd);
    }
}


void
rp_reusable_connection(rp_connection_t *c, rp_uint_t reusable)
{
    rp_log_debug1(RP_LOG_DEBUG_CORE, c->log, 0,
                   "reusable connection: %ui", reusable);

    if (c->reusable) {
        rp_queue_remove(&c->queue);
        rp_cycle->reusable_connections_n--;

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_waiting, -1);
#endif
    }

    c->reusable = reusable;

    if (reusable) {
        /* need cast as rp_cycle is volatile */

        rp_queue_insert_head(
            (rp_queue_t *) &rp_cycle->reusable_connections_queue, &c->queue);
        rp_cycle->reusable_connections_n++;

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_waiting, 1);
#endif
    }
}


static void
rp_drain_connections(rp_cycle_t *cycle)
{
    rp_uint_t         i, n;
    rp_queue_t       *q;
    rp_connection_t  *c;

    n = rp_max(rp_min(32, cycle->reusable_connections_n / 8), 1);

    for (i = 0; i < n; i++) {
        if (rp_queue_empty(&cycle->reusable_connections_queue)) {
            break;
        }

        q = rp_queue_last(&cycle->reusable_connections_queue);
        c = rp_queue_data(q, rp_connection_t, queue);

        rp_log_debug0(RP_LOG_DEBUG_CORE, c->log, 0,
                       "reusing connection");

        c->close = 1;
        c->read->handler(c->read);
    }
}


void
rp_close_idle_connections(rp_cycle_t *cycle)
{
    rp_uint_t         i;
    rp_connection_t  *c;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        /* THREAD: lock */

        if (c[i].fd != (rp_socket_t) -1 && c[i].idle) {
            c[i].close = 1;
            c[i].read->handler(c[i].read);
        }
    }
}


rp_int_t
rp_connection_local_sockaddr(rp_connection_t *c, rp_str_t *s,
    rp_uint_t port)
{
    socklen_t             len;
    rp_uint_t            addr;
    rp_sockaddr_t        sa;
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    rp_uint_t            i;
    struct sockaddr_in6  *sin6;
#endif

    addr = 0;

    if (c->local_socklen) {
        switch (c->local_sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            for (i = 0; addr == 0 && i < 16; i++) {
                addr |= sin6->sin6_addr.s6_addr[i];
            }

            break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            addr = 1;
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            addr = sin->sin_addr.s_addr;
            break;
        }
    }

    if (addr == 0) {

        len = sizeof(rp_sockaddr_t);

        if (getsockname(c->fd, &sa.sockaddr, &len) == -1) {
            rp_connection_error(c, rp_socket_errno, "getsockname() failed");
            return RP_ERROR;
        }

        c->local_sockaddr = rp_palloc(c->pool, len);
        if (c->local_sockaddr == NULL) {
            return RP_ERROR;
        }

        rp_memcpy(c->local_sockaddr, &sa, len);

        c->local_socklen = len;
    }

    if (s == NULL) {
        return RP_OK;
    }

    s->len = rp_sock_ntop(c->local_sockaddr, c->local_socklen,
                           s->data, s->len, port);

    return RP_OK;
}


rp_int_t
rp_tcp_nodelay(rp_connection_t *c)
{
    int  tcp_nodelay;

    if (c->tcp_nodelay != RP_TCP_NODELAY_UNSET) {
        return RP_OK;
    }

    rp_log_debug0(RP_LOG_DEBUG_CORE, c->log, 0, "tcp_nodelay");

    tcp_nodelay = 1;

    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const void *) &tcp_nodelay, sizeof(int))
        == -1)
    {
#if (RP_SOLARIS)
        if (c->log_error == RP_ERROR_INFO) {

            /* Solaris returns EINVAL if a socket has been shut down */
            c->log_error = RP_ERROR_IGNORE_EINVAL;

            rp_connection_error(c, rp_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");

            c->log_error = RP_ERROR_INFO;

            return RP_ERROR;
        }
#endif

        rp_connection_error(c, rp_socket_errno,
                             "setsockopt(TCP_NODELAY) failed");
        return RP_ERROR;
    }

    c->tcp_nodelay = RP_TCP_NODELAY_SET;

    return RP_OK;
}


rp_int_t
rp_connection_error(rp_connection_t *c, rp_err_t err, char *text)
{
    rp_uint_t  level;

    /* Winsock may return RP_ECONNABORTED instead of RP_ECONNRESET */

    if ((err == RP_ECONNRESET
#if (RP_WIN32)
         || err == RP_ECONNABORTED
#endif
        ) && c->log_error == RP_ERROR_IGNORE_ECONNRESET)
    {
        return 0;
    }

#if (RP_SOLARIS)
    if (err == RP_EINVAL && c->log_error == RP_ERROR_IGNORE_EINVAL) {
        return 0;
    }
#endif

    if (err == 0
        || err == RP_ECONNRESET
#if (RP_WIN32)
        || err == RP_ECONNABORTED
#else
        || err == RP_EPIPE
#endif
        || err == RP_ENOTCONN
        || err == RP_ETIMEDOUT
        || err == RP_ECONNREFUSED
        || err == RP_ENETDOWN
        || err == RP_ENETUNREACH
        || err == RP_EHOSTDOWN
        || err == RP_EHOSTUNREACH)
    {
        switch (c->log_error) {

        case RP_ERROR_IGNORE_EINVAL:
        case RP_ERROR_IGNORE_ECONNRESET:
        case RP_ERROR_INFO:
            level = RP_LOG_INFO;
            break;

        default:
            level = RP_LOG_ERR;
        }

    } else {
        level = RP_LOG_ALERT;
    }

    rp_log_error(level, c->log, err, text);

    return RP_ERROR;
}
