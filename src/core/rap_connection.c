
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


rap_os_io_t  rap_io;


static void rap_drain_connections(rap_cycle_t *cycle);


rap_listening_t *
rap_create_listening(rap_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    size_t            len;
    rap_listening_t  *ls;
    struct sockaddr  *sa;
    u_char            text[RAP_SOCKADDR_STRLEN];

    ls = rap_array_push(&cf->cycle->listening);
    if (ls == NULL) {
        return NULL;
    }

    rap_memzero(ls, sizeof(rap_listening_t));

    sa = rap_palloc(cf->pool, socklen);
    if (sa == NULL) {
        return NULL;
    }

    rap_memcpy(sa, sockaddr, socklen);

    ls->sockaddr = sa;
    ls->socklen = socklen;

    len = rap_sock_ntop(sa, socklen, text, RAP_SOCKADDR_STRLEN, 1);
    ls->addr_text.len = len;

    switch (ls->sockaddr->sa_family) {
#if (RAP_HAVE_INET6)
    case AF_INET6:
        ls->addr_text_max_len = RAP_INET6_ADDRSTRLEN;
        break;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        ls->addr_text_max_len = RAP_UNIX_ADDRSTRLEN;
        len++;
        break;
#endif
    case AF_INET:
        ls->addr_text_max_len = RAP_INET_ADDRSTRLEN;
        break;
    default:
        ls->addr_text_max_len = RAP_SOCKADDR_STRLEN;
        break;
    }

    ls->addr_text.data = rap_pnalloc(cf->pool, len);
    if (ls->addr_text.data == NULL) {
        return NULL;
    }

    rap_memcpy(ls->addr_text.data, text, len);

#if !(RAP_WIN32)
    rap_rbtree_init(&ls->rbtree, &ls->sentinel, rap_udp_rbtree_insert_value);
#endif

    ls->fd = (rap_socket_t) -1;
    ls->type = SOCK_STREAM;

    ls->backlog = RAP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

#if (RAP_HAVE_SETFIB)
    ls->setfib = -1;
#endif

#if (RAP_HAVE_TCP_FASTOPEN)
    ls->fastopen = -1;
#endif

    return ls;
}


rap_int_t
rap_clone_listening(rap_cycle_t *cycle, rap_listening_t *ls)
{
#if (RAP_HAVE_REUSEPORT)

    rap_int_t         n;
    rap_core_conf_t  *ccf;
    rap_listening_t   ols;

    if (!ls->reuseport || ls->worker != 0) {
        return RAP_OK;
    }

    ols = *ls;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    for (n = 1; n < ccf->worker_processes; n++) {

        /* create a socket for each worker process */

        ls = rap_array_push(&cycle->listening);
        if (ls == NULL) {
            return RAP_ERROR;
        }

        *ls = ols;
        ls->worker = n;
    }

#endif

    return RAP_OK;
}


rap_int_t
rap_set_inherited_sockets(rap_cycle_t *cycle)
{
    size_t                     len;
    rap_uint_t                 i;
    rap_listening_t           *ls;
    socklen_t                  olen;
#if (RAP_HAVE_DEFERRED_ACCEPT || RAP_HAVE_TCP_FASTOPEN)
    rap_err_t                  err;
#endif
#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    struct accept_filter_arg   af;
#endif
#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    int                        timeout;
#endif
#if (RAP_HAVE_REUSEPORT)
    int                        reuseport;
#endif

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        ls[i].sockaddr = rap_palloc(cycle->pool, sizeof(rap_sockaddr_t));
        if (ls[i].sockaddr == NULL) {
            return RAP_ERROR;
        }

        ls[i].socklen = sizeof(rap_sockaddr_t);
        if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
            rap_log_error(RAP_LOG_CRIT, cycle->log, rap_socket_errno,
                          "getsockname() of the inherited "
                          "socket #%d failed", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        if (ls[i].socklen > (socklen_t) sizeof(rap_sockaddr_t)) {
            ls[i].socklen = sizeof(rap_sockaddr_t);
        }

        switch (ls[i].sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            ls[i].addr_text_max_len = RAP_INET6_ADDRSTRLEN;
            len = RAP_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;
            break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            ls[i].addr_text_max_len = RAP_UNIX_ADDRSTRLEN;
            len = RAP_UNIX_ADDRSTRLEN;
            break;
#endif

        case AF_INET:
            ls[i].addr_text_max_len = RAP_INET_ADDRSTRLEN;
            len = RAP_INET_ADDRSTRLEN + sizeof(":65535") - 1;
            break;

        default:
            rap_log_error(RAP_LOG_CRIT, cycle->log, rap_socket_errno,
                          "the inherited socket #%d has "
                          "an unsupported protocol family", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        ls[i].addr_text.data = rap_pnalloc(cycle->pool, len);
        if (ls[i].addr_text.data == NULL) {
            return RAP_ERROR;
        }

        len = rap_sock_ntop(ls[i].sockaddr, ls[i].socklen,
                            ls[i].addr_text.data, len, 1);
        if (len == 0) {
            return RAP_ERROR;
        }

        ls[i].addr_text.len = len;

        ls[i].backlog = RAP_LISTEN_BACKLOG;

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_TYPE, (void *) &ls[i].type,
                       &olen)
            == -1)
        {
            rap_log_error(RAP_LOG_CRIT, cycle->log, rap_socket_errno,
                          "getsockopt(SO_TYPE) %V failed", &ls[i].addr_text);
            ls[i].ignore = 1;
            continue;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF, (void *) &ls[i].rcvbuf,
                       &olen)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                          "getsockopt(SO_RCVBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].rcvbuf = -1;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF, (void *) &ls[i].sndbuf,
                       &olen)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                          "getsockopt(SO_SNDBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].sndbuf = -1;
        }

#if 0
        /* SO_SETFIB is currently a set only option */

#if (RAP_HAVE_SETFIB)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                       (void *) &ls[i].setfib, &olen)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                          "getsockopt(SO_SETFIB) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].setfib = -1;
        }

#endif
#endif

#if (RAP_HAVE_REUSEPORT)

        reuseport = 0;
        olen = sizeof(int);

#ifdef SO_REUSEPORT_LB

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
                       (void *) &reuseport, &olen)
            == -1)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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

#if (RAP_HAVE_TCP_FASTOPEN)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                       (void *) &ls[i].fastopen, &olen)
            == -1)
        {
            err = rap_socket_errno;

            if (err != RAP_EOPNOTSUPP && err != RAP_ENOPROTOOPT
                && err != RAP_EINVAL)
            {
                rap_log_error(RAP_LOG_NOTICE, cycle->log, err,
                              "getsockopt(TCP_FASTOPEN) %V failed, ignored",
                              &ls[i].addr_text);
            }

            ls[i].fastopen = -1;
        }

#endif

#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

        rap_memzero(&af, sizeof(struct accept_filter_arg));
        olen = sizeof(struct accept_filter_arg);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &olen)
            == -1)
        {
            err = rap_socket_errno;

            if (err == RAP_EINVAL) {
                continue;
            }

            rap_log_error(RAP_LOG_NOTICE, cycle->log, err,
                          "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (olen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
            continue;
        }

        ls[i].accept_filter = rap_palloc(cycle->pool, 16);
        if (ls[i].accept_filter == NULL) {
            return RAP_ERROR;
        }

        (void) rap_cpystrn((u_char *) ls[i].accept_filter,
                           (u_char *) af.af_name, 16);
#endif

#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

        timeout = 0;
        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &olen)
            == -1)
        {
            err = rap_socket_errno;

            if (err == RAP_EOPNOTSUPP) {
                continue;
            }

            rap_log_error(RAP_LOG_NOTICE, cycle->log, err,
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

    return RAP_OK;
}


rap_int_t
rap_open_listening_sockets(rap_cycle_t *cycle)
{
    int               reuseaddr;
    rap_uint_t        i, tries, failed;
    rap_err_t         err;
    rap_log_t        *log;
    rap_socket_t      s;
    rap_listening_t  *ls;

    reuseaddr = 1;
#if (RAP_SUPPRESS_WARN)
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

#if (RAP_HAVE_REUSEPORT)

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
                    rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed, "
                                  "ignored",
                                  &ls[i].addr_text);
                }

#else

                if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed, ignored",
                                  &ls[i].addr_text);
                }
#endif

                ls[i].add_reuseport = 0;
            }
#endif

            if (ls[i].fd != (rap_socket_t) -1) {
                continue;
            }

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                continue;
            }

            s = rap_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);

            if (s == (rap_socket_t) -1) {
                rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                              rap_socket_n " %V failed", &ls[i].addr_text);
                return RAP_ERROR;
            }

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuseaddr, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                              "setsockopt(SO_REUSEADDR) %V failed",
                              &ls[i].addr_text);

                if (rap_close_socket(s) == -1) {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  rap_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                return RAP_ERROR;
            }

#if (RAP_HAVE_REUSEPORT)

            if (ls[i].reuseport && !rap_test_config) {
                int  reuseport;

                reuseport = 1;

#ifdef SO_REUSEPORT_LB

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed",
                                  &ls[i].addr_text);

                    if (rap_close_socket(s) == -1) {
                        rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                      rap_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RAP_ERROR;
                }

#else

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed",
                                  &ls[i].addr_text);

                    if (rap_close_socket(s) == -1) {
                        rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                      rap_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RAP_ERROR;
                }
#endif
            }
#endif

#if (RAP_HAVE_INET6 && defined IPV6_V6ONLY)

            if (ls[i].sockaddr->sa_family == AF_INET6) {
                int  ipv6only;

                ipv6only = ls[i].ipv6only;

                if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                               (const void *) &ipv6only, sizeof(int))
                    == -1)
                {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  "setsockopt(IPV6_V6ONLY) %V failed, ignored",
                                  &ls[i].addr_text);
                }
            }
#endif
            /* TODO: close on exit */

            if (!(rap_event_flags & RAP_USE_IOCP_EVENT)) {
                if (rap_nonblocking(s) == -1) {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  rap_nonblocking_n " %V failed",
                                  &ls[i].addr_text);

                    if (rap_close_socket(s) == -1) {
                        rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                      rap_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return RAP_ERROR;
                }
            }

            rap_log_debug2(RAP_LOG_DEBUG_CORE, log, 0,
                           "bind() %V #%d ", &ls[i].addr_text, s);

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = rap_socket_errno;

                if (err != RAP_EADDRINUSE || !rap_test_config) {
                    rap_log_error(RAP_LOG_EMERG, log, err,
                                  "bind() to %V failed", &ls[i].addr_text);
                }

                if (rap_close_socket(s) == -1) {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  rap_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != RAP_EADDRINUSE) {
                    return RAP_ERROR;
                }

                if (!rap_test_config) {
                    failed = 1;
                }

                continue;
            }

#if (RAP_HAVE_UNIX_DOMAIN)

            if (ls[i].sockaddr->sa_family == AF_UNIX) {
                mode_t   mode;
                u_char  *name;

                name = ls[i].addr_text.data + sizeof("unix:") - 1;
                mode = (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

                if (chmod((char *) name, mode) == -1) {
                    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                  "chmod() \"%s\" failed", name);
                }

                if (rap_test_config) {
                    if (rap_delete_file(name) == RAP_FILE_ERROR) {
                        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                      rap_delete_file_n " %s failed", name);
                    }
                }
            }
#endif

            if (ls[i].type != SOCK_STREAM) {
                ls[i].fd = s;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                err = rap_socket_errno;

                /*
                 * on OpenVZ after suspend/resume EADDRINUSE
                 * may be returned by listen() instead of bind(), see
                 * https://bugzilla.openvz.org/show_bug.cgi?id=2470
                 */

                if (err != RAP_EADDRINUSE || !rap_test_config) {
                    rap_log_error(RAP_LOG_EMERG, log, err,
                                  "listen() to %V, backlog %d failed",
                                  &ls[i].addr_text, ls[i].backlog);
                }

                if (rap_close_socket(s) == -1) {
                    rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                                  rap_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != RAP_EADDRINUSE) {
                    return RAP_ERROR;
                }

                if (!rap_test_config) {
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

        rap_log_error(RAP_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");

        rap_msleep(500);
    }

    if (failed) {
        rap_log_error(RAP_LOG_EMERG, log, 0, "still could not bind()");
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_configure_listening_sockets(rap_cycle_t *cycle)
{
    int                        value;
    rap_uint_t                 i;
    rap_listening_t           *ls;

#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
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
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(SO_RCVBUF, %d) %V failed, ignored",
                              ls[i].rcvbuf, &ls[i].addr_text);
            }
        }

        if (ls[i].sndbuf != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF,
                           (const void *) &ls[i].sndbuf, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(SO_KEEPALIVE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

#if (RAP_HAVE_KEEPALIVE_TUNABLE)

        if (ls[i].keepidle) {
            value = ls[i].keepidle;

#if (RAP_KEEPALIVE_FACTOR)
            value *= RAP_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPIDLE,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(TCP_KEEPIDLE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepintvl) {
            value = ls[i].keepintvl;

#if (RAP_KEEPALIVE_FACTOR)
            value *= RAP_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPINTVL,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                             "setsockopt(TCP_KEEPINTVL, %d) %V failed, ignored",
                             value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepcnt) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPCNT,
                           (const void *) &ls[i].keepcnt, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(TCP_KEEPCNT, %d) %V failed, ignored",
                              ls[i].keepcnt, &ls[i].addr_text);
            }
        }

#endif

#if (RAP_HAVE_SETFIB)
        if (ls[i].setfib != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                           (const void *) &ls[i].setfib, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(SO_SETFIB, %d) %V failed, ignored",
                              ls[i].setfib, &ls[i].addr_text);
            }
        }
#endif

#if (RAP_HAVE_TCP_FASTOPEN)
        if (ls[i].fastopen != -1) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                           (const void *) &ls[i].fastopen, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(TCP_NODELAY) %V failed, ignored",
                              &ls[i].addr_text);
            }
        }
#endif

        if (ls[i].listen) {

            /* change backlog via listen() */

            if (listen(ls[i].fd, ls[i].backlog) == -1) {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "listen() to %V, backlog %d failed, ignored",
                              &ls[i].addr_text, ls[i].backlog);
            }
        }

        /*
         * setting deferred mode should be last operation on socket,
         * because code may prematurely continue cycle on failure
         */

#if (RAP_HAVE_DEFERRED_ACCEPT)

#ifdef SO_ACCEPTFILTER

        if (ls[i].delete_deferred) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, NULL, 0)
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(SO_ACCEPTFILTER, NULL) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);

                if (ls[i].accept_filter) {
                    rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                                  "could not change the accept filter "
                                  "to \"%s\" for %V, ignored",
                                  ls[i].accept_filter, &ls[i].addr_text);
                }

                continue;
            }

            ls[i].deferred_accept = 0;
        }

        if (ls[i].add_deferred) {
            rap_memzero(&af, sizeof(struct accept_filter_arg));
            (void) rap_cpystrn((u_char *) af.af_name,
                               (u_char *) ls[i].accept_filter, 16);

            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER,
                           &af, sizeof(struct accept_filter_arg))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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

#endif /* RAP_HAVE_DEFERRED_ACCEPT */

#if (RAP_HAVE_IP_RECVDSTADDR)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_RECVDSTADDR,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(IP_RECVDSTADDR) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#elif (RAP_HAVE_IP_PKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_PKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
                              "setsockopt(IP_PKTINFO) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET6)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                rap_log_error(RAP_LOG_ALERT, cycle->log, rap_socket_errno,
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
rap_close_listening_sockets(rap_cycle_t *cycle)
{
    rap_uint_t         i;
    rap_listening_t   *ls;
    rap_connection_t  *c;

    if (rap_event_flags & RAP_USE_IOCP_EVENT) {
        return;
    }

    rap_accept_mutex_held = 0;
    rap_use_accept_mutex = 0;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c) {
            if (c->read->active) {
                if (rap_event_flags & RAP_USE_EPOLL_EVENT) {

                    /*
                     * it seems that Linux-2.6.x OpenVZ sends events
                     * for closed shared listening sockets unless
                     * the events was explicitly deleted
                     */

                    rap_del_event(c->read, RAP_READ_EVENT, 0);

                } else {
                    rap_del_event(c->read, RAP_READ_EVENT, RAP_CLOSE_EVENT);
                }
            }

            rap_free_connection(c);

            c->fd = (rap_socket_t) -1;
        }

        rap_log_debug2(RAP_LOG_DEBUG_CORE, cycle->log, 0,
                       "close listening %V #%d ", &ls[i].addr_text, ls[i].fd);

        if (rap_close_socket(ls[i].fd) == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_socket_errno,
                          rap_close_socket_n " %V failed", &ls[i].addr_text);
        }

#if (RAP_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX
            && rap_process <= RAP_PROCESS_MASTER
            && rap_new_binary == 0)
        {
            u_char *name = ls[i].addr_text.data + sizeof("unix:") - 1;

            if (rap_delete_file(name) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_socket_errno,
                              rap_delete_file_n " %s failed", name);
            }
        }

#endif

        ls[i].fd = (rap_socket_t) -1;
    }

    cycle->listening.nelts = 0;
}


rap_connection_t *
rap_get_connection(rap_socket_t s, rap_log_t *log)
{
    rap_uint_t         instance;
    rap_event_t       *rev, *wev;
    rap_connection_t  *c;

    /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

    if (rap_cycle->files && (rap_uint_t) s >= rap_cycle->files_n) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "the new socket has number %d, "
                      "but only %ui files are available",
                      s, rap_cycle->files_n);
        return NULL;
    }

    c = rap_cycle->free_connections;

    if (c == NULL) {
        rap_drain_connections((rap_cycle_t *) rap_cycle);
        c = rap_cycle->free_connections;
    }

    if (c == NULL) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "%ui worker_connections are not enough",
                      rap_cycle->connection_n);

        return NULL;
    }

    rap_cycle->free_connections = c->data;
    rap_cycle->free_connection_n--;

    if (rap_cycle->files && rap_cycle->files[s] == NULL) {
        rap_cycle->files[s] = c;
    }

    rev = c->read;
    wev = c->write;

    rap_memzero(c, sizeof(rap_connection_t));

    c->read = rev;
    c->write = wev;
    c->fd = s;
    c->log = log;

    instance = rev->instance;

    rap_memzero(rev, sizeof(rap_event_t));
    rap_memzero(wev, sizeof(rap_event_t));

    rev->instance = !instance;
    wev->instance = !instance;

    rev->index = RAP_INVALID_INDEX;
    wev->index = RAP_INVALID_INDEX;

    rev->data = c;
    wev->data = c;

    wev->write = 1;

    return c;
}


void
rap_free_connection(rap_connection_t *c)
{
    c->data = rap_cycle->free_connections;
    rap_cycle->free_connections = c;
    rap_cycle->free_connection_n++;

    if (rap_cycle->files && rap_cycle->files[c->fd] == c) {
        rap_cycle->files[c->fd] = NULL;
    }
}


void
rap_close_connection(rap_connection_t *c)
{
    rap_err_t     err;
    rap_uint_t    log_error, level;
    rap_socket_t  fd;

    if (c->fd == (rap_socket_t) -1) {
        rap_log_error(RAP_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    if (c->write->timer_set) {
        rap_del_timer(c->write);
    }

    if (!c->shared) {
        if (rap_del_conn) {
            rap_del_conn(c, RAP_CLOSE_EVENT);

        } else {
            if (c->read->active || c->read->disabled) {
                rap_del_event(c->read, RAP_READ_EVENT, RAP_CLOSE_EVENT);
            }

            if (c->write->active || c->write->disabled) {
                rap_del_event(c->write, RAP_WRITE_EVENT, RAP_CLOSE_EVENT);
            }
        }
    }

    if (c->read->posted) {
        rap_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        rap_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    rap_reusable_connection(c, 0);

    log_error = c->log_error;

    rap_free_connection(c);

    fd = c->fd;
    c->fd = (rap_socket_t) -1;

    if (c->shared) {
        return;
    }

    if (rap_close_socket(fd) == -1) {

        err = rap_socket_errno;

        if (err == RAP_ECONNRESET || err == RAP_ENOTCONN) {

            switch (log_error) {

            case RAP_ERROR_INFO:
                level = RAP_LOG_INFO;
                break;

            case RAP_ERROR_ERR:
                level = RAP_LOG_ERR;
                break;

            default:
                level = RAP_LOG_CRIT;
            }

        } else {
            level = RAP_LOG_CRIT;
        }

        rap_log_error(level, c->log, err, rap_close_socket_n " %d failed", fd);
    }
}


void
rap_reusable_connection(rap_connection_t *c, rap_uint_t reusable)
{
    rap_log_debug1(RAP_LOG_DEBUG_CORE, c->log, 0,
                   "reusable connection: %ui", reusable);

    if (c->reusable) {
        rap_queue_remove(&c->queue);
        rap_cycle->reusable_connections_n--;

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_waiting, -1);
#endif
    }

    c->reusable = reusable;

    if (reusable) {
        /* need cast as rap_cycle is volatile */

        rap_queue_insert_head(
            (rap_queue_t *) &rap_cycle->reusable_connections_queue, &c->queue);
        rap_cycle->reusable_connections_n++;

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_waiting, 1);
#endif
    }
}


static void
rap_drain_connections(rap_cycle_t *cycle)
{
    rap_uint_t         i, n;
    rap_queue_t       *q;
    rap_connection_t  *c;

    n = rap_max(rap_min(32, cycle->reusable_connections_n / 8), 1);

    for (i = 0; i < n; i++) {
        if (rap_queue_empty(&cycle->reusable_connections_queue)) {
            break;
        }

        q = rap_queue_last(&cycle->reusable_connections_queue);
        c = rap_queue_data(q, rap_connection_t, queue);

        rap_log_debug0(RAP_LOG_DEBUG_CORE, c->log, 0,
                       "reusing connection");

        c->close = 1;
        c->read->handler(c->read);
    }
}


void
rap_close_idle_connections(rap_cycle_t *cycle)
{
    rap_uint_t         i;
    rap_connection_t  *c;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        /* THREAD: lock */

        if (c[i].fd != (rap_socket_t) -1 && c[i].idle) {
            c[i].close = 1;
            c[i].read->handler(c[i].read);
        }
    }
}


rap_int_t
rap_connection_local_sockaddr(rap_connection_t *c, rap_str_t *s,
    rap_uint_t port)
{
    socklen_t             len;
    rap_uint_t            addr;
    rap_sockaddr_t        sa;
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    rap_uint_t            i;
    struct sockaddr_in6  *sin6;
#endif

    addr = 0;

    if (c->local_socklen) {
        switch (c->local_sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            for (i = 0; addr == 0 && i < 16; i++) {
                addr |= sin6->sin6_addr.s6_addr[i];
            }

            break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
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

        len = sizeof(rap_sockaddr_t);

        if (getsockname(c->fd, &sa.sockaddr, &len) == -1) {
            rap_connection_error(c, rap_socket_errno, "getsockname() failed");
            return RAP_ERROR;
        }

        c->local_sockaddr = rap_palloc(c->pool, len);
        if (c->local_sockaddr == NULL) {
            return RAP_ERROR;
        }

        rap_memcpy(c->local_sockaddr, &sa, len);

        c->local_socklen = len;
    }

    if (s == NULL) {
        return RAP_OK;
    }

    s->len = rap_sock_ntop(c->local_sockaddr, c->local_socklen,
                           s->data, s->len, port);

    return RAP_OK;
}


rap_int_t
rap_tcp_nodelay(rap_connection_t *c)
{
    int  tcp_nodelay;

    if (c->tcp_nodelay != RAP_TCP_NODELAY_UNSET) {
        return RAP_OK;
    }

    rap_log_debug0(RAP_LOG_DEBUG_CORE, c->log, 0, "tcp_nodelay");

    tcp_nodelay = 1;

    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const void *) &tcp_nodelay, sizeof(int))
        == -1)
    {
#if (RAP_SOLARIS)
        if (c->log_error == RAP_ERROR_INFO) {

            /* Solaris returns EINVAL if a socket has been shut down */
            c->log_error = RAP_ERROR_IGNORE_EINVAL;

            rap_connection_error(c, rap_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");

            c->log_error = RAP_ERROR_INFO;

            return RAP_ERROR;
        }
#endif

        rap_connection_error(c, rap_socket_errno,
                             "setsockopt(TCP_NODELAY) failed");
        return RAP_ERROR;
    }

    c->tcp_nodelay = RAP_TCP_NODELAY_SET;

    return RAP_OK;
}


rap_int_t
rap_connection_error(rap_connection_t *c, rap_err_t err, char *text)
{
    rap_uint_t  level;

    /* Winsock may return RAP_ECONNABORTED instead of RAP_ECONNRESET */

    if ((err == RAP_ECONNRESET
#if (RAP_WIN32)
         || err == RAP_ECONNABORTED
#endif
        ) && c->log_error == RAP_ERROR_IGNORE_ECONNRESET)
    {
        return 0;
    }

#if (RAP_SOLARIS)
    if (err == RAP_EINVAL && c->log_error == RAP_ERROR_IGNORE_EINVAL) {
        return 0;
    }
#endif

    if (err == 0
        || err == RAP_ECONNRESET
#if (RAP_WIN32)
        || err == RAP_ECONNABORTED
#else
        || err == RAP_EPIPE
#endif
        || err == RAP_ENOTCONN
        || err == RAP_ETIMEDOUT
        || err == RAP_ECONNREFUSED
        || err == RAP_ENETDOWN
        || err == RAP_ENETUNREACH
        || err == RAP_EHOSTDOWN
        || err == RAP_EHOSTUNREACH)
    {
        switch (c->log_error) {

        case RAP_ERROR_IGNORE_EINVAL:
        case RAP_ERROR_IGNORE_ECONNRESET:
        case RAP_ERROR_INFO:
            level = RAP_LOG_INFO;
            break;

        default:
            level = RAP_LOG_ERR;
        }

    } else {
        level = RAP_LOG_ALERT;
    }

    rap_log_error(level, c->log, err, text);

    return RAP_ERROR;
}
