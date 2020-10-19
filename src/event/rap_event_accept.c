
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static rap_int_t rap_disable_accept_events(rap_cycle_t *cycle, rap_uint_t all);
static void rap_close_accepted_connection(rap_connection_t *c);


void
rap_event_accept(rap_event_t *ev)
{
    socklen_t          socklen;
    rap_err_t          err;
    rap_log_t         *log;
    rap_uint_t         level;
    rap_socket_t       s;
    rap_event_t       *rev, *wev;
    rap_sockaddr_t     sa;
    rap_listening_t   *ls;
    rap_connection_t  *c, *lc;
    rap_event_conf_t  *ecf;
#if (RAP_HAVE_ACCEPT4)
    static rap_uint_t  use_accept4 = 1;
#endif

    if (ev->timedout) {
        if (rap_enable_accept_events((rap_cycle_t *) rap_cycle) != RAP_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = rap_event_get_conf(rap_cycle->conf_ctx, rap_event_core_module);

    if (!(rap_event_flags & RAP_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        socklen = sizeof(rap_sockaddr_t);

#if (RAP_HAVE_ACCEPT4)
        if (use_accept4) {
            s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK);
        } else {
            s = accept(lc->fd, &sa.sockaddr, &socklen);
        }
#else
        s = accept(lc->fd, &sa.sockaddr, &socklen);
#endif

        if (s == (rap_socket_t) -1) {
            err = rap_socket_errno;

            if (err == RAP_EAGAIN) {
                rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, err,
                               "accept() not ready");
                return;
            }

            level = RAP_LOG_ALERT;

            if (err == RAP_ECONNABORTED) {
                level = RAP_LOG_ERR;

            } else if (err == RAP_EMFILE || err == RAP_ENFILE) {
                level = RAP_LOG_CRIT;
            }

#if (RAP_HAVE_ACCEPT4)
            rap_log_error(level, ev->log, err,
                          use_accept4 ? "accept4() failed" : "accept() failed");

            if (use_accept4 && err == RAP_ENOSYS) {
                use_accept4 = 0;
                rap_inherited_nonblocking = 0;
                continue;
            }
#else
            rap_log_error(level, ev->log, err, "accept() failed");
#endif

            if (err == RAP_ECONNABORTED) {
                if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            if (err == RAP_EMFILE || err == RAP_ENFILE) {
                if (rap_disable_accept_events((rap_cycle_t *) rap_cycle, 1)
                    != RAP_OK)
                {
                    return;
                }

                if (rap_use_accept_mutex) {
                    if (rap_accept_mutex_held) {
                        rap_shmtx_unlock(&rap_accept_mutex);
                        rap_accept_mutex_held = 0;
                    }

                    rap_accept_disabled = 1;

                } else {
                    rap_add_timer(ev, ecf->accept_mutex_delay);
                }
            }

            return;
        }

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_accepted, 1);
#endif

        rap_accept_disabled = rap_cycle->connection_n / 8
                              - rap_cycle->free_connection_n;

        c = rap_get_connection(s, ev->log);

        if (c == NULL) {
            if (rap_close_socket(s) == -1) {
                rap_log_error(RAP_LOG_ALERT, ev->log, rap_socket_errno,
                              rap_close_socket_n " failed");
            }

            return;
        }

        c->type = SOCK_STREAM;

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_active, 1);
#endif

        c->pool = rap_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            rap_close_accepted_connection(c);
            return;
        }

        if (socklen > (socklen_t) sizeof(rap_sockaddr_t)) {
            socklen = sizeof(rap_sockaddr_t);
        }

        c->sockaddr = rap_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            rap_close_accepted_connection(c);
            return;
        }

        rap_memcpy(c->sockaddr, &sa, socklen);

        log = rap_palloc(c->pool, sizeof(rap_log_t));
        if (log == NULL) {
            rap_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for iocp and non-blocking mode for others */

        if (rap_inherited_nonblocking) {
            if (rap_event_flags & RAP_USE_IOCP_EVENT) {
                if (rap_blocking(s) == -1) {
                    rap_log_error(RAP_LOG_ALERT, ev->log, rap_socket_errno,
                                  rap_blocking_n " failed");
                    rap_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            if (!(rap_event_flags & RAP_USE_IOCP_EVENT)) {
                if (rap_nonblocking(s) == -1) {
                    rap_log_error(RAP_LOG_ALERT, ev->log, rap_socket_errno,
                                  rap_nonblocking_n " failed");
                    rap_close_accepted_connection(c);
                    return;
                }
            }
        }

        *log = ls->log;

        c->recv = rap_recv;
        c->send = rap_send;
        c->recv_chain = rap_recv_chain;
        c->send_chain = rap_send_chain;

        c->log = log;
        c->pool->log = log;

        c->socklen = socklen;
        c->listening = ls;
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (RAP_HAVE_UNIX_DOMAIN)
        if (c->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = RAP_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = RAP_TCP_NODELAY_DISABLED;
#if (RAP_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }
#endif

        rev = c->read;
        wev = c->write;

        wev->ready = 1;

        if (rap_event_flags & RAP_USE_IOCP_EVENT) {
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
#if (RAP_HAVE_KQUEUE || RAP_HAVE_EPOLLRDHUP)
            rev->available = 1;
#endif
        }

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - rap_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - rap_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = rap_atomic_fetch_add(rap_connection_counter, 1);

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = rap_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                rap_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = rap_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                rap_close_accepted_connection(c);
                return;
            }
        }

#if (RAP_DEBUG)
        {
        rap_str_t  addr;
        u_char     text[RAP_SOCKADDR_STRLEN];

        rap_debug_accepted_connection(ecf, c);

        if (log->log_level & RAP_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = rap_sock_ntop(c->sockaddr, c->socklen, text,
                                     RAP_SOCKADDR_STRLEN, 1);

            rap_log_debug3(RAP_LOG_DEBUG_EVENT, log, 0,
                           "*%uA accept: %V fd:%d", c->number, &addr, s);
        }

        }
#endif

        if (rap_add_conn && (rap_event_flags & RAP_USE_EPOLL_EVENT) == 0) {
            if (rap_add_conn(c) == RAP_ERROR) {
                rap_close_accepted_connection(c);
                return;
            }
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

        if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);
}


rap_int_t
rap_trylock_accept_mutex(rap_cycle_t *cycle)
{
    if (rap_shmtx_trylock(&rap_accept_mutex)) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        if (rap_accept_mutex_held && rap_accept_events == 0) {
            return RAP_OK;
        }

        if (rap_enable_accept_events(cycle) == RAP_ERROR) {
            rap_shmtx_unlock(&rap_accept_mutex);
            return RAP_ERROR;
        }

        rap_accept_events = 0;
        rap_accept_mutex_held = 1;

        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "accept mutex lock failed: %ui", rap_accept_mutex_held);

    if (rap_accept_mutex_held) {
        if (rap_disable_accept_events(cycle, 0) == RAP_ERROR) {
            return RAP_ERROR;
        }

        rap_accept_mutex_held = 0;
    }

    return RAP_OK;
}


rap_int_t
rap_enable_accept_events(rap_cycle_t *cycle)
{
    rap_uint_t         i;
    rap_listening_t   *ls;
    rap_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || c->read->active) {
            continue;
        }

        if (rap_add_event(c->read, RAP_READ_EVENT, 0) == RAP_ERROR) {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_disable_accept_events(rap_cycle_t *cycle, rap_uint_t all)
{
    rap_uint_t         i;
    rap_listening_t   *ls;
    rap_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || !c->read->active) {
            continue;
        }

#if (RAP_HAVE_REUSEPORT)

        /*
         * do not disable accept on worker's own sockets
         * when disabling accept events due to accept mutex
         */

        if (ls[i].reuseport && !all) {
            continue;
        }

#endif

        if (rap_del_event(c->read, RAP_READ_EVENT, RAP_DISABLE_EVENT)
            == RAP_ERROR)
        {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static void
rap_close_accepted_connection(rap_connection_t *c)
{
    rap_socket_t  fd;

    rap_free_connection(c);

    fd = c->fd;
    c->fd = (rap_socket_t) -1;

    if (rap_close_socket(fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, c->log, rap_socket_errno,
                      rap_close_socket_n " failed");
    }

    if (c->pool) {
        rap_destroy_pool(c->pool);
    }

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_active, -1);
#endif
}


u_char *
rap_accept_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    return rap_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}


#if (RAP_DEBUG)

void
rap_debug_accepted_connection(rap_event_conf_t *ecf, rap_connection_t *c)
{
    struct sockaddr_in   *sin;
    rap_cidr_t           *cidr;
    rap_uint_t            i;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    rap_uint_t            n;
#endif

    cidr = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if (cidr[i].family != (rap_uint_t) c->sockaddr->sa_family) {
            goto next;
        }

        switch (cidr[i].family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;
            for (n = 0; n < 16; n++) {
                if ((sin6->sin6_addr.s6_addr[n]
                    & cidr[i].u.in6.mask.s6_addr[n])
                    != cidr[i].u.in6.addr.s6_addr[n])
                {
                    goto next;
                }
            }
            break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->sockaddr;
            if ((sin->sin_addr.s_addr & cidr[i].u.in.mask)
                != cidr[i].u.in.addr)
            {
                goto next;
            }
            break;
        }

        c->log->log_level = RAP_LOG_DEBUG_CONNECTION|RAP_LOG_DEBUG_ALL;
        break;

    next:
        continue;
    }
}

#endif
