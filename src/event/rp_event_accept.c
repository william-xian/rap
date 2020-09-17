
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


static rp_int_t rp_disable_accept_events(rp_cycle_t *cycle, rp_uint_t all);
static void rp_close_accepted_connection(rp_connection_t *c);


void
rp_event_accept(rp_event_t *ev)
{
    socklen_t          socklen;
    rp_err_t          err;
    rp_log_t         *log;
    rp_uint_t         level;
    rp_socket_t       s;
    rp_event_t       *rev, *wev;
    rp_sockaddr_t     sa;
    rp_listening_t   *ls;
    rp_connection_t  *c, *lc;
    rp_event_conf_t  *ecf;
#if (RP_HAVE_ACCEPT4)
    static rp_uint_t  use_accept4 = 1;
#endif

    if (ev->timedout) {
        if (rp_enable_accept_events((rp_cycle_t *) rp_cycle) != RP_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = rp_event_get_conf(rp_cycle->conf_ctx, rp_event_core_module);

    if (!(rp_event_flags & RP_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        socklen = sizeof(rp_sockaddr_t);

#if (RP_HAVE_ACCEPT4)
        if (use_accept4) {
            s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK);
        } else {
            s = accept(lc->fd, &sa.sockaddr, &socklen);
        }
#else
        s = accept(lc->fd, &sa.sockaddr, &socklen);
#endif

        if (s == (rp_socket_t) -1) {
            err = rp_socket_errno;

            if (err == RP_EAGAIN) {
                rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, err,
                               "accept() not ready");
                return;
            }

            level = RP_LOG_ALERT;

            if (err == RP_ECONNABORTED) {
                level = RP_LOG_ERR;

            } else if (err == RP_EMFILE || err == RP_ENFILE) {
                level = RP_LOG_CRIT;
            }

#if (RP_HAVE_ACCEPT4)
            rp_log_error(level, ev->log, err,
                          use_accept4 ? "accept4() failed" : "accept() failed");

            if (use_accept4 && err == RP_ENOSYS) {
                use_accept4 = 0;
                rp_inherited_nonblocking = 0;
                continue;
            }
#else
            rp_log_error(level, ev->log, err, "accept() failed");
#endif

            if (err == RP_ECONNABORTED) {
                if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            if (err == RP_EMFILE || err == RP_ENFILE) {
                if (rp_disable_accept_events((rp_cycle_t *) rp_cycle, 1)
                    != RP_OK)
                {
                    return;
                }

                if (rp_use_accept_mutex) {
                    if (rp_accept_mutex_held) {
                        rp_shmtx_unlock(&rp_accept_mutex);
                        rp_accept_mutex_held = 0;
                    }

                    rp_accept_disabled = 1;

                } else {
                    rp_add_timer(ev, ecf->accept_mutex_delay);
                }
            }

            return;
        }

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_accepted, 1);
#endif

        rp_accept_disabled = rp_cycle->connection_n / 8
                              - rp_cycle->free_connection_n;

        c = rp_get_connection(s, ev->log);

        if (c == NULL) {
            if (rp_close_socket(s) == -1) {
                rp_log_error(RP_LOG_ALERT, ev->log, rp_socket_errno,
                              rp_close_socket_n " failed");
            }

            return;
        }

        c->type = SOCK_STREAM;

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_active, 1);
#endif

        c->pool = rp_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            rp_close_accepted_connection(c);
            return;
        }

        if (socklen > (socklen_t) sizeof(rp_sockaddr_t)) {
            socklen = sizeof(rp_sockaddr_t);
        }

        c->sockaddr = rp_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            rp_close_accepted_connection(c);
            return;
        }

        rp_memcpy(c->sockaddr, &sa, socklen);

        log = rp_palloc(c->pool, sizeof(rp_log_t));
        if (log == NULL) {
            rp_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for iocp and non-blocking mode for others */

        if (rp_inherited_nonblocking) {
            if (rp_event_flags & RP_USE_IOCP_EVENT) {
                if (rp_blocking(s) == -1) {
                    rp_log_error(RP_LOG_ALERT, ev->log, rp_socket_errno,
                                  rp_blocking_n " failed");
                    rp_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            if (!(rp_event_flags & RP_USE_IOCP_EVENT)) {
                if (rp_nonblocking(s) == -1) {
                    rp_log_error(RP_LOG_ALERT, ev->log, rp_socket_errno,
                                  rp_nonblocking_n " failed");
                    rp_close_accepted_connection(c);
                    return;
                }
            }
        }

        *log = ls->log;

        c->recv = rp_recv;
        c->send = rp_send;
        c->recv_chain = rp_recv_chain;
        c->send_chain = rp_send_chain;

        c->log = log;
        c->pool->log = log;

        c->socklen = socklen;
        c->listening = ls;
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (RP_HAVE_UNIX_DOMAIN)
        if (c->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = RP_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = RP_TCP_NODELAY_DISABLED;
#if (RP_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }
#endif

        rev = c->read;
        wev = c->write;

        wev->ready = 1;

        if (rp_event_flags & RP_USE_IOCP_EVENT) {
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
#if (RP_HAVE_KQUEUE || RP_HAVE_EPOLLRDHUP)
            rev->available = 1;
#endif
        }

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - rp_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - rp_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = rp_atomic_fetch_add(rp_connection_counter, 1);

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = rp_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                rp_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = rp_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                rp_close_accepted_connection(c);
                return;
            }
        }

#if (RP_DEBUG)
        {
        rp_str_t  addr;
        u_char     text[RP_SOCKADDR_STRLEN];

        rp_debug_accepted_connection(ecf, c);

        if (log->log_level & RP_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = rp_sock_ntop(c->sockaddr, c->socklen, text,
                                     RP_SOCKADDR_STRLEN, 1);

            rp_log_debug3(RP_LOG_DEBUG_EVENT, log, 0,
                           "*%uA accept: %V fd:%d", c->number, &addr, s);
        }

        }
#endif

        if (rp_add_conn && (rp_event_flags & RP_USE_EPOLL_EVENT) == 0) {
            if (rp_add_conn(c) == RP_ERROR) {
                rp_close_accepted_connection(c);
                return;
            }
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

        if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);
}


rp_int_t
rp_trylock_accept_mutex(rp_cycle_t *cycle)
{
    if (rp_shmtx_trylock(&rp_accept_mutex)) {

        rp_log_debug0(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        if (rp_accept_mutex_held && rp_accept_events == 0) {
            return RP_OK;
        }

        if (rp_enable_accept_events(cycle) == RP_ERROR) {
            rp_shmtx_unlock(&rp_accept_mutex);
            return RP_ERROR;
        }

        rp_accept_events = 0;
        rp_accept_mutex_held = 1;

        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                   "accept mutex lock failed: %ui", rp_accept_mutex_held);

    if (rp_accept_mutex_held) {
        if (rp_disable_accept_events(cycle, 0) == RP_ERROR) {
            return RP_ERROR;
        }

        rp_accept_mutex_held = 0;
    }

    return RP_OK;
}


rp_int_t
rp_enable_accept_events(rp_cycle_t *cycle)
{
    rp_uint_t         i;
    rp_listening_t   *ls;
    rp_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || c->read->active) {
            continue;
        }

        if (rp_add_event(c->read, RP_READ_EVENT, 0) == RP_ERROR) {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_disable_accept_events(rp_cycle_t *cycle, rp_uint_t all)
{
    rp_uint_t         i;
    rp_listening_t   *ls;
    rp_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || !c->read->active) {
            continue;
        }

#if (RP_HAVE_REUSEPORT)

        /*
         * do not disable accept on worker's own sockets
         * when disabling accept events due to accept mutex
         */

        if (ls[i].reuseport && !all) {
            continue;
        }

#endif

        if (rp_del_event(c->read, RP_READ_EVENT, RP_DISABLE_EVENT)
            == RP_ERROR)
        {
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static void
rp_close_accepted_connection(rp_connection_t *c)
{
    rp_socket_t  fd;

    rp_free_connection(c);

    fd = c->fd;
    c->fd = (rp_socket_t) -1;

    if (rp_close_socket(fd) == -1) {
        rp_log_error(RP_LOG_ALERT, c->log, rp_socket_errno,
                      rp_close_socket_n " failed");
    }

    if (c->pool) {
        rp_destroy_pool(c->pool);
    }

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_active, -1);
#endif
}


u_char *
rp_accept_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    return rp_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}


#if (RP_DEBUG)

void
rp_debug_accepted_connection(rp_event_conf_t *ecf, rp_connection_t *c)
{
    struct sockaddr_in   *sin;
    rp_cidr_t           *cidr;
    rp_uint_t            i;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    rp_uint_t            n;
#endif

    cidr = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if (cidr[i].family != (rp_uint_t) c->sockaddr->sa_family) {
            goto next;
        }

        switch (cidr[i].family) {

#if (RP_HAVE_INET6)
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

#if (RP_HAVE_UNIX_DOMAIN)
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

        c->log->log_level = RP_LOG_DEBUG_CONNECTION|RP_LOG_DEBUG_ALL;
        break;

    next:
        continue;
    }
}

#endif
