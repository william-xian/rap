
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if !(RP_WIN32)

struct rp_udp_connection_s {
    rp_rbtree_node_t   node;
    rp_connection_t   *connection;
    rp_buf_t          *buffer;
};


static void rp_close_accepted_udp_connection(rp_connection_t *c);
static ssize_t rp_udp_shared_recv(rp_connection_t *c, u_char *buf,
    size_t size);
static rp_int_t rp_insert_udp_connection(rp_connection_t *c);
static rp_connection_t *rp_lookup_udp_connection(rp_listening_t *ls,
    struct sockaddr *sockaddr, socklen_t socklen,
    struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
rp_event_recvmsg(rp_event_t *ev)
{
    ssize_t            n;
    rp_buf_t          buf;
    rp_log_t         *log;
    rp_err_t          err;
    socklen_t          socklen, local_socklen;
    rp_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    rp_sockaddr_t     sa, lsa;
    struct sockaddr   *sockaddr, *local_sockaddr;
    rp_listening_t   *ls;
    rp_event_conf_t  *ecf;
    rp_connection_t  *c, *lc;
    static u_char      buffer[65535];

#if (RP_HAVE_MSGHDR_MSG_CONTROL)

#if (RP_HAVE_IP_RECVDSTADDR)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (RP_HAVE_IP_PKTINFO)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (RP_HAVE_INET6 && RP_HAVE_IPV6_RECVPKTINFO)
    u_char             msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

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
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        rp_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(rp_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (RP_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {

#if (RP_HAVE_IP_RECVDSTADDR || RP_HAVE_IP_PKTINFO)
            if (ls->sockaddr->sa_family == AF_INET) {
                msg.msg_control = &msg_control;
                msg.msg_controllen = sizeof(msg_control);
            }
#endif

#if (RP_HAVE_INET6 && RP_HAVE_IPV6_RECVPKTINFO)
            if (ls->sockaddr->sa_family == AF_INET6) {
                msg.msg_control = &msg_control6;
                msg.msg_controllen = sizeof(msg_control6);
            }
#endif
        }

#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = rp_socket_errno;

            if (err == RP_EAGAIN) {
                rp_log_debug0(RP_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            rp_log_error(RP_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (RP_HAVE_MSGHDR_MSG_CONTROL)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            rp_log_error(RP_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(rp_sockaddr_t)) {
            socklen = sizeof(rp_sockaddr_t);
        }

        if (socklen == 0) {

            /*
             * on Linux recvmsg() returns zero msg_namelen
             * when receiving packets from unbound AF_UNIX sockets
             */

            socklen = sizeof(struct sockaddr);
            rp_memzero(&sa, sizeof(struct sockaddr));
            sa.sockaddr.sa_family = ls->sockaddr->sa_family;
        }

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (RP_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            rp_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {

#if (RP_HAVE_IP_RECVDSTADDR)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_RECVDSTADDR
                    && local_sockaddr->sa_family == AF_INET)
                {
                    struct in_addr      *addr;
                    struct sockaddr_in  *sin;

                    addr = (struct in_addr *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) local_sockaddr;
                    sin->sin_addr = *addr;

                    break;
                }

#elif (RP_HAVE_IP_PKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_PKTINFO
                    && local_sockaddr->sa_family == AF_INET)
                {
                    struct in_pktinfo   *pkt;
                    struct sockaddr_in  *sin;

                    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) local_sockaddr;
                    sin->sin_addr = pkt->ipi_addr;

                    break;
                }

#endif

#if (RP_HAVE_INET6 && RP_HAVE_IPV6_RECVPKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IPV6
                    && cmsg->cmsg_type == IPV6_PKTINFO
                    && local_sockaddr->sa_family == AF_INET6)
                {
                    struct in6_pktinfo   *pkt6;
                    struct sockaddr_in6  *sin6;

                    pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
                    sin6 = (struct sockaddr_in6 *) local_sockaddr;
                    sin6->sin6_addr = pkt6->ipi6_addr;

                    break;
                }

#endif

            }
        }

#endif

        c = rp_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
                                      local_socklen);

        if (c) {

#if (RP_DEBUG)
            if (c->log->log_level & RP_LOG_DEBUG_EVENT) {
                rp_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                               "recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            rp_memzero(&buf, sizeof(rp_buf_t));

            buf.pos = buffer;
            buf.last = buffer + n;

            rev = c->read;

            c->udp->buffer = &buf;

            rev->ready = 1;
            rev->active = 0;

            rev->handler(rev);

            if (c->udp) {
                c->udp->buffer = NULL;
            }

            rev->ready = 0;
            rev->active = 1;

            goto next;
        }

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_accepted, 1);
#endif

        rp_accept_disabled = rp_cycle->connection_n / 8
                              - rp_cycle->free_connection_n;

        c = rp_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (RP_STAT_STUB)
        (void) rp_atomic_fetch_add(rp_stat_active, 1);
#endif

        c->pool = rp_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            rp_close_accepted_udp_connection(c);
            return;
        }

        c->sockaddr = rp_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            rp_close_accepted_udp_connection(c);
            return;
        }

        rp_memcpy(c->sockaddr, sockaddr, socklen);

        log = rp_palloc(c->pool, sizeof(rp_log_t));
        if (log == NULL) {
            rp_close_accepted_udp_connection(c);
            return;
        }

        *log = ls->log;

        c->recv = rp_udp_shared_recv;
        c->send = rp_udp_send;
        c->send_chain = rp_udp_send_chain;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = rp_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                rp_close_accepted_udp_connection(c);
                return;
            }

            rp_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = rp_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            rp_close_accepted_udp_connection(c);
            return;
        }

        c->buffer->last = rp_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

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
                rp_close_accepted_udp_connection(c);
                return;
            }

            c->addr_text.len = rp_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                rp_close_accepted_udp_connection(c);
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

            rp_log_debug4(RP_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        if (rp_insert_udp_connection(c) != RP_OK) {
            rp_close_accepted_udp_connection(c);
            return;
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
rp_close_accepted_udp_connection(rp_connection_t *c)
{
    rp_free_connection(c);

    c->fd = (rp_socket_t) -1;

    if (c->pool) {
        rp_destroy_pool(c->pool);
    }

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_active, -1);
#endif
}


static ssize_t
rp_udp_shared_recv(rp_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    rp_buf_t  *b;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return RP_AGAIN;
    }

    b = c->udp->buffer;

    n = rp_min(b->last - b->pos, (ssize_t) size);

    rp_memcpy(buf, b->pos, n);

    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


void
rp_udp_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_int_t               rc;
    rp_connection_t       *c, *ct;
    rp_rbtree_node_t     **p;
    rp_udp_connection_t   *udp, *udpt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (rp_udp_connection_t *) node;
            c = udp->connection;

            udpt = (rp_udp_connection_t *) temp;
            ct = udpt->connection;

            rc = rp_cmp_sockaddr(c->sockaddr, c->socklen,
                                  ct->sockaddr, ct->socklen, 1);

            if (rc == 0 && c->listening->wildcard) {
                rc = rp_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
                                      ct->local_sockaddr, ct->local_socklen, 1);
            }

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    rp_rbt_red(node);
}


static rp_int_t
rp_insert_udp_connection(rp_connection_t *c)
{
    uint32_t               hash;
    rp_pool_cleanup_t    *cln;
    rp_udp_connection_t  *udp;

    if (c->udp) {
        return RP_OK;
    }

    udp = rp_pcalloc(c->pool, sizeof(rp_udp_connection_t));
    if (udp == NULL) {
        return RP_ERROR;
    }

    udp->connection = c;

    rp_crc32_init(hash);
    rp_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        rp_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    rp_crc32_final(hash);

    udp->node.key = hash;

    cln = rp_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return RP_ERROR;
    }

    cln->data = c;
    cln->handler = rp_delete_udp_connection;

    rp_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return RP_OK;
}


void
rp_delete_udp_connection(void *data)
{
    rp_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    rp_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


static rp_connection_t *
rp_lookup_udp_connection(rp_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    rp_int_t              rc;
    rp_connection_t      *c;
    rp_rbtree_node_t     *node, *sentinel;
    rp_udp_connection_t  *udp;

#if (RP_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            rp_log_debug0(RP_LOG_DEBUG_EVENT, rp_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    rp_crc32_init(hash);
    rp_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        rp_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

    rp_crc32_final(hash);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        udp = (rp_udp_connection_t *) node;

        c = udp->connection;

        rc = rp_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = rp_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#else

void
rp_delete_udp_connection(void *data)
{
    return;
}

#endif
