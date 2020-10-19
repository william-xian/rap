
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#if !(RAP_WIN32)

struct rap_udp_connection_s {
    rap_rbtree_node_t   node;
    rap_connection_t   *connection;
    rap_buf_t          *buffer;
};


static void rap_close_accepted_udp_connection(rap_connection_t *c);
static ssize_t rap_udp_shared_recv(rap_connection_t *c, u_char *buf,
    size_t size);
static rap_int_t rap_insert_udp_connection(rap_connection_t *c);
static rap_connection_t *rap_lookup_udp_connection(rap_listening_t *ls,
    struct sockaddr *sockaddr, socklen_t socklen,
    struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
rap_event_recvmsg(rap_event_t *ev)
{
    ssize_t            n;
    rap_buf_t          buf;
    rap_log_t         *log;
    rap_err_t          err;
    socklen_t          socklen, local_socklen;
    rap_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    rap_sockaddr_t     sa, lsa;
    struct sockaddr   *sockaddr, *local_sockaddr;
    rap_listening_t   *ls;
    rap_event_conf_t  *ecf;
    rap_connection_t  *c, *lc;
    static u_char      buffer[65535];

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

#if (RAP_HAVE_IP_RECVDSTADDR)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (RAP_HAVE_IP_PKTINFO)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)
    u_char             msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

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
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        rap_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(rap_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {

#if (RAP_HAVE_IP_RECVDSTADDR || RAP_HAVE_IP_PKTINFO)
            if (ls->sockaddr->sa_family == AF_INET) {
                msg.msg_control = &msg_control;
                msg.msg_controllen = sizeof(msg_control);
            }
#endif

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)
            if (ls->sockaddr->sa_family == AF_INET6) {
                msg.msg_control = &msg_control6;
                msg.msg_controllen = sizeof(msg_control6);
            }
#endif
        }

#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = rap_socket_errno;

            if (err == RAP_EAGAIN) {
                rap_log_debug0(RAP_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            rap_log_error(RAP_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            rap_log_error(RAP_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(rap_sockaddr_t)) {
            socklen = sizeof(rap_sockaddr_t);
        }

        if (socklen == 0) {

            /*
             * on Linux recvmsg() returns zero msg_namelen
             * when receiving packets from unbound AF_UNIX sockets
             */

            socklen = sizeof(struct sockaddr);
            rap_memzero(&sa, sizeof(struct sockaddr));
            sa.sockaddr.sa_family = ls->sockaddr->sa_family;
        }

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (RAP_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            rap_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {

#if (RAP_HAVE_IP_RECVDSTADDR)

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

#elif (RAP_HAVE_IP_PKTINFO)

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

#if (RAP_HAVE_INET6 && RAP_HAVE_IPV6_RECVPKTINFO)

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

        c = rap_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
                                      local_socklen);

        if (c) {

#if (RAP_DEBUG)
            if (c->log->log_level & RAP_LOG_DEBUG_EVENT) {
                rap_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            rap_memzero(&buf, sizeof(rap_buf_t));

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

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_accepted, 1);
#endif

        rap_accept_disabled = rap_cycle->connection_n / 8
                              - rap_cycle->free_connection_n;

        c = rap_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (RAP_STAT_STUB)
        (void) rap_atomic_fetch_add(rap_stat_active, 1);
#endif

        c->pool = rap_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            rap_close_accepted_udp_connection(c);
            return;
        }

        c->sockaddr = rap_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            rap_close_accepted_udp_connection(c);
            return;
        }

        rap_memcpy(c->sockaddr, sockaddr, socklen);

        log = rap_palloc(c->pool, sizeof(rap_log_t));
        if (log == NULL) {
            rap_close_accepted_udp_connection(c);
            return;
        }

        *log = ls->log;

        c->recv = rap_udp_shared_recv;
        c->send = rap_udp_send;
        c->send_chain = rap_udp_send_chain;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = rap_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                rap_close_accepted_udp_connection(c);
                return;
            }

            rap_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = rap_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            rap_close_accepted_udp_connection(c);
            return;
        }

        c->buffer->last = rap_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

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
                rap_close_accepted_udp_connection(c);
                return;
            }

            c->addr_text.len = rap_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                rap_close_accepted_udp_connection(c);
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

            rap_log_debug4(RAP_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        if (rap_insert_udp_connection(c) != RAP_OK) {
            rap_close_accepted_udp_connection(c);
            return;
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
rap_close_accepted_udp_connection(rap_connection_t *c)
{
    rap_free_connection(c);

    c->fd = (rap_socket_t) -1;

    if (c->pool) {
        rap_destroy_pool(c->pool);
    }

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_active, -1);
#endif
}


static ssize_t
rap_udp_shared_recv(rap_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    rap_buf_t  *b;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return RAP_AGAIN;
    }

    b = c->udp->buffer;

    n = rap_min(b->last - b->pos, (ssize_t) size);

    rap_memcpy(buf, b->pos, n);

    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


void
rap_udp_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    rap_int_t               rc;
    rap_connection_t       *c, *ct;
    rap_rbtree_node_t     **p;
    rap_udp_connection_t   *udp, *udpt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (rap_udp_connection_t *) node;
            c = udp->connection;

            udpt = (rap_udp_connection_t *) temp;
            ct = udpt->connection;

            rc = rap_cmp_sockaddr(c->sockaddr, c->socklen,
                                  ct->sockaddr, ct->socklen, 1);

            if (rc == 0 && c->listening->wildcard) {
                rc = rap_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
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
    rap_rbt_red(node);
}


static rap_int_t
rap_insert_udp_connection(rap_connection_t *c)
{
    uint32_t               hash;
    rap_pool_cleanup_t    *cln;
    rap_udp_connection_t  *udp;

    if (c->udp) {
        return RAP_OK;
    }

    udp = rap_pcalloc(c->pool, sizeof(rap_udp_connection_t));
    if (udp == NULL) {
        return RAP_ERROR;
    }

    udp->connection = c;

    rap_crc32_init(hash);
    rap_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        rap_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    rap_crc32_final(hash);

    udp->node.key = hash;

    cln = rap_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->data = c;
    cln->handler = rap_delete_udp_connection;

    rap_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return RAP_OK;
}


void
rap_delete_udp_connection(void *data)
{
    rap_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    rap_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


static rap_connection_t *
rap_lookup_udp_connection(rap_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    rap_int_t              rc;
    rap_connection_t      *c;
    rap_rbtree_node_t     *node, *sentinel;
    rap_udp_connection_t  *udp;

#if (RAP_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, rap_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    rap_crc32_init(hash);
    rap_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        rap_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

    rap_crc32_final(hash);

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

        udp = (rap_udp_connection_t *) node;

        c = udp->connection;

        rc = rap_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = rap_cmp_sockaddr(local_sockaddr, local_socklen,
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
rap_delete_udp_connection(void *data)
{
    return;
}

#endif
