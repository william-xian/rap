
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define RP_RESOLVER_UDP_SIZE   4096

#define RP_RESOLVER_TCP_RSIZE  (2 + 65535)
#define RP_RESOLVER_TCP_WSIZE  8192


typedef struct {
    u_char  ident_hi;
    u_char  ident_lo;
    u_char  flags_hi;
    u_char  flags_lo;
    u_char  nqs_hi;
    u_char  nqs_lo;
    u_char  nan_hi;
    u_char  nan_lo;
    u_char  nns_hi;
    u_char  nns_lo;
    u_char  nar_hi;
    u_char  nar_lo;
} rp_resolver_hdr_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
} rp_resolver_qs_t;


typedef struct {
    u_char  type_hi;
    u_char  type_lo;
    u_char  class_hi;
    u_char  class_lo;
    u_char  ttl[4];
    u_char  len_hi;
    u_char  len_lo;
} rp_resolver_an_t;


#define rp_resolver_node(n)                                                 \
    (rp_resolver_node_t *)                                                  \
        ((u_char *) (n) - offsetof(rp_resolver_node_t, node))


static rp_int_t rp_udp_connect(rp_resolver_connection_t *rec);
static rp_int_t rp_tcp_connect(rp_resolver_connection_t *rec);


static void rp_resolver_cleanup(void *data);
static void rp_resolver_cleanup_tree(rp_resolver_t *r, rp_rbtree_t *tree);
static rp_int_t rp_resolve_name_locked(rp_resolver_t *r,
    rp_resolver_ctx_t *ctx, rp_str_t *name);
static void rp_resolver_expire(rp_resolver_t *r, rp_rbtree_t *tree,
    rp_queue_t *queue);
static rp_int_t rp_resolver_send_query(rp_resolver_t *r,
    rp_resolver_node_t *rn);
static rp_int_t rp_resolver_send_udp_query(rp_resolver_t *r,
    rp_resolver_connection_t *rec, u_char *query, u_short qlen);
static rp_int_t rp_resolver_send_tcp_query(rp_resolver_t *r,
    rp_resolver_connection_t *rec, u_char *query, u_short qlen);
static rp_int_t rp_resolver_create_name_query(rp_resolver_t *r,
    rp_resolver_node_t *rn, rp_str_t *name);
static rp_int_t rp_resolver_create_srv_query(rp_resolver_t *r,
    rp_resolver_node_t *rn, rp_str_t *name);
static rp_int_t rp_resolver_create_addr_query(rp_resolver_t *r,
    rp_resolver_node_t *rn, rp_resolver_addr_t *addr);
static void rp_resolver_resend_handler(rp_event_t *ev);
static time_t rp_resolver_resend(rp_resolver_t *r, rp_rbtree_t *tree,
    rp_queue_t *queue);
static rp_uint_t rp_resolver_resend_empty(rp_resolver_t *r);
static void rp_resolver_udp_read(rp_event_t *rev);
static void rp_resolver_tcp_write(rp_event_t *wev);
static void rp_resolver_tcp_read(rp_event_t *rev);
static void rp_resolver_process_response(rp_resolver_t *r, u_char *buf,
    size_t n, rp_uint_t tcp);
static void rp_resolver_process_a(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t qtype,
    rp_uint_t nan, rp_uint_t trunc, rp_uint_t ans);
static void rp_resolver_process_srv(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t nan,
    rp_uint_t trunc, rp_uint_t ans);
static void rp_resolver_process_ptr(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t nan);
static rp_resolver_node_t *rp_resolver_lookup_name(rp_resolver_t *r,
    rp_str_t *name, uint32_t hash);
static rp_resolver_node_t *rp_resolver_lookup_srv(rp_resolver_t *r,
    rp_str_t *name, uint32_t hash);
static rp_resolver_node_t *rp_resolver_lookup_addr(rp_resolver_t *r,
    in_addr_t addr);
static void rp_resolver_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
static rp_int_t rp_resolver_copy(rp_resolver_t *r, rp_str_t *name,
    u_char *buf, u_char *src, u_char *last);
static rp_int_t rp_resolver_set_timeout(rp_resolver_t *r,
    rp_resolver_ctx_t *ctx);
static void rp_resolver_timeout_handler(rp_event_t *ev);
static void rp_resolver_free_node(rp_resolver_t *r, rp_resolver_node_t *rn);
static void *rp_resolver_alloc(rp_resolver_t *r, size_t size);
static void *rp_resolver_calloc(rp_resolver_t *r, size_t size);
static void rp_resolver_free(rp_resolver_t *r, void *p);
static void rp_resolver_free_locked(rp_resolver_t *r, void *p);
static void *rp_resolver_dup(rp_resolver_t *r, void *src, size_t size);
static rp_resolver_addr_t *rp_resolver_export(rp_resolver_t *r,
    rp_resolver_node_t *rn, rp_uint_t rotate);
static void rp_resolver_report_srv(rp_resolver_t *r, rp_resolver_ctx_t *ctx);
static u_char *rp_resolver_log_error(rp_log_t *log, u_char *buf, size_t len);
static void rp_resolver_resolve_srv_names(rp_resolver_ctx_t *ctx,
    rp_resolver_node_t *rn);
static void rp_resolver_srv_names_handler(rp_resolver_ctx_t *ctx);
static rp_int_t rp_resolver_cmp_srvs(const void *one, const void *two);

#if (RP_HAVE_INET6)
static void rp_resolver_rbtree_insert_addr6_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
static rp_resolver_node_t *rp_resolver_lookup_addr6(rp_resolver_t *r,
    struct in6_addr *addr, uint32_t hash);
#endif


rp_resolver_t *
rp_resolver_create(rp_conf_t *cf, rp_str_t *names, rp_uint_t n)
{
    rp_str_t                   s;
    rp_url_t                   u;
    rp_uint_t                  i, j;
    rp_resolver_t             *r;
    rp_pool_cleanup_t         *cln;
    rp_resolver_connection_t  *rec;

    r = rp_pcalloc(cf->pool, sizeof(rp_resolver_t));
    if (r == NULL) {
        return NULL;
    }

    r->event = rp_pcalloc(cf->pool, sizeof(rp_event_t));
    if (r->event == NULL) {
        return NULL;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = rp_resolver_cleanup;
    cln->data = r;

    rp_rbtree_init(&r->name_rbtree, &r->name_sentinel,
                    rp_resolver_rbtree_insert_value);

    rp_rbtree_init(&r->srv_rbtree, &r->srv_sentinel,
                    rp_resolver_rbtree_insert_value);

    rp_rbtree_init(&r->addr_rbtree, &r->addr_sentinel,
                    rp_rbtree_insert_value);

    rp_queue_init(&r->name_resend_queue);
    rp_queue_init(&r->srv_resend_queue);
    rp_queue_init(&r->addr_resend_queue);

    rp_queue_init(&r->name_expire_queue);
    rp_queue_init(&r->srv_expire_queue);
    rp_queue_init(&r->addr_expire_queue);

#if (RP_HAVE_INET6)
    r->ipv6 = 1;

    rp_rbtree_init(&r->addr6_rbtree, &r->addr6_sentinel,
                    rp_resolver_rbtree_insert_addr6_value);

    rp_queue_init(&r->addr6_resend_queue);

    rp_queue_init(&r->addr6_expire_queue);
#endif

    r->event->handler = rp_resolver_resend_handler;
    r->event->data = r;
    r->event->log = &cf->cycle->new_log;
    r->event->cancelable = 1;
    r->ident = -1;

    r->resend_timeout = 5;
    r->tcp_timeout = 5;
    r->expire = 30;
    r->valid = 0;

    r->log = &cf->cycle->new_log;
    r->log_level = RP_LOG_ERR;

    if (n) {
        if (rp_array_init(&r->connections, cf->pool, n,
                           sizeof(rp_resolver_connection_t))
            != RP_OK)
        {
            return NULL;
        }
    }

    for (i = 0; i < n; i++) {
        if (rp_strncmp(names[i].data, "valid=", 6) == 0) {
            s.len = names[i].len - 6;
            s.data = names[i].data + 6;

            r->valid = rp_parse_time(&s, 1);

            if (r->valid == (time_t) RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }

#if (RP_HAVE_INET6)
        if (rp_strncmp(names[i].data, "ipv6=", 5) == 0) {

            if (rp_strcmp(&names[i].data[5], "on") == 0) {
                r->ipv6 = 1;

            } else if (rp_strcmp(&names[i].data[5], "off") == 0) {
                r->ipv6 = 0;

            } else {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &names[i]);
                return NULL;
            }

            continue;
        }
#endif

        rp_memzero(&u, sizeof(rp_url_t));

        u.url = names[i];
        u.default_port = 53;

        if (rp_parse_url(cf->pool, &u) != RP_OK) {
            if (u.err) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "%s in resolver \"%V\"",
                                   u.err, &u.url);
            }

            return NULL;
        }

        rec = rp_array_push_n(&r->connections, u.naddrs);
        if (rec == NULL) {
            return NULL;
        }

        rp_memzero(rec, u.naddrs * sizeof(rp_resolver_connection_t));

        for (j = 0; j < u.naddrs; j++) {
            rec[j].sockaddr = u.addrs[j].sockaddr;
            rec[j].socklen = u.addrs[j].socklen;
            rec[j].server = u.addrs[j].name;
            rec[j].resolver = r;
        }
    }

    if (n && r->connections.nelts == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "no name servers defined");
        return NULL;
    }

    return r;
}


static void
rp_resolver_cleanup(void *data)
{
    rp_resolver_t  *r = data;

    rp_uint_t                  i;
    rp_resolver_connection_t  *rec;

    rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0, "cleanup resolver");

    rp_resolver_cleanup_tree(r, &r->name_rbtree);

    rp_resolver_cleanup_tree(r, &r->srv_rbtree);

    rp_resolver_cleanup_tree(r, &r->addr_rbtree);

#if (RP_HAVE_INET6)
    rp_resolver_cleanup_tree(r, &r->addr6_rbtree);
#endif

    if (r->event->timer_set) {
        rp_del_timer(r->event);
    }

    rec = r->connections.elts;

    for (i = 0; i < r->connections.nelts; i++) {
        if (rec[i].udp) {
            rp_close_connection(rec[i].udp);
        }

        if (rec[i].tcp) {
            rp_close_connection(rec[i].tcp);
        }

        if (rec[i].read_buf) {
            rp_resolver_free(r, rec[i].read_buf->start);
            rp_resolver_free(r, rec[i].read_buf);
        }

        if (rec[i].write_buf) {
            rp_resolver_free(r, rec[i].write_buf->start);
            rp_resolver_free(r, rec[i].write_buf);
        }
    }
}


static void
rp_resolver_cleanup_tree(rp_resolver_t *r, rp_rbtree_t *tree)
{
    rp_resolver_ctx_t   *ctx, *next;
    rp_resolver_node_t  *rn;

    while (tree->root != tree->sentinel) {

        rn = rp_resolver_node(rp_rbtree_min(tree->root, tree->sentinel));

        rp_queue_remove(&rn->queue);

        for (ctx = rn->waiting; ctx; ctx = next) {
            next = ctx->next;

            if (ctx->event) {
                if (ctx->event->timer_set) {
                    rp_del_timer(ctx->event);
                }

                rp_resolver_free(r, ctx->event);
            }

            rp_resolver_free(r, ctx);
        }

        rp_rbtree_delete(tree, &rn->node);

        rp_resolver_free_node(r, rn);
    }
}


rp_resolver_ctx_t *
rp_resolve_start(rp_resolver_t *r, rp_resolver_ctx_t *temp)
{
    in_addr_t            addr;
    rp_resolver_ctx_t  *ctx;

    if (temp) {
        addr = rp_inet_addr(temp->name.data, temp->name.len);

        if (addr != INADDR_NONE) {
            temp->resolver = r;
            temp->state = RP_OK;
            temp->naddrs = 1;
            temp->addrs = &temp->addr;
            temp->addr.sockaddr = (struct sockaddr *) &temp->sin;
            temp->addr.socklen = sizeof(struct sockaddr_in);
            rp_memzero(&temp->sin, sizeof(struct sockaddr_in));
            temp->sin.sin_family = AF_INET;
            temp->sin.sin_addr.s_addr = addr;
            temp->quick = 1;

            return temp;
        }
    }

    if (r->connections.nelts == 0) {
        return RP_NO_RESOLVER;
    }

    ctx = rp_resolver_calloc(r, sizeof(rp_resolver_ctx_t));

    if (ctx) {
        ctx->resolver = r;
    }

    return ctx;
}


rp_int_t
rp_resolve_name(rp_resolver_ctx_t *ctx)
{
    size_t           slen;
    rp_int_t        rc;
    rp_str_t        name;
    rp_resolver_t  *r;

    r = ctx->resolver;

    if (ctx->name.len > 0 && ctx->name.data[ctx->name.len - 1] == '.') {
        ctx->name.len--;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\"", &ctx->name);

    if (ctx->quick) {
        ctx->handler(ctx);
        return RP_OK;
    }

    if (ctx->service.len) {
        slen = ctx->service.len;

        if (rp_strlchr(ctx->service.data,
                        ctx->service.data + ctx->service.len, '.')
            == NULL)
        {
            slen += sizeof("_._tcp") - 1;
        }

        name.len = slen + 1 + ctx->name.len;

        name.data = rp_resolver_alloc(r, name.len);
        if (name.data == NULL) {
            goto failed;
        }

        if (slen == ctx->service.len) {
            rp_sprintf(name.data, "%V.%V", &ctx->service, &ctx->name);

        } else {
            rp_sprintf(name.data, "_%V._tcp.%V", &ctx->service, &ctx->name);
        }

        /* lock name mutex */

        rc = rp_resolve_name_locked(r, ctx, &name);

        rp_resolver_free(r, name.data);

    } else {
        /* lock name mutex */

        rc = rp_resolve_name_locked(r, ctx, &ctx->name);
    }

    if (rc == RP_OK) {
        return RP_OK;
    }

    /* unlock name mutex */

    if (rc == RP_AGAIN) {
        return RP_OK;
    }

    /* RP_ERROR */

    if (ctx->event) {
        rp_resolver_free(r, ctx->event);
    }

failed:

    rp_resolver_free(r, ctx);

    return RP_ERROR;
}


void
rp_resolve_name_done(rp_resolver_ctx_t *ctx)
{
    rp_uint_t            i;
    rp_resolver_t       *r;
    rp_resolver_ctx_t   *w, **p;
    rp_resolver_node_t  *rn;

    r = ctx->resolver;

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve name done: %i", ctx->state);

    if (ctx->quick) {
        return;
    }

    if (ctx->event && ctx->event->timer_set) {
        rp_del_timer(ctx->event);
    }

    /* lock name mutex */

    if (ctx->nsrvs) {
        for (i = 0; i < ctx->nsrvs; i++) {
            if (ctx->srvs[i].ctx) {
                rp_resolve_name_done(ctx->srvs[i].ctx);
            }

            if (ctx->srvs[i].addrs) {
                rp_resolver_free(r, ctx->srvs[i].addrs->sockaddr);
                rp_resolver_free(r, ctx->srvs[i].addrs);
            }

            rp_resolver_free(r, ctx->srvs[i].name.data);
        }

        rp_resolver_free(r, ctx->srvs);
    }

    if (ctx->state == RP_AGAIN || ctx->state == RP_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }

            rp_log_error(RP_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &ctx->name);
        }
    }

done:

    if (ctx->service.len) {
        rp_resolver_expire(r, &r->srv_rbtree, &r->srv_expire_queue);

    } else {
        rp_resolver_expire(r, &r->name_rbtree, &r->name_expire_queue);
    }

    /* unlock name mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        rp_resolver_free_locked(r, ctx->event);
    }

    rp_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && rp_resolver_resend_empty(r)) {
        rp_del_timer(r->event);
    }
}


static rp_int_t
rp_resolve_name_locked(rp_resolver_t *r, rp_resolver_ctx_t *ctx,
    rp_str_t *name)
{
    uint32_t              hash;
    rp_int_t             rc;
    rp_str_t             cname;
    rp_uint_t            i, naddrs;
    rp_queue_t          *resend_queue, *expire_queue;
    rp_rbtree_t         *tree;
    rp_resolver_ctx_t   *next, *last;
    rp_resolver_addr_t  *addrs;
    rp_resolver_node_t  *rn;

    rp_strlow(name->data, name->data, name->len);

    hash = rp_crc32_short(name->data, name->len);

    if (ctx->service.len) {
        rn = rp_resolver_lookup_srv(r, name, hash);

        tree = &r->srv_rbtree;
        resend_queue = &r->srv_resend_queue;
        expire_queue = &r->srv_expire_queue;

    } else {
        rn = rp_resolver_lookup_name(r, name, hash);

        tree = &r->name_rbtree;
        resend_queue = &r->name_resend_queue;
        expire_queue = &r->name_expire_queue;
    }

    if (rn) {

        /* ctx can be a list after RP_RESOLVE_CNAME */
        for (last = ctx; last->next; last = last->next);

        if (rn->valid >= rp_time()) {

            rp_log_debug0(RP_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            rp_queue_remove(&rn->queue);

            rn->expire = rp_time() + r->expire;

            rp_queue_insert_head(expire_queue, &rn->queue);

            naddrs = (rn->naddrs == (u_short) -1) ? 0 : rn->naddrs;
#if (RP_HAVE_INET6)
            naddrs += (rn->naddrs6 == (u_short) -1) ? 0 : rn->naddrs6;
#endif

            if (naddrs) {

                if (naddrs == 1 && rn->naddrs == 1) {
                    addrs = NULL;

                } else {
                    addrs = rp_resolver_export(r, rn, 1);
                    if (addrs == NULL) {
                        return RP_ERROR;
                    }
                }

                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    ctx->state = RP_OK;
                    ctx->valid = rn->valid;
                    ctx->naddrs = naddrs;

                    if (addrs == NULL) {
                        ctx->addrs = &ctx->addr;
                        ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                        ctx->addr.socklen = sizeof(struct sockaddr_in);
                        rp_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                        ctx->sin.sin_family = AF_INET;
                        ctx->sin.sin_addr.s_addr = rn->u.addr;

                    } else {
                        ctx->addrs = addrs;
                    }

                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                if (addrs != NULL) {
                    rp_resolver_free(r, addrs->sockaddr);
                    rp_resolver_free(r, addrs);
                }

                return RP_OK;
            }

            if (rn->nsrvs) {
                last->next = rn->waiting;
                rn->waiting = NULL;

                /* unlock name mutex */

                do {
                    next = ctx->next;

                    rp_resolver_resolve_srv_names(ctx, rn);

                    ctx = next;
                } while (ctx);

                return RP_OK;
            }

            /* RP_RESOLVE_CNAME */

            if (ctx->recursion++ < RP_RESOLVER_MAX_RECURSION) {

                cname.len = rn->cnlen;
                cname.data = rn->u.cname;

                return rp_resolve_name_locked(r, ctx, &cname);
            }

            last->next = rn->waiting;
            rn->waiting = NULL;

            /* unlock name mutex */

            do {
                ctx->state = RP_RESOLVE_NXDOMAIN;
                ctx->valid = rp_time() + (r->valid ? r->valid : 10);
                next = ctx->next;

                ctx->handler(ctx);

                ctx = next;
            } while (ctx);

            return RP_OK;
        }

        if (rn->waiting) {
            if (rp_resolver_set_timeout(r, ctx) != RP_OK) {
                return RP_ERROR;
            }

            last->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = RP_AGAIN;
            ctx->async = 1;

            do {
                ctx->node = rn;
                ctx = ctx->next;
            } while (ctx);

            return RP_AGAIN;
        }

        rp_queue_remove(&rn->queue);

        /* lock alloc mutex */

        if (rn->query) {
            rp_resolver_free_locked(r, rn->query);
            rn->query = NULL;
#if (RP_HAVE_INET6)
            rn->query6 = NULL;
#endif
        }

        if (rn->cnlen) {
            rp_resolver_free_locked(r, rn->u.cname);
        }

        if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
            rp_resolver_free_locked(r, rn->u.addrs);
        }

#if (RP_HAVE_INET6)
        if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
            rp_resolver_free_locked(r, rn->u6.addrs6);
        }
#endif

        if (rn->nsrvs) {
            for (i = 0; i < (rp_uint_t) rn->nsrvs; i++) {
                if (rn->u.srvs[i].name.data) {
                    rp_resolver_free_locked(r, rn->u.srvs[i].name.data);
                }
            }

            rp_resolver_free_locked(r, rn->u.srvs);
        }

        /* unlock alloc mutex */

    } else {

        rn = rp_resolver_alloc(r, sizeof(rp_resolver_node_t));
        if (rn == NULL) {
            return RP_ERROR;
        }

        rn->name = rp_resolver_dup(r, name->data, name->len);
        if (rn->name == NULL) {
            rp_resolver_free(r, rn);
            return RP_ERROR;
        }

        rn->node.key = hash;
        rn->nlen = (u_short) name->len;
        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

        rp_rbtree_insert(tree, &rn->node);
    }

    if (ctx->service.len) {
        rc = rp_resolver_create_srv_query(r, rn, name);

    } else {
        rc = rp_resolver_create_name_query(r, rn, name);
    }

    if (rc == RP_ERROR) {
        goto failed;
    }

    if (rc == RP_DECLINED) {
        rp_rbtree_delete(tree, &rn->node);

        rp_resolver_free(r, rn->query);
        rp_resolver_free(r, rn->name);
        rp_resolver_free(r, rn);

        do {
            ctx->state = RP_RESOLVE_NXDOMAIN;
            next = ctx->next;

            ctx->handler(ctx);

            ctx = next;
        } while (ctx);

        return RP_OK;
    }

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

    rn->naddrs = (u_short) -1;
    rn->tcp = 0;
#if (RP_HAVE_INET6)
    rn->naddrs6 = r->ipv6 ? (u_short) -1 : 0;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (rp_resolver_send_query(r, rn) != RP_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) rp_resolver_send_query(r, rn);
    }

    if (rp_resolver_set_timeout(r, ctx) != RP_OK) {
        goto failed;
    }

    if (rp_resolver_resend_empty(r)) {
        rp_add_timer(r->event, (rp_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = rp_time() + r->resend_timeout;

    rp_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->valid = 0;
    rn->ttl = RP_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    ctx->state = RP_AGAIN;
    ctx->async = 1;

    do {
        ctx->node = rn;
        ctx = ctx->next;
    } while (ctx);

    return RP_AGAIN;

failed:

    rp_rbtree_delete(tree, &rn->node);

    if (rn->query) {
        rp_resolver_free(r, rn->query);
    }

    rp_resolver_free(r, rn->name);

    rp_resolver_free(r, rn);

    return RP_ERROR;
}


rp_int_t
rp_resolve_addr(rp_resolver_ctx_t *ctx)
{
    u_char               *name;
    in_addr_t             addr;
    rp_queue_t          *resend_queue, *expire_queue;
    rp_rbtree_t         *tree;
    rp_resolver_t       *r;
    struct sockaddr_in   *sin;
    rp_resolver_node_t  *rn;
#if (RP_HAVE_INET6)
    uint32_t              hash;
    struct sockaddr_in6  *sin6;
#endif

#if (RP_SUPPRESS_WARN)
    addr = 0;
#if (RP_HAVE_INET6)
    hash = 0;
    sin6 = NULL;
#endif
#endif

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) ctx->addr.sockaddr;
        hash = rp_crc32_short(sin6->sin6_addr.s6_addr, 16);

        /* lock addr mutex */

        rn = rp_resolver_lookup_addr6(r, &sin6->sin6_addr, hash);

        tree = &r->addr6_rbtree;
        resend_queue = &r->addr6_resend_queue;
        expire_queue = &r->addr6_expire_queue;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) ctx->addr.sockaddr;
        addr = ntohl(sin->sin_addr.s_addr);

        /* lock addr mutex */

        rn = rp_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        resend_queue = &r->addr_resend_queue;
        expire_queue = &r->addr_expire_queue;
    }

    if (rn) {

        if (rn->valid >= rp_time()) {

            rp_log_debug0(RP_LOG_DEBUG_CORE, r->log, 0, "resolve cached");

            rp_queue_remove(&rn->queue);

            rn->expire = rp_time() + r->expire;

            rp_queue_insert_head(expire_queue, &rn->queue);

            name = rp_resolver_dup(r, rn->name, rn->nlen);
            if (name == NULL) {
                rp_resolver_free(r, ctx);
                return RP_ERROR;
            }

            ctx->name.len = rn->nlen;
            ctx->name.data = name;

            /* unlock addr mutex */

            ctx->state = RP_OK;
            ctx->valid = rn->valid;

            ctx->handler(ctx);

            rp_resolver_free(r, name);

            return RP_OK;
        }

        if (rn->waiting) {
            if (rp_resolver_set_timeout(r, ctx) != RP_OK) {
                return RP_ERROR;
            }

            ctx->next = rn->waiting;
            rn->waiting = ctx;
            ctx->state = RP_AGAIN;
            ctx->async = 1;
            ctx->node = rn;

            /* unlock addr mutex */

            return RP_OK;
        }

        rp_queue_remove(&rn->queue);

        rp_resolver_free(r, rn->query);
        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

    } else {
        rn = rp_resolver_alloc(r, sizeof(rp_resolver_node_t));
        if (rn == NULL) {
            goto failed;
        }

        switch (ctx->addr.sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            rn->addr6 = sin6->sin6_addr;
            rn->node.key = hash;
            break;
#endif

        default: /* AF_INET */
            rn->node.key = addr;
        }

        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

        rp_rbtree_insert(tree, &rn->node);
    }

    if (rp_resolver_create_addr_query(r, rn, &ctx->addr) != RP_OK) {
        goto failed;
    }

    rn->last_connection = r->last_connection++;
    if (r->last_connection == r->connections.nelts) {
        r->last_connection = 0;
    }

    rn->naddrs = (u_short) -1;
    rn->tcp = 0;
#if (RP_HAVE_INET6)
    rn->naddrs6 = (u_short) -1;
    rn->tcp6 = 0;
#endif
    rn->nsrvs = 0;

    if (rp_resolver_send_query(r, rn) != RP_OK) {

        /* immediately retry once on failure */

        rn->last_connection++;
        if (rn->last_connection == r->connections.nelts) {
            rn->last_connection = 0;
        }

        (void) rp_resolver_send_query(r, rn);
    }

    if (rp_resolver_set_timeout(r, ctx) != RP_OK) {
        goto failed;
    }

    if (rp_resolver_resend_empty(r)) {
        rp_add_timer(r->event, (rp_msec_t) (r->resend_timeout * 1000));
    }

    rn->expire = rp_time() + r->resend_timeout;

    rp_queue_insert_head(resend_queue, &rn->queue);

    rn->code = 0;
    rn->cnlen = 0;
    rn->name = NULL;
    rn->nlen = 0;
    rn->valid = 0;
    rn->ttl = RP_MAX_UINT32_VALUE;
    rn->waiting = ctx;

    /* unlock addr mutex */

    ctx->state = RP_AGAIN;
    ctx->async = 1;
    ctx->node = rn;

    return RP_OK;

failed:

    if (rn) {
        rp_rbtree_delete(tree, &rn->node);

        if (rn->query) {
            rp_resolver_free(r, rn->query);
        }

        rp_resolver_free(r, rn);
    }

    /* unlock addr mutex */

    if (ctx->event) {
        rp_resolver_free(r, ctx->event);
    }

    rp_resolver_free(r, ctx);

    return RP_ERROR;
}


void
rp_resolve_addr_done(rp_resolver_ctx_t *ctx)
{
    rp_queue_t          *expire_queue;
    rp_rbtree_t         *tree;
    rp_resolver_t       *r;
    rp_resolver_ctx_t   *w, **p;
    rp_resolver_node_t  *rn;

    r = ctx->resolver;

    switch (ctx->addr.sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;
        break;
#endif

    default: /* AF_INET */
        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve addr done: %i", ctx->state);

    if (ctx->event && ctx->event->timer_set) {
        rp_del_timer(ctx->event);
    }

    /* lock addr mutex */

    if (ctx->state == RP_AGAIN || ctx->state == RP_RESOLVE_TIMEDOUT) {

        rn = ctx->node;

        if (rn) {
            p = &rn->waiting;
            w = rn->waiting;

            while (w) {
                if (w == ctx) {
                    *p = w->next;

                    goto done;
                }

                p = &w->next;
                w = w->next;
            }
        }

        {
            u_char     text[RP_SOCKADDR_STRLEN];
            rp_str_t  addrtext;

            addrtext.data = text;
            addrtext.len = rp_sock_ntop(ctx->addr.sockaddr, ctx->addr.socklen,
                                         text, RP_SOCKADDR_STRLEN, 0);

            rp_log_error(RP_LOG_ALERT, r->log, 0,
                          "could not cancel %V resolving", &addrtext);
        }
    }

done:

    rp_resolver_expire(r, tree, expire_queue);

    /* unlock addr mutex */

    /* lock alloc mutex */

    if (ctx->event) {
        rp_resolver_free_locked(r, ctx->event);
    }

    rp_resolver_free_locked(r, ctx);

    /* unlock alloc mutex */

    if (r->event->timer_set && rp_resolver_resend_empty(r)) {
        rp_del_timer(r->event);
    }
}


static void
rp_resolver_expire(rp_resolver_t *r, rp_rbtree_t *tree, rp_queue_t *queue)
{
    time_t                now;
    rp_uint_t            i;
    rp_queue_t          *q;
    rp_resolver_node_t  *rn;

    rp_log_debug0(RP_LOG_DEBUG_CORE, r->log, 0, "resolver expire");

    now = rp_time();

    for (i = 0; i < 2; i++) {
        if (rp_queue_empty(queue)) {
            return;
        }

        q = rp_queue_last(queue);

        rn = rp_queue_data(q, rp_resolver_node_t, queue);

        if (now <= rn->expire) {
            return;
        }

        rp_log_debug2(RP_LOG_DEBUG_CORE, r->log, 0,
                       "resolver expire \"%*s\"", (size_t) rn->nlen, rn->name);

        rp_queue_remove(q);

        rp_rbtree_delete(tree, &rn->node);

        rp_resolver_free_node(r, rn);
    }
}


static rp_int_t
rp_resolver_send_query(rp_resolver_t *r, rp_resolver_node_t *rn)
{
    rp_int_t                   rc;
    rp_resolver_connection_t  *rec;

    rec = r->connections.elts;
    rec = &rec[rn->last_connection];

    if (rec->log.handler == NULL) {
        rec->log = *r->log;
        rec->log.handler = rp_resolver_log_error;
        rec->log.data = rec;
        rec->log.action = "resolving";
    }

    if (rn->naddrs == (u_short) -1) {
        rc = rn->tcp ? rp_resolver_send_tcp_query(r, rec, rn->query, rn->qlen)
                     : rp_resolver_send_udp_query(r, rec, rn->query, rn->qlen);

        if (rc != RP_OK) {
            return rc;
        }
    }

#if (RP_HAVE_INET6)

    if (rn->query6 && rn->naddrs6 == (u_short) -1) {
        rc = rn->tcp6
                    ? rp_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen)
                    : rp_resolver_send_udp_query(r, rec, rn->query6, rn->qlen);

        if (rc != RP_OK) {
            return rc;
        }
    }

#endif

    return RP_OK;
}


static rp_int_t
rp_resolver_send_udp_query(rp_resolver_t *r, rp_resolver_connection_t  *rec,
    u_char *query, u_short qlen)
{
    ssize_t  n;

    if (rec->udp == NULL) {
        if (rp_udp_connect(rec) != RP_OK) {
            return RP_ERROR;
        }

        rec->udp->data = rec;
        rec->udp->read->handler = rp_resolver_udp_read;
        rec->udp->read->resolver = 1;
    }

    n = rp_send(rec->udp, query, qlen);

    if (n == RP_ERROR) {
        goto failed;
    }

    if ((size_t) n != (size_t) qlen) {
        rp_log_error(RP_LOG_CRIT, &rec->log, 0, "send() incomplete");
        goto failed;
    }

    return RP_OK;

failed:

    rp_close_connection(rec->udp);
    rec->udp = NULL;

    return RP_ERROR;
}


static rp_int_t
rp_resolver_send_tcp_query(rp_resolver_t *r, rp_resolver_connection_t *rec,
    u_char *query, u_short qlen)
{
    rp_buf_t  *b;
    rp_int_t   rc;

    rc = RP_OK;

    if (rec->tcp == NULL) {
        b = rec->read_buf;

        if (b == NULL) {
            b = rp_resolver_calloc(r, sizeof(rp_buf_t));
            if (b == NULL) {
                return RP_ERROR;
            }

            b->start = rp_resolver_alloc(r, RP_RESOLVER_TCP_RSIZE);
            if (b->start == NULL) {
                rp_resolver_free(r, b);
                return RP_ERROR;
            }

            b->end = b->start + RP_RESOLVER_TCP_RSIZE;

            rec->read_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        b = rec->write_buf;

        if (b == NULL) {
            b = rp_resolver_calloc(r, sizeof(rp_buf_t));
            if (b == NULL) {
                return RP_ERROR;
            }

            b->start = rp_resolver_alloc(r, RP_RESOLVER_TCP_WSIZE);
            if (b->start == NULL) {
                rp_resolver_free(r, b);
                return RP_ERROR;
            }

            b->end = b->start + RP_RESOLVER_TCP_WSIZE;

            rec->write_buf = b;
        }

        b->pos = b->start;
        b->last = b->start;

        rc = rp_tcp_connect(rec);
        if (rc == RP_ERROR) {
            return RP_ERROR;
        }

        rec->tcp->data = rec;
        rec->tcp->write->handler = rp_resolver_tcp_write;
        rec->tcp->read->handler = rp_resolver_tcp_read;
        rec->tcp->read->resolver = 1;

        rp_add_timer(rec->tcp->write, (rp_msec_t) (r->tcp_timeout * 1000));
    }

    b = rec->write_buf;

    if (b->end - b->last <  2 + qlen) {
        rp_log_error(RP_LOG_CRIT, &rec->log, 0, "buffer overflow");
        return RP_ERROR;
    }

    *b->last++ = (u_char) (qlen >> 8);
    *b->last++ = (u_char) qlen;
    b->last = rp_cpymem(b->last, query, qlen);

    if (rc == RP_OK) {
        rp_resolver_tcp_write(rec->tcp->write);
    }

    return RP_OK;
}


static void
rp_resolver_resend_handler(rp_event_t *ev)
{
    time_t           timer, atimer, stimer, ntimer;
#if (RP_HAVE_INET6)
    time_t           a6timer;
#endif
    rp_resolver_t  *r;

    r = ev->data;

    rp_log_debug0(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolver resend handler");

    /* lock name mutex */

    ntimer = rp_resolver_resend(r, &r->name_rbtree, &r->name_resend_queue);

    stimer = rp_resolver_resend(r, &r->srv_rbtree, &r->srv_resend_queue);

    /* unlock name mutex */

    /* lock addr mutex */

    atimer = rp_resolver_resend(r, &r->addr_rbtree, &r->addr_resend_queue);

    /* unlock addr mutex */

#if (RP_HAVE_INET6)

    /* lock addr6 mutex */

    a6timer = rp_resolver_resend(r, &r->addr6_rbtree, &r->addr6_resend_queue);

    /* unlock addr6 mutex */

#endif

    timer = ntimer;

    if (timer == 0) {
        timer = atimer;

    } else if (atimer) {
        timer = rp_min(timer, atimer);
    }

    if (timer == 0) {
        timer = stimer;

    } else if (stimer) {
        timer = rp_min(timer, stimer);
    }

#if (RP_HAVE_INET6)

    if (timer == 0) {
        timer = a6timer;

    } else if (a6timer) {
        timer = rp_min(timer, a6timer);
    }

#endif

    if (timer) {
        rp_add_timer(r->event, (rp_msec_t) (timer * 1000));
    }
}


static time_t
rp_resolver_resend(rp_resolver_t *r, rp_rbtree_t *tree, rp_queue_t *queue)
{
    time_t                now;
    rp_queue_t          *q;
    rp_resolver_node_t  *rn;

    now = rp_time();

    for ( ;; ) {
        if (rp_queue_empty(queue)) {
            return 0;
        }

        q = rp_queue_last(queue);

        rn = rp_queue_data(q, rp_resolver_node_t, queue);

        if (now < rn->expire) {
            return rn->expire - now;
        }

        rp_log_debug3(RP_LOG_DEBUG_CORE, r->log, 0,
                       "resolver resend \"%*s\" %p",
                       (size_t) rn->nlen, rn->name, rn->waiting);

        rp_queue_remove(q);

        if (rn->waiting) {

            if (++rn->last_connection == r->connections.nelts) {
                rn->last_connection = 0;
            }

            (void) rp_resolver_send_query(r, rn);

            rn->expire = now + r->resend_timeout;

            rp_queue_insert_head(queue, q);

            continue;
        }

        rp_rbtree_delete(tree, &rn->node);

        rp_resolver_free_node(r, rn);
    }
}


static rp_uint_t
rp_resolver_resend_empty(rp_resolver_t *r)
{
    return rp_queue_empty(&r->name_resend_queue)
           && rp_queue_empty(&r->srv_resend_queue)
#if (RP_HAVE_INET6)
           && rp_queue_empty(&r->addr6_resend_queue)
#endif
           && rp_queue_empty(&r->addr_resend_queue);
}


static void
rp_resolver_udp_read(rp_event_t *rev)
{
    ssize_t                     n;
    rp_connection_t           *c;
    rp_resolver_connection_t  *rec;
    u_char                      buf[RP_RESOLVER_UDP_SIZE];

    c = rev->data;
    rec = c->data;

    do {
        n = rp_udp_recv(c, buf, RP_RESOLVER_UDP_SIZE);

        if (n < 0) {
            return;
        }

        rp_resolver_process_response(rec->resolver, buf, n, 0);

    } while (rev->ready);
}


static void
rp_resolver_tcp_write(rp_event_t *wev)
{
    off_t                       sent;
    ssize_t                     n;
    rp_buf_t                  *b;
    rp_resolver_t             *r;
    rp_connection_t           *c;
    rp_resolver_connection_t  *rec;

    c = wev->data;
    rec = c->data;
    b = rec->write_buf;
    r = rec->resolver;

    if (wev->timedout) {
        goto failed;
    }

    sent = c->sent;

    while (wev->ready && b->pos < b->last) {
        n = rp_send(c, b->pos, b->last - b->pos);

        if (n == RP_AGAIN) {
            break;
        }

        if (n == RP_ERROR) {
            goto failed;
        }

        b->pos += n;
    }

    if (b->pos != b->start) {
        b->last = rp_movemem(b->start, b->pos, b->last - b->pos);
        b->pos = b->start;
    }

    if (c->sent != sent) {
        rp_add_timer(wev, (rp_msec_t) (r->tcp_timeout * 1000));
    }

    if (rp_handle_write_event(wev, 0) != RP_OK) {
        goto failed;
    }

    return;

failed:

    rp_close_connection(c);
    rec->tcp = NULL;
}


static void
rp_resolver_tcp_read(rp_event_t *rev)
{
    u_char                     *p;
    size_t                      size;
    ssize_t                     n;
    u_short                     qlen;
    rp_buf_t                  *b;
    rp_resolver_t             *r;
    rp_connection_t           *c;
    rp_resolver_connection_t  *rec;

    c = rev->data;
    rec = c->data;
    b = rec->read_buf;
    r = rec->resolver;

    while (rev->ready) {
        n = rp_recv(c, b->last, b->end - b->last);

        if (n == RP_AGAIN) {
            break;
        }

        if (n == RP_ERROR || n == 0) {
            goto failed;
        }

        b->last += n;

        for ( ;; ) {
            p = b->pos;
            size = b->last - p;

            if (size < 2) {
                break;
            }

            qlen = (u_short) *p++ << 8;
            qlen += *p++;

            if (size < (size_t) (2 + qlen)) {
                break;
            }

            rp_resolver_process_response(r, p, qlen, 1);

            b->pos += 2 + qlen;
        }

        if (b->pos != b->start) {
            b->last = rp_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;
        }
    }

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        goto failed;
    }

    return;

failed:

    rp_close_connection(c);
    rec->tcp = NULL;
}


static void
rp_resolver_process_response(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t tcp)
{
    char                 *err;
    rp_uint_t            i, times, ident, qident, flags, code, nqs, nan, trunc,
                          qtype, qclass;
#if (RP_HAVE_INET6)
    rp_uint_t            qident6;
#endif
    rp_queue_t          *q;
    rp_resolver_qs_t    *qs;
    rp_resolver_hdr_t   *response;
    rp_resolver_node_t  *rn;

    if (n < sizeof(rp_resolver_hdr_t)) {
        goto short_response;
    }

    response = (rp_resolver_hdr_t *) buf;

    ident = (response->ident_hi << 8) + response->ident_lo;
    flags = (response->flags_hi << 8) + response->flags_lo;
    nqs = (response->nqs_hi << 8) + response->nqs_lo;
    nan = (response->nan_hi << 8) + response->nan_lo;
    trunc = flags & 0x0200;

    rp_log_debug6(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response %ui fl:%04Xi %ui/%ui/%ud/%ud",
                   ident, flags, nqs, nan,
                   (response->nns_hi << 8) + response->nns_lo,
                   (response->nar_hi << 8) + response->nar_lo);

    /* response to a standard query */
    if ((flags & 0xf870) != 0x8000 || (trunc && tcp)) {
        rp_log_error(r->log_level, r->log, 0,
                      "invalid %s DNS response %ui fl:%04Xi",
                      tcp ? "TCP" : "UDP", ident, flags);
        return;
    }

    code = flags & 0xf;

    if (code == RP_RESOLVE_FORMERR) {

        times = 0;

        for (q = rp_queue_head(&r->name_resend_queue);
             q != rp_queue_sentinel(&r->name_resend_queue) && times++ < 100;
             q = rp_queue_next(q))
        {
            rn = rp_queue_data(q, rp_resolver_node_t, queue);
            qident = (rn->query[0] << 8) + rn->query[1];

            if (qident == ident) {
                goto dns_error_name;
            }

#if (RP_HAVE_INET6)
            if (rn->query6) {
                qident6 = (rn->query6[0] << 8) + rn->query6[1];

                if (qident6 == ident) {
                    goto dns_error_name;
                }
            }
#endif
        }

        goto dns_error;
    }

    if (code > RP_RESOLVE_REFUSED) {
        goto dns_error;
    }

    if (nqs != 1) {
        err = "invalid number of questions in DNS response";
        goto done;
    }

    i = sizeof(rp_resolver_hdr_t);

    while (i < (rp_uint_t) n) {
        if (buf[i] == '\0') {
            goto found;
        }

        i += 1 + buf[i];
    }

    goto short_response;

found:

    if (i++ == sizeof(rp_resolver_hdr_t)) {
        err = "zero-length domain name in DNS response";
        goto done;
    }

    if (i + sizeof(rp_resolver_qs_t) + nan * (2 + sizeof(rp_resolver_an_t))
        > (rp_uint_t) n)
    {
        goto short_response;
    }

    qs = (rp_resolver_qs_t *) &buf[i];

    qtype = (qs->type_hi << 8) + qs->type_lo;
    qclass = (qs->class_hi << 8) + qs->class_lo;

    rp_log_debug2(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolver DNS response qt:%ui cl:%ui", qtype, qclass);

    if (qclass != 1) {
        rp_log_error(r->log_level, r->log, 0,
                      "unknown query class %ui in DNS response", qclass);
        return;
    }

    switch (qtype) {

    case RP_RESOLVE_A:
#if (RP_HAVE_INET6)
    case RP_RESOLVE_AAAA:
#endif

        rp_resolver_process_a(r, buf, n, ident, code, qtype, nan, trunc,
                               i + sizeof(rp_resolver_qs_t));

        break;

    case RP_RESOLVE_SRV:

        rp_resolver_process_srv(r, buf, n, ident, code, nan, trunc,
                                 i + sizeof(rp_resolver_qs_t));

        break;

    case RP_RESOLVE_PTR:

        rp_resolver_process_ptr(r, buf, n, ident, code, nan);

        break;

    default:
        rp_log_error(r->log_level, r->log, 0,
                      "unknown query type %ui in DNS response", qtype);
        return;
    }

    return;

short_response:

    err = "short DNS response";

done:

    rp_log_error(r->log_level, r->log, 0, err);

    return;

dns_error_name:

    rp_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui, name:\"%*s\"",
                  code, rp_resolver_strerror(code), ident,
                  (size_t) rn->nlen, rn->name);
    return;

dns_error:

    rp_log_error(r->log_level, r->log, 0,
                  "DNS error (%ui: %s), query id:%ui",
                  code, rp_resolver_strerror(code), ident);
    return;
}


static void
rp_resolver_process_a(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t qtype,
    rp_uint_t nan, rp_uint_t trunc, rp_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    in_addr_t                  *addr;
    rp_str_t                   name;
    rp_uint_t                  type, class, qident, naddrs, a, i, j, start;
#if (RP_HAVE_INET6)
    struct in6_addr            *addr6;
#endif
    rp_resolver_an_t          *an;
    rp_resolver_ctx_t         *ctx, *next;
    rp_resolver_node_t        *rn;
    rp_resolver_addr_t        *addrs;
    rp_resolver_connection_t  *rec;

    if (rp_resolver_copy(r, &name, buf,
                          buf + sizeof(rp_resolver_hdr_t), buf + n)
        != RP_OK)
    {
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = rp_crc32_short(name.data, name.len);

    /* lock name mutex */

    rn = rp_resolver_lookup_name(r, &name, hash);

    if (rn == NULL) {
        rp_log_error(r->log_level, r->log, 0,
                      "unexpected response for %V", &name);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    switch (qtype) {

#if (RP_HAVE_INET6)
    case RP_RESOLVE_AAAA:

        if (rn->query6 == NULL || rn->naddrs6 != (u_short) -1) {
            rp_log_error(r->log_level, r->log, 0,
                          "unexpected response for %V", &name);
            rp_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp6) {
            rp_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query6[0] << 8) + rn->query6[1];

        break;
#endif

    default: /* RP_RESOLVE_A */

        if (rn->query == NULL || rn->naddrs != (u_short) -1) {
            rp_log_error(r->log_level, r->log, 0,
                          "unexpected response for %V", &name);
            rp_resolver_free(r, name.data);
            goto failed;
        }

        if (trunc && rn->tcp) {
            rp_resolver_free(r, name.data);
            goto failed;
        }

        qident = (rn->query[0] << 8) + rn->query[1];
    }

    if (ident != qident) {
        rp_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui response for %V, expect %ui",
                      ident, &name, qident);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    rp_resolver_free(r, name.data);

    if (trunc) {

        rp_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            rp_rbtree_delete(&r->name_rbtree, &rn->node);
            rp_resolver_free_node(r, rn);
            goto next;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        switch (qtype) {

#if (RP_HAVE_INET6)
        case RP_RESOLVE_AAAA:

            rn->tcp6 = 1;

            (void) rp_resolver_send_tcp_query(r, rec, rn->query6, rn->qlen);

            break;
#endif

        default: /* RP_RESOLVE_A */

            rn->tcp = 1;

            (void) rp_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);
        }

        rn->expire = rp_time() + r->resend_timeout;

        rp_queue_insert_head(&r->name_resend_queue, &rn->queue);

        goto next;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {

#if (RP_HAVE_INET6)
        switch (qtype) {

        case RP_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs) {
                goto export;
            }

            break;

        default: /* RP_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                goto next;
            }

            if (rn->naddrs6) {
                goto export;
            }
        }
#endif

        code = RP_RESOLVE_NXDOMAIN;
    }

    if (code) {

#if (RP_HAVE_INET6)
        switch (qtype) {

        case RP_RESOLVE_AAAA:

            rn->naddrs6 = 0;

            if (rn->naddrs == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }

            break;

        default: /* RP_RESOLVE_A */

            rn->naddrs = 0;

            if (rn->naddrs6 == (u_short) -1) {
                rn->code = (u_char) code;
                goto next;
            }
        }
#endif

        next = rn->waiting;
        rn->waiting = NULL;

        rp_queue_remove(&rn->queue);

        rp_rbtree_delete(&r->name_rbtree, &rn->node);

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = rp_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        rp_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    naddrs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(rp_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (rp_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = rp_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(rp_resolver_an_t);

        switch (type) {

        case RP_RESOLVE_A:

            if (qtype != RP_RESOLVE_A) {
                err = "unexpected A record in DNS response";
                goto invalid;
            }

            if (len != 4) {
                err = "invalid A record in DNS response";
                goto invalid;
            }

            if (i + 4 > n) {
                goto short_response;
            }

            naddrs++;

            break;

#if (RP_HAVE_INET6)
        case RP_RESOLVE_AAAA:

            if (qtype != RP_RESOLVE_AAAA) {
                err = "unexpected AAAA record in DNS response";
                goto invalid;
            }

            if (len != 16) {
                err = "invalid AAAA record in DNS response";
                goto invalid;
            }

            if (i + 16 > n) {
                goto short_response;
            }

            naddrs++;

            break;
#endif

        case RP_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case RP_RESOLVE_DNAME:

            break;

        default:

            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui", type);
        }

        i += len;
    }

    rp_log_debug3(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolver naddrs:%ui cname:%p ttl:%uD",
                   naddrs, cname, rn->ttl);

    if (naddrs) {

        switch (qtype) {

#if (RP_HAVE_INET6)
        case RP_RESOLVE_AAAA:

            if (naddrs == 1) {
                addr6 = &rn->u6.addr6;
                rn->naddrs6 = 1;

            } else {
                addr6 = rp_resolver_alloc(r, naddrs * sizeof(struct in6_addr));
                if (addr6 == NULL) {
                    goto failed;
                }

                rn->u6.addrs6 = addr6;
                rn->naddrs6 = (u_short) naddrs;
            }

#if (RP_SUPPRESS_WARN)
            addr = NULL;
#endif

            break;
#endif

        default: /* RP_RESOLVE_A */

            if (naddrs == 1) {
                addr = &rn->u.addr;
                rn->naddrs = 1;

            } else {
                addr = rp_resolver_alloc(r, naddrs * sizeof(in_addr_t));
                if (addr == NULL) {
                    goto failed;
                }

                rn->u.addrs = addr;
                rn->naddrs = (u_short) naddrs;
            }

#if (RP_HAVE_INET6 && RP_SUPPRESS_WARN)
            addr6 = NULL;
#endif
        }

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (rp_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(rp_resolver_an_t);

            if (type == RP_RESOLVE_A) {

                addr[j] = htonl((buf[i] << 24) + (buf[i + 1] << 16)
                                + (buf[i + 2] << 8) + (buf[i + 3]));

                if (++j == naddrs) {

#if (RP_HAVE_INET6)
                    if (rn->naddrs6 == (u_short) -1) {
                        goto next;
                    }
#endif

                    break;
                }
            }

#if (RP_HAVE_INET6)
            else if (type == RP_RESOLVE_AAAA) {

                rp_memcpy(addr6[j].s6_addr, &buf[i], 16);

                if (++j == naddrs) {

                    if (rn->naddrs == (u_short) -1) {
                        goto next;
                    }

                    break;
                }
            }
#endif

            i += len;
        }
    }

    switch (qtype) {

#if (RP_HAVE_INET6)
    case RP_RESOLVE_AAAA:

        if (rn->naddrs6 == (u_short) -1) {
            rn->naddrs6 = 0;
        }

        break;
#endif

    default: /* RP_RESOLVE_A */

        if (rn->naddrs == (u_short) -1) {
            rn->naddrs = 0;
        }
    }

    if (rn->naddrs != (u_short) -1
#if (RP_HAVE_INET6)
        && rn->naddrs6 != (u_short) -1
#endif
        && rn->naddrs
#if (RP_HAVE_INET6)
           + rn->naddrs6
#endif
           > 0)
    {

#if (RP_HAVE_INET6)
    export:
#endif

        naddrs = rn->naddrs;
#if (RP_HAVE_INET6)
        naddrs += rn->naddrs6;
#endif

        if (naddrs == 1 && rn->naddrs == 1) {
            addrs = NULL;

        } else {
            addrs = rp_resolver_export(r, rn, 0);
            if (addrs == NULL) {
                goto failed;
            }
        }

        rp_queue_remove(&rn->queue);

        rn->valid = rp_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = rp_time() + r->expire;

        rp_queue_insert_head(&r->name_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        /* unlock name mutex */

        while (next) {
            ctx = next;
            ctx->state = RP_OK;
            ctx->valid = rn->valid;
            ctx->naddrs = naddrs;

            if (addrs == NULL) {
                ctx->addrs = &ctx->addr;
                ctx->addr.sockaddr = (struct sockaddr *) &ctx->sin;
                ctx->addr.socklen = sizeof(struct sockaddr_in);
                rp_memzero(&ctx->sin, sizeof(struct sockaddr_in));
                ctx->sin.sin_family = AF_INET;
                ctx->sin.sin_addr.s_addr = rn->u.addr;

            } else {
                ctx->addrs = addrs;
            }

            next = ctx->next;

            ctx->handler(ctx);
        }

        if (addrs != NULL) {
            rp_resolver_free(r, addrs->sockaddr);
            rp_resolver_free(r, addrs);
        }

        rp_resolver_free(r, rn->query);
        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

        return;
    }

    if (cname) {

        /* CNAME only */

        if (rn->naddrs == (u_short) -1
#if (RP_HAVE_INET6)
            || rn->naddrs6 == (u_short) -1
#endif
            )
        {
            goto next;
        }

        if (rp_resolver_copy(r, &name, buf, cname, buf + n) != RP_OK) {
            goto failed;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        rp_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

        rn->valid = rp_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = rp_time() + r->expire;

        rp_queue_insert_head(&r->name_expire_queue, &rn->queue);

        rp_resolver_free(r, rn->query);
        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= RP_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = RP_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) rp_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    rp_log_error(r->log_level, r->log, 0,
                  "no A or CNAME types in DNS response");
    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    rp_log_error(r->log_level, r->log, 0, err);

    return;

failed:

next:

    /* unlock name mutex */

    return;
}


static void
rp_resolver_process_srv(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t nan,
    rp_uint_t trunc, rp_uint_t ans)
{
    char                       *err;
    u_char                     *cname;
    size_t                      len;
    int32_t                     ttl;
    uint32_t                    hash;
    rp_str_t                   name;
    rp_uint_t                  type, qident, class, start, nsrvs, a, i, j;
    rp_resolver_an_t          *an;
    rp_resolver_ctx_t         *ctx, *next;
    rp_resolver_srv_t         *srvs;
    rp_resolver_node_t        *rn;
    rp_resolver_connection_t  *rec;

    if (rp_resolver_copy(r, &name, buf,
                          buf + sizeof(rp_resolver_hdr_t), buf + n)
        != RP_OK)
    {
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    hash = rp_crc32_short(name.data, name.len);

    rn = rp_resolver_lookup_srv(r, &name, hash);

    if (rn == NULL || rn->query == NULL) {
        rp_log_error(r->log_level, r->log, 0,
                      "unexpected response for %V", &name);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    if (trunc && rn->tcp) {
        rp_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        rp_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui response for %V, expect %ui",
                      ident, &name, qident);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    rp_resolver_free(r, name.data);

    if (trunc) {

        rp_queue_remove(&rn->queue);

        if (rn->waiting == NULL) {
            rp_rbtree_delete(&r->srv_rbtree, &rn->node);
            rp_resolver_free_node(r, rn);
            return;
        }

        rec = r->connections.elts;
        rec = &rec[rn->last_connection];

        rn->tcp = 1;

        (void) rp_resolver_send_tcp_query(r, rec, rn->query, rn->qlen);

        rn->expire = rp_time() + r->resend_timeout;

        rp_queue_insert_head(&r->srv_resend_queue, &rn->queue);

        return;
    }

    if (code == 0 && rn->code) {
        code = rn->code;
    }

    if (code == 0 && nan == 0) {
        code = RP_RESOLVE_NXDOMAIN;
    }

    if (code) {
        next = rn->waiting;
        rn->waiting = NULL;

        rp_queue_remove(&rn->queue);

        rp_rbtree_delete(&r->srv_rbtree, &rn->node);

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = rp_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        rp_resolver_free_node(r, rn);

        return;
    }

    i = ans;
    nsrvs = 0;
    cname = NULL;

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(rp_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (rp_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rn->ttl = rp_min(rn->ttl, (uint32_t) ttl);

        i += sizeof(rp_resolver_an_t);

        switch (type) {

        case RP_RESOLVE_SRV:

            if (i + 6 > n) {
                goto short_response;
            }

            if (rp_resolver_copy(r, NULL, buf, &buf[i + 6], buf + n)
                != RP_OK)
            {
                goto failed;
            }

            nsrvs++;

            break;

        case RP_RESOLVE_CNAME:

            cname = &buf[i];

            break;

        case RP_RESOLVE_DNAME:

            break;

        default:

            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui", type);
        }

        i += len;
    }

    rp_log_debug3(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolver nsrvs:%ui cname:%p ttl:%uD",
                   nsrvs, cname, rn->ttl);

    if (nsrvs) {

        srvs = rp_resolver_calloc(r, nsrvs * sizeof(rp_resolver_srv_t));
        if (srvs == NULL) {
            goto failed;
        }

        rn->u.srvs = srvs;
        rn->nsrvs = (u_short) nsrvs;

        j = 0;
        i = ans;

        for (a = 0; a < nan; a++) {

            for ( ;; ) {

                if (buf[i] & 0xc0) {
                    i += 2;
                    break;
                }

                if (buf[i] == 0) {
                    i++;
                    break;
                }

                i += 1 + buf[i];
            }

            an = (rp_resolver_an_t *) &buf[i];

            type = (an->type_hi << 8) + an->type_lo;
            len = (an->len_hi << 8) + an->len_lo;

            i += sizeof(rp_resolver_an_t);

            if (type == RP_RESOLVE_SRV) {

                srvs[j].priority = (buf[i] << 8) + buf[i + 1];
                srvs[j].weight = (buf[i + 2] << 8) + buf[i + 3];

                if (srvs[j].weight == 0) {
                    srvs[j].weight = 1;
                }

                srvs[j].port = (buf[i + 4] << 8) + buf[i + 5];

                if (rp_resolver_copy(r, &srvs[j].name, buf, &buf[i + 6],
                                      buf + n)
                    != RP_OK)
                {
                    goto failed;
                }

                j++;
            }

            i += len;
        }

        rp_sort(srvs, nsrvs, sizeof(rp_resolver_srv_t),
                 rp_resolver_cmp_srvs);

        rp_resolver_free(r, rn->query);
        rn->query = NULL;

        rp_queue_remove(&rn->queue);

        rn->valid = rp_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = rp_time() + r->expire;

        rp_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        next = rn->waiting;
        rn->waiting = NULL;

        while (next) {
            ctx = next;
            next = ctx->next;

            rp_resolver_resolve_srv_names(ctx, rn);
        }

        return;
    }

    rn->nsrvs = 0;

    if (cname) {

        /* CNAME only */

        if (rp_resolver_copy(r, &name, buf, cname, buf + n) != RP_OK) {
            goto failed;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0,
                       "resolver cname:\"%V\"", &name);

        rp_queue_remove(&rn->queue);

        rn->cnlen = (u_short) name.len;
        rn->u.cname = name.data;

        rn->valid = rp_time() + (r->valid ? r->valid : (time_t) rn->ttl);
        rn->expire = rp_time() + r->expire;

        rp_queue_insert_head(&r->srv_expire_queue, &rn->queue);

        rp_resolver_free(r, rn->query);
        rn->query = NULL;
#if (RP_HAVE_INET6)
        rn->query6 = NULL;
#endif

        ctx = rn->waiting;
        rn->waiting = NULL;

        if (ctx) {

            if (ctx->recursion++ >= RP_RESOLVER_MAX_RECURSION) {

                /* unlock name mutex */

                do {
                    ctx->state = RP_RESOLVE_NXDOMAIN;
                    next = ctx->next;

                    ctx->handler(ctx);

                    ctx = next;
                } while (ctx);

                return;
            }

            for (next = ctx; next; next = next->next) {
                next->node = NULL;
            }

            (void) rp_resolve_name_locked(r, ctx, &name);
        }

        /* unlock name mutex */

        return;
    }

    rp_log_error(r->log_level, r->log, 0, "no SRV type in DNS response");

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock name mutex */

    rp_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock name mutex */

    return;
}


static void
rp_resolver_resolve_srv_names(rp_resolver_ctx_t *ctx, rp_resolver_node_t *rn)
{
    rp_uint_t                i;
    rp_resolver_t           *r;
    rp_resolver_ctx_t       *cctx;
    rp_resolver_srv_name_t  *srvs;

    r = ctx->resolver;

    ctx->node = NULL;
    ctx->state = RP_OK;
    ctx->valid = rn->valid;
    ctx->count = rn->nsrvs;

    srvs = rp_resolver_calloc(r, rn->nsrvs * sizeof(rp_resolver_srv_name_t));
    if (srvs == NULL) {
        goto failed;
    }

    ctx->srvs = srvs;
    ctx->nsrvs = rn->nsrvs;

    if (ctx->event && ctx->event->timer_set) {
        rp_del_timer(ctx->event);
    }

    for (i = 0; i < (rp_uint_t) rn->nsrvs; i++) {
        srvs[i].name.data = rp_resolver_alloc(r, rn->u.srvs[i].name.len);
        if (srvs[i].name.data == NULL) {
            goto failed;
        }

        srvs[i].name.len = rn->u.srvs[i].name.len;
        rp_memcpy(srvs[i].name.data, rn->u.srvs[i].name.data,
                   srvs[i].name.len);

        cctx = rp_resolve_start(r, NULL);
        if (cctx == NULL) {
            goto failed;
        }

        cctx->name = srvs[i].name;
        cctx->handler = rp_resolver_srv_names_handler;
        cctx->data = ctx;
        cctx->srvs = &srvs[i];
        cctx->timeout = ctx->timeout;

        srvs[i].priority = rn->u.srvs[i].priority;
        srvs[i].weight = rn->u.srvs[i].weight;
        srvs[i].port = rn->u.srvs[i].port;
        srvs[i].ctx = cctx;

        if (rp_resolve_name(cctx) == RP_ERROR) {
            srvs[i].ctx = NULL;
            goto failed;
        }
    }

    return;

failed:

    ctx->state = RP_ERROR;
    ctx->valid = rp_time() + (r->valid ? r->valid : 10);

    ctx->handler(ctx);
}


static void
rp_resolver_srv_names_handler(rp_resolver_ctx_t *cctx)
{
    rp_uint_t                i;
    rp_addr_t               *addrs;
    rp_resolver_t           *r;
    rp_sockaddr_t           *sockaddr;
    rp_resolver_ctx_t       *ctx;
    rp_resolver_srv_name_t  *srv;

    r = cctx->resolver;
    ctx = cctx->data;
    srv = cctx->srvs;

    ctx->count--;
    ctx->async |= cctx->async;

    srv->ctx = NULL;
    srv->state = cctx->state;

    if (cctx->naddrs) {

        ctx->valid = rp_min(ctx->valid, cctx->valid);

        addrs = rp_resolver_calloc(r, cctx->naddrs * sizeof(rp_addr_t));
        if (addrs == NULL) {
            srv->state = RP_ERROR;
            goto done;
        }

        sockaddr = rp_resolver_alloc(r, cctx->naddrs * sizeof(rp_sockaddr_t));
        if (sockaddr == NULL) {
            rp_resolver_free(r, addrs);
            srv->state = RP_ERROR;
            goto done;
        }

        for (i = 0; i < cctx->naddrs; i++) {
            addrs[i].sockaddr = &sockaddr[i].sockaddr;
            addrs[i].socklen = cctx->addrs[i].socklen;

            rp_memcpy(&sockaddr[i], cctx->addrs[i].sockaddr,
                       addrs[i].socklen);

            rp_inet_set_port(addrs[i].sockaddr, srv->port);
        }

        srv->addrs = addrs;
        srv->naddrs = cctx->naddrs;
    }

done:

    rp_resolve_name_done(cctx);

    if (ctx->count == 0) {
        rp_resolver_report_srv(r, ctx);
    }
}


static void
rp_resolver_process_ptr(rp_resolver_t *r, u_char *buf, size_t n,
    rp_uint_t ident, rp_uint_t code, rp_uint_t nan)
{
    char                 *err;
    size_t                len;
    in_addr_t             addr;
    int32_t               ttl;
    rp_int_t             octet;
    rp_str_t             name;
    rp_uint_t            mask, type, class, qident, a, i, start;
    rp_queue_t          *expire_queue;
    rp_rbtree_t         *tree;
    rp_resolver_an_t    *an;
    rp_resolver_ctx_t   *ctx, *next;
    rp_resolver_node_t  *rn;
#if (RP_HAVE_INET6)
    uint32_t              hash;
    rp_int_t             digit;
    struct in6_addr       addr6;
#endif

    if (rp_resolver_copy(r, &name, buf,
                          buf + sizeof(rp_resolver_hdr_t), buf + n)
        != RP_OK)
    {
        return;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0, "resolver qs:%V", &name);

    /* AF_INET */

    addr = 0;
    i = sizeof(rp_resolver_hdr_t);

    for (mask = 0; mask < 32; mask += 8) {
        len = buf[i++];

        octet = rp_atoi(&buf[i], len);
        if (octet == RP_ERROR || octet > 255) {
            goto invalid_in_addr_arpa;
        }

        addr += octet << mask;
        i += len;
    }

    if (rp_strcasecmp(&buf[i], (u_char *) "\7in-addr\4arpa") == 0) {
        i += sizeof("\7in-addr\4arpa");

        /* lock addr mutex */

        rn = rp_resolver_lookup_addr(r, addr);

        tree = &r->addr_rbtree;
        expire_queue = &r->addr_expire_queue;

        goto valid;
    }

invalid_in_addr_arpa:

#if (RP_HAVE_INET6)

    i = sizeof(rp_resolver_hdr_t);

    for (octet = 15; octet >= 0; octet--) {
        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = rp_hextoi(&buf[i++], 1);
        if (digit == RP_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] = (u_char) digit;

        if (buf[i++] != '\1') {
            goto invalid_ip6_arpa;
        }

        digit = rp_hextoi(&buf[i++], 1);
        if (digit == RP_ERROR) {
            goto invalid_ip6_arpa;
        }

        addr6.s6_addr[octet] += (u_char) (digit * 16);
    }

    if (rp_strcasecmp(&buf[i], (u_char *) "\3ip6\4arpa") == 0) {
        i += sizeof("\3ip6\4arpa");

        /* lock addr mutex */

        hash = rp_crc32_short(addr6.s6_addr, 16);
        rn = rp_resolver_lookup_addr6(r, &addr6, hash);

        tree = &r->addr6_rbtree;
        expire_queue = &r->addr6_expire_queue;

        goto valid;
    }

invalid_ip6_arpa:
#endif

    rp_log_error(r->log_level, r->log, 0,
                  "invalid in-addr.arpa or ip6.arpa name in DNS response");
    rp_resolver_free(r, name.data);
    return;

valid:

    if (rn == NULL || rn->query == NULL) {
        rp_log_error(r->log_level, r->log, 0,
                      "unexpected response for %V", &name);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    qident = (rn->query[0] << 8) + rn->query[1];

    if (ident != qident) {
        rp_log_error(r->log_level, r->log, 0,
                      "wrong ident %ui response for %V, expect %ui",
                      ident, &name, qident);
        rp_resolver_free(r, name.data);
        goto failed;
    }

    rp_resolver_free(r, name.data);

    if (code == 0 && nan == 0) {
        code = RP_RESOLVE_NXDOMAIN;
    }

    if (code) {
        next = rn->waiting;
        rn->waiting = NULL;

        rp_queue_remove(&rn->queue);

        rp_rbtree_delete(tree, &rn->node);

        /* unlock addr mutex */

        while (next) {
            ctx = next;
            ctx->state = code;
            ctx->valid = rp_time() + (r->valid ? r->valid : 10);
            next = ctx->next;

            ctx->handler(ctx);
        }

        rp_resolver_free_node(r, rn);

        return;
    }

    i += sizeof(rp_resolver_qs_t);

    for (a = 0; a < nan; a++) {

        start = i;

        while (i < n) {

            if (buf[i] & 0xc0) {
                i += 2;
                goto found;
            }

            if (buf[i] == 0) {
                i++;
                goto test_length;
            }

            i += 1 + buf[i];
        }

        goto short_response;

    test_length:

        if (i - start < 2) {
            err = "invalid name in DNS response";
            goto invalid;
        }

    found:

        if (i + sizeof(rp_resolver_an_t) >= n) {
            goto short_response;
        }

        an = (rp_resolver_an_t *) &buf[i];

        type = (an->type_hi << 8) + an->type_lo;
        class = (an->class_hi << 8) + an->class_lo;
        len = (an->len_hi << 8) + an->len_lo;
        ttl = (an->ttl[0] << 24) + (an->ttl[1] << 16)
            + (an->ttl[2] << 8) + (an->ttl[3]);

        if (class != 1) {
            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR class %ui", class);
            goto failed;
        }

        if (ttl < 0) {
            ttl = 0;
        }

        rp_log_debug3(RP_LOG_DEBUG_CORE, r->log, 0,
                      "resolver qt:%ui cl:%ui len:%uz",
                      type, class, len);

        i += sizeof(rp_resolver_an_t);

        switch (type) {

        case RP_RESOLVE_PTR:

            goto ptr;

        case RP_RESOLVE_CNAME:

            break;

        default:

            rp_log_error(r->log_level, r->log, 0,
                          "unexpected RR type %ui", type);
        }

        i += len;
    }

    /* unlock addr mutex */

    rp_log_error(r->log_level, r->log, 0,
                  "no PTR type in DNS response");
    return;

ptr:

    if (rp_resolver_copy(r, &name, buf, buf + i, buf + n) != RP_OK) {
        goto failed;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, r->log, 0, "resolver an:%V", &name);

    if (name.len != (size_t) rn->nlen
        || rp_strncmp(name.data, rn->name, name.len) != 0)
    {
        if (rn->nlen) {
            rp_resolver_free(r, rn->name);
        }

        rn->nlen = (u_short) name.len;
        rn->name = name.data;

        name.data = rp_resolver_dup(r, rn->name, name.len);
        if (name.data == NULL) {
            goto failed;
        }
    }

    rp_queue_remove(&rn->queue);

    rn->valid = rp_time() + (r->valid ? r->valid : ttl);
    rn->expire = rp_time() + r->expire;

    rp_queue_insert_head(expire_queue, &rn->queue);

    next = rn->waiting;
    rn->waiting = NULL;

    /* unlock addr mutex */

    while (next) {
        ctx = next;
        ctx->state = RP_OK;
        ctx->valid = rn->valid;
        ctx->name = name;
        next = ctx->next;

        ctx->handler(ctx);
    }

    rp_resolver_free(r, name.data);

    return;

short_response:

    err = "short DNS response";

invalid:

    /* unlock addr mutex */

    rp_log_error(r->log_level, r->log, 0, err);

    return;

failed:

    /* unlock addr mutex */

    return;
}


static rp_resolver_node_t *
rp_resolver_lookup_name(rp_resolver_t *r, rp_str_t *name, uint32_t hash)
{
    rp_int_t             rc;
    rp_rbtree_node_t    *node, *sentinel;
    rp_resolver_node_t  *rn;

    node = r->name_rbtree.root;
    sentinel = r->name_rbtree.sentinel;

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

        rn = rp_resolver_node(node);

        rc = rp_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static rp_resolver_node_t *
rp_resolver_lookup_srv(rp_resolver_t *r, rp_str_t *name, uint32_t hash)
{
    rp_int_t             rc;
    rp_rbtree_node_t    *node, *sentinel;
    rp_resolver_node_t  *rn;

    node = r->srv_rbtree.root;
    sentinel = r->srv_rbtree.sentinel;

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

        rn = rp_resolver_node(node);

        rc = rp_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}


static rp_resolver_node_t *
rp_resolver_lookup_addr(rp_resolver_t *r, in_addr_t addr)
{
    rp_rbtree_node_t  *node, *sentinel;

    node = r->addr_rbtree.root;
    sentinel = r->addr_rbtree.sentinel;

    while (node != sentinel) {

        if (addr < node->key) {
            node = node->left;
            continue;
        }

        if (addr > node->key) {
            node = node->right;
            continue;
        }

        /* addr == node->key */

        return rp_resolver_node(node);
    }

    /* not found */

    return NULL;
}


#if (RP_HAVE_INET6)

static rp_resolver_node_t *
rp_resolver_lookup_addr6(rp_resolver_t *r, struct in6_addr *addr,
    uint32_t hash)
{
    rp_int_t             rc;
    rp_rbtree_node_t    *node, *sentinel;
    rp_resolver_node_t  *rn;

    node = r->addr6_rbtree.root;
    sentinel = r->addr6_rbtree.sentinel;

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

        rn = rp_resolver_node(node);

        rc = rp_memcmp(addr, &rn->addr6, 16);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}

#endif


static void
rp_resolver_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t    **p;
    rp_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = rp_resolver_node(node);
            rn_temp = rp_resolver_node(temp);

            p = (rp_memn2cmp(rn->name, rn_temp->name, rn->nlen, rn_temp->nlen)
                 < 0) ? &temp->left : &temp->right;
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


#if (RP_HAVE_INET6)

static void
rp_resolver_rbtree_insert_addr6_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t    **p;
    rp_resolver_node_t   *rn, *rn_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            rn = rp_resolver_node(node);
            rn_temp = rp_resolver_node(temp);

            p = (rp_memcmp(&rn->addr6, &rn_temp->addr6, 16)
                 < 0) ? &temp->left : &temp->right;
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

#endif


static rp_int_t
rp_resolver_create_name_query(rp_resolver_t *r, rp_resolver_node_t *rn,
    rp_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    rp_uint_t           ident;
    rp_resolver_qs_t   *qs;
    rp_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(rp_resolver_hdr_t) + nlen + sizeof(rp_resolver_qs_t);

#if (RP_HAVE_INET6)
    p = rp_resolver_alloc(r, r->ipv6 ? len * 2 : len);
#else
    p = rp_resolver_alloc(r, len);
#endif
    if (p == NULL) {
        return RP_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

#if (RP_HAVE_INET6)
    if (r->ipv6) {
        rn->query6 = p + len;
    }
#endif

    query = (rp_resolver_hdr_t *) p;

    ident = rp_random();

    rp_log_debug2(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" A %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(rp_resolver_hdr_t) + nlen;

    qs = (rp_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = RP_RESOLVE_A;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* convert "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return RP_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return RP_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return RP_DECLINED;
    }

    *p = (u_char) len;

#if (RP_HAVE_INET6)
    if (!r->ipv6) {
        return RP_OK;
    }

    p = rn->query6;

    rp_memcpy(p, rn->query, rn->qlen);

    query = (rp_resolver_hdr_t *) p;

    ident = rp_random();

    rp_log_debug2(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" AAAA %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    p += sizeof(rp_resolver_hdr_t) + nlen;

    qs = (rp_resolver_qs_t *) p;

    qs->type_lo = RP_RESOLVE_AAAA;
#endif

    return RP_OK;
}


static rp_int_t
rp_resolver_create_srv_query(rp_resolver_t *r, rp_resolver_node_t *rn,
    rp_str_t *name)
{
    u_char              *p, *s;
    size_t               len, nlen;
    rp_uint_t           ident;
    rp_resolver_qs_t   *qs;
    rp_resolver_hdr_t  *query;

    nlen = name->len ? (1 + name->len + 1) : 1;

    len = sizeof(rp_resolver_hdr_t) + nlen + sizeof(rp_resolver_qs_t);

    p = rp_resolver_alloc(r, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    rn->qlen = (u_short) len;
    rn->query = p;

    query = (rp_resolver_hdr_t *) p;

    ident = rp_random();

    rp_log_debug2(RP_LOG_DEBUG_CORE, r->log, 0,
                   "resolve: \"%V\" SRV %i", name, ident & 0xffff);

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(rp_resolver_hdr_t) + nlen;

    qs = (rp_resolver_qs_t *) p;

    /* query type */
    qs->type_hi = 0; qs->type_lo = RP_RESOLVE_SRV;

    /* IN query class */
    qs->class_hi = 0; qs->class_lo = 1;

    /* converts "www.example.com" to "\3www\7example\3com\0" */

    len = 0;
    p--;
    *p-- = '\0';

    if (name->len == 0)  {
        return RP_DECLINED;
    }

    for (s = name->data + name->len - 1; s >= name->data; s--) {
        if (*s != '.') {
            *p = *s;
            len++;

        } else {
            if (len == 0 || len > 255) {
                return RP_DECLINED;
            }

            *p = (u_char) len;
            len = 0;
        }

        p--;
    }

    if (len == 0 || len > 255) {
        return RP_DECLINED;
    }

    *p = (u_char) len;

    return RP_OK;
}


static rp_int_t
rp_resolver_create_addr_query(rp_resolver_t *r, rp_resolver_node_t *rn,
    rp_resolver_addr_t *addr)
{
    u_char               *p, *d;
    size_t                len;
    in_addr_t             inaddr;
    rp_int_t             n;
    rp_uint_t            ident;
    rp_resolver_hdr_t   *query;
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (addr->sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        len = sizeof(rp_resolver_hdr_t)
              + 64 + sizeof(".ip6.arpa.") - 1
              + sizeof(rp_resolver_qs_t);

        break;
#endif

    default: /* AF_INET */
        len = sizeof(rp_resolver_hdr_t)
              + sizeof(".255.255.255.255.in-addr.arpa.") - 1
              + sizeof(rp_resolver_qs_t);
    }

    p = rp_resolver_alloc(r, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    rn->query = p;
    query = (rp_resolver_hdr_t *) p;

    ident = rp_random();

    query->ident_hi = (u_char) ((ident >> 8) & 0xff);
    query->ident_lo = (u_char) (ident & 0xff);

    /* recursion query */
    query->flags_hi = 1; query->flags_lo = 0;

    /* one question */
    query->nqs_hi = 0; query->nqs_lo = 1;
    query->nan_hi = 0; query->nan_lo = 0;
    query->nns_hi = 0; query->nns_lo = 0;
    query->nar_hi = 0; query->nar_lo = 0;

    p += sizeof(rp_resolver_hdr_t);

    switch (addr->sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;

        for (n = 15; n >= 0; n--) {
            p = rp_sprintf(p, "\1%xd\1%xd",
                            sin6->sin6_addr.s6_addr[n] & 0xf,
                            (sin6->sin6_addr.s6_addr[n] >> 4) & 0xf);
        }

        p = rp_cpymem(p, "\3ip6\4arpa\0", 10);

        break;
#endif

    default: /* AF_INET */

        sin = (struct sockaddr_in *) addr->sockaddr;
        inaddr = ntohl(sin->sin_addr.s_addr);

        for (n = 0; n < 32; n += 8) {
            d = rp_sprintf(&p[1], "%ud", (inaddr >> n) & 0xff);
            *p = (u_char) (d - &p[1]);
            p = d;
        }

        p = rp_cpymem(p, "\7in-addr\4arpa\0", 14);
    }

    /* query type "PTR", IN query class */
    p = rp_cpymem(p, "\0\14\0\1", 4);

    rn->qlen = (u_short) (p - rn->query);

    return RP_OK;
}


static rp_int_t
rp_resolver_copy(rp_resolver_t *r, rp_str_t *name, u_char *buf, u_char *src,
    u_char *last)
{
    char        *err;
    u_char      *p, *dst;
    ssize_t      len;
    rp_uint_t   i, n;

    p = src;
    len = -1;

    /*
     * compression pointers allow to create endless loop, so we set limit;
     * 128 pointers should be enough to store 255-byte name
     */

    for (i = 0; i < 128; i++) {
        n = *p++;

        if (n == 0) {
            goto done;
        }

        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *p;
            p = &buf[n];

        } else {
            len += 1 + n;
            p = &p[n];
        }

        if (p >= last) {
            err = "name is out of response";
            goto invalid;
        }
    }

    err = "compression pointers loop";

invalid:

    rp_log_error(r->log_level, r->log, 0, err);

    return RP_ERROR;

done:

    if (name == NULL) {
        return RP_OK;
    }

    if (len == -1) {
        rp_str_null(name);
        return RP_OK;
    }

    dst = rp_resolver_alloc(r, len);
    if (dst == NULL) {
        return RP_ERROR;
    }

    name->data = dst;

    n = *src++;

    for ( ;; ) {
        if (n & 0xc0) {
            n = ((n & 0x3f) << 8) + *src;
            src = &buf[n];

            n = *src++;

        } else {
            rp_strlow(dst, src, n);
            dst += n;
            src += n;

            n = *src++;

            if (n != 0) {
                *dst++ = '.';
            }
        }

        if (n == 0) {
            name->len = dst - name->data;
            return RP_OK;
        }
    }
}


static rp_int_t
rp_resolver_set_timeout(rp_resolver_t *r, rp_resolver_ctx_t *ctx)
{
    if (ctx->event || ctx->timeout == 0) {
        return RP_OK;
    }

    ctx->event = rp_resolver_calloc(r, sizeof(rp_event_t));
    if (ctx->event == NULL) {
        return RP_ERROR;
    }

    ctx->event->handler = rp_resolver_timeout_handler;
    ctx->event->data = ctx;
    ctx->event->log = r->log;
    ctx->event->cancelable = ctx->cancelable;
    ctx->ident = -1;

    rp_add_timer(ctx->event, ctx->timeout);

    return RP_OK;
}


static void
rp_resolver_timeout_handler(rp_event_t *ev)
{
    rp_resolver_ctx_t  *ctx;

    ctx = ev->data;

    ctx->state = RP_RESOLVE_TIMEDOUT;

    ctx->handler(ctx);
}


static void
rp_resolver_free_node(rp_resolver_t *r, rp_resolver_node_t *rn)
{
    rp_uint_t  i;

    /* lock alloc mutex */

    if (rn->query) {
        rp_resolver_free_locked(r, rn->query);
    }

    if (rn->name) {
        rp_resolver_free_locked(r, rn->name);
    }

    if (rn->cnlen) {
        rp_resolver_free_locked(r, rn->u.cname);
    }

    if (rn->naddrs > 1 && rn->naddrs != (u_short) -1) {
        rp_resolver_free_locked(r, rn->u.addrs);
    }

#if (RP_HAVE_INET6)
    if (rn->naddrs6 > 1 && rn->naddrs6 != (u_short) -1) {
        rp_resolver_free_locked(r, rn->u6.addrs6);
    }
#endif

    if (rn->nsrvs) {
        for (i = 0; i < (rp_uint_t) rn->nsrvs; i++) {
            if (rn->u.srvs[i].name.data) {
                rp_resolver_free_locked(r, rn->u.srvs[i].name.data);
            }
        }

        rp_resolver_free_locked(r, rn->u.srvs);
    }

    rp_resolver_free_locked(r, rn);

    /* unlock alloc mutex */
}


static void *
rp_resolver_alloc(rp_resolver_t *r, size_t size)
{
    u_char  *p;

    /* lock alloc mutex */

    p = rp_alloc(size, r->log);

    /* unlock alloc mutex */

    return p;
}


static void *
rp_resolver_calloc(rp_resolver_t *r, size_t size)
{
    u_char  *p;

    p = rp_resolver_alloc(r, size);

    if (p) {
        rp_memzero(p, size);
    }

    return p;
}


static void
rp_resolver_free(rp_resolver_t *r, void *p)
{
    /* lock alloc mutex */

    rp_free(p);

    /* unlock alloc mutex */
}


static void
rp_resolver_free_locked(rp_resolver_t *r, void *p)
{
    rp_free(p);
}


static void *
rp_resolver_dup(rp_resolver_t *r, void *src, size_t size)
{
    void  *dst;

    dst = rp_resolver_alloc(r, size);

    if (dst == NULL) {
        return dst;
    }

    rp_memcpy(dst, src, size);

    return dst;
}


static rp_resolver_addr_t *
rp_resolver_export(rp_resolver_t *r, rp_resolver_node_t *rn,
    rp_uint_t rotate)
{
    rp_uint_t            d, i, j, n;
    in_addr_t            *addr;
    rp_sockaddr_t       *sockaddr;
    struct sockaddr_in   *sin;
    rp_resolver_addr_t  *dst;
#if (RP_HAVE_INET6)
    struct in6_addr      *addr6;
    struct sockaddr_in6  *sin6;
#endif

    n = rn->naddrs;
#if (RP_HAVE_INET6)
    n += rn->naddrs6;
#endif

    dst = rp_resolver_calloc(r, n * sizeof(rp_resolver_addr_t));
    if (dst == NULL) {
        return NULL;
    }

    sockaddr = rp_resolver_calloc(r, n * sizeof(rp_sockaddr_t));
    if (sockaddr == NULL) {
        rp_resolver_free(r, dst);
        return NULL;
    }

    i = 0;
    d = rotate ? rp_random() % n : 0;

    if (rn->naddrs) {
        j = rotate ? rp_random() % rn->naddrs : 0;

        addr = (rn->naddrs == 1) ? &rn->u.addr : rn->u.addrs;

        do {
            sin = &sockaddr[d].sockaddr_in;
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = addr[j++];
            dst[d].sockaddr = (struct sockaddr *) sin;
            dst[d++].socklen = sizeof(struct sockaddr_in);

            if (d == n) {
                d = 0;
            }

            if (j == (rp_uint_t) rn->naddrs) {
                j = 0;
            }
        } while (++i < (rp_uint_t) rn->naddrs);
    }

#if (RP_HAVE_INET6)
    if (rn->naddrs6) {
        j = rotate ? rp_random() % rn->naddrs6 : 0;

        addr6 = (rn->naddrs6 == 1) ? &rn->u6.addr6 : rn->u6.addrs6;

        do {
            sin6 = &sockaddr[d].sockaddr_in6;
            sin6->sin6_family = AF_INET6;
            rp_memcpy(sin6->sin6_addr.s6_addr, addr6[j++].s6_addr, 16);
            dst[d].sockaddr = (struct sockaddr *) sin6;
            dst[d++].socklen = sizeof(struct sockaddr_in6);

            if (d == n) {
                d = 0;
            }

            if (j == rn->naddrs6) {
                j = 0;
            }
        } while (++i < n);
    }
#endif

    return dst;
}


static void
rp_resolver_report_srv(rp_resolver_t *r, rp_resolver_ctx_t *ctx)
{
    rp_uint_t                naddrs, nsrvs, nw, i, j, k, l, m, n, w;
    rp_resolver_addr_t      *addrs;
    rp_resolver_srv_name_t  *srvs;

    srvs = ctx->srvs;
    nsrvs = ctx->nsrvs;

    naddrs = 0;

    for (i = 0; i < nsrvs; i++) {
        if (srvs[i].state == RP_ERROR) {
            ctx->state = RP_ERROR;
            ctx->valid = rp_time() + (r->valid ? r->valid : 10);

            ctx->handler(ctx);
            return;
        }

        naddrs += srvs[i].naddrs;
    }

    if (naddrs == 0) {
        ctx->state = srvs[0].state;

        for (i = 0; i < nsrvs; i++) {
            if (srvs[i].state == RP_RESOLVE_NXDOMAIN) {
                ctx->state = RP_RESOLVE_NXDOMAIN;
                break;
            }
        }

        ctx->valid = rp_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    addrs = rp_resolver_calloc(r, naddrs * sizeof(rp_resolver_addr_t));
    if (addrs == NULL) {
        ctx->state = RP_ERROR;
        ctx->valid = rp_time() + (r->valid ? r->valid : 10);

        ctx->handler(ctx);
        return;
    }

    i = 0;
    n = 0;

    do {
        nw = 0;

        for (j = i; j < nsrvs; j++) {
            if (srvs[j].priority != srvs[i].priority) {
                break;
            }

            nw += srvs[j].naddrs * srvs[j].weight;
        }

        if (nw == 0) {
            goto next_srv;
        }

        w = rp_random() % nw;

        for (k = i; k < j; k++) {
            if (w < srvs[k].naddrs * srvs[k].weight) {
                break;
            }

            w -= srvs[k].naddrs * srvs[k].weight;
        }

        for (l = i; l < j; l++) {

            for (m = 0; m < srvs[k].naddrs; m++) {
                addrs[n].socklen = srvs[k].addrs[m].socklen;
                addrs[n].sockaddr = srvs[k].addrs[m].sockaddr;
                addrs[n].name = srvs[k].name;
                addrs[n].priority = srvs[k].priority;
                addrs[n].weight = srvs[k].weight;
                n++;
            }

            if (++k == j) {
                k = i;
            }
        }

next_srv:

        i = j;

    } while (i < ctx->nsrvs);

    ctx->state = RP_OK;
    ctx->addrs = addrs;
    ctx->naddrs = naddrs;

    ctx->handler(ctx);

    rp_resolver_free(r, addrs);
}


char *
rp_resolver_strerror(rp_int_t err)
{
    static char *errors[] = {
        "Format error",     /* FORMERR */
        "Server failure",   /* SERVFAIL */
        "Host not found",   /* NXDOMAIN */
        "Unimplemented",    /* NOTIMP */
        "Operation refused" /* REFUSED */
    };

    if (err > 0 && err < 6) {
        return errors[err - 1];
    }

    if (err == RP_RESOLVE_TIMEDOUT) {
        return "Operation timed out";
    }

    return "Unknown error";
}


static u_char *
rp_resolver_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    rp_resolver_connection_t  *rec;

    p = buf;

    if (log->action) {
        p = rp_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    rec = log->data;

    if (rec) {
        p = rp_snprintf(p, len, ", resolver: %V", &rec->server);
    }

    return p;
}


static rp_int_t
rp_udp_connect(rp_resolver_connection_t *rec)
{
    int                rc;
    rp_int_t          event;
    rp_event_t       *rev, *wev;
    rp_socket_t       s;
    rp_connection_t  *c;

    s = rp_socket(rec->sockaddr->sa_family, SOCK_DGRAM, 0);

    rp_log_debug1(RP_LOG_DEBUG_EVENT, &rec->log, 0, "UDP socket %d", s);

    if (s == (rp_socket_t) -1) {
        rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                      rp_socket_n " failed");
        return RP_ERROR;
    }

    c = rp_get_connection(s, &rec->log);

    if (c == NULL) {
        if (rp_close_socket(s) == -1) {
            rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                          rp_close_socket_n " failed");
        }

        return RP_ERROR;
    }

    if (rp_nonblocking(s) == -1) {
        rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                      rp_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->udp = c;

    c->number = rp_atomic_fetch_add(rp_connection_counter, 1);

    rp_log_debug3(RP_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

    /* TODO: iocp */

    if (rc == -1) {
        rp_log_error(RP_LOG_CRIT, &rec->log, rp_socket_errno,
                      "connect() failed");

        goto failed;
    }

    /* UDP sockets are always ready to write */
    wev->ready = 1;

    event = (rp_event_flags & RP_USE_CLEAR_EVENT) ?
                /* kqueue, epoll */                 RP_CLEAR_EVENT:
                /* select, poll, /dev/poll */       RP_LEVEL_EVENT;
                /* eventport event type has no meaning: oneshot only */

    if (rp_add_event(rev, RP_READ_EVENT, event) != RP_OK) {
        goto failed;
    }

    return RP_OK;

failed:

    rp_close_connection(c);
    rec->udp = NULL;

    return RP_ERROR;
}


static rp_int_t
rp_tcp_connect(rp_resolver_connection_t *rec)
{
    int                rc;
    rp_int_t          event;
    rp_err_t          err;
    rp_uint_t         level;
    rp_socket_t       s;
    rp_event_t       *rev, *wev;
    rp_connection_t  *c;

    s = rp_socket(rec->sockaddr->sa_family, SOCK_STREAM, 0);

    rp_log_debug1(RP_LOG_DEBUG_EVENT, &rec->log, 0, "TCP socket %d", s);

    if (s == (rp_socket_t) -1) {
        rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                      rp_socket_n " failed");
        return RP_ERROR;
    }

    c = rp_get_connection(s, &rec->log);

    if (c == NULL) {
        if (rp_close_socket(s) == -1) {
            rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                          rp_close_socket_n " failed");
        }

        return RP_ERROR;
    }

    if (rp_nonblocking(s) == -1) {
        rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
                      rp_nonblocking_n " failed");

        goto failed;
    }

    rev = c->read;
    wev = c->write;

    rev->log = &rec->log;
    wev->log = &rec->log;

    rec->tcp = c;

    c->number = rp_atomic_fetch_add(rp_connection_counter, 1);

    if (rp_add_conn) {
        if (rp_add_conn(c) == RP_ERROR) {
            goto failed;
        }
    }

    rp_log_debug3(RP_LOG_DEBUG_EVENT, &rec->log, 0,
                   "connect to %V, fd:%d #%uA", &rec->server, s, c->number);

    rc = connect(s, rec->sockaddr, rec->socklen);

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

            rp_log_error(level, &rec->log, err, "connect() to %V failed",
                          &rec->server);

            rp_close_connection(c);
            rec->tcp = NULL;

            return RP_ERROR;
        }
    }

    if (rp_add_conn) {
        if (rc == -1) {

            /* RP_EINPROGRESS */

            return RP_AGAIN;
        }

        rp_log_debug0(RP_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

        wev->ready = 1;

        return RP_OK;
    }

    if (rp_event_flags & RP_USE_IOCP_EVENT) {

        rp_log_debug1(RP_LOG_DEBUG_EVENT, &rec->log, rp_socket_errno,
                       "connect(): %d", rc);

        if (rp_blocking(s) == -1) {
            rp_log_error(RP_LOG_ALERT, &rec->log, rp_socket_errno,
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

    rp_log_debug0(RP_LOG_DEBUG_EVENT, &rec->log, 0, "connected");

    wev->ready = 1;

    return RP_OK;

failed:

    rp_close_connection(c);
    rec->tcp = NULL;

    return RP_ERROR;
}


static rp_int_t
rp_resolver_cmp_srvs(const void *one, const void *two)
{
    rp_int_t            p1, p2;
    rp_resolver_srv_t  *first, *second;

    first = (rp_resolver_srv_t *) one;
    second = (rp_resolver_srv_t *) two;

    p1 = first->priority;
    p2 = second->priority;

    return p1 - p2;
}
