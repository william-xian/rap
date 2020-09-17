
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#ifndef _RP_RESOLVER_H_INCLUDED_
#define _RP_RESOLVER_H_INCLUDED_


#define RP_RESOLVE_A         1
#define RP_RESOLVE_CNAME     5
#define RP_RESOLVE_PTR       12
#define RP_RESOLVE_MX        15
#define RP_RESOLVE_TXT       16
#if (RP_HAVE_INET6)
#define RP_RESOLVE_AAAA      28
#endif
#define RP_RESOLVE_SRV       33
#define RP_RESOLVE_DNAME     39

#define RP_RESOLVE_FORMERR   1
#define RP_RESOLVE_SERVFAIL  2
#define RP_RESOLVE_NXDOMAIN  3
#define RP_RESOLVE_NOTIMP    4
#define RP_RESOLVE_REFUSED   5
#define RP_RESOLVE_TIMEDOUT  RP_ETIMEDOUT


#define RP_NO_RESOLVER       (void *) -1

#define RP_RESOLVER_MAX_RECURSION    50


typedef struct rp_resolver_s  rp_resolver_t;


typedef struct {
    rp_connection_t         *udp;
    rp_connection_t         *tcp;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rp_str_t                 server;
    rp_log_t                 log;
    rp_buf_t                *read_buf;
    rp_buf_t                *write_buf;
    rp_resolver_t           *resolver;
} rp_resolver_connection_t;


typedef struct rp_resolver_ctx_s  rp_resolver_ctx_t;

typedef void (*rp_resolver_handler_pt)(rp_resolver_ctx_t *ctx);


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rp_str_t                 name;
    u_short                   priority;
    u_short                   weight;
} rp_resolver_addr_t;


typedef struct {
    rp_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;
} rp_resolver_srv_t;


typedef struct {
    rp_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;

    rp_resolver_ctx_t       *ctx;
    rp_int_t                 state;

    rp_uint_t                naddrs;
    rp_addr_t               *addrs;
} rp_resolver_srv_name_t;


typedef struct {
    rp_rbtree_node_t         node;
    rp_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;

#if (RP_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif

    u_short                   nlen;
    u_short                   qlen;

    u_char                   *query;
#if (RP_HAVE_INET6)
    u_char                   *query6;
#endif

    union {
        in_addr_t             addr;
        in_addr_t            *addrs;
        u_char               *cname;
        rp_resolver_srv_t   *srvs;
    } u;

    u_char                    code;
    u_short                   naddrs;
    u_short                   nsrvs;
    u_short                   cnlen;

#if (RP_HAVE_INET6)
    union {
        struct in6_addr       addr6;
        struct in6_addr      *addrs6;
    } u6;

    u_short                   naddrs6;
#endif

    time_t                    expire;
    time_t                    valid;
    uint32_t                  ttl;

    unsigned                  tcp:1;
#if (RP_HAVE_INET6)
    unsigned                  tcp6:1;
#endif

    rp_uint_t                last_connection;

    rp_resolver_ctx_t       *waiting;
} rp_resolver_node_t;


struct rp_resolver_s {
    /* has to be pointer because of "incomplete type" */
    rp_event_t              *event;
    void                     *dummy;
    rp_log_t                *log;

    /* event ident must be after 3 pointers as in rp_connection_t */
    rp_int_t                 ident;

    /* simple round robin DNS peers balancer */
    rp_array_t               connections;
    rp_uint_t                last_connection;

    rp_rbtree_t              name_rbtree;
    rp_rbtree_node_t         name_sentinel;

    rp_rbtree_t              srv_rbtree;
    rp_rbtree_node_t         srv_sentinel;

    rp_rbtree_t              addr_rbtree;
    rp_rbtree_node_t         addr_sentinel;

    rp_queue_t               name_resend_queue;
    rp_queue_t               srv_resend_queue;
    rp_queue_t               addr_resend_queue;

    rp_queue_t               name_expire_queue;
    rp_queue_t               srv_expire_queue;
    rp_queue_t               addr_expire_queue;

#if (RP_HAVE_INET6)
    rp_uint_t                ipv6;                 /* unsigned  ipv6:1; */
    rp_rbtree_t              addr6_rbtree;
    rp_rbtree_node_t         addr6_sentinel;
    rp_queue_t               addr6_resend_queue;
    rp_queue_t               addr6_expire_queue;
#endif

    time_t                    resend_timeout;
    time_t                    tcp_timeout;
    time_t                    expire;
    time_t                    valid;

    rp_uint_t                log_level;
};


struct rp_resolver_ctx_s {
    rp_resolver_ctx_t       *next;
    rp_resolver_t           *resolver;
    rp_resolver_node_t      *node;

    /* event ident must be after 3 pointers as in rp_connection_t */
    rp_int_t                 ident;

    rp_int_t                 state;
    rp_str_t                 name;
    rp_str_t                 service;

    time_t                    valid;
    rp_uint_t                naddrs;
    rp_resolver_addr_t      *addrs;
    rp_resolver_addr_t       addr;
    struct sockaddr_in        sin;

    rp_uint_t                count;
    rp_uint_t                nsrvs;
    rp_resolver_srv_name_t  *srvs;

    rp_resolver_handler_pt   handler;
    void                     *data;
    rp_msec_t                timeout;

    unsigned                  quick:1;
    unsigned                  async:1;
    unsigned                  cancelable:1;
    rp_uint_t                recursion;
    rp_event_t              *event;
};


rp_resolver_t *rp_resolver_create(rp_conf_t *cf, rp_str_t *names,
    rp_uint_t n);
rp_resolver_ctx_t *rp_resolve_start(rp_resolver_t *r,
    rp_resolver_ctx_t *temp);
rp_int_t rp_resolve_name(rp_resolver_ctx_t *ctx);
void rp_resolve_name_done(rp_resolver_ctx_t *ctx);
rp_int_t rp_resolve_addr(rp_resolver_ctx_t *ctx);
void rp_resolve_addr_done(rp_resolver_ctx_t *ctx);
char *rp_resolver_strerror(rp_int_t err);


#endif /* _RP_RESOLVER_H_INCLUDED_ */
