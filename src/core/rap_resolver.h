
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#ifndef _RAP_RESOLVER_H_INCLUDED_
#define _RAP_RESOLVER_H_INCLUDED_


#define RAP_RESOLVE_A         1
#define RAP_RESOLVE_CNAME     5
#define RAP_RESOLVE_PTR       12
#define RAP_RESOLVE_MX        15
#define RAP_RESOLVE_TXT       16
#if (RAP_HAVE_INET6)
#define RAP_RESOLVE_AAAA      28
#endif
#define RAP_RESOLVE_SRV       33
#define RAP_RESOLVE_DNAME     39

#define RAP_RESOLVE_FORMERR   1
#define RAP_RESOLVE_SERVFAIL  2
#define RAP_RESOLVE_NXDOMAIN  3
#define RAP_RESOLVE_NOTIMP    4
#define RAP_RESOLVE_REFUSED   5
#define RAP_RESOLVE_TIMEDOUT  RAP_ETIMEDOUT


#define RAP_NO_RESOLVER       (void *) -1

#define RAP_RESOLVER_MAX_RECURSION    50


typedef struct rap_resolver_s  rap_resolver_t;


typedef struct {
    rap_connection_t         *udp;
    rap_connection_t         *tcp;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rap_str_t                 server;
    rap_log_t                 log;
    rap_buf_t                *read_buf;
    rap_buf_t                *write_buf;
    rap_resolver_t           *resolver;
} rap_resolver_connection_t;


typedef struct rap_resolver_ctx_s  rap_resolver_ctx_t;

typedef void (*rap_resolver_handler_pt)(rap_resolver_ctx_t *ctx);


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rap_str_t                 name;
    u_short                   priority;
    u_short                   weight;
} rap_resolver_addr_t;


typedef struct {
    rap_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;
} rap_resolver_srv_t;


typedef struct {
    rap_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;

    rap_resolver_ctx_t       *ctx;
    rap_int_t                 state;

    rap_uint_t                naddrs;
    rap_addr_t               *addrs;
} rap_resolver_srv_name_t;


typedef struct {
    rap_rbtree_node_t         node;
    rap_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;

#if (RAP_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif

    u_short                   nlen;
    u_short                   qlen;

    u_char                   *query;
#if (RAP_HAVE_INET6)
    u_char                   *query6;
#endif

    union {
        in_addr_t             addr;
        in_addr_t            *addrs;
        u_char               *cname;
        rap_resolver_srv_t   *srvs;
    } u;

    u_char                    code;
    u_short                   naddrs;
    u_short                   nsrvs;
    u_short                   cnlen;

#if (RAP_HAVE_INET6)
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
#if (RAP_HAVE_INET6)
    unsigned                  tcp6:1;
#endif

    rap_uint_t                last_connection;

    rap_resolver_ctx_t       *waiting;
} rap_resolver_node_t;


struct rap_resolver_s {
    /* has to be pointer because of "incomplete type" */
    rap_event_t              *event;
    void                     *dummy;
    rap_log_t                *log;

    /* event ident must be after 3 pointers as in rap_connection_t */
    rap_int_t                 ident;

    /* simple round robin DNS peers balancer */
    rap_array_t               connections;
    rap_uint_t                last_connection;

    rap_rbtree_t              name_rbtree;
    rap_rbtree_node_t         name_sentinel;

    rap_rbtree_t              srv_rbtree;
    rap_rbtree_node_t         srv_sentinel;

    rap_rbtree_t              addr_rbtree;
    rap_rbtree_node_t         addr_sentinel;

    rap_queue_t               name_resend_queue;
    rap_queue_t               srv_resend_queue;
    rap_queue_t               addr_resend_queue;

    rap_queue_t               name_expire_queue;
    rap_queue_t               srv_expire_queue;
    rap_queue_t               addr_expire_queue;

#if (RAP_HAVE_INET6)
    rap_uint_t                ipv6;                 /* unsigned  ipv6:1; */
    rap_rbtree_t              addr6_rbtree;
    rap_rbtree_node_t         addr6_sentinel;
    rap_queue_t               addr6_resend_queue;
    rap_queue_t               addr6_expire_queue;
#endif

    time_t                    resend_timeout;
    time_t                    tcp_timeout;
    time_t                    expire;
    time_t                    valid;

    rap_uint_t                log_level;
};


struct rap_resolver_ctx_s {
    rap_resolver_ctx_t       *next;
    rap_resolver_t           *resolver;
    rap_resolver_node_t      *node;

    /* event ident must be after 3 pointers as in rap_connection_t */
    rap_int_t                 ident;

    rap_int_t                 state;
    rap_str_t                 name;
    rap_str_t                 service;

    time_t                    valid;
    rap_uint_t                naddrs;
    rap_resolver_addr_t      *addrs;
    rap_resolver_addr_t       addr;
    struct sockaddr_in        sin;

    rap_uint_t                count;
    rap_uint_t                nsrvs;
    rap_resolver_srv_name_t  *srvs;

    rap_resolver_handler_pt   handler;
    void                     *data;
    rap_msec_t                timeout;

    unsigned                  quick:1;
    unsigned                  async:1;
    unsigned                  cancelable:1;
    rap_uint_t                recursion;
    rap_event_t              *event;
};


rap_resolver_t *rap_resolver_create(rap_conf_t *cf, rap_str_t *names,
    rap_uint_t n);
rap_resolver_ctx_t *rap_resolve_start(rap_resolver_t *r,
    rap_resolver_ctx_t *temp);
rap_int_t rap_resolve_name(rap_resolver_ctx_t *ctx);
void rap_resolve_name_done(rap_resolver_ctx_t *ctx);
rap_int_t rap_resolve_addr(rap_resolver_ctx_t *ctx);
void rap_resolve_addr_done(rap_resolver_ctx_t *ctx);
char *rap_resolver_strerror(rap_int_t err);


#endif /* _RAP_RESOLVER_H_INCLUDED_ */
