
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_INET_H_INCLUDED_
#define _RAP_INET_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define RAP_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define RAP_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (RAP_HAVE_UNIX_DOMAIN)
#define RAP_SOCKADDR_STRLEN   RAP_UNIX_ADDRSTRLEN
#elif (RAP_HAVE_INET6)
#define RAP_SOCKADDR_STRLEN   (RAP_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define RAP_SOCKADDR_STRLEN   (RAP_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define RAP_SOCKADDRLEN       sizeof(rap_sockaddr_t)


typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;
#endif
} rap_sockaddr_t;


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} rap_in_cidr_t;


#if (RAP_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} rap_in6_cidr_t;

#endif


typedef struct {
    rap_uint_t                family;
    union {
        rap_in_cidr_t         in;
#if (RAP_HAVE_INET6)
        rap_in6_cidr_t        in6;
#endif
    } u;
} rap_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rap_str_t                 name;
} rap_addr_t;


typedef struct {
    rap_str_t                 url;
    rap_str_t                 host;
    rap_str_t                 port_text;
    rap_str_t                 uri;

    in_port_t                 port;
    in_port_t                 default_port;
    in_port_t                 last_port;
    int                       family;

    unsigned                  listen:1;
    unsigned                  uri_part:1;
    unsigned                  no_resolve:1;

    unsigned                  no_port:1;
    unsigned                  wildcard:1;

    socklen_t                 socklen;
    rap_sockaddr_t            sockaddr;

    rap_addr_t               *addrs;
    rap_uint_t                naddrs;

    char                     *err;
} rap_url_t;


in_addr_t rap_inet_addr(u_char *text, size_t len);
#if (RAP_HAVE_INET6)
rap_int_t rap_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t rap_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t rap_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, rap_uint_t port);
size_t rap_inet_ntop(int family, void *addr, u_char *text, size_t len);
rap_int_t rap_ptocidr(rap_str_t *text, rap_cidr_t *cidr);
rap_int_t rap_cidr_match(struct sockaddr *sa, rap_array_t *cidrs);
rap_int_t rap_parse_addr(rap_pool_t *pool, rap_addr_t *addr, u_char *text,
    size_t len);
rap_int_t rap_parse_addr_port(rap_pool_t *pool, rap_addr_t *addr,
    u_char *text, size_t len);
rap_int_t rap_parse_url(rap_pool_t *pool, rap_url_t *u);
rap_int_t rap_inet_resolve_host(rap_pool_t *pool, rap_url_t *u);
rap_int_t rap_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, rap_uint_t cmp_port);
in_port_t rap_inet_get_port(struct sockaddr *sa);
void rap_inet_set_port(struct sockaddr *sa, in_port_t port);
rap_uint_t rap_inet_wildcard(struct sockaddr *sa);


#endif /* _RAP_INET_H_INCLUDED_ */
