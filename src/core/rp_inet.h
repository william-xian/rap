
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_INET_H_INCLUDED_
#define _RP_INET_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define RP_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define RP_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (RP_HAVE_UNIX_DOMAIN)
#define RP_SOCKADDR_STRLEN   RP_UNIX_ADDRSTRLEN
#elif (RP_HAVE_INET6)
#define RP_SOCKADDR_STRLEN   (RP_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define RP_SOCKADDR_STRLEN   (RP_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define RP_SOCKADDRLEN       sizeof(rp_sockaddr_t)


typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;
#if (RP_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;
#endif
#if (RP_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;
#endif
} rp_sockaddr_t;


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} rp_in_cidr_t;


#if (RP_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} rp_in6_cidr_t;

#endif


typedef struct {
    rp_uint_t                family;
    union {
        rp_in_cidr_t         in;
#if (RP_HAVE_INET6)
        rp_in6_cidr_t        in6;
#endif
    } u;
} rp_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    rp_str_t                 name;
} rp_addr_t;


typedef struct {
    rp_str_t                 url;
    rp_str_t                 host;
    rp_str_t                 port_text;
    rp_str_t                 uri;

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
    rp_sockaddr_t            sockaddr;

    rp_addr_t               *addrs;
    rp_uint_t                naddrs;

    char                     *err;
} rp_url_t;


in_addr_t rp_inet_addr(u_char *text, size_t len);
#if (RP_HAVE_INET6)
rp_int_t rp_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t rp_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t rp_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, rp_uint_t port);
size_t rp_inet_ntop(int family, void *addr, u_char *text, size_t len);
rp_int_t rp_ptocidr(rp_str_t *text, rp_cidr_t *cidr);
rp_int_t rp_cidr_match(struct sockaddr *sa, rp_array_t *cidrs);
rp_int_t rp_parse_addr(rp_pool_t *pool, rp_addr_t *addr, u_char *text,
    size_t len);
rp_int_t rp_parse_addr_port(rp_pool_t *pool, rp_addr_t *addr,
    u_char *text, size_t len);
rp_int_t rp_parse_url(rp_pool_t *pool, rp_url_t *u);
rp_int_t rp_inet_resolve_host(rp_pool_t *pool, rp_url_t *u);
rp_int_t rp_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, rp_uint_t cmp_port);
in_port_t rp_inet_get_port(struct sockaddr *sa);
void rp_inet_set_port(struct sockaddr *sa, in_port_t port);
rp_uint_t rp_inet_wildcard(struct sockaddr *sa);


#endif /* _RP_INET_H_INCLUDED_ */
