
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


static rap_int_t rap_parse_unix_domain_url(rap_pool_t *pool, rap_url_t *u);
static rap_int_t rap_parse_inet_url(rap_pool_t *pool, rap_url_t *u);
static rap_int_t rap_parse_inet6_url(rap_pool_t *pool, rap_url_t *u);
static rap_int_t rap_inet_add_addr(rap_pool_t *pool, rap_url_t *u,
    struct sockaddr *sockaddr, socklen_t socklen, rap_uint_t total);


in_addr_t
rap_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    in_addr_t    addr;
    rap_uint_t   octet, n;

    addr = 0;
    octet = 0;
    n = 0;

    for (p = text; p < text + len; p++) {
        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');

            if (octet > 255) {
                return INADDR_NONE;
            }

            continue;
        }

        if (c == '.') {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }

        return INADDR_NONE;
    }

    if (n == 3) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}


#if (RAP_HAVE_INET6)

rap_int_t
rap_inet6_addr(u_char *p, size_t len, u_char *addr)
{
    u_char      c, *zero, *digit, *s, *d;
    size_t      len4;
    rap_uint_t  n, nibbles, word;

    if (len == 0) {
        return RAP_ERROR;
    }

    zero = NULL;
    digit = NULL;
    len4 = 0;
    nibbles = 0;
    word = 0;
    n = 8;

    if (p[0] == ':') {
        p++;
        len--;
    }

    for (/* void */; len; len--) {
        c = *p++;

        if (c == ':') {
            if (nibbles) {
                digit = p;
                len4 = len;
                *addr++ = (u_char) (word >> 8);
                *addr++ = (u_char) (word & 0xff);

                if (--n) {
                    nibbles = 0;
                    word = 0;
                    continue;
                }

            } else {
                if (zero == NULL) {
                    digit = p;
                    len4 = len;
                    zero = addr;
                    continue;
                }
            }

            return RAP_ERROR;
        }

        if (c == '.' && nibbles) {
            if (n < 2 || digit == NULL) {
                return RAP_ERROR;
            }

            word = rap_inet_addr(digit, len4 - 1);
            if (word == INADDR_NONE) {
                return RAP_ERROR;
            }

            word = ntohl(word);
            *addr++ = (u_char) ((word >> 24) & 0xff);
            *addr++ = (u_char) ((word >> 16) & 0xff);
            n--;
            break;
        }

        if (++nibbles > 4) {
            return RAP_ERROR;
        }

        if (c >= '0' && c <= '9') {
            word = word * 16 + (c - '0');
            continue;
        }

        c |= 0x20;

        if (c >= 'a' && c <= 'f') {
            word = word * 16 + (c - 'a') + 10;
            continue;
        }

        return RAP_ERROR;
    }

    if (nibbles == 0 && zero == NULL) {
        return RAP_ERROR;
    }

    *addr++ = (u_char) (word >> 8);
    *addr++ = (u_char) (word & 0xff);

    if (--n) {
        if (zero) {
            n *= 2;
            s = addr - 1;
            d = s + n;
            while (s >= zero) {
                *d-- = *s--;
            }
            rap_memzero(zero, n);
            return RAP_OK;
        }

    } else {
        if (zero == NULL) {
            return RAP_OK;
        }
    }

    return RAP_ERROR;
}

#endif


size_t
rap_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text, size_t len,
    rap_uint_t port)
{
    u_char               *p;
#if (RAP_HAVE_INET6 || RAP_HAVE_UNIX_DOMAIN)
    size_t                n;
#endif
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    struct sockaddr_un   *saun;
#endif

    switch (sa->sa_family) {

    case AF_INET:

        sin = (struct sockaddr_in *) sa;
        p = (u_char *) &sin->sin_addr;

        if (port) {
            p = rap_snprintf(text, len, "%ud.%ud.%ud.%ud:%d",
                             p[0], p[1], p[2], p[3], ntohs(sin->sin_port));
        } else {
            p = rap_snprintf(text, len, "%ud.%ud.%ud.%ud",
                             p[0], p[1], p[2], p[3]);
        }

        return (p - text);

#if (RAP_HAVE_INET6)

    case AF_INET6:

        sin6 = (struct sockaddr_in6 *) sa;

        n = 0;

        if (port) {
            text[n++] = '[';
        }

        n = rap_inet6_ntop(sin6->sin6_addr.s6_addr, &text[n], len);

        if (port) {
            n = rap_sprintf(&text[1 + n], "]:%d",
                            ntohs(sin6->sin6_port)) - text;
        }

        return n;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        saun = (struct sockaddr_un *) sa;

        /* on Linux sockaddr might not include sun_path at all */

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)) {
            p = rap_snprintf(text, len, "unix:%Z");

        } else {
            n = rap_strnlen((u_char *) saun->sun_path,
                            socklen - offsetof(struct sockaddr_un, sun_path));
            p = rap_snprintf(text, len, "unix:%*s%Z", n, saun->sun_path);
        }

        /* we do not include trailing zero in address length */

        return (p - text - 1);

#endif

    default:
        return 0;
    }
}


size_t
rap_inet_ntop(int family, void *addr, u_char *text, size_t len)
{
    u_char  *p;

    switch (family) {

    case AF_INET:

        p = addr;

        return rap_snprintf(text, len, "%ud.%ud.%ud.%ud",
                            p[0], p[1], p[2], p[3])
               - text;

#if (RAP_HAVE_INET6)

    case AF_INET6:
        return rap_inet6_ntop(addr, text, len);

#endif

    default:
        return 0;
    }
}


#if (RAP_HAVE_INET6)

size_t
rap_inet6_ntop(u_char *p, u_char *text, size_t len)
{
    u_char      *dst;
    size_t       max, n;
    rap_uint_t   i, zero, last;

    if (len < RAP_INET6_ADDRSTRLEN) {
        return 0;
    }

    zero = (rap_uint_t) -1;
    last = (rap_uint_t) -1;
    max = 1;
    n = 0;

    for (i = 0; i < 16; i += 2) {

        if (p[i] || p[i + 1]) {

            if (max < n) {
                zero = last;
                max = n;
            }

            n = 0;
            continue;
        }

        if (n++ == 0) {
            last = i;
        }
    }

    if (max < n) {
        zero = last;
        max = n;
    }

    dst = text;
    n = 16;

    if (zero == 0) {

        if ((max == 5 && p[10] == 0xff && p[11] == 0xff)
            || (max == 6)
            || (max == 7 && p[14] != 0 && p[15] != 1))
        {
            n = 12;
        }

        *dst++ = ':';
    }

    for (i = 0; i < n; i += 2) {

        if (i == zero) {
            *dst++ = ':';
            i += (max - 1) * 2;
            continue;
        }

        dst = rap_sprintf(dst, "%xd", p[i] * 256 + p[i + 1]);

        if (i < 14) {
            *dst++ = ':';
        }
    }

    if (n == 12) {
        dst = rap_sprintf(dst, "%ud.%ud.%ud.%ud", p[12], p[13], p[14], p[15]);
    }

    return dst - text;
}

#endif


rap_int_t
rap_ptocidr(rap_str_t *text, rap_cidr_t *cidr)
{
    u_char      *addr, *mask, *last;
    size_t       len;
    rap_int_t    shift;
#if (RAP_HAVE_INET6)
    rap_int_t    rc;
    rap_uint_t   s, i;
#endif

    addr = text->data;
    last = addr + text->len;

    mask = rap_strlchr(addr, last, '/');
    len = (mask ? mask : last) - addr;

    cidr->u.in.addr = rap_inet_addr(addr, len);

    if (cidr->u.in.addr != INADDR_NONE) {
        cidr->family = AF_INET;

        if (mask == NULL) {
            cidr->u.in.mask = 0xffffffff;
            return RAP_OK;
        }

#if (RAP_HAVE_INET6)
    } else if (rap_inet6_addr(addr, len, cidr->u.in6.addr.s6_addr) == RAP_OK) {
        cidr->family = AF_INET6;

        if (mask == NULL) {
            rap_memset(cidr->u.in6.mask.s6_addr, 0xff, 16);
            return RAP_OK;
        }

#endif
    } else {
        return RAP_ERROR;
    }

    mask++;

    shift = rap_atoi(mask, last - mask);
    if (shift == RAP_ERROR) {
        return RAP_ERROR;
    }

    switch (cidr->family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        if (shift > 128) {
            return RAP_ERROR;
        }

        addr = cidr->u.in6.addr.s6_addr;
        mask = cidr->u.in6.mask.s6_addr;
        rc = RAP_OK;

        for (i = 0; i < 16; i++) {

            s = (shift > 8) ? 8 : shift;
            shift -= s;

            mask[i] = (u_char) (0xffu << (8 - s));

            if (addr[i] != (addr[i] & mask[i])) {
                rc = RAP_DONE;
                addr[i] &= mask[i];
            }
        }

        return rc;
#endif

    default: /* AF_INET */
        if (shift > 32) {
            return RAP_ERROR;
        }

        if (shift) {
            cidr->u.in.mask = htonl((uint32_t) (0xffffffffu << (32 - shift)));

        } else {
            /* x86 compilers use a shl instruction that shifts by modulo 32 */
            cidr->u.in.mask = 0;
        }

        if (cidr->u.in.addr == (cidr->u.in.addr & cidr->u.in.mask)) {
            return RAP_OK;
        }

        cidr->u.in.addr &= cidr->u.in.mask;

        return RAP_DONE;
    }
}


rap_int_t
rap_cidr_match(struct sockaddr *sa, rap_array_t *cidrs)
{
#if (RAP_HAVE_INET6)
    u_char           *p;
#endif
    in_addr_t         inaddr;
    rap_cidr_t       *cidr;
    rap_uint_t        family, i;
#if (RAP_HAVE_INET6)
    rap_uint_t        n;
    struct in6_addr  *inaddr6;
#endif

#if (RAP_SUPPRESS_WARN)
    inaddr = 0;
#if (RAP_HAVE_INET6)
    inaddr6 = NULL;
#endif
#endif

    family = sa->sa_family;

    if (family == AF_INET) {
        inaddr = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
    }

#if (RAP_HAVE_INET6)
    else if (family == AF_INET6) {
        inaddr6 = &((struct sockaddr_in6 *) sa)->sin6_addr;

        if (IN6_IS_ADDR_V4MAPPED(inaddr6)) {
            family = AF_INET;

            p = inaddr6->s6_addr;

            inaddr = p[12] << 24;
            inaddr += p[13] << 16;
            inaddr += p[14] << 8;
            inaddr += p[15];

            inaddr = htonl(inaddr);
        }
    }
#endif

    for (cidr = cidrs->elts, i = 0; i < cidrs->nelts; i++) {
        if (cidr[i].family != family) {
            goto next;
        }

        switch (family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            for (n = 0; n < 16; n++) {
                if ((inaddr6->s6_addr[n] & cidr[i].u.in6.mask.s6_addr[n])
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
            if ((inaddr & cidr[i].u.in.mask) != cidr[i].u.in.addr) {
                goto next;
            }
            break;
        }

        return RAP_OK;

    next:
        continue;
    }

    return RAP_DECLINED;
}


rap_int_t
rap_parse_addr(rap_pool_t *pool, rap_addr_t *addr, u_char *text, size_t len)
{
    in_addr_t             inaddr;
    rap_uint_t            family;
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct in6_addr       inaddr6;
    struct sockaddr_in6  *sin6;

    /*
     * prevent MSVC8 warning:
     *    potentially uninitialized local variable 'inaddr6' used
     */
    rap_memzero(&inaddr6, sizeof(struct in6_addr));
#endif

    inaddr = rap_inet_addr(text, len);

    if (inaddr != INADDR_NONE) {
        family = AF_INET;
        len = sizeof(struct sockaddr_in);

#if (RAP_HAVE_INET6)
    } else if (rap_inet6_addr(text, len, inaddr6.s6_addr) == RAP_OK) {
        family = AF_INET6;
        len = sizeof(struct sockaddr_in6);

#endif
    } else {
        return RAP_DECLINED;
    }

    addr->sockaddr = rap_pcalloc(pool, len);
    if (addr->sockaddr == NULL) {
        return RAP_ERROR;
    }

    addr->sockaddr->sa_family = (u_char) family;
    addr->socklen = len;

    switch (family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) addr->sockaddr;
        rap_memcpy(sin6->sin6_addr.s6_addr, inaddr6.s6_addr, 16);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) addr->sockaddr;
        sin->sin_addr.s_addr = inaddr;
        break;
    }

    return RAP_OK;
}


rap_int_t
rap_parse_addr_port(rap_pool_t *pool, rap_addr_t *addr, u_char *text,
    size_t len)
{
    u_char     *p, *last;
    size_t      plen;
    rap_int_t   rc, port;

    rc = rap_parse_addr(pool, addr, text, len);

    if (rc != RAP_DECLINED) {
        return rc;
    }

    last = text + len;

#if (RAP_HAVE_INET6)
    if (len && text[0] == '[') {

        p = rap_strlchr(text, last, ']');

        if (p == NULL || p == last - 1 || *++p != ':') {
            return RAP_DECLINED;
        }

        text++;
        len -= 2;

    } else
#endif

    {
        p = rap_strlchr(text, last, ':');

        if (p == NULL) {
            return RAP_DECLINED;
        }
    }

    p++;
    plen = last - p;

    port = rap_atoi(p, plen);

    if (port < 1 || port > 65535) {
        return RAP_DECLINED;
    }

    len -= plen + 1;

    rc = rap_parse_addr(pool, addr, text, len);

    if (rc != RAP_OK) {
        return rc;
    }

    rap_inet_set_port(addr->sockaddr, (in_port_t) port);

    return RAP_OK;
}


rap_int_t
rap_parse_url(rap_pool_t *pool, rap_url_t *u)
{
    u_char  *p;
    size_t   len;

    p = u->url.data;
    len = u->url.len;

    if (len >= 5 && rap_strncasecmp(p, (u_char *) "unix:", 5) == 0) {
        return rap_parse_unix_domain_url(pool, u);
    }

    if (len && p[0] == '[') {
        return rap_parse_inet6_url(pool, u);
    }

    return rap_parse_inet_url(pool, u);
}


static rap_int_t
rap_parse_unix_domain_url(rap_pool_t *pool, rap_url_t *u)
{
#if (RAP_HAVE_UNIX_DOMAIN)
    u_char              *path, *uri, *last;
    size_t               len;
    struct sockaddr_un  *saun;

    len = u->url.len;
    path = u->url.data;

    path += 5;
    len -= 5;

    if (u->uri_part) {

        last = path + len;
        uri = rap_strlchr(path, last, ':');

        if (uri) {
            len = uri - path;
            uri++;
            u->uri.len = last - uri;
            u->uri.data = uri;
        }
    }

    if (len == 0) {
        u->err = "no path in the unix domain socket";
        return RAP_ERROR;
    }

    u->host.len = len++;
    u->host.data = path;

    if (len > sizeof(saun->sun_path)) {
        u->err = "too long path in the unix domain socket";
        return RAP_ERROR;
    }

    u->socklen = sizeof(struct sockaddr_un);
    saun = (struct sockaddr_un *) &u->sockaddr;
    saun->sun_family = AF_UNIX;
    (void) rap_cpystrn((u_char *) saun->sun_path, path, len);

    u->addrs = rap_pcalloc(pool, sizeof(rap_addr_t));
    if (u->addrs == NULL) {
        return RAP_ERROR;
    }

    saun = rap_pcalloc(pool, sizeof(struct sockaddr_un));
    if (saun == NULL) {
        return RAP_ERROR;
    }

    u->family = AF_UNIX;
    u->naddrs = 1;

    saun->sun_family = AF_UNIX;
    (void) rap_cpystrn((u_char *) saun->sun_path, path, len);

    u->addrs[0].sockaddr = (struct sockaddr *) saun;
    u->addrs[0].socklen = sizeof(struct sockaddr_un);
    u->addrs[0].name.len = len + 4;
    u->addrs[0].name.data = u->url.data;

    return RAP_OK;

#else

    u->err = "the unix domain sockets are not supported on this platform";

    return RAP_ERROR;

#endif
}


static rap_int_t
rap_parse_inet_url(rap_pool_t *pool, rap_url_t *u)
{
    u_char              *host, *port, *last, *uri, *args, *dash;
    size_t               len;
    rap_int_t            n;
    struct sockaddr_in  *sin;

    u->socklen = sizeof(struct sockaddr_in);
    sin = (struct sockaddr_in *) &u->sockaddr;
    sin->sin_family = AF_INET;

    u->family = AF_INET;

    host = u->url.data;

    last = host + u->url.len;

    port = rap_strlchr(host, last, ':');

    uri = rap_strlchr(host, last, '/');

    args = rap_strlchr(host, last, '?');

    if (args) {
        if (uri == NULL || args < uri) {
            uri = args;
        }
    }

    if (uri) {
        if (u->listen || !u->uri_part) {
            u->err = "invalid host";
            return RAP_ERROR;
        }

        u->uri.len = last - uri;
        u->uri.data = uri;

        last = uri;

        if (uri < port) {
            port = NULL;
        }
    }

    if (port) {
        port++;

        len = last - port;

        if (u->listen) {
            dash = rap_strlchr(port, last, '-');

            if (dash) {
                dash++;

                n = rap_atoi(dash, last - dash);

                if (n < 1 || n > 65535) {
                    u->err = "invalid port";
                    return RAP_ERROR;
                }

                u->last_port = (in_port_t) n;

                len = dash - port - 1;
            }
        }

        n = rap_atoi(port, len);

        if (n < 1 || n > 65535) {
            u->err = "invalid port";
            return RAP_ERROR;
        }

        if (u->last_port && n > u->last_port) {
            u->err = "invalid port range";
            return RAP_ERROR;
        }

        u->port = (in_port_t) n;
        sin->sin_port = htons((in_port_t) n);

        u->port_text.len = last - port;
        u->port_text.data = port;

        last = port - 1;

    } else {
        if (uri == NULL) {

            if (u->listen) {

                /* test value as port only */

                len = last - host;

                dash = rap_strlchr(host, last, '-');

                if (dash) {
                    dash++;

                    n = rap_atoi(dash, last - dash);

                    if (n == RAP_ERROR) {
                        goto no_port;
                    }

                    if (n < 1 || n > 65535) {
                        u->err = "invalid port";

                    } else {
                        u->last_port = (in_port_t) n;
                    }

                    len = dash - host - 1;
                }

                n = rap_atoi(host, len);

                if (n != RAP_ERROR) {

                    if (u->err) {
                        return RAP_ERROR;
                    }

                    if (n < 1 || n > 65535) {
                        u->err = "invalid port";
                        return RAP_ERROR;
                    }

                    if (u->last_port && n > u->last_port) {
                        u->err = "invalid port range";
                        return RAP_ERROR;
                    }

                    u->port = (in_port_t) n;
                    sin->sin_port = htons((in_port_t) n);
                    sin->sin_addr.s_addr = INADDR_ANY;

                    u->port_text.len = last - host;
                    u->port_text.data = host;

                    u->wildcard = 1;

                    return rap_inet_add_addr(pool, u, &u->sockaddr.sockaddr,
                                             u->socklen, 1);
                }
            }
        }

no_port:

        u->err = NULL;
        u->no_port = 1;
        u->port = u->default_port;
        sin->sin_port = htons(u->default_port);
        u->last_port = 0;
    }

    len = last - host;

    if (len == 0) {
        u->err = "no host";
        return RAP_ERROR;
    }

    u->host.len = len;
    u->host.data = host;

    if (u->listen && len == 1 && *host == '*') {
        sin->sin_addr.s_addr = INADDR_ANY;
        u->wildcard = 1;
        return rap_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);
    }

    sin->sin_addr.s_addr = rap_inet_addr(host, len);

    if (sin->sin_addr.s_addr != INADDR_NONE) {

        if (sin->sin_addr.s_addr == INADDR_ANY) {
            u->wildcard = 1;
        }

        return rap_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);
    }

    if (u->no_resolve) {
        return RAP_OK;
    }

    if (rap_inet_resolve_host(pool, u) != RAP_OK) {
        return RAP_ERROR;
    }

    u->family = u->addrs[0].sockaddr->sa_family;
    u->socklen = u->addrs[0].socklen;
    rap_memcpy(&u->sockaddr, u->addrs[0].sockaddr, u->addrs[0].socklen);
    u->wildcard = rap_inet_wildcard(&u->sockaddr.sockaddr);

    return RAP_OK;
}


static rap_int_t
rap_parse_inet6_url(rap_pool_t *pool, rap_url_t *u)
{
#if (RAP_HAVE_INET6)
    u_char               *p, *host, *port, *last, *uri, *dash;
    size_t                len;
    rap_int_t             n;
    struct sockaddr_in6  *sin6;

    u->socklen = sizeof(struct sockaddr_in6);
    sin6 = (struct sockaddr_in6 *) &u->sockaddr;
    sin6->sin6_family = AF_INET6;

    host = u->url.data + 1;

    last = u->url.data + u->url.len;

    p = rap_strlchr(host, last, ']');

    if (p == NULL) {
        u->err = "invalid host";
        return RAP_ERROR;
    }

    port = p + 1;

    uri = rap_strlchr(port, last, '/');

    if (uri) {
        if (u->listen || !u->uri_part) {
            u->err = "invalid host";
            return RAP_ERROR;
        }

        u->uri.len = last - uri;
        u->uri.data = uri;

        last = uri;
    }

    if (port < last) {
        if (*port != ':') {
            u->err = "invalid host";
            return RAP_ERROR;
        }

        port++;

        len = last - port;

        if (u->listen) {
            dash = rap_strlchr(port, last, '-');

            if (dash) {
                dash++;

                n = rap_atoi(dash, last - dash);

                if (n < 1 || n > 65535) {
                    u->err = "invalid port";
                    return RAP_ERROR;
                }

                u->last_port = (in_port_t) n;

                len = dash - port - 1;
            }
        }

        n = rap_atoi(port, len);

        if (n < 1 || n > 65535) {
            u->err = "invalid port";
            return RAP_ERROR;
        }

        if (u->last_port && n > u->last_port) {
            u->err = "invalid port range";
            return RAP_ERROR;
        }

        u->port = (in_port_t) n;
        sin6->sin6_port = htons((in_port_t) n);

        u->port_text.len = last - port;
        u->port_text.data = port;

    } else {
        u->no_port = 1;
        u->port = u->default_port;
        sin6->sin6_port = htons(u->default_port);
    }

    len = p - host;

    if (len == 0) {
        u->err = "no host";
        return RAP_ERROR;
    }

    u->host.len = len + 2;
    u->host.data = host - 1;

    if (rap_inet6_addr(host, len, sin6->sin6_addr.s6_addr) != RAP_OK) {
        u->err = "invalid IPv6 address";
        return RAP_ERROR;
    }

    if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
        u->wildcard = 1;
    }

    u->family = AF_INET6;

    return rap_inet_add_addr(pool, u, &u->sockaddr.sockaddr, u->socklen, 1);

#else

    u->err = "the INET6 sockets are not supported on this platform";

    return RAP_ERROR;

#endif
}


#if (RAP_HAVE_GETADDRINFO && RAP_HAVE_INET6)

rap_int_t
rap_inet_resolve_host(rap_pool_t *pool, rap_url_t *u)
{
    u_char           *host;
    rap_uint_t        n;
    struct addrinfo   hints, *res, *rp;

    host = rap_alloc(u->host.len + 1, pool->log);
    if (host == NULL) {
        return RAP_ERROR;
    }

    (void) rap_cpystrn(host, u->host.data, u->host.len + 1);

    rap_memzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif

    if (getaddrinfo((char *) host, NULL, &hints, &res) != 0) {
        u->err = "host not found";
        rap_free(host);
        return RAP_ERROR;
    }

    rap_free(host);

    for (n = 0, rp = res; rp != NULL; rp = rp->ai_next) {

        switch (rp->ai_family) {

        case AF_INET:
        case AF_INET6:
            break;

        default:
            continue;
        }

        n++;
    }

    if (n == 0) {
        u->err = "host not found";
        goto failed;
    }

    /* MP: rap_shared_palloc() */

    for (rp = res; rp != NULL; rp = rp->ai_next) {

        switch (rp->ai_family) {

        case AF_INET:
        case AF_INET6:
            break;

        default:
            continue;
        }

        if (rap_inet_add_addr(pool, u, rp->ai_addr, rp->ai_addrlen, n)
            != RAP_OK)
        {
            goto failed;
        }
    }

    freeaddrinfo(res);
    return RAP_OK;

failed:

    freeaddrinfo(res);
    return RAP_ERROR;
}

#else /* !RAP_HAVE_GETADDRINFO || !RAP_HAVE_INET6 */

rap_int_t
rap_inet_resolve_host(rap_pool_t *pool, rap_url_t *u)
{
    u_char              *host;
    rap_uint_t           i, n;
    struct hostent      *h;
    struct sockaddr_in   sin;

    /* AF_INET only */

    rap_memzero(&sin, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = rap_inet_addr(u->host.data, u->host.len);

    if (sin.sin_addr.s_addr == INADDR_NONE) {
        host = rap_alloc(u->host.len + 1, pool->log);
        if (host == NULL) {
            return RAP_ERROR;
        }

        (void) rap_cpystrn(host, u->host.data, u->host.len + 1);

        h = gethostbyname((char *) host);

        rap_free(host);

        if (h == NULL || h->h_addr_list[0] == NULL) {
            u->err = "host not found";
            return RAP_ERROR;
        }

        for (n = 0; h->h_addr_list[n] != NULL; n++) { /* void */ }

        /* MP: rap_shared_palloc() */

        for (i = 0; i < n; i++) {
            sin.sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);

            if (rap_inet_add_addr(pool, u, (struct sockaddr *) &sin,
                                  sizeof(struct sockaddr_in), n)
                != RAP_OK)
            {
                return RAP_ERROR;
            }
        }

    } else {

        /* MP: rap_shared_palloc() */

        if (rap_inet_add_addr(pool, u, (struct sockaddr *) &sin,
                              sizeof(struct sockaddr_in), 1)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}

#endif /* RAP_HAVE_GETADDRINFO && RAP_HAVE_INET6 */


static rap_int_t
rap_inet_add_addr(rap_pool_t *pool, rap_url_t *u, struct sockaddr *sockaddr,
    socklen_t socklen, rap_uint_t total)
{
    u_char           *p;
    size_t            len;
    rap_uint_t        i, nports;
    rap_addr_t       *addr;
    struct sockaddr  *sa;

    nports = u->last_port ? u->last_port - u->port + 1 : 1;

    if (u->addrs == NULL) {
        u->addrs = rap_palloc(pool, total * nports * sizeof(rap_addr_t));
        if (u->addrs == NULL) {
            return RAP_ERROR;
        }
    }

    for (i = 0; i < nports; i++) {
        sa = rap_pcalloc(pool, socklen);
        if (sa == NULL) {
            return RAP_ERROR;
        }

        rap_memcpy(sa, sockaddr, socklen);

        rap_inet_set_port(sa, u->port + i);

        switch (sa->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            len = RAP_INET6_ADDRSTRLEN + sizeof("[]:65536") - 1;
            break;
#endif

        default: /* AF_INET */
            len = RAP_INET_ADDRSTRLEN + sizeof(":65535") - 1;
        }

        p = rap_pnalloc(pool, len);
        if (p == NULL) {
            return RAP_ERROR;
        }

        len = rap_sock_ntop(sa, socklen, p, len, 1);

        addr = &u->addrs[u->naddrs++];

        addr->sockaddr = sa;
        addr->socklen = socklen;

        addr->name.len = len;
        addr->name.data = p;
    }

    return RAP_OK;
}


rap_int_t
rap_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, rap_uint_t cmp_port)
{
    struct sockaddr_in   *sin1, *sin2;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin61, *sin62;
#endif
#if (RAP_HAVE_UNIX_DOMAIN)
    size_t                len;
    struct sockaddr_un   *saun1, *saun2;
#endif

    if (sa1->sa_family != sa2->sa_family) {
        return RAP_DECLINED;
    }

    switch (sa1->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:

        sin61 = (struct sockaddr_in6 *) sa1;
        sin62 = (struct sockaddr_in6 *) sa2;

        if (cmp_port && sin61->sin6_port != sin62->sin6_port) {
            return RAP_DECLINED;
        }

        if (rap_memcmp(&sin61->sin6_addr, &sin62->sin6_addr, 16) != 0) {
            return RAP_DECLINED;
        }

        break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        saun1 = (struct sockaddr_un *) sa1;
        saun2 = (struct sockaddr_un *) sa2;

        if (slen1 < slen2) {
            len = slen1 - offsetof(struct sockaddr_un, sun_path);

        } else {
            len = slen2 - offsetof(struct sockaddr_un, sun_path);
        }

        if (len > sizeof(saun1->sun_path)) {
            len = sizeof(saun1->sun_path);
        }

        if (rap_memcmp(&saun1->sun_path, &saun2->sun_path, len) != 0) {
            return RAP_DECLINED;
        }

        break;
#endif

    default: /* AF_INET */

        sin1 = (struct sockaddr_in *) sa1;
        sin2 = (struct sockaddr_in *) sa2;

        if (cmp_port && sin1->sin_port != sin2->sin_port) {
            return RAP_DECLINED;
        }

        if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
            return RAP_DECLINED;
        }

        break;
    }

    return RAP_OK;
}


in_port_t
rap_inet_get_port(struct sockaddr *sa)
{
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sa->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        return ntohs(sin6->sin6_port);
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        return 0;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        return ntohs(sin->sin_port);
    }
}


void
rap_inet_set_port(struct sockaddr *sa, in_port_t port)
{
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sa->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        sin6->sin6_port = htons(port);
        break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        sin->sin_port = htons(port);
        break;
    }
}


rap_uint_t
rap_inet_wildcard(struct sockaddr *sa)
{
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sa->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) sa;

        if (sin->sin_addr.s_addr == INADDR_ANY) {
            return 1;
        }

        break;

#if (RAP_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;

        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
            return 1;
        }

        break;

#endif
    }

    return 0;
}
