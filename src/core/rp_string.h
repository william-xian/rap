
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STRING_H_INCLUDED_
#define _RP_STRING_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    size_t      len;
    u_char     *data;
} rp_str_t;


typedef struct {
    rp_str_t   key;
    rp_str_t   value;
} rp_keyval_t;


typedef struct {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    u_char     *data;
} rp_variable_value_t;


#define rp_string(str)     { sizeof(str) - 1, (u_char *) str }
#define rp_null_string     { 0, NULL }
#define rp_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define rp_str_null(str)   (str)->len = 0; (str)->data = NULL


#define rp_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define rp_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void rp_strlow(u_char *dst, u_char *src, size_t n);


#define rp_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define rp_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define rp_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define rp_strlen(s)       strlen((const char *) s)

size_t rp_strnlen(u_char *p, size_t n);

#define rp_strchr(s1, c)   strchr((const char *) s1, (int) c)

static rp_inline u_char *
rp_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define rp_memzero(buf, n)       (void) memset(buf, 0, n)
#define rp_memset(buf, c, n)     (void) memset(buf, c, n)

void rp_explicit_memzero(void *buf, size_t n);


#if (RP_MEMCPY_LIMIT)

void *rp_memcpy(void *dst, const void *src, size_t n);
#define rp_cpymem(dst, src, n)   (((u_char *) rp_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define rp_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define rp_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static rp_inline u_char *
rp_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return rp_cpymem(dst, src, len);
    }
}

#else

#define rp_copy                  rp_cpymem

#endif


#define rp_memmove(dst, src, n)   (void) memmove(dst, src, n)
#define rp_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define rp_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


u_char *rp_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *rp_pstrdup(rp_pool_t *pool, rp_str_t *src);
u_char * rp_cdecl rp_sprintf(u_char *buf, const char *fmt, ...);
u_char * rp_cdecl rp_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * rp_cdecl rp_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
u_char *rp_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define rp_vsnprintf(buf, max, fmt, args)                                   \
    rp_vslprintf(buf, buf + (max), fmt, args)

rp_int_t rp_strcasecmp(u_char *s1, u_char *s2);
rp_int_t rp_strncasecmp(u_char *s1, u_char *s2, size_t n);

u_char *rp_strnstr(u_char *s1, char *s2, size_t n);

u_char *rp_strstrn(u_char *s1, char *s2, size_t n);
u_char *rp_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *rp_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

rp_int_t rp_rstrncmp(u_char *s1, u_char *s2, size_t n);
rp_int_t rp_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
rp_int_t rp_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
rp_int_t rp_dns_strcmp(u_char *s1, u_char *s2);
rp_int_t rp_filename_cmp(u_char *s1, u_char *s2, size_t n);

rp_int_t rp_atoi(u_char *line, size_t n);
rp_int_t rp_atofp(u_char *line, size_t n, size_t point);
ssize_t rp_atosz(u_char *line, size_t n);
off_t rp_atoof(u_char *line, size_t n);
time_t rp_atotm(u_char *line, size_t n);
rp_int_t rp_hextoi(u_char *line, size_t n);

u_char *rp_hex_dump(u_char *dst, u_char *src, size_t len);


#define rp_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define rp_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void rp_encode_base64(rp_str_t *dst, rp_str_t *src);
void rp_encode_base64url(rp_str_t *dst, rp_str_t *src);
rp_int_t rp_decode_base64(rp_str_t *dst, rp_str_t *src);
rp_int_t rp_decode_base64url(rp_str_t *dst, rp_str_t *src);

uint32_t rp_utf8_decode(u_char **p, size_t n);
size_t rp_utf8_length(u_char *p, size_t n);
u_char *rp_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define RP_ESCAPE_URI            0
#define RP_ESCAPE_ARGS           1
#define RP_ESCAPE_URI_COMPONENT  2
#define RP_ESCAPE_HTML           3
#define RP_ESCAPE_REFRESH        4
#define RP_ESCAPE_MEMCACHED      5
#define RP_ESCAPE_MAIL_AUTH      6

#define RP_UNESCAPE_URI       1
#define RP_UNESCAPE_REDIRECT  2

uintptr_t rp_escape_uri(u_char *dst, u_char *src, size_t size,
    rp_uint_t type);
void rp_unescape_uri(u_char **dst, u_char **src, size_t size, rp_uint_t type);
uintptr_t rp_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t rp_escape_json(u_char *dst, u_char *src, size_t size);


typedef struct {
    rp_rbtree_node_t         node;
    rp_str_t                 str;
} rp_str_node_t;


void rp_str_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
rp_str_node_t *rp_str_rbtree_lookup(rp_rbtree_t *rbtree, rp_str_t *name,
    uint32_t hash);


void rp_sort(void *base, size_t n, size_t size,
    rp_int_t (*cmp)(const void *, const void *));
#define rp_qsort             qsort


#define rp_value_helper(n)   #n
#define rp_value(n)          rp_value_helper(n)


#endif /* _RP_STRING_H_INCLUDED_ */
