
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_STRING_H_INCLUDED_
#define _RAP_STRING_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    size_t      len;
    u_char     *data;
} rap_str_t;


typedef struct {
    rap_str_t   key;
    rap_str_t   value;
} rap_keyval_t;


typedef struct {
    unsigned    len:28;

    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;

    u_char     *data;
} rap_variable_value_t;


#define rap_string(str)     { sizeof(str) - 1, (u_char *) str }
#define rap_null_string     { 0, NULL }
#define rap_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define rap_str_null(str)   (str)->len = 0; (str)->data = NULL


#define rap_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define rap_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

void rap_strlow(u_char *dst, u_char *src, size_t n);


#define rap_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define rap_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define rap_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define rap_strlen(s)       strlen((const char *) s)

size_t rap_strnlen(u_char *p, size_t n);

#define rap_strchr(s1, c)   strchr((const char *) s1, (int) c)

static rap_inline u_char *
rap_strlchr(u_char *p, u_char *last, u_char c)
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
#define rap_memzero(buf, n)       (void) memset(buf, 0, n)
#define rap_memset(buf, c, n)     (void) memset(buf, c, n)

void rap_explicit_memzero(void *buf, size_t n);


#if (RAP_MEMCPY_LIMIT)

void *rap_memcpy(void *dst, const void *src, size_t n);
#define rap_cpymem(dst, src, n)   (((u_char *) rap_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define rap_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define rap_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static rap_inline u_char *
rap_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return rap_cpymem(dst, src, len);
    }
}

#else

#define rap_copy                  rap_cpymem

#endif


#define rap_memmove(dst, src, n)   (void) memmove(dst, src, n)
#define rap_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define rap_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


u_char *rap_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *rap_pstrdup(rap_pool_t *pool, rap_str_t *src);
u_char * rap_cdecl rap_sprintf(u_char *buf, const char *fmt, ...);
u_char * rap_cdecl rap_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * rap_cdecl rap_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
u_char *rap_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define rap_vsnprintf(buf, max, fmt, args)                                   \
    rap_vslprintf(buf, buf + (max), fmt, args)

rap_int_t rap_strcasecmp(u_char *s1, u_char *s2);
rap_int_t rap_strncasecmp(u_char *s1, u_char *s2, size_t n);

u_char *rap_strnstr(u_char *s1, char *s2, size_t n);

u_char *rap_strstrn(u_char *s1, char *s2, size_t n);
u_char *rap_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *rap_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

rap_int_t rap_rstrncmp(u_char *s1, u_char *s2, size_t n);
rap_int_t rap_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
rap_int_t rap_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
rap_int_t rap_dns_strcmp(u_char *s1, u_char *s2);
rap_int_t rap_filename_cmp(u_char *s1, u_char *s2, size_t n);

rap_int_t rap_atoi(u_char *line, size_t n);
rap_int_t rap_atofp(u_char *line, size_t n, size_t point);
ssize_t rap_atosz(u_char *line, size_t n);
off_t rap_atoof(u_char *line, size_t n);
time_t rap_atotm(u_char *line, size_t n);
rap_int_t rap_hextoi(u_char *line, size_t n);

u_char *rap_hex_dump(u_char *dst, u_char *src, size_t len);


#define rap_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define rap_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void rap_encode_base64(rap_str_t *dst, rap_str_t *src);
void rap_encode_base64url(rap_str_t *dst, rap_str_t *src);
rap_int_t rap_decode_base64(rap_str_t *dst, rap_str_t *src);
rap_int_t rap_decode_base64url(rap_str_t *dst, rap_str_t *src);

uint32_t rap_utf8_decode(u_char **p, size_t n);
size_t rap_utf8_length(u_char *p, size_t n);
u_char *rap_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define RAP_ESCAPE_URI            0
#define RAP_ESCAPE_ARGS           1
#define RAP_ESCAPE_URI_COMPONENT  2
#define RAP_ESCAPE_HTML           3
#define RAP_ESCAPE_REFRESH        4
#define RAP_ESCAPE_MEMCACHED      5
#define RAP_ESCAPE_MAIL_AUTH      6

#define RAP_UNESCAPE_URI       1
#define RAP_UNESCAPE_REDIRECT  2

uintptr_t rap_escape_uri(u_char *dst, u_char *src, size_t size,
    rap_uint_t type);
void rap_unescape_uri(u_char **dst, u_char **src, size_t size, rap_uint_t type);
uintptr_t rap_escape_html(u_char *dst, u_char *src, size_t size);
uintptr_t rap_escape_json(u_char *dst, u_char *src, size_t size);


typedef struct {
    rap_rbtree_node_t         node;
    rap_str_t                 str;
} rap_str_node_t;


void rap_str_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);
rap_str_node_t *rap_str_rbtree_lookup(rap_rbtree_t *rbtree, rap_str_t *name,
    uint32_t hash);


void rap_sort(void *base, size_t n, size_t size,
    rap_int_t (*cmp)(const void *, const void *));
#define rap_qsort             qsort


#define rap_value_helper(n)   #n
#define rap_value(n)          rap_value_helper(n)


#endif /* _RAP_STRING_H_INCLUDED_ */
