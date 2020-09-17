
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HASH_H_INCLUDED_
#define _RP_HASH_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    void             *value;
    u_short           len;
    u_char            name[1];
} rp_hash_elt_t;


typedef struct {
    rp_hash_elt_t  **buckets;
    rp_uint_t        size;
} rp_hash_t;


typedef struct {
    rp_hash_t        hash;
    void             *value;
} rp_hash_wildcard_t;


typedef struct {
    rp_str_t         key;
    rp_uint_t        key_hash;
    void             *value;
} rp_hash_key_t;


typedef rp_uint_t (*rp_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    rp_hash_t            hash;
    rp_hash_wildcard_t  *wc_head;
    rp_hash_wildcard_t  *wc_tail;
} rp_hash_combined_t;


typedef struct {
    rp_hash_t       *hash;
    rp_hash_key_pt   key;

    rp_uint_t        max_size;
    rp_uint_t        bucket_size;

    char             *name;
    rp_pool_t       *pool;
    rp_pool_t       *temp_pool;
} rp_hash_init_t;


#define RP_HASH_SMALL            1
#define RP_HASH_LARGE            2

#define RP_HASH_LARGE_ASIZE      16384
#define RP_HASH_LARGE_HSIZE      10007

#define RP_HASH_WILDCARD_KEY     1
#define RP_HASH_READONLY_KEY     2


typedef struct {
    rp_uint_t        hsize;

    rp_pool_t       *pool;
    rp_pool_t       *temp_pool;

    rp_array_t       keys;
    rp_array_t      *keys_hash;

    rp_array_t       dns_wc_head;
    rp_array_t      *dns_wc_head_hash;

    rp_array_t       dns_wc_tail;
    rp_array_t      *dns_wc_tail_hash;
} rp_hash_keys_arrays_t;


typedef struct {
    rp_uint_t        hash;
    rp_str_t         key;
    rp_str_t         value;
    u_char           *lowcase_key;
} rp_table_elt_t;


void *rp_hash_find(rp_hash_t *hash, rp_uint_t key, u_char *name, size_t len);
void *rp_hash_find_wc_head(rp_hash_wildcard_t *hwc, u_char *name, size_t len);
void *rp_hash_find_wc_tail(rp_hash_wildcard_t *hwc, u_char *name, size_t len);
void *rp_hash_find_combined(rp_hash_combined_t *hash, rp_uint_t key,
    u_char *name, size_t len);

rp_int_t rp_hash_init(rp_hash_init_t *hinit, rp_hash_key_t *names,
    rp_uint_t nelts);
rp_int_t rp_hash_wildcard_init(rp_hash_init_t *hinit, rp_hash_key_t *names,
    rp_uint_t nelts);

#define rp_hash(key, c)   ((rp_uint_t) key * 31 + c)
rp_uint_t rp_hash_key(u_char *data, size_t len);
rp_uint_t rp_hash_key_lc(u_char *data, size_t len);
rp_uint_t rp_hash_strlow(u_char *dst, u_char *src, size_t n);


rp_int_t rp_hash_keys_array_init(rp_hash_keys_arrays_t *ha, rp_uint_t type);
rp_int_t rp_hash_add_key(rp_hash_keys_arrays_t *ha, rp_str_t *key,
    void *value, rp_uint_t flags);


#endif /* _RP_HASH_H_INCLUDED_ */
