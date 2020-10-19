
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HASH_H_INCLUDED_
#define _RAP_HASH_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    void             *value;
    u_short           len;
    u_char            name[1];
} rap_hash_elt_t;


typedef struct {
    rap_hash_elt_t  **buckets;
    rap_uint_t        size;
} rap_hash_t;


typedef struct {
    rap_hash_t        hash;
    void             *value;
} rap_hash_wildcard_t;


typedef struct {
    rap_str_t         key;
    rap_uint_t        key_hash;
    void             *value;
} rap_hash_key_t;


typedef rap_uint_t (*rap_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    rap_hash_t            hash;
    rap_hash_wildcard_t  *wc_head;
    rap_hash_wildcard_t  *wc_tail;
} rap_hash_combined_t;


typedef struct {
    rap_hash_t       *hash;
    rap_hash_key_pt   key;

    rap_uint_t        max_size;
    rap_uint_t        bucket_size;

    char             *name;
    rap_pool_t       *pool;
    rap_pool_t       *temp_pool;
} rap_hash_init_t;


#define RAP_HASH_SMALL            1
#define RAP_HASH_LARGE            2

#define RAP_HASH_LARGE_ASIZE      16384
#define RAP_HASH_LARGE_HSIZE      10007

#define RAP_HASH_WILDCARD_KEY     1
#define RAP_HASH_READONLY_KEY     2


typedef struct {
    rap_uint_t        hsize;

    rap_pool_t       *pool;
    rap_pool_t       *temp_pool;

    rap_array_t       keys;
    rap_array_t      *keys_hash;

    rap_array_t       dns_wc_head;
    rap_array_t      *dns_wc_head_hash;

    rap_array_t       dns_wc_tail;
    rap_array_t      *dns_wc_tail_hash;
} rap_hash_keys_arrays_t;


typedef struct {
    rap_uint_t        hash;
    rap_str_t         key;
    rap_str_t         value;
    u_char           *lowcase_key;
} rap_table_elt_t;


void *rap_hash_find(rap_hash_t *hash, rap_uint_t key, u_char *name, size_t len);
void *rap_hash_find_wc_head(rap_hash_wildcard_t *hwc, u_char *name, size_t len);
void *rap_hash_find_wc_tail(rap_hash_wildcard_t *hwc, u_char *name, size_t len);
void *rap_hash_find_combined(rap_hash_combined_t *hash, rap_uint_t key,
    u_char *name, size_t len);

rap_int_t rap_hash_init(rap_hash_init_t *hinit, rap_hash_key_t *names,
    rap_uint_t nelts);
rap_int_t rap_hash_wildcard_init(rap_hash_init_t *hinit, rap_hash_key_t *names,
    rap_uint_t nelts);

#define rap_hash(key, c)   ((rap_uint_t) key * 31 + c)
rap_uint_t rap_hash_key(u_char *data, size_t len);
rap_uint_t rap_hash_key_lc(u_char *data, size_t len);
rap_uint_t rap_hash_strlow(u_char *dst, u_char *src, size_t n);


rap_int_t rap_hash_keys_array_init(rap_hash_keys_arrays_t *ha, rap_uint_t type);
rap_int_t rap_hash_add_key(rap_hash_keys_arrays_t *ha, rap_str_t *key,
    void *value, rap_uint_t flags);


#endif /* _RAP_HASH_H_INCLUDED_ */
