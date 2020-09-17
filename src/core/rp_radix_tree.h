
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_RADIX_TREE_H_INCLUDED_
#define _RP_RADIX_TREE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct rp_radix_node_s  rp_radix_node_t;

struct rp_radix_node_s {
    rp_radix_node_t  *right;
    rp_radix_node_t  *left;
    rp_radix_node_t  *parent;
    uintptr_t          value;
};


typedef struct {
    rp_radix_node_t  *root;
    rp_pool_t        *pool;
    rp_radix_node_t  *free;
    char              *start;
    size_t             size;
} rp_radix_tree_t;


rp_radix_tree_t *rp_radix_tree_create(rp_pool_t *pool,
    rp_int_t preallocate);

rp_int_t rp_radix32tree_insert(rp_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
rp_int_t rp_radix32tree_delete(rp_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t rp_radix32tree_find(rp_radix_tree_t *tree, uint32_t key);

#if (RP_HAVE_INET6)
rp_int_t rp_radix128tree_insert(rp_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
rp_int_t rp_radix128tree_delete(rp_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t rp_radix128tree_find(rp_radix_tree_t *tree, u_char *key);
#endif


#endif /* _RP_RADIX_TREE_H_INCLUDED_ */
