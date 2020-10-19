
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_RADIX_TREE_H_INCLUDED_
#define _RAP_RADIX_TREE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct rap_radix_node_s  rap_radix_node_t;

struct rap_radix_node_s {
    rap_radix_node_t  *right;
    rap_radix_node_t  *left;
    rap_radix_node_t  *parent;
    uintptr_t          value;
};


typedef struct {
    rap_radix_node_t  *root;
    rap_pool_t        *pool;
    rap_radix_node_t  *free;
    char              *start;
    size_t             size;
} rap_radix_tree_t;


rap_radix_tree_t *rap_radix_tree_create(rap_pool_t *pool,
    rap_int_t preallocate);

rap_int_t rap_radix32tree_insert(rap_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
rap_int_t rap_radix32tree_delete(rap_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t rap_radix32tree_find(rap_radix_tree_t *tree, uint32_t key);

#if (RAP_HAVE_INET6)
rap_int_t rap_radix128tree_insert(rap_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
rap_int_t rap_radix128tree_delete(rap_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t rap_radix128tree_find(rap_radix_tree_t *tree, u_char *key);
#endif


#endif /* _RAP_RADIX_TREE_H_INCLUDED_ */
