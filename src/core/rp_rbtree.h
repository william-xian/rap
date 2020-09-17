
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_RBTREE_H_INCLUDED_
#define _RP_RBTREE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef rp_uint_t  rp_rbtree_key_t;
typedef rp_int_t   rp_rbtree_key_int_t;


typedef struct rp_rbtree_node_s  rp_rbtree_node_t;

struct rp_rbtree_node_s {
    rp_rbtree_key_t       key;
    rp_rbtree_node_t     *left;
    rp_rbtree_node_t     *right;
    rp_rbtree_node_t     *parent;
    u_char                 color;
    u_char                 data;
};


typedef struct rp_rbtree_s  rp_rbtree_t;

typedef void (*rp_rbtree_insert_pt) (rp_rbtree_node_t *root,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);

struct rp_rbtree_s {
    rp_rbtree_node_t     *root;
    rp_rbtree_node_t     *sentinel;
    rp_rbtree_insert_pt   insert;
};


#define rp_rbtree_init(tree, s, i)                                           \
    rp_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void rp_rbtree_insert(rp_rbtree_t *tree, rp_rbtree_node_t *node);
void rp_rbtree_delete(rp_rbtree_t *tree, rp_rbtree_node_t *node);
void rp_rbtree_insert_value(rp_rbtree_node_t *root, rp_rbtree_node_t *node,
    rp_rbtree_node_t *sentinel);
void rp_rbtree_insert_timer_value(rp_rbtree_node_t *root,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
rp_rbtree_node_t *rp_rbtree_next(rp_rbtree_t *tree,
    rp_rbtree_node_t *node);


#define rp_rbt_red(node)               ((node)->color = 1)
#define rp_rbt_black(node)             ((node)->color = 0)
#define rp_rbt_is_red(node)            ((node)->color)
#define rp_rbt_is_black(node)          (!rp_rbt_is_red(node))
#define rp_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define rp_rbtree_sentinel_init(node)  rp_rbt_black(node)


static rp_inline rp_rbtree_node_t *
rp_rbtree_min(rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _RP_RBTREE_H_INCLUDED_ */
