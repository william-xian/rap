
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_RBTREE_H_INCLUDED_
#define _RAP_RBTREE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef rap_uint_t  rap_rbtree_key_t;
typedef rap_int_t   rap_rbtree_key_int_t;


typedef struct rap_rbtree_node_s  rap_rbtree_node_t;

struct rap_rbtree_node_s {
    rap_rbtree_key_t       key;
    rap_rbtree_node_t     *left;
    rap_rbtree_node_t     *right;
    rap_rbtree_node_t     *parent;
    u_char                 color;
    u_char                 data;
};


typedef struct rap_rbtree_s  rap_rbtree_t;

typedef void (*rap_rbtree_insert_pt) (rap_rbtree_node_t *root,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);

struct rap_rbtree_s {
    rap_rbtree_node_t     *root;
    rap_rbtree_node_t     *sentinel;
    rap_rbtree_insert_pt   insert;
};


#define rap_rbtree_init(tree, s, i)                                           \
    rap_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void rap_rbtree_insert(rap_rbtree_t *tree, rap_rbtree_node_t *node);
void rap_rbtree_delete(rap_rbtree_t *tree, rap_rbtree_node_t *node);
void rap_rbtree_insert_value(rap_rbtree_node_t *root, rap_rbtree_node_t *node,
    rap_rbtree_node_t *sentinel);
void rap_rbtree_insert_timer_value(rap_rbtree_node_t *root,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);
rap_rbtree_node_t *rap_rbtree_next(rap_rbtree_t *tree,
    rap_rbtree_node_t *node);


#define rap_rbt_red(node)               ((node)->color = 1)
#define rap_rbt_black(node)             ((node)->color = 0)
#define rap_rbt_is_red(node)            ((node)->color)
#define rap_rbt_is_black(node)          (!rap_rbt_is_red(node))
#define rap_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define rap_rbtree_sentinel_init(node)  rap_rbt_black(node)


static rap_inline rap_rbtree_node_t *
rap_rbtree_min(rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _RAP_RBTREE_H_INCLUDED_ */
