
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


static rp_inline void rp_rbtree_left_rotate(rp_rbtree_node_t **root,
    rp_rbtree_node_t *sentinel, rp_rbtree_node_t *node);
static rp_inline void rp_rbtree_right_rotate(rp_rbtree_node_t **root,
    rp_rbtree_node_t *sentinel, rp_rbtree_node_t *node);


void
rp_rbtree_insert(rp_rbtree_t *tree, rp_rbtree_node_t *node)
{
    rp_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = &tree->root;
    sentinel = tree->sentinel;

    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        rp_rbt_black(node);
        *root = node;

        return;
    }

    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    while (node != *root && rp_rbt_is_red(node->parent)) {

        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;

            if (rp_rbt_is_red(temp)) {
                rp_rbt_black(node->parent);
                rp_rbt_black(temp);
                rp_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    rp_rbtree_left_rotate(root, sentinel, node);
                }

                rp_rbt_black(node->parent);
                rp_rbt_red(node->parent->parent);
                rp_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            temp = node->parent->parent->left;

            if (rp_rbt_is_red(temp)) {
                rp_rbt_black(node->parent);
                rp_rbt_black(temp);
                rp_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    rp_rbtree_right_rotate(root, sentinel, node);
                }

                rp_rbt_black(node->parent);
                rp_rbt_red(node->parent->parent);
                rp_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    rp_rbt_black(*root);
}


void
rp_rbtree_insert_value(rp_rbtree_node_t *temp, rp_rbtree_node_t *node,
    rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    rp_rbt_red(node);
}


void
rp_rbtree_insert_timer_value(rp_rbtree_node_t *temp, rp_rbtree_node_t *node,
    rp_rbtree_node_t *sentinel)
{
    rp_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((rp_rbtree_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    rp_rbt_red(node);
}


void
rp_rbtree_delete(rp_rbtree_t *tree, rp_rbtree_node_t *node)
{
    rp_uint_t           red;
    rp_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        temp = node->left;
        subst = node;

    } else {
        subst = rp_rbtree_min(node->right, sentinel);
        temp = subst->right;
    }

    if (subst == *root) {
        *root = temp;
        rp_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = rp_rbt_is_red(subst);

    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst == node) {

        temp->parent = subst->parent;

    } else {

        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        rp_rbt_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    if (red) {
        return;
    }

    /* a delete fixup */

    while (temp != *root && rp_rbt_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (rp_rbt_is_red(w)) {
                rp_rbt_black(w);
                rp_rbt_red(temp->parent);
                rp_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (rp_rbt_is_black(w->left) && rp_rbt_is_black(w->right)) {
                rp_rbt_red(w);
                temp = temp->parent;

            } else {
                if (rp_rbt_is_black(w->right)) {
                    rp_rbt_black(w->left);
                    rp_rbt_red(w);
                    rp_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                rp_rbt_copy_color(w, temp->parent);
                rp_rbt_black(temp->parent);
                rp_rbt_black(w->right);
                rp_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (rp_rbt_is_red(w)) {
                rp_rbt_black(w);
                rp_rbt_red(temp->parent);
                rp_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (rp_rbt_is_black(w->left) && rp_rbt_is_black(w->right)) {
                rp_rbt_red(w);
                temp = temp->parent;

            } else {
                if (rp_rbt_is_black(w->left)) {
                    rp_rbt_black(w->right);
                    rp_rbt_red(w);
                    rp_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                rp_rbt_copy_color(w, temp->parent);
                rp_rbt_black(temp->parent);
                rp_rbt_black(w->left);
                rp_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    rp_rbt_black(temp);
}


static rp_inline void
rp_rbtree_left_rotate(rp_rbtree_node_t **root, rp_rbtree_node_t *sentinel,
    rp_rbtree_node_t *node)
{
    rp_rbtree_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


static rp_inline void
rp_rbtree_right_rotate(rp_rbtree_node_t **root, rp_rbtree_node_t *sentinel,
    rp_rbtree_node_t *node)
{
    rp_rbtree_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}


rp_rbtree_node_t *
rp_rbtree_next(rp_rbtree_t *tree, rp_rbtree_node_t *node)
{
    rp_rbtree_node_t  *root, *sentinel, *parent;

    sentinel = tree->sentinel;

    if (node->right != sentinel) {
        return rp_rbtree_min(node->right, sentinel);
    }

    root = tree->root;

    for ( ;; ) {
        parent = node->parent;

        if (node == root) {
            return NULL;
        }

        if (node == parent->left) {
            return parent;
        }

        node = parent;
    }
}
