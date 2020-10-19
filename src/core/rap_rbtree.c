
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


static rap_inline void rap_rbtree_left_rotate(rap_rbtree_node_t **root,
    rap_rbtree_node_t *sentinel, rap_rbtree_node_t *node);
static rap_inline void rap_rbtree_right_rotate(rap_rbtree_node_t **root,
    rap_rbtree_node_t *sentinel, rap_rbtree_node_t *node);


void
rap_rbtree_insert(rap_rbtree_t *tree, rap_rbtree_node_t *node)
{
    rap_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = &tree->root;
    sentinel = tree->sentinel;

    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        rap_rbt_black(node);
        *root = node;

        return;
    }

    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    while (node != *root && rap_rbt_is_red(node->parent)) {

        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;

            if (rap_rbt_is_red(temp)) {
                rap_rbt_black(node->parent);
                rap_rbt_black(temp);
                rap_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    rap_rbtree_left_rotate(root, sentinel, node);
                }

                rap_rbt_black(node->parent);
                rap_rbt_red(node->parent->parent);
                rap_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            temp = node->parent->parent->left;

            if (rap_rbt_is_red(temp)) {
                rap_rbt_black(node->parent);
                rap_rbt_black(temp);
                rap_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    rap_rbtree_right_rotate(root, sentinel, node);
                }

                rap_rbt_black(node->parent);
                rap_rbt_red(node->parent->parent);
                rap_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    rap_rbt_black(*root);
}


void
rap_rbtree_insert_value(rap_rbtree_node_t *temp, rap_rbtree_node_t *node,
    rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t  **p;

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
    rap_rbt_red(node);
}


void
rap_rbtree_insert_timer_value(rap_rbtree_node_t *temp, rap_rbtree_node_t *node,
    rap_rbtree_node_t *sentinel)
{
    rap_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((rap_rbtree_key_int_t) (node->key - temp->key) < 0)
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
    rap_rbt_red(node);
}


void
rap_rbtree_delete(rap_rbtree_t *tree, rap_rbtree_node_t *node)
{
    rap_uint_t           red;
    rap_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

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
        subst = rap_rbtree_min(node->right, sentinel);
        temp = subst->right;
    }

    if (subst == *root) {
        *root = temp;
        rap_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = rap_rbt_is_red(subst);

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
        rap_rbt_copy_color(subst, node);

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

    while (temp != *root && rap_rbt_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (rap_rbt_is_red(w)) {
                rap_rbt_black(w);
                rap_rbt_red(temp->parent);
                rap_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (rap_rbt_is_black(w->left) && rap_rbt_is_black(w->right)) {
                rap_rbt_red(w);
                temp = temp->parent;

            } else {
                if (rap_rbt_is_black(w->right)) {
                    rap_rbt_black(w->left);
                    rap_rbt_red(w);
                    rap_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                rap_rbt_copy_color(w, temp->parent);
                rap_rbt_black(temp->parent);
                rap_rbt_black(w->right);
                rap_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (rap_rbt_is_red(w)) {
                rap_rbt_black(w);
                rap_rbt_red(temp->parent);
                rap_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (rap_rbt_is_black(w->left) && rap_rbt_is_black(w->right)) {
                rap_rbt_red(w);
                temp = temp->parent;

            } else {
                if (rap_rbt_is_black(w->left)) {
                    rap_rbt_black(w->right);
                    rap_rbt_red(w);
                    rap_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                rap_rbt_copy_color(w, temp->parent);
                rap_rbt_black(temp->parent);
                rap_rbt_black(w->left);
                rap_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    rap_rbt_black(temp);
}


static rap_inline void
rap_rbtree_left_rotate(rap_rbtree_node_t **root, rap_rbtree_node_t *sentinel,
    rap_rbtree_node_t *node)
{
    rap_rbtree_node_t  *temp;

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


static rap_inline void
rap_rbtree_right_rotate(rap_rbtree_node_t **root, rap_rbtree_node_t *sentinel,
    rap_rbtree_node_t *node)
{
    rap_rbtree_node_t  *temp;

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


rap_rbtree_node_t *
rap_rbtree_next(rap_rbtree_t *tree, rap_rbtree_node_t *node)
{
    rap_rbtree_node_t  *root, *sentinel, *parent;

    sentinel = tree->sentinel;

    if (node->right != sentinel) {
        return rap_rbtree_min(node->right, sentinel);
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
