#include "ngx_ebtree.h"

/* This function is used to build a tree of duplicates by adding a new node to
 * a subtree of at least 2 entries. It will probably never be needed inlined,
 * and it is not for end-user.
 */
static forceinline ngx_ebt_node_t *
ngx_ebt_insert_dup(ngx_ebt_node_t *sub, ngx_ebt_node_t *new)
{
    ngx_ebt_node_t *head = sub;

    ngx_ebt_troot_t *new_left = ngx_ebt_dotag(&new->branches, NGX_EB_LEFT);
    ngx_ebt_troot_t *new_rght = ngx_ebt_dotag(&new->branches, NGX_EB_RGHT);
    ngx_ebt_troot_t *new_leaf = ngx_ebt_dotag(&new->branches, NGX_EB_LEAF);

    /* first, identify the deepest hole on the right branch */
    while (ngx_ebt_gettag(head->branches.b[NGX_EB_RGHT]) != NGX_EB_LEAF) {
        ngx_ebt_node_t *last = head;
        head = container_of(ngx_ebt_untag(head->branches.b[NGX_EB_RGHT],
                    NGX_EB_NODE),
                ngx_ebt_node_t, branches);
        if (head->bit > last->bit + 1)
            sub = head;     /* there's a hole here */
    }

    /* Here we have a leaf attached to (head)->b[NGX_EB_RGHT] */
    if (head->bit < -1) {
        /* A hole exists just before the leaf, we insert there */
        new->bit = -1;
        sub = container_of(ngx_ebt_untag(head->branches.b[NGX_EB_RGHT],
                    NGX_EB_LEAF),
                ngx_ebt_node_t, branches);
        head->branches.b[NGX_EB_RGHT] = ngx_ebt_dotag(&new->branches, NGX_EB_NODE);

        new->node_p = sub->leaf_p;
        new->leaf_p = new_rght;
        sub->leaf_p = new_left;
        new->branches.b[NGX_EB_LEFT] = ngx_ebt_dotag(&sub->branches, NGX_EB_LEAF);
        new->branches.b[NGX_EB_RGHT] = new_leaf;
        return new;
    } else {
        int side;
        /* No hole was found before a leaf. We have to insert above
         * <sub>. Note that we cannot be certain that <sub> is attached
         * to the right of its parent, as this is only true if <sub>
         * is inside the dup tree, not at the head.
         */
        new->bit = sub->bit - 1; /* install at the lowest level */
        side = ngx_ebt_gettag(sub->node_p);
        head = container_of(ngx_ebt_untag(sub->node_p, side),
                ngx_ebt_node_t, branches);
        head->branches.b[side] = ngx_ebt_dotag(&new->branches, NGX_EB_NODE);

        new->node_p = sub->node_p;
        new->leaf_p = new_rght;
        sub->node_p = new_left;
        new->branches.b[NGX_EB_LEFT] = ngx_ebt_dotag(&sub->branches, NGX_EB_NODE);
        new->branches.b[NGX_EB_RGHT] = new_leaf;
        return new;
    }
}

ngx_ebt_node_t *
ngx_ebt_insert(ngx_ebt_root_t *root, ngx_ebt_node_t *node)
{
    int                 old_node_bit;
    uint32_t            side;
    ngx_ebt_key_t       newkey;
    ngx_ebt_node_t     *old;
    ngx_ebt_troot_t    *troot, **up_ptr;
    ngx_ebt_troot_t    *root_right;
    ngx_ebt_troot_t    *new_left, *new_rght;
    ngx_ebt_troot_t    *new_leaf;

    side = NGX_EB_LEFT;
    troot = root->b[NGX_EB_LEFT];
    root_right = root->b[NGX_EB_RGHT];

    if (unlikely(troot == NULL)) {
        /* Tree is empty, insert the leaf part below the left branch */
        root->b[NGX_EB_LEFT] = ngx_ebt_dotag(&node->branches, NGX_EB_LEAF);
        node->leaf_p = ngx_ebt_dotag(root, NGX_EB_LEFT);
        node->node_p = NULL; /* node part unused */

        return node;
    }

    /* The tree descent is fairly easy :
     *  - first, check if we have reached a leaf node
     *  - second, check if we have gone too far
     *  - third, reiterate
     * Everywhere, we use <new> for the node node we are inserting, <root>
     * for the node we attach it to, and <old> for the node we are
     * displacing below <new>. <troot> will always point to the future node
     * (tagged with its type). <side> carries the side the node <new> is
     * attached to below its parent, which is also where previous node
     * was attached. <newkey> carries the key being inserted.
     */
    newkey = node->key;

    while (1) {
        if (ngx_ebt_gettag(troot) == NGX_EB_LEAF) {
            /* insert above a leaf */
            old = container_of(ngx_ebt_untag(troot, NGX_EB_LEAF),
                    ngx_ebt_node_t, branches);
            node->node_p = old->leaf_p;
            up_ptr = &old->leaf_p;
            break;
        }

        /* OK we're walking down this link */
        old = container_of(ngx_ebt_untag(troot, NGX_EB_NODE),
                ngx_ebt_node_t, branches);
        old_node_bit = old->bit;

        /* Stop going down when we don't have common bits anymore. We
         * also stop in front of a duplicates tree because it means we
         * have to insert above.
         */

        if ((old_node_bit < 0) || /* we're above a duplicate tree, stop here */
                (((node->key ^ old->key) >> old_node_bit) >= NGX_EB_NODE_BRANCHES)) {
            /* The tree did not contain the key, so we insert <new> before the node
             * <old>, and set ->bit to designate the lowest bit position in <new>
             * which applies to ->branches.b[].
             */
            node->node_p = old->node_p;
            up_ptr = &old->node_p;
            break;
        }

        /* walk down */
        root = &old->branches;
        side = (newkey >> old_node_bit) & NGX_EB_NODE_BRANCH_MASK;
        troot = root->b[side];
    }

    new_left = ngx_ebt_dotag(&node->branches, NGX_EB_LEFT);
    new_rght = ngx_ebt_dotag(&node->branches, NGX_EB_RGHT);
    new_leaf = ngx_ebt_dotag(&node->branches, NGX_EB_LEAF);

    /* We need the common higher bits between node->key and old->key.
     * What differences are there between node->key and the node here ?
     * NOTE that bit(new) is always < bit(root) because highest
     * bit of node->key and old->key are identical here (otherwise they
     * would sit on different branches).
     */

    // note that if NGX_EB_NODE_BITS > 1, we should check that it's still >= 0
    node->bit = flsnz(node->key ^ old->key) - NGX_EB_NODE_BITS;

    if (node->key == old->key) {
        node->bit = -1; /* mark as new dup tree, just in case */

        if (likely(ngx_ebt_gettag(root_right))) {
            /* we refuse to duplicate this key if the tree is
             * tagged as containing only unique keys.
             */
            return old;
        }

        if (ngx_ebt_gettag(troot) != NGX_EB_LEAF) {
            /* there was already a dup tree below */
            return ngx_ebt_insert_dup(old, node);
        }
        /* otherwise fall through */
    }

    if (node->key >= old->key) {
        node->branches.b[NGX_EB_LEFT] = troot;
        node->branches.b[NGX_EB_RGHT] = new_leaf;
        node->leaf_p = new_rght;
        *up_ptr = new_left;
    } else {
        node->branches.b[NGX_EB_LEFT] = new_leaf;
        node->branches.b[NGX_EB_RGHT] = troot;
        node->leaf_p = new_left;
        *up_ptr = new_rght;
    }

    /* Ok, now we are inserting <new> between <root> and <old>. <old>'s
     * parent is already set to <new>, and the <root>'s branch is still in
     * <side>. Update the root's leaf till we have it. Note that we can also
     * find the side by checking the side of node->node_p.
     */

    root->b[side] = ngx_ebt_dotag(&node->branches, NGX_EB_NODE);
    return node;
}

/* Removes a leaf node from the tree if it was still in it. Marks the node
 * as unlinked.
 */
void ngx_ebt_delete(ngx_ebt_node_t *node)
{
    uint32_t          pside, gpside, sibtype;
    ngx_ebt_node_t   *parent;
    ngx_ebt_root_t   *gparent;

    if (!node->leaf_p)
        return;

    /* we need the parent, our side, and the grand parent */
    pside = ngx_ebt_gettag(node->leaf_p);
    parent = ngx_ebt_root_to_node(ngx_ebt_untag(node->leaf_p, pside));

    /* We likely have to release the parent link, unless it's the root,
     * in which case we only set our branch to NULL. Note that we can
     * only be attached to the root by its left branch.
     */

    if (ngx_ebt_clrtag(parent->branches.b[NGX_EB_RGHT]) == NULL) {
        /* we're just below the root, it's trivial. */
        parent->branches.b[NGX_EB_LEFT] = NULL;
        goto delete_unlink;
    }

    /* To release our parent, we have to identify our sibling, and reparent
     * it directly to/from the grand parent. Note that the sibling can
     * either be a link or a leaf.
     */

    gpside = ngx_ebt_gettag(parent->node_p);
    gparent = ngx_ebt_untag(parent->node_p, gpside);

    gparent->b[gpside] = parent->branches.b[!pside];
    sibtype = ngx_ebt_gettag(gparent->b[gpside]);

    if (sibtype == NGX_EB_LEAF) {
        ngx_ebt_root_to_node(ngx_ebt_untag(gparent->b[gpside], NGX_EB_LEAF)) \
            ->leaf_p = ngx_ebt_dotag(gparent, gpside);
    } else {
        ngx_ebt_root_to_node(ngx_ebt_untag(gparent->b[gpside], NGX_EB_NODE)) \
            ->node_p = ngx_ebt_dotag(gparent, gpside);
    }
    /* Mark the parent unused. Note that we do not check if the parent is
     * our own node, but that's not a problem because if it is, it will be
     * marked unused at the same time, which we'll use below to know we can
     * safely remove it.
     */
    parent->node_p = NULL;

    /* The parent node has been detached, and is currently unused. It may
     * belong to another node, so we cannot remove it that way. Also, our
     * own node part might still be used. so we can use this spare node
     * to replace ours if needed.
     */

    /* If our link part is unused, we can safely exit now */
    if (!node->node_p)
        goto delete_unlink;

    /* From now on, <node> and <parent> are necessarily different, and the
     * <node>'s node part is in use. By definition, <parent> is at least
     * below <node>, so keeping its key for the bit string is OK.
     */

    parent->node_p = node->node_p;
    parent->branches = node->branches;
    parent->bit = node->bit;

    /* We must now update the new node's parent... */
    gpside = ngx_ebt_gettag(parent->node_p);
    gparent = ngx_ebt_untag(parent->node_p, gpside);
    gparent->b[gpside] = ngx_ebt_dotag(&parent->branches, NGX_EB_NODE);

    /* ... and its branches */
    for (pside = 0; pside <= 1; pside++) {
        if (ngx_ebt_gettag(parent->branches.b[pside]) == NGX_EB_NODE) {
            ngx_ebt_root_to_node( \
                    ngx_ebt_untag(parent->branches.b[pside], NGX_EB_NODE))->node_p =
                ngx_ebt_dotag(&parent->branches, pside);
        } else {
            ngx_ebt_root_to_node( \
                    ngx_ebt_untag(parent->branches.b[pside], NGX_EB_LEAF))->leaf_p =
                ngx_ebt_dotag(&parent->branches, pside);
        }
    }

delete_unlink:
    /* Now the node has been completely unlinked */
    node->leaf_p = NULL;
    return; /* tree is not empty yet */
}


/*
 * Find the first occurrence of the lowest key in the tree <root>, which is
 * equal to or greater than <x>. NULL is returned is no key matches.
 */
ngx_ebt_node_t *
ngx_ebt_lookup_ge(ngx_ebt_root_t *root, ngx_ebt_key_t x)
{
    ngx_ebt_node_t    *node;
    ngx_ebt_troot_t   *troot;

    troot = root->b[NGX_EB_LEFT];
    if (unlikely(troot == NULL))
        return NULL;

    while (1) {
        if ((ngx_ebt_gettag(troot) == NGX_EB_LEAF)) {
            /* We reached a leaf, which means that the whole upper
             * parts were common. We will return either the current
             * node or its next one if the former is too small.
             */
            node = container_of(ngx_ebt_untag(troot, NGX_EB_LEAF),
                    ngx_ebt_node_t, branches);
            if (node->key >= x)
                return node;
            /* return next */
            troot = node->leaf_p;
            break;
        }
        node = container_of(ngx_ebt_untag(troot, NGX_EB_NODE),
                ngx_ebt_node_t, branches);

        if (node->bit < 0) {
            /* We're at the top of a dup tree. Either we got a
             * matching value and we return the leftmost node, or
             * we don't and we skip the whole subtree to return the
             * next node after the subtree. Note that since we're
             * at the top of the dup tree, we can simply return the
             * next node without first trying to escape from the
             * tree.
             */
            if (node->key >= x) {
                troot = node->branches.b[NGX_EB_LEFT];
                while (ngx_ebt_gettag(troot) != NGX_EB_LEAF)
                    troot = (ngx_ebt_untag(troot, NGX_EB_NODE))->b[NGX_EB_LEFT];
                return container_of(ngx_ebt_untag(troot, NGX_EB_LEAF),
                        ngx_ebt_node_t, branches);
            }
            /* return next */
            troot = node->node_p;
            break;
        }

        if (((x ^ node->key) >> node->bit) >= NGX_EB_NODE_BRANCHES) {
            /* No more common bits at all. Either this node is too
             * large and we need to get its lowest value, or it is too
             * small, and we need to get the next value.
             */
            if ((node->key >> node->bit) > (x >> node->bit)) {
                troot = node->branches.b[NGX_EB_LEFT];
                return ngx_ebt_walk_down(troot, NGX_EB_LEFT);
            }

            /* Further values will be too low here, so return the next
             * unique node (if it exists).
             */
            troot = node->node_p;
            break;
        }
        troot = node->branches.b[(x >> node->bit) & NGX_EB_NODE_BRANCH_MASK];
    }

    /* If we get here, it means we want to report next node after the
     * current one which is not below. <troot> is already initialised
     * to the parent's branches.
     */
    while (ngx_ebt_gettag(troot) != NGX_EB_LEFT)
        /* Walking up from right branch, so we cannot be below root */
        troot = (ngx_ebt_root_to_node(ngx_ebt_untag(troot, NGX_EB_RGHT)))->node_p;

    /* Note that <troot> cannot be NULL at this stage */
    troot = (ngx_ebt_untag(troot, NGX_EB_LEFT))->b[NGX_EB_RGHT];
    if (ngx_ebt_clrtag(troot) == NULL)
        return NULL;

    return ngx_ebt_walk_down(troot, NGX_EB_LEFT);
}

