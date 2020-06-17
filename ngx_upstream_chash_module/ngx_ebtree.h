#ifndef  _NGX_EBTREE_H_INCLUDED_
#define  _NGX_EBTREE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

/* By default, gcc does not inline large chunks of code, but we want it to
 * respect our choices.
 */
#if !defined(forceinline)
#if __GNUC__ < 3
#define forceinline inline
#else
#define forceinline inline __attribute__((always_inline))
#endif
#endif

/*
 * Gcc >= 3 provides the ability for the programme to give hints to the
 * compiler about what branch of an if is most likely to be taken. This
 * helps the compiler produce the most compact critical paths, which is
 * generally better for the cache and to reduce the number of jumps.
 */
#if !defined(likely)
#if __GNUC__ < 3
#define __builtin_expect(x,y) (x)
#define likely(x) (x)
#define unlikely(x) (x)
#elif __GNUC__ < 4
/* gcc 3.x does the best job at this */
#define likely(x) (__builtin_expect((x) != 0, 1))
#define unlikely(x) (__builtin_expect((x) != 0, 0))
#else
/* GCC 4.x is stupid, it performs the comparison then compares it to 1,
 * so we cheat in a dirty way to prevent it from doing this. This will
 * only work with ints and booleans though.
 */
#define likely(x) (x)
#define unlikely(x) (__builtin_expect((unsigned long)(x), 0))
#endif
#endif

/* Linux-like "container_of". It returns a pointer to the structure of type
 * <type> which has its member <name> stored at address <ptr>.
     */
#ifndef container_of
#define container_of(ptr, type, name) \
        ((type *)(((unsigned char *)(ptr)) - ((long)&((type *)0)->name)))
#endif

static inline int flsnz(int x)
{
    int r;
    __asm__("bsrl %1,%0\n"
        : "=r" (r) : "rm" (x));
    return r+1;
}

static inline int flsnz8(u_char x)
{
    int r;
    __asm__("movzbl %%al, %%eax\n"
        "bsrl %%eax,%0\n"
        : "=r" (r) : "a" (x));
    return r+1;
}

/* Be careful not to tweak those values. The walking code is optimized for NULL
 * detection on the assumption that the following values are intact.
 */
#define NGX_EB_LEFT     0
#define NGX_EB_RGHT     1
#define NGX_EB_LEAF     0
#define NGX_EB_NODE     1

/* Number of bits per node, and number of leaves per node */
#define NGX_EB_NODE_BITS          1
#define NGX_EB_NODE_BRANCHES      (1 << NGX_EB_NODE_BITS)
#define NGX_EB_NODE_BRANCH_MASK   (NGX_EB_NODE_BRANCHES - 1)

#define NGX_EB_NODE_IN_TREE(node) ((node)->leaf_p != NULL)

/* The root of a tree is an ngx_ebt_root_t initialized with both pointers NULL.
 * During its life, only the left pointer will change. The right one will
 * always remain NULL, which is the way we detect it.
 */
#define NGX_EBT_ROOT                  \
    (ngx_ebt_root_t) {                \
      .b = {[0] = NULL, [1] = NULL }, \
    }

typedef void        ngx_ebt_troot_t;
typedef uint32_t    ngx_ebt_key_t;

typedef struct {
    ngx_ebt_troot_t    *b[NGX_EB_NODE_BRANCHES];
} ngx_ebt_root_t;

typedef struct {
    ngx_ebt_root_t      branches;
    ngx_ebt_troot_t    *node_p;
    ngx_ebt_troot_t    *leaf_p;

    int16_t             bit;
    uint16_t            pfx;

    uint32_t            key;
} ngx_ebt_node_t;

/* Converts a root pointer to its equivalent ngx_ebt_troot_t pointer,
 * ready to be stored in ->branch[], leaf_p or node_p. NULL is not
 * conserved. To be used with NGX_EB_LEAF, NGX_EB_NODE, NGX_EB_LEFT
 * or NGX_EB_RGHT in <tag>.
 */
static inline ngx_ebt_troot_t *
ngx_ebt_dotag(const ngx_ebt_root_t *root, const int tag)
{
    return (ngx_ebt_troot_t *)((unsigned char *)root + tag);
}

/* Converts an ngx_ebt_troot_t pointer pointer to its equivalent ngx_ebt_root_t
 * pointer, for use with pointers from ->branch[], leaf_p or node_p. NULL is
 * conserved as long as the tree is not corrupted. To be used with NGX_EB_LEAF,
 * NGX_EB_NODE, NGX_EB_LEFT or NGX_EB_RGHT in <tag>.
 */
static inline ngx_ebt_root_t *
ngx_ebt_untag(const ngx_ebt_troot_t *troot, const int tag)
{
    return (ngx_ebt_root_t *)((unsigned char *)troot - tag);
}

/* returns the tag associated with an ngx_ebt_troot_t pointer */
static inline int
ngx_ebt_gettag(ngx_ebt_troot_t *troot)
{
  return (unsigned long)troot & 1;
}

/* Converts a root pointer to its equivalent ngx_ebt_troot_t pointer and clears the
 * tag, no matter what its value was.
 */
static inline ngx_ebt_root_t *
ngx_ebt_clrtag(const ngx_ebt_troot_t *troot)
{
    return (ngx_ebt_root_t *)((unsigned long)troot & ~1UL);
}

/* Returns a pointer to the eb_node holding <root> */
static inline ngx_ebt_node_t *
ngx_ebt_root_to_node(ngx_ebt_root_t *root)
{
  return container_of(root, ngx_ebt_node_t, branches);
}

/* Walks down starting at root pointer <start>, and always walking on side
 * <side>. It either returns the node hosting the first leaf on that side,
 * or NULL if no leaf is found. <start> may either be NULL or a branch pointer.
 * The pointer to the leaf (or NULL) is returned.
 */
static inline ngx_ebt_node_t *
ngx_ebt_walk_down(ngx_ebt_troot_t *start, unsigned int side)
{
    /* A NULL pointer on an empty tree root will be returned as-is */
    while (ngx_ebt_gettag(start) == NGX_EB_NODE)
      start = (ngx_ebt_untag(start, NGX_EB_NODE))->b[side];
    /* NULL is left untouched (root==eb_node, NGX_EB_LEAF==0) */
    return ngx_ebt_root_to_node(ngx_ebt_untag(start, NGX_EB_LEAF));
}

/* Return the first leaf in the tree starting at <root>, or NULL if none */
static inline ngx_ebt_node_t *
ngx_ebt_first(ngx_ebt_root_t *root)
{
    return ngx_ebt_walk_down(root->b[0], NGX_EB_LEFT);
}

/* Return the last leaf in the tree starting at <root>, or NULL if none */
static inline ngx_ebt_node_t *
ngx_ebt_last(ngx_ebt_root_t *root)
{
    return ngx_ebt_walk_down(root->b[0], NGX_EB_RGHT);
}

/* Return previous leaf node before an existing leaf node, or NULL if none. */
static inline ngx_ebt_node_t *
ngx_ebt_prev(ngx_ebt_node_t *node)
{
    ngx_ebt_troot_t *t = node->leaf_p;

    while (ngx_ebt_gettag(t) == NGX_EB_LEFT) {
      /* Walking up from left branch. We must ensure that we never
       * walk beyond root.
       */
      if (unlikely(ngx_ebt_clrtag((ngx_ebt_untag(t, NGX_EB_LEFT))->b[NGX_EB_RGHT]) == NULL))
        return NULL;
      t = (ngx_ebt_root_to_node(ngx_ebt_untag(t, NGX_EB_LEFT)))->node_p;
    }
    /* Note that <t> cannot be NULL at this stage */
    t = (ngx_ebt_untag(t, NGX_EB_RGHT))->b[NGX_EB_LEFT];
    return ngx_ebt_walk_down(t, NGX_EB_RGHT);
}

/* Return next leaf node after an existing leaf node, or NULL if none. */
static inline ngx_ebt_node_t *
ngx_ebt_next(ngx_ebt_node_t *node)
{
    ngx_ebt_troot_t *t = node->leaf_p;

    while (ngx_ebt_gettag(t) != NGX_EB_LEFT)
      /* Walking up from right branch, so we cannot be below root */
      t = (ngx_ebt_root_to_node(ngx_ebt_untag(t, NGX_EB_RGHT)))->node_p;

    /* Note that <t> cannot be NULL at this stage */
    t = (ngx_ebt_untag(t, NGX_EB_LEFT))->b[NGX_EB_RGHT];
    if (ngx_ebt_clrtag(t) == NULL)
      return NULL;
    return ngx_ebt_walk_down(t, NGX_EB_LEFT);
}

/* Return next tree node after <node> which must still be in the tree, or be
 * NULL. Lookup wraps around the end to the beginning. If the next node is the
 * same node, return NULL. This is designed to find a valid next node before
 * deleting one from the tree.
 */
static inline ngx_ebt_node_t *
ngx_ebt_skip_node(ngx_ebt_root_t *root, ngx_ebt_node_t *node)
{
    ngx_ebt_node_t *stop = node;

    if (!node)
      return NULL;

    node = ngx_ebt_next(node);
    if (!node)
      node = ngx_ebt_first(root);

    if (node == stop)
      return NULL;

    return node;
}

ngx_ebt_node_t *ngx_ebt_insert(ngx_ebt_root_t *root, ngx_ebt_node_t *node);
void ngx_ebt_delete(ngx_ebt_node_t *node);
ngx_ebt_node_t *ngx_ebt_lookup_ge(ngx_ebt_root_t *root, ngx_ebt_key_t x);

#endif
