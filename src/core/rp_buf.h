
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_BUF_H_INCLUDED_
#define _RP_BUF_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef void *            rp_buf_tag_t;

typedef struct rp_buf_s  rp_buf_t;

struct rp_buf_s {
    u_char          *pos;
    u_char          *last;
    off_t            file_pos;
    off_t            file_last;

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    rp_buf_tag_t    tag;
    rp_file_t      *file;
    rp_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;

    unsigned         recycled:1;
    unsigned         in_file:1;
    unsigned         flush:1;
    unsigned         sync:1;
    unsigned         last_buf:1;
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    /* STUB */ int   num;
};


struct rp_chain_s {
    rp_buf_t    *buf;
    rp_chain_t  *next;
};


typedef struct {
    rp_int_t    num;
    size_t       size;
} rp_bufs_t;


typedef struct rp_output_chain_ctx_s  rp_output_chain_ctx_t;

typedef rp_int_t (*rp_output_chain_filter_pt)(void *ctx, rp_chain_t *in);

typedef void (*rp_output_chain_aio_pt)(rp_output_chain_ctx_t *ctx,
    rp_file_t *file);

struct rp_output_chain_ctx_s {
    rp_buf_t                   *buf;
    rp_chain_t                 *in;
    rp_chain_t                 *free;
    rp_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (RP_HAVE_FILE_AIO || RP_COMPAT)
    rp_output_chain_aio_pt      aio_handler;
#if (RP_HAVE_AIO_SENDFILE || RP_COMPAT)
    ssize_t                    (*aio_preload)(rp_buf_t *file);
#endif
#endif

#if (RP_THREADS || RP_COMPAT)
    rp_int_t                  (*thread_handler)(rp_thread_task_t *task,
                                                 rp_file_t *file);
    rp_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    rp_pool_t                  *pool;
    rp_int_t                    allocated;
    rp_bufs_t                   bufs;
    rp_buf_tag_t                tag;

    rp_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    rp_chain_t                 *out;
    rp_chain_t                **last;
    rp_connection_t            *connection;
    rp_pool_t                  *pool;
    off_t                        limit;
} rp_chain_writer_ctx_t;


#define RP_CHAIN_ERROR     (rp_chain_t *) RP_ERROR


#define rp_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define rp_buf_in_memory_only(b)   (rp_buf_in_memory(b) && !b->in_file)

#define rp_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !rp_buf_in_memory(b) && !b->in_file)

#define rp_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !rp_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define rp_buf_size(b)                                                      \
    (rp_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

rp_buf_t *rp_create_temp_buf(rp_pool_t *pool, size_t size);
rp_chain_t *rp_create_chain_of_bufs(rp_pool_t *pool, rp_bufs_t *bufs);


#define rp_alloc_buf(pool)  rp_palloc(pool, sizeof(rp_buf_t))
#define rp_calloc_buf(pool) rp_pcalloc(pool, sizeof(rp_buf_t))

rp_chain_t *rp_alloc_chain_link(rp_pool_t *pool);
#define rp_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



rp_int_t rp_output_chain(rp_output_chain_ctx_t *ctx, rp_chain_t *in);
rp_int_t rp_chain_writer(void *ctx, rp_chain_t *in);

rp_int_t rp_chain_add_copy(rp_pool_t *pool, rp_chain_t **chain,
    rp_chain_t *in);
rp_chain_t *rp_chain_get_free_buf(rp_pool_t *p, rp_chain_t **free);
void rp_chain_update_chains(rp_pool_t *p, rp_chain_t **free,
    rp_chain_t **busy, rp_chain_t **out, rp_buf_tag_t tag);

off_t rp_chain_coalesce_file(rp_chain_t **in, off_t limit);

rp_chain_t *rp_chain_update_sent(rp_chain_t *in, off_t sent);

#endif /* _RP_BUF_H_INCLUDED_ */
