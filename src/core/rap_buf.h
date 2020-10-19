
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_BUF_H_INCLUDED_
#define _RAP_BUF_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef void *            rap_buf_tag_t;

typedef struct rap_buf_s  rap_buf_t;

struct rap_buf_s {
    u_char          *pos;
    u_char          *last;
    off_t            file_pos;
    off_t            file_last;

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    rap_buf_tag_t    tag;
    rap_file_t      *file;
    rap_buf_t       *shadow;


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


struct rap_chain_s {
    rap_buf_t    *buf;
    rap_chain_t  *next;
};


typedef struct {
    rap_int_t    num;
    size_t       size;
} rap_bufs_t;


typedef struct rap_output_chain_ctx_s  rap_output_chain_ctx_t;

typedef rap_int_t (*rap_output_chain_filter_pt)(void *ctx, rap_chain_t *in);

typedef void (*rap_output_chain_aio_pt)(rap_output_chain_ctx_t *ctx,
    rap_file_t *file);

struct rap_output_chain_ctx_s {
    rap_buf_t                   *buf;
    rap_chain_t                 *in;
    rap_chain_t                 *free;
    rap_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (RAP_HAVE_FILE_AIO || RAP_COMPAT)
    rap_output_chain_aio_pt      aio_handler;
#if (RAP_HAVE_AIO_SENDFILE || RAP_COMPAT)
    ssize_t                    (*aio_preload)(rap_buf_t *file);
#endif
#endif

#if (RAP_THREADS || RAP_COMPAT)
    rap_int_t                  (*thread_handler)(rap_thread_task_t *task,
                                                 rap_file_t *file);
    rap_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    rap_pool_t                  *pool;
    rap_int_t                    allocated;
    rap_bufs_t                   bufs;
    rap_buf_tag_t                tag;

    rap_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    rap_chain_t                 *out;
    rap_chain_t                **last;
    rap_connection_t            *connection;
    rap_pool_t                  *pool;
    off_t                        limit;
} rap_chain_writer_ctx_t;


#define RAP_CHAIN_ERROR     (rap_chain_t *) RAP_ERROR


#define rap_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define rap_buf_in_memory_only(b)   (rap_buf_in_memory(b) && !b->in_file)

#define rap_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !rap_buf_in_memory(b) && !b->in_file)

#define rap_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !rap_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define rap_buf_size(b)                                                      \
    (rap_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

rap_buf_t *rap_create_temp_buf(rap_pool_t *pool, size_t size);
rap_chain_t *rap_create_chain_of_bufs(rap_pool_t *pool, rap_bufs_t *bufs);


#define rap_alloc_buf(pool)  rap_palloc(pool, sizeof(rap_buf_t))
#define rap_calloc_buf(pool) rap_pcalloc(pool, sizeof(rap_buf_t))

rap_chain_t *rap_alloc_chain_link(rap_pool_t *pool);
#define rap_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



rap_int_t rap_output_chain(rap_output_chain_ctx_t *ctx, rap_chain_t *in);
rap_int_t rap_chain_writer(void *ctx, rap_chain_t *in);

rap_int_t rap_chain_add_copy(rap_pool_t *pool, rap_chain_t **chain,
    rap_chain_t *in);
rap_chain_t *rap_chain_get_free_buf(rap_pool_t *p, rap_chain_t **free);
void rap_chain_update_chains(rap_pool_t *p, rap_chain_t **free,
    rap_chain_t **busy, rap_chain_t **out, rap_buf_tag_t tag);

off_t rap_chain_coalesce_file(rap_chain_t **in, off_t limit);

rap_chain_t *rap_chain_update_sent(rap_chain_t *in, off_t sent);

#endif /* _RAP_BUF_H_INCLUDED_ */
