
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_PIPE_H_INCLUDED_
#define _RP_EVENT_PIPE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


typedef struct rp_event_pipe_s  rp_event_pipe_t;

typedef rp_int_t (*rp_event_pipe_input_filter_pt)(rp_event_pipe_t *p,
                                                    rp_buf_t *buf);
typedef rp_int_t (*rp_event_pipe_output_filter_pt)(void *data,
                                                     rp_chain_t *chain);


struct rp_event_pipe_s {
    rp_connection_t  *upstream;
    rp_connection_t  *downstream;

    rp_chain_t       *free_raw_bufs;
    rp_chain_t       *in;
    rp_chain_t      **last_in;

    rp_chain_t       *writing;

    rp_chain_t       *out;
    rp_chain_t       *free;
    rp_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    rp_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;

    rp_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;

#if (RP_THREADS || RP_COMPAT)
    rp_int_t                       (*thread_handler)(rp_thread_task_t *task,
                                                      rp_file_t *file);
    void                             *thread_ctx;
    rp_thread_task_t                *thread_task;
#endif

    unsigned           read:1;
    unsigned           cacheable:1;
    unsigned           single_buf:1;
    unsigned           free_bufs:1;
    unsigned           upstream_done:1;
    unsigned           upstream_error:1;
    unsigned           upstream_eof:1;
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;
    unsigned           cyclic_temp_file:1;
    unsigned           aio:1;

    rp_int_t          allocated;
    rp_bufs_t         bufs;
    rp_buf_tag_t      tag;

    ssize_t            busy_size;

    off_t              read_length;
    off_t              length;

    off_t              max_temp_file_size;
    ssize_t            temp_file_write_size;

    rp_msec_t         read_timeout;
    rp_msec_t         send_timeout;
    ssize_t            send_lowat;

    rp_pool_t        *pool;
    rp_log_t         *log;

    rp_chain_t       *preread_bufs;
    size_t             preread_size;
    rp_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;

    rp_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


rp_int_t rp_event_pipe(rp_event_pipe_t *p, rp_int_t do_write);
rp_int_t rp_event_pipe_copy_input_filter(rp_event_pipe_t *p, rp_buf_t *buf);
rp_int_t rp_event_pipe_add_free_buf(rp_event_pipe_t *p, rp_buf_t *b);


#endif /* _RP_EVENT_PIPE_H_INCLUDED_ */
