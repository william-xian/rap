
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_PIPE_H_INCLUDED_
#define _RAP_EVENT_PIPE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


typedef struct rap_event_pipe_s  rap_event_pipe_t;

typedef rap_int_t (*rap_event_pipe_input_filter_pt)(rap_event_pipe_t *p,
                                                    rap_buf_t *buf);
typedef rap_int_t (*rap_event_pipe_output_filter_pt)(void *data,
                                                     rap_chain_t *chain);


struct rap_event_pipe_s {
    rap_connection_t  *upstream;
    rap_connection_t  *downstream;

    rap_chain_t       *free_raw_bufs;
    rap_chain_t       *in;
    rap_chain_t      **last_in;

    rap_chain_t       *writing;

    rap_chain_t       *out;
    rap_chain_t       *free;
    rap_chain_t       *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    rap_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;

    rap_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;

#if (RAP_THREADS || RAP_COMPAT)
    rap_int_t                       (*thread_handler)(rap_thread_task_t *task,
                                                      rap_file_t *file);
    void                             *thread_ctx;
    rap_thread_task_t                *thread_task;
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

    rap_int_t          allocated;
    rap_bufs_t         bufs;
    rap_buf_tag_t      tag;

    ssize_t            busy_size;

    off_t              read_length;
    off_t              length;

    off_t              max_temp_file_size;
    ssize_t            temp_file_write_size;

    rap_msec_t         read_timeout;
    rap_msec_t         send_timeout;
    ssize_t            send_lowat;

    rap_pool_t        *pool;
    rap_log_t         *log;

    rap_chain_t       *preread_bufs;
    size_t             preread_size;
    rap_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;

    rap_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


rap_int_t rap_event_pipe(rap_event_pipe_t *p, rap_int_t do_write);
rap_int_t rap_event_pipe_copy_input_filter(rap_event_pipe_t *p, rap_buf_t *buf);
rap_int_t rap_event_pipe_add_free_buf(rap_event_pipe_t *p, rap_buf_t *b);


#endif /* _RAP_EVENT_PIPE_H_INCLUDED_ */
