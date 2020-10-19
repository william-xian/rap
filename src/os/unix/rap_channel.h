
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CHANNEL_H_INCLUDED_
#define _RAP_CHANNEL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


typedef struct {
    rap_uint_t  command;
    rap_pid_t   pid;
    rap_int_t   slot;
    rap_fd_t    fd;
} rap_channel_t;


rap_int_t rap_write_channel(rap_socket_t s, rap_channel_t *ch, size_t size,
    rap_log_t *log);
rap_int_t rap_read_channel(rap_socket_t s, rap_channel_t *ch, size_t size,
    rap_log_t *log);
rap_int_t rap_add_channel_event(rap_cycle_t *cycle, rap_fd_t fd,
    rap_int_t event, rap_event_handler_pt handler);
void rap_close_channel(rap_fd_t *fd, rap_log_t *log);


#endif /* _RAP_CHANNEL_H_INCLUDED_ */
