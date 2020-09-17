
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CHANNEL_H_INCLUDED_
#define _RP_CHANNEL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


typedef struct {
    rp_uint_t  command;
    rp_pid_t   pid;
    rp_int_t   slot;
    rp_fd_t    fd;
} rp_channel_t;


rp_int_t rp_write_channel(rp_socket_t s, rp_channel_t *ch, size_t size,
    rp_log_t *log);
rp_int_t rp_read_channel(rp_socket_t s, rp_channel_t *ch, size_t size,
    rp_log_t *log);
rp_int_t rp_add_channel_event(rp_cycle_t *cycle, rp_fd_t fd,
    rp_int_t event, rp_event_handler_pt handler);
void rp_close_channel(rp_fd_t *fd, rp_log_t *log);


#endif /* _RP_CHANNEL_H_INCLUDED_ */
