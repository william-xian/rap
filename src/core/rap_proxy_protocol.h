
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PROXY_PROTOCOL_H_INCLUDED_
#define _RAP_PROXY_PROTOCOL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_PROXY_PROTOCOL_MAX_HEADER  107


struct rap_proxy_protocol_s {
    rap_str_t           src_addr;
    rap_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
};


u_char *rap_proxy_protocol_read(rap_connection_t *c, u_char *buf,
    u_char *last);
u_char *rap_proxy_protocol_write(rap_connection_t *c, u_char *buf,
    u_char *last);


#endif /* _RAP_PROXY_PROTOCOL_H_INCLUDED_ */
