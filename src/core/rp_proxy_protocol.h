
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PROXY_PROTOCOL_H_INCLUDED_
#define _RP_PROXY_PROTOCOL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_PROXY_PROTOCOL_MAX_HEADER  107


struct rp_proxy_protocol_s {
    rp_str_t           src_addr;
    rp_str_t           dst_addr;
    in_port_t           src_port;
    in_port_t           dst_port;
};


u_char *rp_proxy_protocol_read(rp_connection_t *c, u_char *buf,
    u_char *last);
u_char *rp_proxy_protocol_write(rp_connection_t *c, u_char *buf,
    u_char *last);


#endif /* _RP_PROXY_PROTOCOL_H_INCLUDED_ */
