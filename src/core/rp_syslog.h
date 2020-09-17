
/*
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SYSLOG_H_INCLUDED_
#define _RP_SYSLOG_H_INCLUDED_


typedef struct {
    rp_uint_t        facility;
    rp_uint_t        severity;
    rp_str_t         tag;

    rp_addr_t        server;
    rp_connection_t  conn;
    unsigned          busy:1;
    unsigned          nohostname:1;
} rp_syslog_peer_t;


char *rp_syslog_process_conf(rp_conf_t *cf, rp_syslog_peer_t *peer);
u_char *rp_syslog_add_header(rp_syslog_peer_t *peer, u_char *buf);
void rp_syslog_writer(rp_log_t *log, rp_uint_t level, u_char *buf,
    size_t len);
ssize_t rp_syslog_send(rp_syslog_peer_t *peer, u_char *buf, size_t len);


#endif /* _RP_SYSLOG_H_INCLUDED_ */
