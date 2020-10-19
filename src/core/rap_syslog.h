
/*
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SYSLOG_H_INCLUDED_
#define _RAP_SYSLOG_H_INCLUDED_


typedef struct {
    rap_uint_t        facility;
    rap_uint_t        severity;
    rap_str_t         tag;

    rap_addr_t        server;
    rap_connection_t  conn;
    unsigned          busy:1;
    unsigned          nohostname:1;
} rap_syslog_peer_t;


char *rap_syslog_process_conf(rap_conf_t *cf, rap_syslog_peer_t *peer);
u_char *rap_syslog_add_header(rap_syslog_peer_t *peer, u_char *buf);
void rap_syslog_writer(rap_log_t *log, rap_uint_t level, u_char *buf,
    size_t len);
ssize_t rap_syslog_send(rap_syslog_peer_t *peer, u_char *buf, size_t len);


#endif /* _RAP_SYSLOG_H_INCLUDED_ */
