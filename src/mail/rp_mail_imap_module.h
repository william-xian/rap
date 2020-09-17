
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_MAIL_IMAP_MODULE_H_INCLUDED_
#define _RP_MAIL_IMAP_MODULE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_mail.h>


typedef struct {
    size_t       client_buffer_size;

    rp_str_t    capability;
    rp_str_t    starttls_capability;
    rp_str_t    starttls_only_capability;

    rp_uint_t   auth_methods;

    rp_array_t  capabilities;
} rp_mail_imap_srv_conf_t;


void rp_mail_imap_init_session(rp_mail_session_t *s, rp_connection_t *c);
void rp_mail_imap_init_protocol(rp_event_t *rev);
void rp_mail_imap_auth_state(rp_event_t *rev);
rp_int_t rp_mail_imap_parse_command(rp_mail_session_t *s);


extern rp_module_t  rp_mail_imap_module;


#endif /* _RP_MAIL_IMAP_MODULE_H_INCLUDED_ */
