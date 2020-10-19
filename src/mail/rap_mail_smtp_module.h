
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_MAIL_SMTP_MODULE_H_INCLUDED_
#define _RAP_MAIL_SMTP_MODULE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_mail.h>
#include <rap_mail_smtp_module.h>


typedef struct {
    rap_msec_t   greeting_delay;

    size_t       client_buffer_size;

    rap_str_t    capability;
    rap_str_t    starttls_capability;
    rap_str_t    starttls_only_capability;

    rap_str_t    server_name;
    rap_str_t    greeting;

    rap_uint_t   auth_methods;

    rap_array_t  capabilities;
} rap_mail_smtp_srv_conf_t;


void rap_mail_smtp_init_session(rap_mail_session_t *s, rap_connection_t *c);
void rap_mail_smtp_init_protocol(rap_event_t *rev);
void rap_mail_smtp_auth_state(rap_event_t *rev);
rap_int_t rap_mail_smtp_parse_command(rap_mail_session_t *s);


extern rap_module_t  rap_mail_smtp_module;


#endif /* _RAP_MAIL_SMTP_MODULE_H_INCLUDED_ */
