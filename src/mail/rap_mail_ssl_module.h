
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_MAIL_SSL_H_INCLUDED_
#define _RAP_MAIL_SSL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_mail.h>


#define RAP_MAIL_STARTTLS_OFF   0
#define RAP_MAIL_STARTTLS_ON    1
#define RAP_MAIL_STARTTLS_ONLY  2


typedef struct {
    rap_flag_t       enable;
    rap_flag_t       prefer_server_ciphers;

    rap_ssl_t        ssl;

    rap_uint_t       starttls;
    rap_uint_t       listen;
    rap_uint_t       protocols;

    rap_uint_t       verify;
    rap_uint_t       verify_depth;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    rap_array_t     *certificates;
    rap_array_t     *certificate_keys;

    rap_str_t        dhparam;
    rap_str_t        ecdh_curve;
    rap_str_t        client_certificate;
    rap_str_t        trusted_certificate;
    rap_str_t        crl;

    rap_str_t        ciphers;

    rap_array_t     *passwords;

    rap_shm_zone_t  *shm_zone;

    rap_flag_t       session_tickets;
    rap_array_t     *session_ticket_keys;

    u_char          *file;
    rap_uint_t       line;
} rap_mail_ssl_conf_t;


extern rap_module_t  rap_mail_ssl_module;


#endif /* _RAP_MAIL_SSL_H_INCLUDED_ */
