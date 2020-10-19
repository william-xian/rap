
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_SSL_H_INCLUDED_
#define _RAP_HTTP_SSL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_flag_t                      enable;

    rap_ssl_t                       ssl;

    rap_flag_t                      prefer_server_ciphers;
    rap_flag_t                      early_data;

    rap_uint_t                      protocols;

    rap_uint_t                      verify;
    rap_uint_t                      verify_depth;

    size_t                          buffer_size;

    ssize_t                         builtin_session_cache;

    time_t                          session_timeout;

    rap_array_t                    *certificates;
    rap_array_t                    *certificate_keys;

    rap_array_t                    *certificate_values;
    rap_array_t                    *certificate_key_values;

    rap_str_t                       dhparam;
    rap_str_t                       ecdh_curve;
    rap_str_t                       client_certificate;
    rap_str_t                       trusted_certificate;
    rap_str_t                       crl;

    rap_str_t                       ciphers;

    rap_array_t                    *passwords;

    rap_shm_zone_t                 *shm_zone;

    rap_flag_t                      session_tickets;
    rap_array_t                    *session_ticket_keys;

    rap_flag_t                      stapling;
    rap_flag_t                      stapling_verify;
    rap_str_t                       stapling_file;
    rap_str_t                       stapling_responder;

    u_char                         *file;
    rap_uint_t                      line;
} rap_http_ssl_srv_conf_t;


extern rap_module_t  rap_http_ssl_module;


#endif /* _RAP_HTTP_SSL_H_INCLUDED_ */
