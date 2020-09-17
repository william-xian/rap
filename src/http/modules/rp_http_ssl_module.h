
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_SSL_H_INCLUDED_
#define _RP_HTTP_SSL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_flag_t                      enable;

    rp_ssl_t                       ssl;

    rp_flag_t                      prefer_server_ciphers;
    rp_flag_t                      early_data;

    rp_uint_t                      protocols;

    rp_uint_t                      verify;
    rp_uint_t                      verify_depth;

    size_t                          buffer_size;

    ssize_t                         builtin_session_cache;

    time_t                          session_timeout;

    rp_array_t                    *certificates;
    rp_array_t                    *certificate_keys;

    rp_array_t                    *certificate_values;
    rp_array_t                    *certificate_key_values;

    rp_str_t                       dhparam;
    rp_str_t                       ecdh_curve;
    rp_str_t                       client_certificate;
    rp_str_t                       trusted_certificate;
    rp_str_t                       crl;

    rp_str_t                       ciphers;

    rp_array_t                    *passwords;

    rp_shm_zone_t                 *shm_zone;

    rp_flag_t                      session_tickets;
    rp_array_t                    *session_ticket_keys;

    rp_flag_t                      stapling;
    rp_flag_t                      stapling_verify;
    rp_str_t                       stapling_file;
    rp_str_t                       stapling_responder;

    u_char                         *file;
    rp_uint_t                      line;
} rp_http_ssl_srv_conf_t;


extern rp_module_t  rp_http_ssl_module;


#endif /* _RP_HTTP_SSL_H_INCLUDED_ */
