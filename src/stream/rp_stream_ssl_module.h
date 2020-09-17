
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_STREAM_SSL_H_INCLUDED_
#define _RP_STREAM_SSL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_msec_t       handshake_timeout;

    rp_flag_t       prefer_server_ciphers;

    rp_ssl_t        ssl;

    rp_uint_t       listen;
    rp_uint_t       protocols;

    rp_uint_t       verify;
    rp_uint_t       verify_depth;

    ssize_t          builtin_session_cache;

    time_t           session_timeout;

    rp_array_t     *certificates;
    rp_array_t     *certificate_keys;

    rp_array_t     *certificate_values;
    rp_array_t     *certificate_key_values;

    rp_str_t        dhparam;
    rp_str_t        ecdh_curve;
    rp_str_t        client_certificate;
    rp_str_t        trusted_certificate;
    rp_str_t        crl;

    rp_str_t        ciphers;

    rp_array_t     *passwords;

    rp_shm_zone_t  *shm_zone;

    rp_flag_t       session_tickets;
    rp_array_t     *session_ticket_keys;

    u_char          *file;
    rp_uint_t       line;
} rp_stream_ssl_conf_t;


extern rp_module_t  rp_stream_ssl_module;


#endif /* _RP_STREAM_SSL_H_INCLUDED_ */
