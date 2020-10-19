
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_mail.h>


#define RAP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RAP_DEFAULT_ECDH_CURVE  "auto"


static void *rap_mail_ssl_create_conf(rap_conf_t *cf);
static char *rap_mail_ssl_merge_conf(rap_conf_t *cf, void *parent, void *child);

static char *rap_mail_ssl_enable(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_ssl_starttls(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_conf_enum_t  rap_mail_starttls_state[] = {
    { rap_string("off"), RAP_MAIL_STARTTLS_OFF },
    { rap_string("on"), RAP_MAIL_STARTTLS_ON },
    { rap_string("only"), RAP_MAIL_STARTTLS_ONLY },
    { rap_null_string, 0 }
};



static rap_conf_bitmask_t  rap_mail_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};


static rap_conf_enum_t  rap_mail_ssl_verify[] = {
    { rap_string("off"), 0 },
    { rap_string("on"), 1 },
    { rap_string("optional"), 2 },
    { rap_string("optional_no_ca"), 3 },
    { rap_null_string, 0 }
};


static rap_conf_deprecated_t  rap_mail_ssl_deprecated = {
    rap_conf_deprecated, "ssl", "listen ... ssl"
};


static rap_command_t  rap_mail_ssl_commands[] = {

    { rap_string("ssl"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_mail_ssl_enable,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, enable),
      &rap_mail_ssl_deprecated },

    { rap_string("starttls"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_mail_ssl_starttls,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, starttls),
      rap_mail_starttls_state },

    { rap_string("ssl_certificate"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, certificates),
      NULL },

    { rap_string("ssl_certificate_key"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, certificate_keys),
      NULL },

    { rap_string("ssl_password_file"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_mail_ssl_password_file,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_dhparam"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, dhparam),
      NULL },

    { rap_string("ssl_ecdh_curve"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, ecdh_curve),
      NULL },

    { rap_string("ssl_protocols"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, protocols),
      &rap_mail_ssl_protocols },

    { rap_string("ssl_ciphers"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, ciphers),
      NULL },

    { rap_string("ssl_prefer_server_ciphers"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { rap_string("ssl_session_cache"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE12,
      rap_mail_ssl_session_cache,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("ssl_session_tickets"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, session_tickets),
      NULL },

    { rap_string("ssl_session_ticket_key"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, session_ticket_keys),
      NULL },

    { rap_string("ssl_session_timeout"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_sec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, session_timeout),
      NULL },

    { rap_string("ssl_verify_client"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, verify),
      &rap_mail_ssl_verify },

    { rap_string("ssl_verify_depth"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, verify_depth),
      NULL },

    { rap_string("ssl_client_certificate"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, client_certificate),
      NULL },

    { rap_string("ssl_trusted_certificate"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, trusted_certificate),
      NULL },

    { rap_string("ssl_crl"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_ssl_conf_t, crl),
      NULL },

      rap_null_command
};


static rap_mail_module_t  rap_mail_ssl_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_ssl_create_conf,              /* create server configuration */
    rap_mail_ssl_merge_conf                /* merge server configuration */
};


rap_module_t  rap_mail_ssl_module = {
    RAP_MODULE_V1,
    &rap_mail_ssl_module_ctx,              /* module context */
    rap_mail_ssl_commands,                 /* module directives */
    RAP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_str_t rap_mail_ssl_sess_id_ctx = rap_string("MAIL");


static void *
rap_mail_ssl_create_conf(rap_conf_t *cf)
{
    rap_mail_ssl_conf_t  *scf;

    scf = rap_pcalloc(cf->pool, sizeof(rap_mail_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     scf->listen = 0;
     *     scf->protocols = 0;
     *     scf->dhparam = { 0, NULL };
     *     scf->ecdh_curve = { 0, NULL };
     *     scf->client_certificate = { 0, NULL };
     *     scf->trusted_certificate = { 0, NULL };
     *     scf->crl = { 0, NULL };
     *     scf->ciphers = { 0, NULL };
     *     scf->shm_zone = NULL;
     */

    scf->enable = RAP_CONF_UNSET;
    scf->starttls = RAP_CONF_UNSET_UINT;
    scf->certificates = RAP_CONF_UNSET_PTR;
    scf->certificate_keys = RAP_CONF_UNSET_PTR;
    scf->passwords = RAP_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = RAP_CONF_UNSET;
    scf->verify = RAP_CONF_UNSET_UINT;
    scf->verify_depth = RAP_CONF_UNSET_UINT;
    scf->builtin_session_cache = RAP_CONF_UNSET;
    scf->session_timeout = RAP_CONF_UNSET;
    scf->session_tickets = RAP_CONF_UNSET;
    scf->session_ticket_keys = RAP_CONF_UNSET_PTR;

    return scf;
}


static char *
rap_mail_ssl_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_ssl_conf_t *prev = parent;
    rap_mail_ssl_conf_t *conf = child;

    char                *mode;
    rap_pool_cleanup_t  *cln;

    rap_conf_merge_value(conf->enable, prev->enable, 0);
    rap_conf_merge_uint_value(conf->starttls, prev->starttls,
                         RAP_MAIL_STARTTLS_OFF);

    rap_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rap_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rap_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                          |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

    rap_conf_merge_uint_value(conf->verify, prev->verify, 0);
    rap_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    rap_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    rap_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    rap_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    rap_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    rap_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         RAP_DEFAULT_ECDH_CURVE);

    rap_conf_merge_str_value(conf->client_certificate,
                         prev->client_certificate, "");
    rap_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    rap_conf_merge_str_value(conf->crl, prev->crl, "");

    rap_conf_merge_str_value(conf->ciphers, prev->ciphers, RAP_DEFAULT_CIPHERS);


    conf->ssl.log = cf->log;

    if (conf->listen) {
        mode = "listen ... ssl";

    } else if (conf->enable) {
        mode = "ssl";

    } else if (conf->starttls != RAP_MAIL_STARTTLS_OFF) {
        mode = "starttls";

    } else {
        return RAP_CONF_OK;
    }

    if (conf->file == NULL) {
        conf->file = prev->file;
        conf->line = prev->line;
    }

    if (conf->certificates == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"%s\" directive in %s:%ui",
                      ((rap_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      mode, conf->file, conf->line);
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_create(&conf->ssl, conf->protocols, NULL) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(&conf->ssl);
        return RAP_CONF_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (rap_ssl_certificates(cf, &conf->ssl, conf->certificates,
                             conf->certificate_keys, conf->passwords)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_verify_client");
            return RAP_CONF_ERROR;
        }

        if (rap_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

        if (rap_ssl_trusted_certificate(cf, &conf->ssl,
                                        &conf->trusted_certificate,
                                        conf->verify_depth)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

        if (rap_ssl_crl(cf, &conf->ssl, &conf->crl) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (rap_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, RAP_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (rap_ssl_session_cache(&conf->ssl, &rap_mail_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    rap_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (rap_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_ssl_enable(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = rap_conf_set_flag_slot(cf, cmd, conf);

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    if (scf->enable && (rap_int_t) scf->starttls > RAP_MAIL_STARTTLS_OFF) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"starttls\" directive conflicts with \"ssl on\"");
        return RAP_CONF_ERROR;
    }

    if (!scf->listen) {
        scf->file = cf->conf_file->file.name.data;
        scf->line = cf->conf_file->line;
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_ssl_starttls(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = rap_conf_set_enum_slot(cf, cmd, conf);

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    if (scf->enable == 1 && (rap_int_t) scf->starttls > RAP_MAIL_STARTTLS_OFF) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"ssl\" directive conflicts with \"starttls\"");
        return RAP_CONF_ERROR;
    }

    if (!scf->listen) {
        scf->file = cf->conf_file->file.name.data;
        scf->line = cf->conf_file->line;
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_ssl_conf_t  *scf = conf;

    rap_str_t  *value;

    if (scf->passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_ssl_session_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_ssl_conf_t  *scf = conf;

    size_t       len;
    rap_str_t   *value, name, size;
    rap_int_t    n;
    rap_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rap_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = RAP_SSL_NO_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = RAP_SSL_NONE_SCACHE;
            continue;
        }

        if (rap_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = RAP_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && rap_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = rap_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == RAP_ERROR) {
                goto invalid;
            }

            scf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && rap_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = rap_parse_size(&size);

            if (n == RAP_ERROR) {
                goto invalid;
            }

            if (n < (rap_int_t) (8 * rap_pagesize)) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return RAP_CONF_ERROR;
            }

            scf->shm_zone = rap_shared_memory_add(cf, &name, n,
                                                   &rap_mail_ssl_module);
            if (scf->shm_zone == NULL) {
                return RAP_CONF_ERROR;
            }

            scf->shm_zone->init = rap_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == RAP_CONF_UNSET) {
        scf->builtin_session_cache = RAP_SSL_NO_BUILTIN_SCACHE;
    }

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RAP_CONF_ERROR;
}
