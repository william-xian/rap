
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_mail.h>


#define RP_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define RP_DEFAULT_ECDH_CURVE  "auto"


static void *rp_mail_ssl_create_conf(rp_conf_t *cf);
static char *rp_mail_ssl_merge_conf(rp_conf_t *cf, void *parent, void *child);

static char *rp_mail_ssl_enable(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_ssl_starttls(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_conf_enum_t  rp_mail_starttls_state[] = {
    { rp_string("off"), RP_MAIL_STARTTLS_OFF },
    { rp_string("on"), RP_MAIL_STARTTLS_ON },
    { rp_string("only"), RP_MAIL_STARTTLS_ONLY },
    { rp_null_string, 0 }
};



static rp_conf_bitmask_t  rp_mail_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};


static rp_conf_enum_t  rp_mail_ssl_verify[] = {
    { rp_string("off"), 0 },
    { rp_string("on"), 1 },
    { rp_string("optional"), 2 },
    { rp_string("optional_no_ca"), 3 },
    { rp_null_string, 0 }
};


static rp_conf_deprecated_t  rp_mail_ssl_deprecated = {
    rp_conf_deprecated, "ssl", "listen ... ssl"
};


static rp_command_t  rp_mail_ssl_commands[] = {

    { rp_string("ssl"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_mail_ssl_enable,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, enable),
      &rp_mail_ssl_deprecated },

    { rp_string("starttls"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_mail_ssl_starttls,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, starttls),
      rp_mail_starttls_state },

    { rp_string("ssl_certificate"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, certificates),
      NULL },

    { rp_string("ssl_certificate_key"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, certificate_keys),
      NULL },

    { rp_string("ssl_password_file"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_mail_ssl_password_file,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_dhparam"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, dhparam),
      NULL },

    { rp_string("ssl_ecdh_curve"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, ecdh_curve),
      NULL },

    { rp_string("ssl_protocols"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, protocols),
      &rp_mail_ssl_protocols },

    { rp_string("ssl_ciphers"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, ciphers),
      NULL },

    { rp_string("ssl_prefer_server_ciphers"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { rp_string("ssl_session_cache"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE12,
      rp_mail_ssl_session_cache,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("ssl_session_tickets"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, session_tickets),
      NULL },

    { rp_string("ssl_session_ticket_key"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, session_ticket_keys),
      NULL },

    { rp_string("ssl_session_timeout"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_sec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, session_timeout),
      NULL },

    { rp_string("ssl_verify_client"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, verify),
      &rp_mail_ssl_verify },

    { rp_string("ssl_verify_depth"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, verify_depth),
      NULL },

    { rp_string("ssl_client_certificate"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, client_certificate),
      NULL },

    { rp_string("ssl_trusted_certificate"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, trusted_certificate),
      NULL },

    { rp_string("ssl_crl"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_ssl_conf_t, crl),
      NULL },

      rp_null_command
};


static rp_mail_module_t  rp_mail_ssl_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_ssl_create_conf,              /* create server configuration */
    rp_mail_ssl_merge_conf                /* merge server configuration */
};


rp_module_t  rp_mail_ssl_module = {
    RP_MODULE_V1,
    &rp_mail_ssl_module_ctx,              /* module context */
    rp_mail_ssl_commands,                 /* module directives */
    RP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t rp_mail_ssl_sess_id_ctx = rp_string("MAIL");


static void *
rp_mail_ssl_create_conf(rp_conf_t *cf)
{
    rp_mail_ssl_conf_t  *scf;

    scf = rp_pcalloc(cf->pool, sizeof(rp_mail_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
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

    scf->enable = RP_CONF_UNSET;
    scf->starttls = RP_CONF_UNSET_UINT;
    scf->certificates = RP_CONF_UNSET_PTR;
    scf->certificate_keys = RP_CONF_UNSET_PTR;
    scf->passwords = RP_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = RP_CONF_UNSET;
    scf->verify = RP_CONF_UNSET_UINT;
    scf->verify_depth = RP_CONF_UNSET_UINT;
    scf->builtin_session_cache = RP_CONF_UNSET;
    scf->session_timeout = RP_CONF_UNSET;
    scf->session_tickets = RP_CONF_UNSET;
    scf->session_ticket_keys = RP_CONF_UNSET_PTR;

    return scf;
}


static char *
rp_mail_ssl_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_ssl_conf_t *prev = parent;
    rp_mail_ssl_conf_t *conf = child;

    char                *mode;
    rp_pool_cleanup_t  *cln;

    rp_conf_merge_value(conf->enable, prev->enable, 0);
    rp_conf_merge_uint_value(conf->starttls, prev->starttls,
                         RP_MAIL_STARTTLS_OFF);

    rp_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    rp_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    rp_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                          |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

    rp_conf_merge_uint_value(conf->verify, prev->verify, 0);
    rp_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    rp_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    rp_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    rp_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    rp_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    rp_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         RP_DEFAULT_ECDH_CURVE);

    rp_conf_merge_str_value(conf->client_certificate,
                         prev->client_certificate, "");
    rp_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    rp_conf_merge_str_value(conf->crl, prev->crl, "");

    rp_conf_merge_str_value(conf->ciphers, prev->ciphers, RP_DEFAULT_CIPHERS);


    conf->ssl.log = cf->log;

    if (conf->listen) {
        mode = "listen ... ssl";

    } else if (conf->enable) {
        mode = "ssl";

    } else if (conf->starttls != RP_MAIL_STARTTLS_OFF) {
        mode = "starttls";

    } else {
        return RP_CONF_OK;
    }

    if (conf->file == NULL) {
        conf->file = prev->file;
        conf->line = prev->line;
    }

    if (conf->certificates == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"%s\" directive in %s:%ui",
                      ((rp_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      mode, conf->file, conf->line);
        return RP_CONF_ERROR;
    }

    if (rp_ssl_create(&conf->ssl, conf->protocols, NULL) != RP_OK) {
        return RP_CONF_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rp_ssl_cleanup_ctx(&conf->ssl);
        return RP_CONF_ERROR;
    }

    cln->handler = rp_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (rp_ssl_certificates(cf, &conf->ssl, conf->certificates,
                             conf->certificate_keys, conf->passwords)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_verify_client");
            return RP_CONF_ERROR;
        }

        if (rp_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

        if (rp_ssl_trusted_certificate(cf, &conf->ssl,
                                        &conf->trusted_certificate,
                                        conf->verify_depth)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

        if (rp_ssl_crl(cf, &conf->ssl, &conf->crl) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    if (rp_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    if (rp_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != RP_OK) {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, RP_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (rp_ssl_session_cache(&conf->ssl, &rp_mail_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    rp_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (rp_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_mail_ssl_enable(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = rp_conf_set_flag_slot(cf, cmd, conf);

    if (rv != RP_CONF_OK) {
        return rv;
    }

    if (scf->enable && (rp_int_t) scf->starttls > RP_MAIL_STARTTLS_OFF) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"starttls\" directive conflicts with \"ssl on\"");
        return RP_CONF_ERROR;
    }

    if (!scf->listen) {
        scf->file = cf->conf_file->file.name.data;
        scf->line = cf->conf_file->line;
    }

    return RP_CONF_OK;
}


static char *
rp_mail_ssl_starttls(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = rp_conf_set_enum_slot(cf, cmd, conf);

    if (rv != RP_CONF_OK) {
        return rv;
    }

    if (scf->enable == 1 && (rp_int_t) scf->starttls > RP_MAIL_STARTTLS_OFF) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"ssl\" directive conflicts with \"starttls\"");
        return RP_CONF_ERROR;
    }

    if (!scf->listen) {
        scf->file = cf->conf_file->file.name.data;
        scf->line = cf->conf_file->line;
    }

    return RP_CONF_OK;
}


static char *
rp_mail_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_ssl_conf_t  *scf = conf;

    rp_str_t  *value;

    if (scf->passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_mail_ssl_session_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_ssl_conf_t  *scf = conf;

    size_t       len;
    rp_str_t   *value, name, size;
    rp_int_t    n;
    rp_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = RP_SSL_NO_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = RP_SSL_NONE_SCACHE;
            continue;
        }

        if (rp_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = RP_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && rp_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = rp_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == RP_ERROR) {
                goto invalid;
            }

            scf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && rp_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
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

            n = rp_parse_size(&size);

            if (n == RP_ERROR) {
                goto invalid;
            }

            if (n < (rp_int_t) (8 * rp_pagesize)) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return RP_CONF_ERROR;
            }

            scf->shm_zone = rp_shared_memory_add(cf, &name, n,
                                                   &rp_mail_ssl_module);
            if (scf->shm_zone == NULL) {
                return RP_CONF_ERROR;
            }

            scf->shm_zone->init = rp_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == RP_CONF_UNSET) {
        scf->builtin_session_cache = RP_SSL_NO_BUILTIN_SCACHE;
    }

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return RP_CONF_ERROR;
}
