
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_pop3_module.h>


static void *rap_mail_pop3_create_srv_conf(rap_conf_t *cf);
static char *rap_mail_pop3_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);


static rap_str_t  rap_mail_pop3_default_capabilities[] = {
    rap_string("TOP"),
    rap_string("USER"),
    rap_string("UIDL"),
    rap_null_string
};


static rap_conf_bitmask_t  rap_mail_pop3_auth_methods[] = {
    { rap_string("plain"), RAP_MAIL_AUTH_PLAIN_ENABLED },
    { rap_string("apop"), RAP_MAIL_AUTH_APOP_ENABLED },
    { rap_string("cram-md5"), RAP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rap_string("external"), RAP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rap_null_string, 0 }
};


static rap_str_t  rap_mail_pop3_auth_methods_names[] = {
    rap_string("PLAIN"),
    rap_string("LOGIN"),
    rap_null_string,  /* APOP */
    rap_string("CRAM-MD5"),
    rap_string("EXTERNAL"),
    rap_null_string   /* NONE */
};


static rap_mail_protocol_t  rap_mail_pop3_protocol = {
    rap_string("pop3"),
    { 110, 995, 0, 0 },
    RAP_MAIL_POP3_PROTOCOL,

    rap_mail_pop3_init_session,
    rap_mail_pop3_init_protocol,
    rap_mail_pop3_parse_command,
    rap_mail_pop3_auth_state,

    rap_string("-ERR internal server error" CRLF),
    rap_string("-ERR SSL certificate error" CRLF),
    rap_string("-ERR No required SSL certificate" CRLF)
};


static rap_command_t  rap_mail_pop3_commands[] = {

    { rap_string("pop3_capabilities"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_capabilities,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_pop3_srv_conf_t, capabilities),
      NULL },

    { rap_string("pop3_auth"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_pop3_srv_conf_t, auth_methods),
      &rap_mail_pop3_auth_methods },

      rap_null_command
};


static rap_mail_module_t  rap_mail_pop3_module_ctx = {
    &rap_mail_pop3_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_pop3_create_srv_conf,         /* create server configuration */
    rap_mail_pop3_merge_srv_conf           /* merge server configuration */
};


rap_module_t  rap_mail_pop3_module = {
    RAP_MODULE_V1,
    &rap_mail_pop3_module_ctx,             /* module context */
    rap_mail_pop3_commands,                /* module directives */
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


static void *
rap_mail_pop3_create_srv_conf(rap_conf_t *cf)
{
    rap_mail_pop3_srv_conf_t  *pscf;

    pscf = rap_pcalloc(cf->pool, sizeof(rap_mail_pop3_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    if (rap_array_init(&pscf->capabilities, cf->pool, 4, sizeof(rap_str_t))
        != RAP_OK)
    {
        return NULL;
    }

    return pscf;
}


static char *
rap_mail_pop3_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_pop3_srv_conf_t *prev = parent;
    rap_mail_pop3_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size, stls_only_size;
    rap_str_t   *c, *d;
    rap_uint_t   i, m;

    rap_conf_merge_bitmask_value(conf->auth_methods,
                                 prev->auth_methods,
                                 (RAP_CONF_BITMASK_SET
                                  |RAP_MAIL_AUTH_PLAIN_ENABLED));

    if (conf->auth_methods & RAP_MAIL_AUTH_PLAIN_ENABLED) {
        conf->auth_methods |= RAP_MAIL_AUTH_LOGIN_ENABLED;
    }

    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = rap_mail_pop3_default_capabilities; d->len; d++) {
            c = rap_array_push(&conf->capabilities);
            if (c == NULL) {
                return RAP_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("+OK Capability list follows" CRLF) - 1
           + sizeof("." CRLF) - 1;

    stls_only_size = size + sizeof("STLS" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += c[i].len + sizeof(CRLF) - 1;

        if (rap_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        stls_only_size += c[i].len + sizeof(CRLF) - 1;
    }

    size += sizeof("SASL") - 1 + sizeof(CRLF) - 1;

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rap_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += 1 + rap_mail_pop3_auth_methods_names[i].len;
        }
    }

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = rap_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        p = rap_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = rap_cpymem(p, "SASL", sizeof("SASL") - 1);

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rap_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = rap_cpymem(p, rap_mail_pop3_auth_methods_names[i].data,
                           rap_mail_pop3_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p++ = LF;

    *p++ = '.'; *p++ = CR; *p = LF;


    size += sizeof("STLS" CRLF) - 1;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rap_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof("." CRLF) - 1));

    p = rap_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;


    size = sizeof("+OK methods supported:" CRLF) - 1
           + sizeof("." CRLF) - 1;

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rap_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += rap_mail_pop3_auth_methods_names[i].len
                    + sizeof(CRLF) - 1;
        }
    }

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->auth_capability.data = p;
    conf->auth_capability.len = size;

    p = rap_cpymem(p, "+OK methods supported:" CRLF,
                   sizeof("+OK methods supported:" CRLF) - 1);

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rap_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            p = rap_cpymem(p, rap_mail_pop3_auth_methods_names[i].data,
                           rap_mail_pop3_auth_methods_names[i].len);
            *p++ = CR; *p++ = LF;
        }
    }

    *p++ = '.'; *p++ = CR; *p = LF;


    p = rap_pnalloc(cf->pool, stls_only_size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = stls_only_size;
    conf->starttls_only_capability.data = p;

    p = rap_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        if (rap_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        p = rap_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = rap_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;

    return RAP_CONF_OK;
}
