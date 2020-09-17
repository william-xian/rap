
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_pop3_module.h>


static void *rp_mail_pop3_create_srv_conf(rp_conf_t *cf);
static char *rp_mail_pop3_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);


static rp_str_t  rp_mail_pop3_default_capabilities[] = {
    rp_string("TOP"),
    rp_string("USER"),
    rp_string("UIDL"),
    rp_null_string
};


static rp_conf_bitmask_t  rp_mail_pop3_auth_methods[] = {
    { rp_string("plain"), RP_MAIL_AUTH_PLAIN_ENABLED },
    { rp_string("apop"), RP_MAIL_AUTH_APOP_ENABLED },
    { rp_string("cram-md5"), RP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rp_string("external"), RP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rp_null_string, 0 }
};


static rp_str_t  rp_mail_pop3_auth_methods_names[] = {
    rp_string("PLAIN"),
    rp_string("LOGIN"),
    rp_null_string,  /* APOP */
    rp_string("CRAM-MD5"),
    rp_string("EXTERNAL"),
    rp_null_string   /* NONE */
};


static rp_mail_protocol_t  rp_mail_pop3_protocol = {
    rp_string("pop3"),
    { 110, 995, 0, 0 },
    RP_MAIL_POP3_PROTOCOL,

    rp_mail_pop3_init_session,
    rp_mail_pop3_init_protocol,
    rp_mail_pop3_parse_command,
    rp_mail_pop3_auth_state,

    rp_string("-ERR internal server error" CRLF),
    rp_string("-ERR SSL certificate error" CRLF),
    rp_string("-ERR No required SSL certificate" CRLF)
};


static rp_command_t  rp_mail_pop3_commands[] = {

    { rp_string("pop3_capabilities"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_capabilities,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_pop3_srv_conf_t, capabilities),
      NULL },

    { rp_string("pop3_auth"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_pop3_srv_conf_t, auth_methods),
      &rp_mail_pop3_auth_methods },

      rp_null_command
};


static rp_mail_module_t  rp_mail_pop3_module_ctx = {
    &rp_mail_pop3_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_pop3_create_srv_conf,         /* create server configuration */
    rp_mail_pop3_merge_srv_conf           /* merge server configuration */
};


rp_module_t  rp_mail_pop3_module = {
    RP_MODULE_V1,
    &rp_mail_pop3_module_ctx,             /* module context */
    rp_mail_pop3_commands,                /* module directives */
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


static void *
rp_mail_pop3_create_srv_conf(rp_conf_t *cf)
{
    rp_mail_pop3_srv_conf_t  *pscf;

    pscf = rp_pcalloc(cf->pool, sizeof(rp_mail_pop3_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    if (rp_array_init(&pscf->capabilities, cf->pool, 4, sizeof(rp_str_t))
        != RP_OK)
    {
        return NULL;
    }

    return pscf;
}


static char *
rp_mail_pop3_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_pop3_srv_conf_t *prev = parent;
    rp_mail_pop3_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size, stls_only_size;
    rp_str_t   *c, *d;
    rp_uint_t   i, m;

    rp_conf_merge_bitmask_value(conf->auth_methods,
                                 prev->auth_methods,
                                 (RP_CONF_BITMASK_SET
                                  |RP_MAIL_AUTH_PLAIN_ENABLED));

    if (conf->auth_methods & RP_MAIL_AUTH_PLAIN_ENABLED) {
        conf->auth_methods |= RP_MAIL_AUTH_LOGIN_ENABLED;
    }

    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = rp_mail_pop3_default_capabilities; d->len; d++) {
            c = rp_array_push(&conf->capabilities);
            if (c == NULL) {
                return RP_CONF_ERROR;
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

        if (rp_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        stls_only_size += c[i].len + sizeof(CRLF) - 1;
    }

    size += sizeof("SASL") - 1 + sizeof(CRLF) - 1;

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rp_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += 1 + rp_mail_pop3_auth_methods_names[i].len;
        }
    }

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = rp_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        p = rp_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = rp_cpymem(p, "SASL", sizeof("SASL") - 1);

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rp_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = rp_cpymem(p, rp_mail_pop3_auth_methods_names[i].data,
                           rp_mail_pop3_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p++ = LF;

    *p++ = '.'; *p++ = CR; *p = LF;


    size += sizeof("STLS" CRLF) - 1;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rp_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof("." CRLF) - 1));

    p = rp_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;


    size = sizeof("+OK methods supported:" CRLF) - 1
           + sizeof("." CRLF) - 1;

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rp_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += rp_mail_pop3_auth_methods_names[i].len
                    + sizeof(CRLF) - 1;
        }
    }

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->auth_capability.data = p;
    conf->auth_capability.len = size;

    p = rp_cpymem(p, "+OK methods supported:" CRLF,
                   sizeof("+OK methods supported:" CRLF) - 1);

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (rp_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            p = rp_cpymem(p, rp_mail_pop3_auth_methods_names[i].data,
                           rp_mail_pop3_auth_methods_names[i].len);
            *p++ = CR; *p++ = LF;
        }
    }

    *p++ = '.'; *p++ = CR; *p = LF;


    p = rp_pnalloc(cf->pool, stls_only_size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = stls_only_size;
    conf->starttls_only_capability.data = p;

    p = rp_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        if (rp_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        p = rp_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = rp_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;

    return RP_CONF_OK;
}
