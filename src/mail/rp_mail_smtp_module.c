
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_smtp_module.h>


static void *rp_mail_smtp_create_srv_conf(rp_conf_t *cf);
static char *rp_mail_smtp_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);


static rp_conf_bitmask_t  rp_mail_smtp_auth_methods[] = {
    { rp_string("plain"), RP_MAIL_AUTH_PLAIN_ENABLED },
    { rp_string("login"), RP_MAIL_AUTH_LOGIN_ENABLED },
    { rp_string("cram-md5"), RP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rp_string("external"), RP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rp_string("none"), RP_MAIL_AUTH_NONE_ENABLED },
    { rp_null_string, 0 }
};


static rp_str_t  rp_mail_smtp_auth_methods_names[] = {
    rp_string("PLAIN"),
    rp_string("LOGIN"),
    rp_null_string,  /* APOP */
    rp_string("CRAM-MD5"),
    rp_string("EXTERNAL"),
    rp_null_string   /* NONE */
};


static rp_mail_protocol_t  rp_mail_smtp_protocol = {
    rp_string("smtp"),
    { 25, 465, 587, 0 },
    RP_MAIL_SMTP_PROTOCOL,

    rp_mail_smtp_init_session,
    rp_mail_smtp_init_protocol,
    rp_mail_smtp_parse_command,
    rp_mail_smtp_auth_state,

    rp_string("451 4.3.2 Internal server error" CRLF),
    rp_string("421 4.7.1 SSL certificate error" CRLF),
    rp_string("421 4.7.1 No required SSL certificate" CRLF)
};


static rp_command_t  rp_mail_smtp_commands[] = {

    { rp_string("smtp_client_buffer"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_smtp_srv_conf_t, client_buffer_size),
      NULL },

    { rp_string("smtp_greeting_delay"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_smtp_srv_conf_t, greeting_delay),
      NULL },

    { rp_string("smtp_capabilities"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_capabilities,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_smtp_srv_conf_t, capabilities),
      NULL },

    { rp_string("smtp_auth"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_smtp_srv_conf_t, auth_methods),
      &rp_mail_smtp_auth_methods },

      rp_null_command
};


static rp_mail_module_t  rp_mail_smtp_module_ctx = {
    &rp_mail_smtp_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_smtp_create_srv_conf,         /* create server configuration */
    rp_mail_smtp_merge_srv_conf           /* merge server configuration */
};


rp_module_t  rp_mail_smtp_module = {
    RP_MODULE_V1,
    &rp_mail_smtp_module_ctx,             /* module context */
    rp_mail_smtp_commands,                /* module directives */
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
rp_mail_smtp_create_srv_conf(rp_conf_t *cf)
{
    rp_mail_smtp_srv_conf_t  *sscf;

    sscf = rp_pcalloc(cf->pool, sizeof(rp_mail_smtp_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->client_buffer_size = RP_CONF_UNSET_SIZE;
    sscf->greeting_delay = RP_CONF_UNSET_MSEC;

    if (rp_array_init(&sscf->capabilities, cf->pool, 4, sizeof(rp_str_t))
        != RP_OK)
    {
        return NULL;
    }

    return sscf;
}


static char *
rp_mail_smtp_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_smtp_srv_conf_t *prev = parent;
    rp_mail_smtp_srv_conf_t *conf = child;

    u_char                    *p, *auth, *last;
    size_t                     size;
    rp_str_t                 *c;
    rp_uint_t                 i, m, auth_enabled;
    rp_mail_core_srv_conf_t  *cscf;

    rp_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) rp_pagesize);

    rp_conf_merge_msec_value(conf->greeting_delay,
                              prev->greeting_delay, 0);

    rp_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (RP_CONF_BITMASK_SET
                               |RP_MAIL_AUTH_PLAIN_ENABLED
                               |RP_MAIL_AUTH_LOGIN_ENABLED));


    cscf = rp_mail_conf_get_module_srv_conf(cf, rp_mail_core_module);

    size = sizeof("220  ESMTP ready" CRLF) - 1 + cscf->server_name.len;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->greeting.len = size;
    conf->greeting.data = p;

    *p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
    p = rp_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    rp_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);


    size = sizeof("250 " CRLF) - 1 + cscf->server_name.len;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->server_name.len = size;
    conf->server_name.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    p = rp_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p = LF;


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    size = sizeof("250-") - 1 + cscf->server_name.len + sizeof(CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += sizeof("250 ") - 1 + c[i].len + sizeof(CRLF) - 1;
    }

    auth_enabled = 0;

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + rp_mail_smtp_auth_methods_names[i].len;
            auth_enabled = 1;
        }
    }

    if (auth_enabled) {
        size += sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;
    }

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    last = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
    p = rp_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p++ = LF;

    for (i = 0; i < conf->capabilities.nelts; i++) {
        last = p;
        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
        p = rp_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    auth = p;

    if (auth_enabled) {
        last = p;

        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
        *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';

        for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
             m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
             m <<= 1, i++)
        {
            if (m & conf->auth_methods) {
                *p++ = ' ';
                p = rp_cpymem(p, rp_mail_smtp_auth_methods_names[i].data,
                               rp_mail_smtp_auth_methods_names[i].len);
            }
        }

        *p++ = CR; *p = LF;

    } else {
        last[3] = ' ';
    }

    size += sizeof("250 STARTTLS" CRLF) - 1;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rp_cpymem(p, conf->capability.data, conf->capability.len);

    rp_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    p = conf->starttls_capability.data
        + (last - conf->capability.data) + 3;
    *p = '-';

    size = (auth - conf->capability.data)
            + sizeof("250 STARTTLS" CRLF) - 1;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = rp_cpymem(p, conf->capability.data, auth - conf->capability.data);

    rp_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    if (last < auth) {
        p = conf->starttls_only_capability.data
            + (last - conf->capability.data) + 3;
        *p = '-';
    }

    return RP_CONF_OK;
}
