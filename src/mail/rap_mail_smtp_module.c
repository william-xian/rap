
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_smtp_module.h>


static void *rap_mail_smtp_create_srv_conf(rap_conf_t *cf);
static char *rap_mail_smtp_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);


static rap_conf_bitmask_t  rap_mail_smtp_auth_methods[] = {
    { rap_string("plain"), RAP_MAIL_AUTH_PLAIN_ENABLED },
    { rap_string("login"), RAP_MAIL_AUTH_LOGIN_ENABLED },
    { rap_string("cram-md5"), RAP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rap_string("external"), RAP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rap_string("none"), RAP_MAIL_AUTH_NONE_ENABLED },
    { rap_null_string, 0 }
};


static rap_str_t  rap_mail_smtp_auth_methods_names[] = {
    rap_string("PLAIN"),
    rap_string("LOGIN"),
    rap_null_string,  /* APOP */
    rap_string("CRAM-MD5"),
    rap_string("EXTERNAL"),
    rap_null_string   /* NONE */
};


static rap_mail_protocol_t  rap_mail_smtp_protocol = {
    rap_string("smtp"),
    { 25, 465, 587, 0 },
    RAP_MAIL_SMTP_PROTOCOL,

    rap_mail_smtp_init_session,
    rap_mail_smtp_init_protocol,
    rap_mail_smtp_parse_command,
    rap_mail_smtp_auth_state,

    rap_string("451 4.3.2 Internal server error" CRLF),
    rap_string("421 4.7.1 SSL certificate error" CRLF),
    rap_string("421 4.7.1 No required SSL certificate" CRLF)
};


static rap_command_t  rap_mail_smtp_commands[] = {

    { rap_string("smtp_client_buffer"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_smtp_srv_conf_t, client_buffer_size),
      NULL },

    { rap_string("smtp_greeting_delay"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_smtp_srv_conf_t, greeting_delay),
      NULL },

    { rap_string("smtp_capabilities"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_capabilities,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_smtp_srv_conf_t, capabilities),
      NULL },

    { rap_string("smtp_auth"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_smtp_srv_conf_t, auth_methods),
      &rap_mail_smtp_auth_methods },

      rap_null_command
};


static rap_mail_module_t  rap_mail_smtp_module_ctx = {
    &rap_mail_smtp_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_smtp_create_srv_conf,         /* create server configuration */
    rap_mail_smtp_merge_srv_conf           /* merge server configuration */
};


rap_module_t  rap_mail_smtp_module = {
    RAP_MODULE_V1,
    &rap_mail_smtp_module_ctx,             /* module context */
    rap_mail_smtp_commands,                /* module directives */
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
rap_mail_smtp_create_srv_conf(rap_conf_t *cf)
{
    rap_mail_smtp_srv_conf_t  *sscf;

    sscf = rap_pcalloc(cf->pool, sizeof(rap_mail_smtp_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->client_buffer_size = RAP_CONF_UNSET_SIZE;
    sscf->greeting_delay = RAP_CONF_UNSET_MSEC;

    if (rap_array_init(&sscf->capabilities, cf->pool, 4, sizeof(rap_str_t))
        != RAP_OK)
    {
        return NULL;
    }

    return sscf;
}


static char *
rap_mail_smtp_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_smtp_srv_conf_t *prev = parent;
    rap_mail_smtp_srv_conf_t *conf = child;

    u_char                    *p, *auth, *last;
    size_t                     size;
    rap_str_t                 *c;
    rap_uint_t                 i, m, auth_enabled;
    rap_mail_core_srv_conf_t  *cscf;

    rap_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_msec_value(conf->greeting_delay,
                              prev->greeting_delay, 0);

    rap_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (RAP_CONF_BITMASK_SET
                               |RAP_MAIL_AUTH_PLAIN_ENABLED
                               |RAP_MAIL_AUTH_LOGIN_ENABLED));


    cscf = rap_mail_conf_get_module_srv_conf(cf, rap_mail_core_module);

    size = sizeof("220  ESMTP ready" CRLF) - 1 + cscf->server_name.len;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->greeting.len = size;
    conf->greeting.data = p;

    *p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
    p = rap_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    rap_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);


    size = sizeof("250 " CRLF) - 1 + cscf->server_name.len;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->server_name.len = size;
    conf->server_name.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    p = rap_cpymem(p, cscf->server_name.data, cscf->server_name.len);
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

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + rap_mail_smtp_auth_methods_names[i].len;
            auth_enabled = 1;
        }
    }

    if (auth_enabled) {
        size += sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;
    }

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    last = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
    p = rap_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p++ = LF;

    for (i = 0; i < conf->capabilities.nelts; i++) {
        last = p;
        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
        p = rap_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    auth = p;

    if (auth_enabled) {
        last = p;

        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
        *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';

        for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
             m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
             m <<= 1, i++)
        {
            if (m & conf->auth_methods) {
                *p++ = ' ';
                p = rap_cpymem(p, rap_mail_smtp_auth_methods_names[i].data,
                               rap_mail_smtp_auth_methods_names[i].len);
            }
        }

        *p++ = CR; *p = LF;

    } else {
        last[3] = ' ';
    }

    size += sizeof("250 STARTTLS" CRLF) - 1;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rap_cpymem(p, conf->capability.data, conf->capability.len);

    rap_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    p = conf->starttls_capability.data
        + (last - conf->capability.data) + 3;
    *p = '-';

    size = (auth - conf->capability.data)
            + sizeof("250 STARTTLS" CRLF) - 1;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = rap_cpymem(p, conf->capability.data, auth - conf->capability.data);

    rap_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    if (last < auth) {
        p = conf->starttls_only_capability.data
            + (last - conf->capability.data) + 3;
        *p = '-';
    }

    return RAP_CONF_OK;
}
