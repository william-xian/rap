
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_imap_module.h>


static void *rap_mail_imap_create_srv_conf(rap_conf_t *cf);
static char *rap_mail_imap_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);


static rap_str_t  rap_mail_imap_default_capabilities[] = {
    rap_string("IMAP4"),
    rap_string("IMAP4rev1"),
    rap_string("UIDPLUS"),
    rap_null_string
};


static rap_conf_bitmask_t  rap_mail_imap_auth_methods[] = {
    { rap_string("plain"), RAP_MAIL_AUTH_PLAIN_ENABLED },
    { rap_string("login"), RAP_MAIL_AUTH_LOGIN_ENABLED },
    { rap_string("cram-md5"), RAP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rap_string("external"), RAP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rap_null_string, 0 }
};


static rap_str_t  rap_mail_imap_auth_methods_names[] = {
    rap_string("AUTH=PLAIN"),
    rap_string("AUTH=LOGIN"),
    rap_null_string,  /* APOP */
    rap_string("AUTH=CRAM-MD5"),
    rap_string("AUTH=EXTERNAL"),
    rap_null_string   /* NONE */
};


static rap_mail_protocol_t  rap_mail_imap_protocol = {
    rap_string("imap"),
    { 143, 993, 0, 0 },
    RAP_MAIL_IMAP_PROTOCOL,

    rap_mail_imap_init_session,
    rap_mail_imap_init_protocol,
    rap_mail_imap_parse_command,
    rap_mail_imap_auth_state,

    rap_string("* BAD internal server error" CRLF),
    rap_string("* BYE SSL certificate error" CRLF),
    rap_string("* BYE No required SSL certificate" CRLF)
};


static rap_command_t  rap_mail_imap_commands[] = {

    { rap_string("imap_client_buffer"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_imap_srv_conf_t, client_buffer_size),
      NULL },

    { rap_string("imap_capabilities"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_capabilities,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_imap_srv_conf_t, capabilities),
      NULL },

    { rap_string("imap_auth"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_imap_srv_conf_t, auth_methods),
      &rap_mail_imap_auth_methods },

      rap_null_command
};


static rap_mail_module_t  rap_mail_imap_module_ctx = {
    &rap_mail_imap_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_imap_create_srv_conf,         /* create server configuration */
    rap_mail_imap_merge_srv_conf           /* merge server configuration */
};


rap_module_t  rap_mail_imap_module = {
    RAP_MODULE_V1,
    &rap_mail_imap_module_ctx,             /* module context */
    rap_mail_imap_commands,                /* module directives */
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
rap_mail_imap_create_srv_conf(rap_conf_t *cf)
{
    rap_mail_imap_srv_conf_t  *iscf;

    iscf = rap_pcalloc(cf->pool, sizeof(rap_mail_imap_srv_conf_t));
    if (iscf == NULL) {
        return NULL;
    }

    iscf->client_buffer_size = RAP_CONF_UNSET_SIZE;

    if (rap_array_init(&iscf->capabilities, cf->pool, 4, sizeof(rap_str_t))
        != RAP_OK)
    {
        return NULL;
    }

    return iscf;
}


static char *
rap_mail_imap_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_imap_srv_conf_t *prev = parent;
    rap_mail_imap_srv_conf_t *conf = child;

    u_char      *p, *auth;
    size_t       size;
    rap_str_t   *c, *d;
    rap_uint_t   i, m;

    rap_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (RAP_CONF_BITMASK_SET
                               |RAP_MAIL_AUTH_PLAIN_ENABLED));


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = rap_mail_imap_default_capabilities; d->len; d++) {
            c = rap_array_push(&conf->capabilities);
            if (c == NULL) {
                return RAP_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("* CAPABILITY" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += 1 + c[i].len;
    }

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + rap_mail_imap_auth_methods_names[i].len;
        }
    }

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = rap_cpymem(p, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        *p++ = ' ';
        p = rap_cpymem(p, c[i].data, c[i].len);
    }

    auth = p;

    for (m = RAP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RAP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = rap_cpymem(p, rap_mail_imap_auth_methods_names[i].data,
                           rap_mail_imap_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p = LF;


    size += sizeof(" STARTTLS") - 1;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rap_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof(CRLF) - 1));
    p = rap_cpymem(p, " STARTTLS", sizeof(" STARTTLS") - 1);
    *p++ = CR; *p = LF;


    size = (auth - conf->capability.data) + sizeof(CRLF) - 1
            + sizeof(" STARTTLS LOGINDISABLED") - 1;

    p = rap_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RAP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = rap_cpymem(p, conf->capability.data,
                   auth - conf->capability.data);
    p = rap_cpymem(p, " STARTTLS LOGINDISABLED",
                   sizeof(" STARTTLS LOGINDISABLED") - 1);
    *p++ = CR; *p = LF;

    return RAP_CONF_OK;
}
