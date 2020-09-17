
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_imap_module.h>


static void *rp_mail_imap_create_srv_conf(rp_conf_t *cf);
static char *rp_mail_imap_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);


static rp_str_t  rp_mail_imap_default_capabilities[] = {
    rp_string("IMAP4"),
    rp_string("IMAP4rev1"),
    rp_string("UIDPLUS"),
    rp_null_string
};


static rp_conf_bitmask_t  rp_mail_imap_auth_methods[] = {
    { rp_string("plain"), RP_MAIL_AUTH_PLAIN_ENABLED },
    { rp_string("login"), RP_MAIL_AUTH_LOGIN_ENABLED },
    { rp_string("cram-md5"), RP_MAIL_AUTH_CRAM_MD5_ENABLED },
    { rp_string("external"), RP_MAIL_AUTH_EXTERNAL_ENABLED },
    { rp_null_string, 0 }
};


static rp_str_t  rp_mail_imap_auth_methods_names[] = {
    rp_string("AUTH=PLAIN"),
    rp_string("AUTH=LOGIN"),
    rp_null_string,  /* APOP */
    rp_string("AUTH=CRAM-MD5"),
    rp_string("AUTH=EXTERNAL"),
    rp_null_string   /* NONE */
};


static rp_mail_protocol_t  rp_mail_imap_protocol = {
    rp_string("imap"),
    { 143, 993, 0, 0 },
    RP_MAIL_IMAP_PROTOCOL,

    rp_mail_imap_init_session,
    rp_mail_imap_init_protocol,
    rp_mail_imap_parse_command,
    rp_mail_imap_auth_state,

    rp_string("* BAD internal server error" CRLF),
    rp_string("* BYE SSL certificate error" CRLF),
    rp_string("* BYE No required SSL certificate" CRLF)
};


static rp_command_t  rp_mail_imap_commands[] = {

    { rp_string("imap_client_buffer"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_imap_srv_conf_t, client_buffer_size),
      NULL },

    { rp_string("imap_capabilities"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_capabilities,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_imap_srv_conf_t, capabilities),
      NULL },

    { rp_string("imap_auth"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_imap_srv_conf_t, auth_methods),
      &rp_mail_imap_auth_methods },

      rp_null_command
};


static rp_mail_module_t  rp_mail_imap_module_ctx = {
    &rp_mail_imap_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_imap_create_srv_conf,         /* create server configuration */
    rp_mail_imap_merge_srv_conf           /* merge server configuration */
};


rp_module_t  rp_mail_imap_module = {
    RP_MODULE_V1,
    &rp_mail_imap_module_ctx,             /* module context */
    rp_mail_imap_commands,                /* module directives */
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
rp_mail_imap_create_srv_conf(rp_conf_t *cf)
{
    rp_mail_imap_srv_conf_t  *iscf;

    iscf = rp_pcalloc(cf->pool, sizeof(rp_mail_imap_srv_conf_t));
    if (iscf == NULL) {
        return NULL;
    }

    iscf->client_buffer_size = RP_CONF_UNSET_SIZE;

    if (rp_array_init(&iscf->capabilities, cf->pool, 4, sizeof(rp_str_t))
        != RP_OK)
    {
        return NULL;
    }

    return iscf;
}


static char *
rp_mail_imap_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_imap_srv_conf_t *prev = parent;
    rp_mail_imap_srv_conf_t *conf = child;

    u_char      *p, *auth;
    size_t       size;
    rp_str_t   *c, *d;
    rp_uint_t   i, m;

    rp_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) rp_pagesize);

    rp_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (RP_CONF_BITMASK_SET
                               |RP_MAIL_AUTH_PLAIN_ENABLED));


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = rp_mail_imap_default_capabilities; d->len; d++) {
            c = rp_array_push(&conf->capabilities);
            if (c == NULL) {
                return RP_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("* CAPABILITY" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += 1 + c[i].len;
    }

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + rp_mail_imap_auth_methods_names[i].len;
        }
    }

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = rp_cpymem(p, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        *p++ = ' ';
        p = rp_cpymem(p, c[i].data, c[i].len);
    }

    auth = p;

    for (m = RP_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= RP_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = rp_cpymem(p, rp_mail_imap_auth_methods_names[i].data,
                           rp_mail_imap_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p = LF;


    size += sizeof(" STARTTLS") - 1;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = rp_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof(CRLF) - 1));
    p = rp_cpymem(p, " STARTTLS", sizeof(" STARTTLS") - 1);
    *p++ = CR; *p = LF;


    size = (auth - conf->capability.data) + sizeof(CRLF) - 1
            + sizeof(" STARTTLS LOGINDISABLED") - 1;

    p = rp_pnalloc(cf->pool, size);
    if (p == NULL) {
        return RP_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = rp_cpymem(p, conf->capability.data,
                   auth - conf->capability.data);
    p = rp_cpymem(p, " STARTTLS LOGINDISABLED",
                   sizeof(" STARTTLS LOGINDISABLED") - 1);
    *p++ = CR; *p = LF;

    return RP_CONF_OK;
}
