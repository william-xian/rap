
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    size_t      sbrk_size;
} rap_http_degradation_main_conf_t;


typedef struct {
    rap_uint_t  degrade;
} rap_http_degradation_loc_conf_t;


static rap_conf_enum_t  rap_http_degrade[] = {
    { rap_string("204"), 204 },
    { rap_string("444"), 444 },
    { rap_null_string, 0 }
};


static void *rap_http_degradation_create_main_conf(rap_conf_t *cf);
static void *rap_http_degradation_create_loc_conf(rap_conf_t *cf);
static char *rap_http_degradation_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_degradation(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_degradation_init(rap_conf_t *cf);


static rap_command_t  rap_http_degradation_commands[] = {

    { rap_string("degradation"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_http_degradation,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("degrade"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_degradation_loc_conf_t, degrade),
      &rap_http_degrade },

      rap_null_command
};


static rap_http_module_t  rap_http_degradation_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_degradation_init,             /* postconfiguration */

    rap_http_degradation_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_degradation_create_loc_conf,  /* create location configuration */
    rap_http_degradation_merge_loc_conf    /* merge location configuration */
};


rap_module_t  rap_http_degradation_module = {
    RAP_MODULE_V1,
    &rap_http_degradation_module_ctx,      /* module context */
    rap_http_degradation_commands,         /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_http_degradation_handler(rap_http_request_t *r)
{
    rap_http_degradation_loc_conf_t  *dlcf;

    dlcf = rap_http_get_module_loc_conf(r, rap_http_degradation_module);

    if (dlcf->degrade && rap_http_degraded(r)) {
        return dlcf->degrade;
    }

    return RAP_DECLINED;
}


rap_uint_t
rap_http_degraded(rap_http_request_t *r)
{
    time_t                             now;
    rap_uint_t                         log;
    static size_t                      sbrk_size;
    static time_t                      sbrk_time;
    rap_http_degradation_main_conf_t  *dmcf;

    dmcf = rap_http_get_module_main_conf(r, rap_http_degradation_module);

    if (dmcf->sbrk_size) {

        log = 0;
        now = rap_time();

        /* lock mutex */

        if (now != sbrk_time) {

            /*
             * ELF/i386 is loaded at 0x08000000, 128M
             * ELF/amd64 is loaded at 0x00400000, 4M
             *
             * use a function address to subtract the loading address
             */

            sbrk_size = (size_t) sbrk(0) - ((uintptr_t) rap_palloc & ~0x3FFFFF);
            sbrk_time = now;
            log = 1;
        }

        /* unlock mutex */

        if (sbrk_size >= dmcf->sbrk_size) {
            if (log) {
                rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
                              "degradation sbrk:%uzM",
                              sbrk_size / (1024 * 1024));
            }

            return 1;
        }
    }

    return 0;
}


static void *
rap_http_degradation_create_main_conf(rap_conf_t *cf)
{
    rap_http_degradation_main_conf_t  *dmcf;

    dmcf = rap_pcalloc(cf->pool, sizeof(rap_http_degradation_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    return dmcf;
}


static void *
rap_http_degradation_create_loc_conf(rap_conf_t *cf)
{
    rap_http_degradation_loc_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_degradation_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->degrade = RAP_CONF_UNSET_UINT;

    return conf;
}


static char *
rap_http_degradation_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_degradation_loc_conf_t  *prev = parent;
    rap_http_degradation_loc_conf_t  *conf = child;

    rap_conf_merge_uint_value(conf->degrade, prev->degrade, 0);

    return RAP_CONF_OK;
}


static char *
rap_http_degradation(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_degradation_main_conf_t  *dmcf = conf;

    rap_str_t  *value, s;

    value = cf->args->elts;

    if (rap_strncmp(value[1].data, "sbrk=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        dmcf->sbrk_size = rap_parse_size(&s);
        if (dmcf->sbrk_size == (size_t) RAP_ERROR) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid sbrk size \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        return RAP_CONF_OK;
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[1]);

    return RAP_CONF_ERROR;
}


static rap_int_t
rap_http_degradation_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_degradation_handler;

    return RAP_OK;
}
