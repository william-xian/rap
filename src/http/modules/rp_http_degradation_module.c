
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    size_t      sbrk_size;
} rp_http_degradation_main_conf_t;


typedef struct {
    rp_uint_t  degrade;
} rp_http_degradation_loc_conf_t;


static rp_conf_enum_t  rp_http_degrade[] = {
    { rp_string("204"), 204 },
    { rp_string("444"), 444 },
    { rp_null_string, 0 }
};


static void *rp_http_degradation_create_main_conf(rp_conf_t *cf);
static void *rp_http_degradation_create_loc_conf(rp_conf_t *cf);
static char *rp_http_degradation_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_degradation(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_degradation_init(rp_conf_t *cf);


static rp_command_t  rp_http_degradation_commands[] = {

    { rp_string("degradation"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_http_degradation,
      RP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rp_string("degrade"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_degradation_loc_conf_t, degrade),
      &rp_http_degrade },

      rp_null_command
};


static rp_http_module_t  rp_http_degradation_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_degradation_init,             /* postconfiguration */

    rp_http_degradation_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_degradation_create_loc_conf,  /* create location configuration */
    rp_http_degradation_merge_loc_conf    /* merge location configuration */
};


rp_module_t  rp_http_degradation_module = {
    RP_MODULE_V1,
    &rp_http_degradation_module_ctx,      /* module context */
    rp_http_degradation_commands,         /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_http_degradation_handler(rp_http_request_t *r)
{
    rp_http_degradation_loc_conf_t  *dlcf;

    dlcf = rp_http_get_module_loc_conf(r, rp_http_degradation_module);

    if (dlcf->degrade && rp_http_degraded(r)) {
        return dlcf->degrade;
    }

    return RP_DECLINED;
}


rp_uint_t
rp_http_degraded(rp_http_request_t *r)
{
    time_t                             now;
    rp_uint_t                         log;
    static size_t                      sbrk_size;
    static time_t                      sbrk_time;
    rp_http_degradation_main_conf_t  *dmcf;

    dmcf = rp_http_get_module_main_conf(r, rp_http_degradation_module);

    if (dmcf->sbrk_size) {

        log = 0;
        now = rp_time();

        /* lock mutex */

        if (now != sbrk_time) {

            /*
             * ELF/i386 is loaded at 0x08000000, 128M
             * ELF/amd64 is loaded at 0x00400000, 4M
             *
             * use a function address to subtract the loading address
             */

            sbrk_size = (size_t) sbrk(0) - ((uintptr_t) rp_palloc & ~0x3FFFFF);
            sbrk_time = now;
            log = 1;
        }

        /* unlock mutex */

        if (sbrk_size >= dmcf->sbrk_size) {
            if (log) {
                rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
                              "degradation sbrk:%uzM",
                              sbrk_size / (1024 * 1024));
            }

            return 1;
        }
    }

    return 0;
}


static void *
rp_http_degradation_create_main_conf(rp_conf_t *cf)
{
    rp_http_degradation_main_conf_t  *dmcf;

    dmcf = rp_pcalloc(cf->pool, sizeof(rp_http_degradation_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    return dmcf;
}


static void *
rp_http_degradation_create_loc_conf(rp_conf_t *cf)
{
    rp_http_degradation_loc_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_degradation_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->degrade = RP_CONF_UNSET_UINT;

    return conf;
}


static char *
rp_http_degradation_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_degradation_loc_conf_t  *prev = parent;
    rp_http_degradation_loc_conf_t  *conf = child;

    rp_conf_merge_uint_value(conf->degrade, prev->degrade, 0);

    return RP_CONF_OK;
}


static char *
rp_http_degradation(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_degradation_main_conf_t  *dmcf = conf;

    rp_str_t  *value, s;

    value = cf->args->elts;

    if (rp_strncmp(value[1].data, "sbrk=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        dmcf->sbrk_size = rp_parse_size(&s);
        if (dmcf->sbrk_size == (size_t) RP_ERROR) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid sbrk size \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        return RP_CONF_OK;
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[1]);

    return RP_CONF_ERROR;
}


static rp_int_t
rp_http_degradation_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_degradation_handler;

    return RP_OK;
}
