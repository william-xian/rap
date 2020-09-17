
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>

/*
 * declare Profiler interface here because
 * <google/profiler.h> is C++ header file
 */

int ProfilerStart(u_char* fname);
void ProfilerStop(void);
void ProfilerRegisterThread(void);


static void *rp_google_perftools_create_conf(rp_cycle_t *cycle);
static rp_int_t rp_google_perftools_worker(rp_cycle_t *cycle);


typedef struct {
    rp_str_t  profiles;
} rp_google_perftools_conf_t;


static rp_command_t  rp_google_perftools_commands[] = {

    { rp_string("google_perftools_profiles"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      0,
      offsetof(rp_google_perftools_conf_t, profiles),
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_google_perftools_module_ctx = {
    rp_string("google_perftools"),
    rp_google_perftools_create_conf,
    NULL
};


rp_module_t  rp_google_perftools_module = {
    RP_MODULE_V1,
    &rp_google_perftools_module_ctx,      /* module context */
    rp_google_perftools_commands,         /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rp_google_perftools_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static void *
rp_google_perftools_create_conf(rp_cycle_t *cycle)
{
    rp_google_perftools_conf_t  *gptcf;

    gptcf = rp_pcalloc(cycle->pool, sizeof(rp_google_perftools_conf_t));
    if (gptcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc()
     *
     *     gptcf->profiles = { 0, NULL };
     */

    return gptcf;
}


static rp_int_t
rp_google_perftools_worker(rp_cycle_t *cycle)
{
    u_char                       *profile;
    rp_google_perftools_conf_t  *gptcf;

    gptcf = (rp_google_perftools_conf_t *)
                rp_get_conf(cycle->conf_ctx, rp_google_perftools_module);

    if (gptcf->profiles.len == 0) {
        return RP_OK;
    }

    profile = rp_alloc(gptcf->profiles.len + RP_INT_T_LEN + 2, cycle->log);
    if (profile == NULL) {
        return RP_OK;
    }

    if (getenv("CPUPROFILE")) {
        /* disable inherited Profiler enabled in master process */
        ProfilerStop();
    }

    rp_sprintf(profile, "%V.%d%Z", &gptcf->profiles, rp_pid);

    if (ProfilerStart(profile)) {
        /* start ITIMER_PROF timer */
        ProfilerRegisterThread();

    } else {
        rp_log_error(RP_LOG_CRIT, cycle->log, rp_errno,
                      "ProfilerStart(%s) failed", profile);
    }

    rp_free(profile);

    return RP_OK;
}


/* ProfilerStop() is called on Profiler destruction */
