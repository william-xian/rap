
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>

/*
 * declare Profiler interface here because
 * <google/profiler.h> is C++ header file
 */

int ProfilerStart(u_char* fname);
void ProfilerStop(void);
void ProfilerRegisterThread(void);


static void *rap_google_perftools_create_conf(rap_cycle_t *cycle);
static rap_int_t rap_google_perftools_worker(rap_cycle_t *cycle);


typedef struct {
    rap_str_t  profiles;
} rap_google_perftools_conf_t;


static rap_command_t  rap_google_perftools_commands[] = {

    { rap_string("google_perftools_profiles"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      0,
      offsetof(rap_google_perftools_conf_t, profiles),
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_google_perftools_module_ctx = {
    rap_string("google_perftools"),
    rap_google_perftools_create_conf,
    NULL
};


rap_module_t  rap_google_perftools_module = {
    RAP_MODULE_V1,
    &rap_google_perftools_module_ctx,      /* module context */
    rap_google_perftools_commands,         /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rap_google_perftools_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static void *
rap_google_perftools_create_conf(rap_cycle_t *cycle)
{
    rap_google_perftools_conf_t  *gptcf;

    gptcf = rap_pcalloc(cycle->pool, sizeof(rap_google_perftools_conf_t));
    if (gptcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc()
     *
     *     gptcf->profiles = { 0, NULL };
     */

    return gptcf;
}


static rap_int_t
rap_google_perftools_worker(rap_cycle_t *cycle)
{
    u_char                       *profile;
    rap_google_perftools_conf_t  *gptcf;

    gptcf = (rap_google_perftools_conf_t *)
                rap_get_conf(cycle->conf_ctx, rap_google_perftools_module);

    if (gptcf->profiles.len == 0) {
        return RAP_OK;
    }

    profile = rap_alloc(gptcf->profiles.len + RAP_INT_T_LEN + 2, cycle->log);
    if (profile == NULL) {
        return RAP_OK;
    }

    if (getenv("CPUPROFILE")) {
        /* disable inherited Profiler enabled in master process */
        ProfilerStop();
    }

    rap_sprintf(profile, "%V.%d%Z", &gptcf->profiles, rap_pid);

    if (ProfilerStart(profile)) {
        /* start ITIMER_PROF timer */
        ProfilerRegisterThread();

    } else {
        rap_log_error(RAP_LOG_CRIT, cycle->log, rap_errno,
                      "ProfilerStart(%s) failed", profile);
    }

    rap_free(profile);

    return RAP_OK;
}


/* ProfilerStop() is called on Profiler destruction */
