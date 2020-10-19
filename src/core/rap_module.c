
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#define RAP_MAX_DYNAMIC_MODULES  128


static rap_uint_t rap_module_index(rap_cycle_t *cycle);
static rap_uint_t rap_module_ctx_index(rap_cycle_t *cycle, rap_uint_t type,
    rap_uint_t index);


rap_uint_t         rap_max_module;
static rap_uint_t  rap_modules_n;


rap_int_t
rap_preinit_modules(void)
{
    rap_uint_t  i;

    for (i = 0; rap_modules[i]; i++) {
        rap_modules[i]->index = i;
        rap_modules[i]->name = rap_module_names[i];
    }

    rap_modules_n = i;
    rap_max_module = rap_modules_n + RAP_MAX_DYNAMIC_MODULES;

    return RAP_OK;
}


rap_int_t
rap_cycle_modules(rap_cycle_t *cycle)
{
    /*
     * create a list of modules to be used for this cycle,
     * copy static modules to it
     */

    cycle->modules = rap_pcalloc(cycle->pool, (rap_max_module + 1)
                                              * sizeof(rap_module_t *));
    if (cycle->modules == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(cycle->modules, rap_modules,
               rap_modules_n * sizeof(rap_module_t *));

    cycle->modules_n = rap_modules_n;

    return RAP_OK;
}


rap_int_t
rap_init_modules(rap_cycle_t *cycle)
{
    rap_uint_t  i;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_module) {
            if (cycle->modules[i]->init_module(cycle) != RAP_OK) {
                return RAP_ERROR;
            }
        }
    }

    return RAP_OK;
}


rap_int_t
rap_count_modules(rap_cycle_t *cycle, rap_uint_t type)
{
    rap_uint_t     i, next, max;
    rap_module_t  *module;

    next = 0;
    max = 0;

    /* count appropriate modules, set up their indices */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->type != type) {
            continue;
        }

        if (module->ctx_index != RAP_MODULE_UNSET_INDEX) {

            /* if ctx_index was assigned, preserve it */

            if (module->ctx_index > max) {
                max = module->ctx_index;
            }

            if (module->ctx_index == next) {
                next++;
            }

            continue;
        }

        /* search for some free index */

        module->ctx_index = rap_module_ctx_index(cycle, type, next);

        if (module->ctx_index > max) {
            max = module->ctx_index;
        }

        next = module->ctx_index + 1;
    }

    /*
     * make sure the number returned is big enough for previous
     * cycle as well, else there will be problems if the number
     * will be stored in a global variable (as it's used to be)
     * and we'll have to roll back to the previous cycle
     */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index > max) {
                max = module->ctx_index;
            }
        }
    }

    /* prevent loading of additional modules */

    cycle->modules_used = 1;

    return max + 1;
}


rap_int_t
rap_add_module(rap_conf_t *cf, rap_str_t *file, rap_module_t *module,
    char **order)
{
    void               *rv;
    rap_uint_t          i, m, before;
    rap_core_module_t  *core_module;

    if (cf->cycle->modules_n >= rap_max_module) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "too many modules loaded");
        return RAP_ERROR;
    }

    if (module->version != rap_version) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "module \"%V\" version %ui instead of %ui",
                           file, module->version, (rap_uint_t) rap_version);
        return RAP_ERROR;
    }

    if (rap_strcmp(module->signature, RAP_MODULE_SIGNATURE) != 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "module \"%V\" is not binary compatible",
                           file);
        return RAP_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (rap_strcmp(cf->cycle->modules[m]->name, module->name) == 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "module \"%s\" is already loaded",
                               module->name);
            return RAP_ERROR;
        }
    }

    /*
     * if the module wasn't previously loaded, assign an index
     */

    if (module->index == RAP_MODULE_UNSET_INDEX) {
        module->index = rap_module_index(cf->cycle);

        if (module->index >= rap_max_module) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "too many modules loaded");
            return RAP_ERROR;
        }
    }

    /*
     * put the module into the cycle->modules array
     */

    before = cf->cycle->modules_n;

    if (order) {
        for (i = 0; order[i]; i++) {
            if (rap_strcmp(order[i], module->name) == 0) {
                i++;
                break;
            }
        }

        for ( /* void */ ; order[i]; i++) {

#if 0
            rap_log_debug2(RAP_LOG_DEBUG_CORE, cf->log, 0,
                           "module: %s before %s",
                           module->name, order[i]);
#endif

            for (m = 0; m < before; m++) {
                if (rap_strcmp(cf->cycle->modules[m]->name, order[i]) == 0) {

                    rap_log_debug3(RAP_LOG_DEBUG_CORE, cf->log, 0,
                                   "module: %s before %s:%i",
                                   module->name, order[i], m);

                    before = m;
                    break;
                }
            }
        }
    }

    /* put the module before modules[before] */

    if (before != cf->cycle->modules_n) {
        rap_memmove(&cf->cycle->modules[before + 1],
                    &cf->cycle->modules[before],
                    (cf->cycle->modules_n - before) * sizeof(rap_module_t *));
    }

    cf->cycle->modules[before] = module;
    cf->cycle->modules_n++;

    if (module->type == RAP_CORE_MODULE) {

        /*
         * we are smart enough to initialize core modules;
         * other modules are expected to be loaded before
         * initialization - e.g., http modules must be loaded
         * before http{} block
         */

        core_module = module->ctx;

        if (core_module->create_conf) {
            rv = core_module->create_conf(cf->cycle);
            if (rv == NULL) {
                return RAP_ERROR;
            }

            cf->cycle->conf_ctx[module->index] = rv;
        }
    }

    return RAP_OK;
}


static rap_uint_t
rap_module_index(rap_cycle_t *cycle)
{
    rap_uint_t     i, index;
    rap_module_t  *module;

    index = 0;

again:

    /* find an unused index */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->index == index) {
            index++;
            goto again;
        }
    }

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->index == index) {
                index++;
                goto again;
            }
        }
    }

    return index;
}


static rap_uint_t
rap_module_ctx_index(rap_cycle_t *cycle, rap_uint_t type, rap_uint_t index)
{
    rap_uint_t     i;
    rap_module_t  *module;

again:

    /* find an unused ctx_index */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->type != type) {
            continue;
        }

        if (module->ctx_index == index) {
            index++;
            goto again;
        }
    }

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index == index) {
                index++;
                goto again;
            }
        }
    }

    return index;
}
