
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#define RP_MAX_DYNAMIC_MODULES  128


static rp_uint_t rp_module_index(rp_cycle_t *cycle);
static rp_uint_t rp_module_ctx_index(rp_cycle_t *cycle, rp_uint_t type,
    rp_uint_t index);


rp_uint_t         rp_max_module;
static rp_uint_t  rp_modules_n;


rp_int_t
rp_preinit_modules(void)
{
    rp_uint_t  i;

    for (i = 0; rp_modules[i]; i++) {
        rp_modules[i]->index = i;
        rp_modules[i]->name = rp_module_names[i];
    }

    rp_modules_n = i;
    rp_max_module = rp_modules_n + RP_MAX_DYNAMIC_MODULES;

    return RP_OK;
}


rp_int_t
rp_cycle_modules(rp_cycle_t *cycle)
{
    /*
     * create a list of modules to be used for this cycle,
     * copy static modules to it
     */

    cycle->modules = rp_pcalloc(cycle->pool, (rp_max_module + 1)
                                              * sizeof(rp_module_t *));
    if (cycle->modules == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(cycle->modules, rp_modules,
               rp_modules_n * sizeof(rp_module_t *));

    cycle->modules_n = rp_modules_n;

    return RP_OK;
}


rp_int_t
rp_init_modules(rp_cycle_t *cycle)
{
    rp_uint_t  i;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_module) {
            if (cycle->modules[i]->init_module(cycle) != RP_OK) {
                return RP_ERROR;
            }
        }
    }

    return RP_OK;
}


rp_int_t
rp_count_modules(rp_cycle_t *cycle, rp_uint_t type)
{
    rp_uint_t     i, next, max;
    rp_module_t  *module;

    next = 0;
    max = 0;

    /* count appropriate modules, set up their indices */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->type != type) {
            continue;
        }

        if (module->ctx_index != RP_MODULE_UNSET_INDEX) {

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

        module->ctx_index = rp_module_ctx_index(cycle, type, next);

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


rp_int_t
rp_add_module(rp_conf_t *cf, rp_str_t *file, rp_module_t *module,
    char **order)
{
    void               *rv;
    rp_uint_t          i, m, before;
    rp_core_module_t  *core_module;

    if (cf->cycle->modules_n >= rp_max_module) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "too many modules loaded");
        return RP_ERROR;
    }

    if (module->version != rap_version) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "module \"%V\" version %ui instead of %ui",
                           file, module->version, (rp_uint_t) rap_version);
        return RP_ERROR;
    }

    if (rp_strcmp(module->signature, RP_MODULE_SIGNATURE) != 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "module \"%V\" is not binary compatible",
                           file);
        return RP_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (rp_strcmp(cf->cycle->modules[m]->name, module->name) == 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "module \"%s\" is already loaded",
                               module->name);
            return RP_ERROR;
        }
    }

    /*
     * if the module wasn't previously loaded, assign an index
     */

    if (module->index == RP_MODULE_UNSET_INDEX) {
        module->index = rp_module_index(cf->cycle);

        if (module->index >= rp_max_module) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "too many modules loaded");
            return RP_ERROR;
        }
    }

    /*
     * put the module into the cycle->modules array
     */

    before = cf->cycle->modules_n;

    if (order) {
        for (i = 0; order[i]; i++) {
            if (rp_strcmp(order[i], module->name) == 0) {
                i++;
                break;
            }
        }

        for ( /* void */ ; order[i]; i++) {

#if 0
            rp_log_debug2(RP_LOG_DEBUG_CORE, cf->log, 0,
                           "module: %s before %s",
                           module->name, order[i]);
#endif

            for (m = 0; m < before; m++) {
                if (rp_strcmp(cf->cycle->modules[m]->name, order[i]) == 0) {

                    rp_log_debug3(RP_LOG_DEBUG_CORE, cf->log, 0,
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
        rp_memmove(&cf->cycle->modules[before + 1],
                    &cf->cycle->modules[before],
                    (cf->cycle->modules_n - before) * sizeof(rp_module_t *));
    }

    cf->cycle->modules[before] = module;
    cf->cycle->modules_n++;

    if (module->type == RP_CORE_MODULE) {

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
                return RP_ERROR;
            }

            cf->cycle->conf_ctx[module->index] = rv;
        }
    }

    return RP_OK;
}


static rp_uint_t
rp_module_index(rp_cycle_t *cycle)
{
    rp_uint_t     i, index;
    rp_module_t  *module;

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


static rp_uint_t
rp_module_ctx_index(rp_cycle_t *cycle, rp_uint_t type, rp_uint_t index)
{
    rp_uint_t     i;
    rp_module_t  *module;

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
