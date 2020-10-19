
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static void rap_destroy_cycle_pools(rap_conf_t *conf);
static rap_int_t rap_init_zone_pool(rap_cycle_t *cycle,
    rap_shm_zone_t *shm_zone);
static rap_int_t rap_test_lockfile(u_char *file, rap_log_t *log);
static void rap_clean_old_cycles(rap_event_t *ev);
static void rap_shutdown_timer_handler(rap_event_t *ev);


volatile rap_cycle_t  *rap_cycle;
rap_array_t            rap_old_cycles;

static rap_pool_t     *rap_temp_pool;
static rap_event_t     rap_cleaner_event;
static rap_event_t     rap_shutdown_event;

rap_uint_t             rap_test_config;
rap_uint_t             rap_dump_config;
rap_uint_t             rap_quiet_mode;


/* STUB NAME */
static rap_connection_t  dumb;
/* STUB */


rap_cycle_t *
rap_init_cycle(rap_cycle_t *old_cycle)
{
    void                *rv;
    char               **senv;
    rap_uint_t           i, n;
    rap_log_t           *log;
    rap_time_t          *tp;
    rap_conf_t           conf;
    rap_pool_t          *pool;
    rap_cycle_t         *cycle, **old;
    rap_shm_zone_t      *shm_zone, *oshm_zone;
    rap_list_part_t     *part, *opart;
    rap_open_file_t     *file;
    rap_listening_t     *ls, *nls;
    rap_core_conf_t     *ccf, *old_ccf;
    rap_core_module_t   *module;
    char                 hostname[RAP_MAXHOSTNAMELEN];

    rap_timezone_update();

    /* force localtime update with a new timezone */

    tp = rap_timeofday();
    tp->sec = 0;

    rap_time_update();


    log = old_cycle->log;

    pool = rap_create_pool(RAP_CYCLE_POOL_SIZE, log);
    if (pool == NULL) {
        return NULL;
    }
    pool->log = log;

    cycle = rap_pcalloc(pool, sizeof(rap_cycle_t));
    if (cycle == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    cycle->pool = pool;
    cycle->log = log;
    cycle->old_cycle = old_cycle;

    cycle->conf_prefix.len = old_cycle->conf_prefix.len;
    cycle->conf_prefix.data = rap_pstrdup(pool, &old_cycle->conf_prefix);
    if (cycle->conf_prefix.data == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    cycle->prefix.len = old_cycle->prefix.len;
    cycle->prefix.data = rap_pstrdup(pool, &old_cycle->prefix);
    if (cycle->prefix.data == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    cycle->conf_file.len = old_cycle->conf_file.len;
    cycle->conf_file.data = rap_pnalloc(pool, old_cycle->conf_file.len + 1);
    if (cycle->conf_file.data == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }
    rap_cpystrn(cycle->conf_file.data, old_cycle->conf_file.data,
                old_cycle->conf_file.len + 1);

    cycle->conf_param.len = old_cycle->conf_param.len;
    cycle->conf_param.data = rap_pstrdup(pool, &old_cycle->conf_param);
    if (cycle->conf_param.data == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }


    n = old_cycle->paths.nelts ? old_cycle->paths.nelts : 10;

    if (rap_array_init(&cycle->paths, pool, n, sizeof(rap_path_t *))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return NULL;
    }

    rap_memzero(cycle->paths.elts, n * sizeof(rap_path_t *));


    if (rap_array_init(&cycle->config_dump, pool, 1, sizeof(rap_conf_dump_t))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return NULL;
    }

    rap_rbtree_init(&cycle->config_dump_rbtree, &cycle->config_dump_sentinel,
                    rap_str_rbtree_insert_value);

    if (old_cycle->open_files.part.nelts) {
        n = old_cycle->open_files.part.nelts;
        for (part = old_cycle->open_files.part.next; part; part = part->next) {
            n += part->nelts;
        }

    } else {
        n = 20;
    }

    if (rap_list_init(&cycle->open_files, pool, n, sizeof(rap_open_file_t))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return NULL;
    }


    if (old_cycle->shared_memory.part.nelts) {
        n = old_cycle->shared_memory.part.nelts;
        for (part = old_cycle->shared_memory.part.next; part; part = part->next)
        {
            n += part->nelts;
        }

    } else {
        n = 1;
    }

    if (rap_list_init(&cycle->shared_memory, pool, n, sizeof(rap_shm_zone_t))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return NULL;
    }

    n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;

    if (rap_array_init(&cycle->listening, pool, n, sizeof(rap_listening_t))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return NULL;
    }

    rap_memzero(cycle->listening.elts, n * sizeof(rap_listening_t));


    rap_queue_init(&cycle->reusable_connections_queue);


    cycle->conf_ctx = rap_pcalloc(pool, rap_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }


    if (gethostname(hostname, RAP_MAXHOSTNAMELEN) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "gethostname() failed");
        rap_destroy_pool(pool);
        return NULL;
    }

    /* on Linux gethostname() silently truncates name that does not fit */

    hostname[RAP_MAXHOSTNAMELEN - 1] = '\0';
    cycle->hostname.len = rap_strlen(hostname);

    cycle->hostname.data = rap_pnalloc(pool, cycle->hostname.len);
    if (cycle->hostname.data == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    rap_strlow(cycle->hostname.data, (u_char *) hostname, cycle->hostname.len);


    if (rap_cycle_modules(cycle) != RAP_OK) {
        rap_destroy_pool(pool);
        return NULL;
    }


    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != RAP_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                rap_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[cycle->modules[i]->index] = rv;
        }
    }


    senv = environ;


    rap_memzero(&conf, sizeof(rap_conf_t));
    /* STUB: init array ? */
    conf.args = rap_array_create(pool, 10, sizeof(rap_str_t));
    if (conf.args == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    conf.temp_pool = rap_create_pool(RAP_CYCLE_POOL_SIZE, log);
    if (conf.temp_pool == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }


    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = RAP_CORE_MODULE;
    conf.cmd_type = RAP_MAIN_CONF;

#if 0
    log->log_level = RAP_LOG_DEBUG_ALL;
#endif

    if (rap_conf_param(&conf) != RAP_CONF_OK) {
        environ = senv;
        rap_destroy_cycle_pools(&conf);
        return NULL;
    }

    if (rap_conf_parse(&conf, &cycle->conf_file) != RAP_CONF_OK) {
        environ = senv;
        rap_destroy_cycle_pools(&conf);
        return NULL;
    }

    if (rap_test_config && !rap_quiet_mode) {
        rap_log_stderr(0, "the configuration file %s syntax is ok",
                       cycle->conf_file.data);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != RAP_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle,
                                  cycle->conf_ctx[cycle->modules[i]->index])
                == RAP_CONF_ERROR)
            {
                environ = senv;
                rap_destroy_cycle_pools(&conf);
                return NULL;
            }
        }
    }

    if (rap_process == RAP_PROCESS_SIGNALLER) {
        return cycle;
    }

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (rap_test_config) {

        if (rap_create_pidfile(&ccf->pid, log) != RAP_OK) {
            goto failed;
        }

    } else if (!rap_is_init_cycle(old_cycle)) {

        /*
         * we do not create the pid file in the first rap_init_cycle() call
         * because we need to write the demonized process pid
         */

        old_ccf = (rap_core_conf_t *) rap_get_conf(old_cycle->conf_ctx,
                                                   rap_core_module);
        if (ccf->pid.len != old_ccf->pid.len
            || rap_strcmp(ccf->pid.data, old_ccf->pid.data) != 0)
        {
            /* new pid file name */

            if (rap_create_pidfile(&ccf->pid, log) != RAP_OK) {
                goto failed;
            }

            rap_delete_pidfile(old_cycle);
        }
    }


    if (rap_test_lockfile(cycle->lock_file.data, log) != RAP_OK) {
        goto failed;
    }


    if (rap_create_paths(cycle, ccf->user) != RAP_OK) {
        goto failed;
    }


    if (rap_log_open_default(cycle) != RAP_OK) {
        goto failed;
    }

    /* open the new files */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].name.len == 0) {
            continue;
        }

        file[i].fd = rap_open_file(file[i].name.data,
                                   RAP_FILE_APPEND,
                                   RAP_FILE_CREATE_OR_OPEN,
                                   RAP_FILE_DEFAULT_ACCESS);

        rap_log_debug3(RAP_LOG_DEBUG_CORE, log, 0,
                       "log: %p %d \"%s\"",
                       &file[i], file[i].fd, file[i].name.data);

        if (file[i].fd == RAP_INVALID_FILE) {
            rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                          rap_open_file_n " \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }

#if !(RAP_WIN32)
        if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
            rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }
#endif
    }

    cycle->log = &cycle->new_log;
    pool->log = &cycle->new_log;


    /* create shared memory */

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (shm_zone[i].shm.size == 0) {
            rap_log_error(RAP_LOG_EMERG, log, 0,
                          "zero size shared memory zone \"%V\"",
                          &shm_zone[i].shm.name);
            goto failed;
        }

        shm_zone[i].shm.log = cycle->log;

        opart = &old_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                n = 0;
            }

            if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                continue;
            }

            if (rap_strncmp(shm_zone[i].shm.name.data,
                            oshm_zone[n].shm.name.data,
                            shm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag
                && shm_zone[i].shm.size == oshm_zone[n].shm.size
                && !shm_zone[i].noreuse)
            {
                shm_zone[i].shm.addr = oshm_zone[n].shm.addr;
#if (RAP_WIN32)
                shm_zone[i].shm.handle = oshm_zone[n].shm.handle;
#endif

                if (shm_zone[i].init(&shm_zone[i], oshm_zone[n].data)
                    != RAP_OK)
                {
                    goto failed;
                }

                goto shm_zone_found;
            }

            break;
        }

        if (rap_shm_alloc(&shm_zone[i].shm) != RAP_OK) {
            goto failed;
        }

        if (rap_init_zone_pool(cycle, &shm_zone[i]) != RAP_OK) {
            goto failed;
        }

        if (shm_zone[i].init(&shm_zone[i], NULL) != RAP_OK) {
            goto failed;
        }

    shm_zone_found:

        continue;
    }


    /* handle the listening sockets */

    if (old_cycle->listening.nelts) {
        ls = old_cycle->listening.elts;
        for (i = 0; i < old_cycle->listening.nelts; i++) {
            ls[i].remain = 0;
        }

        nls = cycle->listening.elts;
        for (n = 0; n < cycle->listening.nelts; n++) {

            for (i = 0; i < old_cycle->listening.nelts; i++) {
                if (ls[i].ignore) {
                    continue;
                }

                if (ls[i].remain) {
                    continue;
                }

                if (ls[i].type != nls[n].type) {
                    continue;
                }

                if (rap_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
                                     ls[i].sockaddr, ls[i].socklen, 1)
                    == RAP_OK)
                {
                    nls[n].fd = ls[i].fd;
                    nls[n].previous = &ls[i];
                    ls[i].remain = 1;

                    if (ls[i].backlog != nls[n].backlog) {
                        nls[n].listen = 1;
                    }

#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                    /*
                     * FreeBSD, except the most recent versions,
                     * could not remove accept filter
                     */
                    nls[n].deferred_accept = ls[i].deferred_accept;

                    if (ls[i].accept_filter && nls[n].accept_filter) {
                        if (rap_strcmp(ls[i].accept_filter,
                                       nls[n].accept_filter)
                            != 0)
                        {
                            nls[n].delete_deferred = 1;
                            nls[n].add_deferred = 1;
                        }

                    } else if (ls[i].accept_filter) {
                        nls[n].delete_deferred = 1;

                    } else if (nls[n].accept_filter) {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                    if (ls[i].deferred_accept && !nls[n].deferred_accept) {
                        nls[n].delete_deferred = 1;

                    } else if (ls[i].deferred_accept != nls[n].deferred_accept)
                    {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (RAP_HAVE_REUSEPORT)
                    if (nls[n].reuseport && !ls[i].reuseport) {
                        nls[n].add_reuseport = 1;
                    }
#endif

                    break;
                }
            }

            if (nls[n].fd == (rap_socket_t) -1) {
                nls[n].open = 1;
#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                if (nls[n].accept_filter) {
                    nls[n].add_deferred = 1;
                }
#endif
#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
                if (nls[n].deferred_accept) {
                    nls[n].add_deferred = 1;
                }
#endif
            }
        }

    } else {
        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            ls[i].open = 1;
#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            if (ls[i].accept_filter) {
                ls[i].add_deferred = 1;
            }
#endif
#if (RAP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            if (ls[i].deferred_accept) {
                ls[i].add_deferred = 1;
            }
#endif
        }
    }

    if (rap_open_listening_sockets(cycle) != RAP_OK) {
        goto failed;
    }

    if (!rap_test_config) {
        rap_configure_listening_sockets(cycle);
    }


    /* commit the new cycle configuration */

    if (!rap_use_stderr) {
        (void) rap_log_redirect_stderr(cycle);
    }

    pool->log = cycle->log;

    if (rap_init_modules(cycle) != RAP_OK) {
        /* fatal */
        exit(1);
    }


    /* close and delete stuff that lefts from an old cycle */

    /* free the unnecessary shared memory */

    opart = &old_cycle->shared_memory.part;
    oshm_zone = opart->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= opart->nelts) {
            if (opart->next == NULL) {
                goto old_shm_zone_done;
            }
            opart = opart->next;
            oshm_zone = opart->elts;
            i = 0;
        }

        part = &cycle->shared_memory.part;
        shm_zone = part->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                shm_zone = part->elts;
                n = 0;
            }

            if (oshm_zone[i].shm.name.len != shm_zone[n].shm.name.len) {
                continue;
            }

            if (rap_strncmp(oshm_zone[i].shm.name.data,
                            shm_zone[n].shm.name.data,
                            oshm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (oshm_zone[i].tag == shm_zone[n].tag
                && oshm_zone[i].shm.size == shm_zone[n].shm.size
                && !oshm_zone[i].noreuse)
            {
                goto live_shm_zone;
            }

            break;
        }

        rap_shm_free(&oshm_zone[i].shm);

    live_shm_zone:

        continue;
    }

old_shm_zone_done:


    /* close the unnecessary listening sockets */

    ls = old_cycle->listening.elts;
    for (i = 0; i < old_cycle->listening.nelts; i++) {

        if (ls[i].remain || ls[i].fd == (rap_socket_t) -1) {
            continue;
        }

        if (rap_close_socket(ls[i].fd) == -1) {
            rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                          rap_close_socket_n " listening socket on %V failed",
                          &ls[i].addr_text);
        }

#if (RAP_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX) {
            u_char  *name;

            name = ls[i].addr_text.data + sizeof("unix:") - 1;

            rap_log_error(RAP_LOG_WARN, cycle->log, 0,
                          "deleting socket %s", name);

            if (rap_delete_file(name) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_socket_errno,
                              rap_delete_file_n " %s failed", name);
            }
        }

#endif
    }


    /* close the unnecessary open files */

    part = &old_cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].fd == RAP_INVALID_FILE || file[i].fd == rap_stderr) {
            continue;
        }

        if (rap_close_file(file[i].fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                          rap_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    rap_destroy_pool(conf.temp_pool);

    if (rap_process == RAP_PROCESS_MASTER || rap_is_init_cycle(old_cycle)) {

        rap_destroy_pool(old_cycle->pool);
        cycle->old_cycle = NULL;

        return cycle;
    }


    if (rap_temp_pool == NULL) {
        rap_temp_pool = rap_create_pool(128, cycle->log);
        if (rap_temp_pool == NULL) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                          "could not create rap_temp_pool");
            exit(1);
        }

        n = 10;

        if (rap_array_init(&rap_old_cycles, rap_temp_pool, n,
                           sizeof(rap_cycle_t *))
            != RAP_OK)
        {
            exit(1);
        }

        rap_memzero(rap_old_cycles.elts, n * sizeof(rap_cycle_t *));

        rap_cleaner_event.handler = rap_clean_old_cycles;
        rap_cleaner_event.log = cycle->log;
        rap_cleaner_event.data = &dumb;
        dumb.fd = (rap_socket_t) -1;
    }

    rap_temp_pool->log = cycle->log;

    old = rap_array_push(&rap_old_cycles);
    if (old == NULL) {
        exit(1);
    }
    *old = old_cycle;

    if (!rap_cleaner_event.timer_set) {
        rap_add_timer(&rap_cleaner_event, 30000);
        rap_cleaner_event.timer_set = 1;
    }

    return cycle;


failed:

    if (!rap_is_init_cycle(old_cycle)) {
        old_ccf = (rap_core_conf_t *) rap_get_conf(old_cycle->conf_ctx,
                                                   rap_core_module);
        if (old_ccf->environment) {
            environ = old_ccf->environment;
        }
    }

    /* rollback the new cycle configuration */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].fd == RAP_INVALID_FILE || file[i].fd == rap_stderr) {
            continue;
        }

        if (rap_close_file(file[i].fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                          rap_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    /* free the newly created shared memory */

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (shm_zone[i].shm.addr == NULL) {
            continue;
        }

        opart = &old_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                n = 0;
            }

            if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                continue;
            }

            if (rap_strncmp(shm_zone[i].shm.name.data,
                            oshm_zone[n].shm.name.data,
                            shm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag
                && shm_zone[i].shm.size == oshm_zone[n].shm.size
                && !shm_zone[i].noreuse)
            {
                goto old_shm_zone_found;
            }

            break;
        }

        rap_shm_free(&shm_zone[i].shm);

    old_shm_zone_found:

        continue;
    }

    if (rap_test_config) {
        rap_destroy_cycle_pools(&conf);
        return NULL;
    }

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].fd == (rap_socket_t) -1 || !ls[i].open) {
            continue;
        }

        if (rap_close_socket(ls[i].fd) == -1) {
            rap_log_error(RAP_LOG_EMERG, log, rap_socket_errno,
                          rap_close_socket_n " %V failed",
                          &ls[i].addr_text);
        }
    }

    rap_destroy_cycle_pools(&conf);

    return NULL;
}


static void
rap_destroy_cycle_pools(rap_conf_t *conf)
{
    rap_destroy_pool(conf->temp_pool);
    rap_destroy_pool(conf->pool);
}


static rap_int_t
rap_init_zone_pool(rap_cycle_t *cycle, rap_shm_zone_t *zn)
{
    u_char           *file;
    rap_slab_pool_t  *sp;

    sp = (rap_slab_pool_t *) zn->shm.addr;

    if (zn->shm.exists) {

        if (sp == sp->addr) {
            return RAP_OK;
        }

#if (RAP_WIN32)

        /* remap at the required address */

        if (rap_shm_remap(&zn->shm, sp->addr) != RAP_OK) {
            return RAP_ERROR;
        }

        sp = (rap_slab_pool_t *) zn->shm.addr;

        if (sp == sp->addr) {
            return RAP_OK;
        }

#endif

        rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                      "shared zone \"%V\" has no equal addresses: %p vs %p",
                      &zn->shm.name, sp->addr, sp);
        return RAP_ERROR;
    }

    sp->end = zn->shm.addr + zn->shm.size;
    sp->min_shift = 3;
    sp->addr = zn->shm.addr;

#if (RAP_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = rap_pnalloc(cycle->pool,
                       cycle->lock_file.len + zn->shm.name.len + 1);
    if (file == NULL) {
        return RAP_ERROR;
    }

    (void) rap_sprintf(file, "%V%V%Z", &cycle->lock_file, &zn->shm.name);

#endif

    if (rap_shmtx_create(&sp->mutex, &sp->lock, file) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_slab_init(sp);

    return RAP_OK;
}


rap_int_t
rap_create_pidfile(rap_str_t *name, rap_log_t *log)
{
    size_t      len;
    rap_uint_t  create;
    rap_file_t  file;
    u_char      pid[RAP_INT64_LEN + 2];

    if (rap_process > RAP_PROCESS_MASTER) {
        return RAP_OK;
    }

    rap_memzero(&file, sizeof(rap_file_t));

    file.name = *name;
    file.log = log;

    create = rap_test_config ? RAP_FILE_CREATE_OR_OPEN : RAP_FILE_TRUNCATE;

    file.fd = rap_open_file(file.name.data, RAP_FILE_RDWR,
                            create, RAP_FILE_DEFAULT_ACCESS);

    if (file.fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      rap_open_file_n " \"%s\" failed", file.name.data);
        return RAP_ERROR;
    }

    if (!rap_test_config) {
        len = rap_snprintf(pid, RAP_INT64_LEN + 2, "%P%N", rap_pid) - pid;

        if (rap_write_file(&file, pid, len, 0) == RAP_ERROR) {
            return RAP_ERROR;
        }
    }

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_close_file_n " \"%s\" failed", file.name.data);
    }

    return RAP_OK;
}


void
rap_delete_pidfile(rap_cycle_t *cycle)
{
    u_char           *name;
    rap_core_conf_t  *ccf;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    name = rap_new_binary ? ccf->oldpid.data : ccf->pid.data;

    if (rap_delete_file(name) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      rap_delete_file_n " \"%s\" failed", name);
    }
}


rap_int_t
rap_signal_process(rap_cycle_t *cycle, char *sig)
{
    ssize_t           n;
    rap_pid_t         pid;
    rap_file_t        file;
    rap_core_conf_t  *ccf;
    u_char            buf[RAP_INT64_LEN + 2];

    rap_log_error(RAP_LOG_NOTICE, cycle->log, 0, "signal process started");

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    rap_memzero(&file, sizeof(rap_file_t));

    file.name = ccf->pid;
    file.log = cycle->log;

    file.fd = rap_open_file(file.name.data, RAP_FILE_RDONLY,
                            RAP_FILE_OPEN, RAP_FILE_DEFAULT_ACCESS);

    if (file.fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_ERR, cycle->log, rap_errno,
                      rap_open_file_n " \"%s\" failed", file.name.data);
        return 1;
    }

    n = rap_read_file(&file, buf, RAP_INT64_LEN + 2, 0);

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", file.name.data);
    }

    if (n == RAP_ERROR) {
        return 1;
    }

    while (n-- && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    pid = rap_atoi(buf, ++n);

    if (pid == (rap_pid_t) RAP_ERROR) {
        rap_log_error(RAP_LOG_ERR, cycle->log, 0,
                      "invalid PID number \"%*s\" in \"%s\"",
                      n, buf, file.name.data);
        return 1;
    }

    return rap_os_signal_process(cycle, sig, pid);

}


static rap_int_t
rap_test_lockfile(u_char *file, rap_log_t *log)
{
#if !(RAP_HAVE_ATOMIC_OPS)
    rap_fd_t  fd;

    fd = rap_open_file(file, RAP_FILE_RDWR, RAP_FILE_CREATE_OR_OPEN,
                       RAP_FILE_DEFAULT_ACCESS);

    if (fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      rap_open_file_n " \"%s\" failed", file);
        return RAP_ERROR;
    }

    if (rap_close_file(fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_close_file_n " \"%s\" failed", file);
    }

    if (rap_delete_file(file) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      rap_delete_file_n " \"%s\" failed", file);
    }

#endif

    return RAP_OK;
}


void
rap_reopen_files(rap_cycle_t *cycle, rap_uid_t user)
{
    rap_fd_t          fd;
    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_open_file_t  *file;

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].name.len == 0) {
            continue;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], cycle->log);
        }

        fd = rap_open_file(file[i].name.data, RAP_FILE_APPEND,
                           RAP_FILE_CREATE_OR_OPEN, RAP_FILE_DEFAULT_ACCESS);

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reopen file \"%s\", old:%d new:%d",
                       file[i].name.data, file[i].fd, fd);

        if (fd == RAP_INVALID_FILE) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          rap_open_file_n " \"%s\" failed", file[i].name.data);
            continue;
        }

#if !(RAP_WIN32)
        if (user != (rap_uid_t) RAP_CONF_UNSET_UINT) {
            rap_file_info_t  fi;

            if (rap_file_info(file[i].name.data, &fi) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              rap_file_info_n " \"%s\" failed",
                              file[i].name.data);

                if (rap_close_file(fd) == RAP_FILE_ERROR) {
                    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                  rap_close_file_n " \"%s\" failed",
                                  file[i].name.data);
                }

                continue;
            }

            if (fi.st_uid != user) {
                if (chown((const char *) file[i].name.data, user, -1) == -1) {
                    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                  "chown(\"%s\", %d) failed",
                                  file[i].name.data, user);

                    if (rap_close_file(fd) == RAP_FILE_ERROR) {
                        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                      rap_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }

            if ((fi.st_mode & (S_IRUSR|S_IWUSR)) != (S_IRUSR|S_IWUSR)) {

                fi.st_mode |= (S_IRUSR|S_IWUSR);

                if (chmod((const char *) file[i].name.data, fi.st_mode) == -1) {
                    rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                  "chmod() \"%s\" failed", file[i].name.data);

                    if (rap_close_file(fd) == RAP_FILE_ERROR) {
                        rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                                      rap_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }
        }

        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);

            if (rap_close_file(fd) == RAP_FILE_ERROR) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                              rap_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#endif

        if (rap_close_file(file[i].fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          rap_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }

        file[i].fd = fd;
    }

    (void) rap_log_redirect_stderr(cycle);
}


rap_shm_zone_t *
rap_shared_memory_add(rap_conf_t *cf, rap_str_t *name, size_t size, void *tag)
{
    rap_uint_t        i;
    rap_shm_zone_t   *shm_zone;
    rap_list_part_t  *part;

    part = &cf->cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (rap_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                            "the shared memory zone \"%V\" is "
                            "already declared for a different use",
                            &shm_zone[i].shm.name);
            return NULL;
        }

        if (shm_zone[i].shm.size == 0) {
            shm_zone[i].shm.size = size;
        }

        if (size && size != shm_zone[i].shm.size) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                            "the size %uz of shared memory zone \"%V\" "
                            "conflicts with already declared size %uz",
                            size, &shm_zone[i].shm.name, shm_zone[i].shm.size);
            return NULL;
        }

        return &shm_zone[i];
    }

    shm_zone = rap_list_push(&cf->cycle->shared_memory);

    if (shm_zone == NULL) {
        return NULL;
    }

    shm_zone->data = NULL;
    shm_zone->shm.log = cf->cycle->log;
    shm_zone->shm.addr = NULL;
    shm_zone->shm.size = size;
    shm_zone->shm.name = *name;
    shm_zone->shm.exists = 0;
    shm_zone->init = NULL;
    shm_zone->tag = tag;
    shm_zone->noreuse = 0;

    return shm_zone;
}


static void
rap_clean_old_cycles(rap_event_t *ev)
{
    rap_uint_t     i, n, found, live;
    rap_log_t     *log;
    rap_cycle_t  **cycle;

    log = rap_cycle->log;
    rap_temp_pool->log = log;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, log, 0, "clean old cycles");

    live = 0;

    cycle = rap_old_cycles.elts;
    for (i = 0; i < rap_old_cycles.nelts; i++) {

        if (cycle[i] == NULL) {
            continue;
        }

        found = 0;

        for (n = 0; n < cycle[i]->connection_n; n++) {
            if (cycle[i]->connections[n].fd != (rap_socket_t) -1) {
                found = 1;

                rap_log_debug1(RAP_LOG_DEBUG_CORE, log, 0, "live fd:%ui", n);

                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        rap_log_debug1(RAP_LOG_DEBUG_CORE, log, 0, "clean old cycle: %ui", i);

        rap_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    rap_log_debug1(RAP_LOG_DEBUG_CORE, log, 0, "old cycles status: %ui", live);

    if (live) {
        rap_add_timer(ev, 30000);

    } else {
        rap_destroy_pool(rap_temp_pool);
        rap_temp_pool = NULL;
        rap_old_cycles.nelts = 0;
    }
}


void
rap_set_shutdown_timer(rap_cycle_t *cycle)
{
    rap_core_conf_t  *ccf;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (ccf->shutdown_timeout) {
        rap_shutdown_event.handler = rap_shutdown_timer_handler;
        rap_shutdown_event.data = cycle;
        rap_shutdown_event.log = cycle->log;
        rap_shutdown_event.cancelable = 1;

        rap_add_timer(&rap_shutdown_event, ccf->shutdown_timeout);
    }
}


static void
rap_shutdown_timer_handler(rap_event_t *ev)
{
    rap_uint_t         i;
    rap_cycle_t       *cycle;
    rap_connection_t  *c;

    cycle = ev->data;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        if (c[i].fd == (rap_socket_t) -1
            || c[i].read == NULL
            || c[i].read->accept
            || c[i].read->channel
            || c[i].read->resolver)
        {
            continue;
        }

        rap_log_debug1(RAP_LOG_DEBUG_CORE, ev->log, 0,
                       "*%uA shutdown timeout", c[i].number);

        c[i].close = 1;
        c[i].error = 1;

        c[i].read->handler(c[i].read);
    }
}
