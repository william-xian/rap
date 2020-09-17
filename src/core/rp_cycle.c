
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


static void rp_destroy_cycle_pools(rp_conf_t *conf);
static rp_int_t rp_init_zone_pool(rp_cycle_t *cycle,
    rp_shm_zone_t *shm_zone);
static rp_int_t rp_test_lockfile(u_char *file, rp_log_t *log);
static void rp_clean_old_cycles(rp_event_t *ev);
static void rp_shutdown_timer_handler(rp_event_t *ev);


volatile rp_cycle_t  *rp_cycle;
rp_array_t            rp_old_cycles;

static rp_pool_t     *rp_temp_pool;
static rp_event_t     rp_cleaner_event;
static rp_event_t     rp_shutdown_event;

rp_uint_t             rp_test_config;
rp_uint_t             rp_dump_config;
rp_uint_t             rp_quiet_mode;


/* STUB NAME */
static rp_connection_t  dumb;
/* STUB */


rp_cycle_t *
rp_init_cycle(rp_cycle_t *old_cycle)
{
    void                *rv;
    char               **senv;
    rp_uint_t           i, n;
    rp_log_t           *log;
    rp_time_t          *tp;
    rp_conf_t           conf;
    rp_pool_t          *pool;
    rp_cycle_t         *cycle, **old;
    rp_shm_zone_t      *shm_zone, *oshm_zone;
    rp_list_part_t     *part, *opart;
    rp_open_file_t     *file;
    rp_listening_t     *ls, *nls;
    rp_core_conf_t     *ccf, *old_ccf;
    rp_core_module_t   *module;
    char                 hostname[RP_MAXHOSTNAMELEN];

    rp_timezone_update();

    /* force localtime update with a new timezone */

    tp = rp_timeofday();
    tp->sec = 0;

    rp_time_update();


    log = old_cycle->log;

    pool = rp_create_pool(RP_CYCLE_POOL_SIZE, log);
    if (pool == NULL) {
        return NULL;
    }
    pool->log = log;

    cycle = rp_pcalloc(pool, sizeof(rp_cycle_t));
    if (cycle == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    cycle->pool = pool;
    cycle->log = log;
    cycle->old_cycle = old_cycle;

    cycle->conf_prefix.len = old_cycle->conf_prefix.len;
    cycle->conf_prefix.data = rp_pstrdup(pool, &old_cycle->conf_prefix);
    if (cycle->conf_prefix.data == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    cycle->prefix.len = old_cycle->prefix.len;
    cycle->prefix.data = rp_pstrdup(pool, &old_cycle->prefix);
    if (cycle->prefix.data == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    cycle->conf_file.len = old_cycle->conf_file.len;
    cycle->conf_file.data = rp_pnalloc(pool, old_cycle->conf_file.len + 1);
    if (cycle->conf_file.data == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }
    rp_cpystrn(cycle->conf_file.data, old_cycle->conf_file.data,
                old_cycle->conf_file.len + 1);

    cycle->conf_param.len = old_cycle->conf_param.len;
    cycle->conf_param.data = rp_pstrdup(pool, &old_cycle->conf_param);
    if (cycle->conf_param.data == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }


    n = old_cycle->paths.nelts ? old_cycle->paths.nelts : 10;

    if (rp_array_init(&cycle->paths, pool, n, sizeof(rp_path_t *))
        != RP_OK)
    {
        rp_destroy_pool(pool);
        return NULL;
    }

    rp_memzero(cycle->paths.elts, n * sizeof(rp_path_t *));


    if (rp_array_init(&cycle->config_dump, pool, 1, sizeof(rp_conf_dump_t))
        != RP_OK)
    {
        rp_destroy_pool(pool);
        return NULL;
    }

    rp_rbtree_init(&cycle->config_dump_rbtree, &cycle->config_dump_sentinel,
                    rp_str_rbtree_insert_value);

    if (old_cycle->open_files.part.nelts) {
        n = old_cycle->open_files.part.nelts;
        for (part = old_cycle->open_files.part.next; part; part = part->next) {
            n += part->nelts;
        }

    } else {
        n = 20;
    }

    if (rp_list_init(&cycle->open_files, pool, n, sizeof(rp_open_file_t))
        != RP_OK)
    {
        rp_destroy_pool(pool);
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

    if (rp_list_init(&cycle->shared_memory, pool, n, sizeof(rp_shm_zone_t))
        != RP_OK)
    {
        rp_destroy_pool(pool);
        return NULL;
    }

    n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;

    if (rp_array_init(&cycle->listening, pool, n, sizeof(rp_listening_t))
        != RP_OK)
    {
        rp_destroy_pool(pool);
        return NULL;
    }

    rp_memzero(cycle->listening.elts, n * sizeof(rp_listening_t));


    rp_queue_init(&cycle->reusable_connections_queue);


    cycle->conf_ctx = rp_pcalloc(pool, rp_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }


    if (gethostname(hostname, RP_MAXHOSTNAMELEN) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "gethostname() failed");
        rp_destroy_pool(pool);
        return NULL;
    }

    /* on Linux gethostname() silently truncates name that does not fit */

    hostname[RP_MAXHOSTNAMELEN - 1] = '\0';
    cycle->hostname.len = rp_strlen(hostname);

    cycle->hostname.data = rp_pnalloc(pool, cycle->hostname.len);
    if (cycle->hostname.data == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    rp_strlow(cycle->hostname.data, (u_char *) hostname, cycle->hostname.len);


    if (rp_cycle_modules(cycle) != RP_OK) {
        rp_destroy_pool(pool);
        return NULL;
    }


    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != RP_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                rp_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[cycle->modules[i]->index] = rv;
        }
    }


    senv = environ;


    rp_memzero(&conf, sizeof(rp_conf_t));
    /* STUB: init array ? */
    conf.args = rp_array_create(pool, 10, sizeof(rp_str_t));
    if (conf.args == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    conf.temp_pool = rp_create_pool(RP_CYCLE_POOL_SIZE, log);
    if (conf.temp_pool == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }


    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = RP_CORE_MODULE;
    conf.cmd_type = RP_MAIN_CONF;

#if 0
    log->log_level = RP_LOG_DEBUG_ALL;
#endif

    if (rp_conf_param(&conf) != RP_CONF_OK) {
        environ = senv;
        rp_destroy_cycle_pools(&conf);
        return NULL;
    }

    if (rp_conf_parse(&conf, &cycle->conf_file) != RP_CONF_OK) {
        environ = senv;
        rp_destroy_cycle_pools(&conf);
        return NULL;
    }

    if (rp_test_config && !rp_quiet_mode) {
        rp_log_stderr(0, "the configuration file %s syntax is ok",
                       cycle->conf_file.data);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != RP_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle,
                                  cycle->conf_ctx[cycle->modules[i]->index])
                == RP_CONF_ERROR)
            {
                environ = senv;
                rp_destroy_cycle_pools(&conf);
                return NULL;
            }
        }
    }

    if (rp_process == RP_PROCESS_SIGNALLER) {
        return cycle;
    }

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (rp_test_config) {

        if (rp_create_pidfile(&ccf->pid, log) != RP_OK) {
            goto failed;
        }

    } else if (!rp_is_init_cycle(old_cycle)) {

        /*
         * we do not create the pid file in the first rp_init_cycle() call
         * because we need to write the demonized process pid
         */

        old_ccf = (rp_core_conf_t *) rp_get_conf(old_cycle->conf_ctx,
                                                   rp_core_module);
        if (ccf->pid.len != old_ccf->pid.len
            || rp_strcmp(ccf->pid.data, old_ccf->pid.data) != 0)
        {
            /* new pid file name */

            if (rp_create_pidfile(&ccf->pid, log) != RP_OK) {
                goto failed;
            }

            rp_delete_pidfile(old_cycle);
        }
    }


    if (rp_test_lockfile(cycle->lock_file.data, log) != RP_OK) {
        goto failed;
    }


    if (rp_create_paths(cycle, ccf->user) != RP_OK) {
        goto failed;
    }


    if (rp_log_open_default(cycle) != RP_OK) {
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

        file[i].fd = rp_open_file(file[i].name.data,
                                   RP_FILE_APPEND,
                                   RP_FILE_CREATE_OR_OPEN,
                                   RP_FILE_DEFAULT_ACCESS);

        rp_log_debug3(RP_LOG_DEBUG_CORE, log, 0,
                       "log: %p %d \"%s\"",
                       &file[i], file[i].fd, file[i].name.data);

        if (file[i].fd == RP_INVALID_FILE) {
            rp_log_error(RP_LOG_EMERG, log, rp_errno,
                          rp_open_file_n " \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }

#if !(RP_WIN32)
        if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
            rp_log_error(RP_LOG_EMERG, log, rp_errno,
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
            rp_log_error(RP_LOG_EMERG, log, 0,
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

            if (rp_strncmp(shm_zone[i].shm.name.data,
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
#if (RP_WIN32)
                shm_zone[i].shm.handle = oshm_zone[n].shm.handle;
#endif

                if (shm_zone[i].init(&shm_zone[i], oshm_zone[n].data)
                    != RP_OK)
                {
                    goto failed;
                }

                goto shm_zone_found;
            }

            break;
        }

        if (rp_shm_alloc(&shm_zone[i].shm) != RP_OK) {
            goto failed;
        }

        if (rp_init_zone_pool(cycle, &shm_zone[i]) != RP_OK) {
            goto failed;
        }

        if (shm_zone[i].init(&shm_zone[i], NULL) != RP_OK) {
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

                if (rp_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
                                     ls[i].sockaddr, ls[i].socklen, 1)
                    == RP_OK)
                {
                    nls[n].fd = ls[i].fd;
                    nls[n].previous = &ls[i];
                    ls[i].remain = 1;

                    if (ls[i].backlog != nls[n].backlog) {
                        nls[n].listen = 1;
                    }

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                    /*
                     * FreeBSD, except the most recent versions,
                     * could not remove accept filter
                     */
                    nls[n].deferred_accept = ls[i].deferred_accept;

                    if (ls[i].accept_filter && nls[n].accept_filter) {
                        if (rp_strcmp(ls[i].accept_filter,
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

#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                    if (ls[i].deferred_accept && !nls[n].deferred_accept) {
                        nls[n].delete_deferred = 1;

                    } else if (ls[i].deferred_accept != nls[n].deferred_accept)
                    {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (RP_HAVE_REUSEPORT)
                    if (nls[n].reuseport && !ls[i].reuseport) {
                        nls[n].add_reuseport = 1;
                    }
#endif

                    break;
                }
            }

            if (nls[n].fd == (rp_socket_t) -1) {
                nls[n].open = 1;
#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                if (nls[n].accept_filter) {
                    nls[n].add_deferred = 1;
                }
#endif
#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
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
#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            if (ls[i].accept_filter) {
                ls[i].add_deferred = 1;
            }
#endif
#if (RP_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            if (ls[i].deferred_accept) {
                ls[i].add_deferred = 1;
            }
#endif
        }
    }

    if (rp_open_listening_sockets(cycle) != RP_OK) {
        goto failed;
    }

    if (!rp_test_config) {
        rp_configure_listening_sockets(cycle);
    }


    /* commit the new cycle configuration */

    if (!rp_use_stderr) {
        (void) rp_log_redirect_stderr(cycle);
    }

    pool->log = cycle->log;

    if (rp_init_modules(cycle) != RP_OK) {
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

            if (rp_strncmp(oshm_zone[i].shm.name.data,
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

        rp_shm_free(&oshm_zone[i].shm);

    live_shm_zone:

        continue;
    }

old_shm_zone_done:


    /* close the unnecessary listening sockets */

    ls = old_cycle->listening.elts;
    for (i = 0; i < old_cycle->listening.nelts; i++) {

        if (ls[i].remain || ls[i].fd == (rp_socket_t) -1) {
            continue;
        }

        if (rp_close_socket(ls[i].fd) == -1) {
            rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                          rp_close_socket_n " listening socket on %V failed",
                          &ls[i].addr_text);
        }

#if (RP_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX) {
            u_char  *name;

            name = ls[i].addr_text.data + sizeof("unix:") - 1;

            rp_log_error(RP_LOG_WARN, cycle->log, 0,
                          "deleting socket %s", name);

            if (rp_delete_file(name) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_socket_errno,
                              rp_delete_file_n " %s failed", name);
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

        if (file[i].fd == RP_INVALID_FILE || file[i].fd == rp_stderr) {
            continue;
        }

        if (rp_close_file(file[i].fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_EMERG, log, rp_errno,
                          rp_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    rp_destroy_pool(conf.temp_pool);

    if (rp_process == RP_PROCESS_MASTER || rp_is_init_cycle(old_cycle)) {

        rp_destroy_pool(old_cycle->pool);
        cycle->old_cycle = NULL;

        return cycle;
    }


    if (rp_temp_pool == NULL) {
        rp_temp_pool = rp_create_pool(128, cycle->log);
        if (rp_temp_pool == NULL) {
            rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                          "could not create rp_temp_pool");
            exit(1);
        }

        n = 10;

        if (rp_array_init(&rp_old_cycles, rp_temp_pool, n,
                           sizeof(rp_cycle_t *))
            != RP_OK)
        {
            exit(1);
        }

        rp_memzero(rp_old_cycles.elts, n * sizeof(rp_cycle_t *));

        rp_cleaner_event.handler = rp_clean_old_cycles;
        rp_cleaner_event.log = cycle->log;
        rp_cleaner_event.data = &dumb;
        dumb.fd = (rp_socket_t) -1;
    }

    rp_temp_pool->log = cycle->log;

    old = rp_array_push(&rp_old_cycles);
    if (old == NULL) {
        exit(1);
    }
    *old = old_cycle;

    if (!rp_cleaner_event.timer_set) {
        rp_add_timer(&rp_cleaner_event, 30000);
        rp_cleaner_event.timer_set = 1;
    }

    return cycle;


failed:

    if (!rp_is_init_cycle(old_cycle)) {
        old_ccf = (rp_core_conf_t *) rp_get_conf(old_cycle->conf_ctx,
                                                   rp_core_module);
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

        if (file[i].fd == RP_INVALID_FILE || file[i].fd == rp_stderr) {
            continue;
        }

        if (rp_close_file(file[i].fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_EMERG, log, rp_errno,
                          rp_close_file_n " \"%s\" failed",
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

            if (rp_strncmp(shm_zone[i].shm.name.data,
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

        rp_shm_free(&shm_zone[i].shm);

    old_shm_zone_found:

        continue;
    }

    if (rp_test_config) {
        rp_destroy_cycle_pools(&conf);
        return NULL;
    }

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].fd == (rp_socket_t) -1 || !ls[i].open) {
            continue;
        }

        if (rp_close_socket(ls[i].fd) == -1) {
            rp_log_error(RP_LOG_EMERG, log, rp_socket_errno,
                          rp_close_socket_n " %V failed",
                          &ls[i].addr_text);
        }
    }

    rp_destroy_cycle_pools(&conf);

    return NULL;
}


static void
rp_destroy_cycle_pools(rp_conf_t *conf)
{
    rp_destroy_pool(conf->temp_pool);
    rp_destroy_pool(conf->pool);
}


static rp_int_t
rp_init_zone_pool(rp_cycle_t *cycle, rp_shm_zone_t *zn)
{
    u_char           *file;
    rp_slab_pool_t  *sp;

    sp = (rp_slab_pool_t *) zn->shm.addr;

    if (zn->shm.exists) {

        if (sp == sp->addr) {
            return RP_OK;
        }

#if (RP_WIN32)

        /* remap at the required address */

        if (rp_shm_remap(&zn->shm, sp->addr) != RP_OK) {
            return RP_ERROR;
        }

        sp = (rp_slab_pool_t *) zn->shm.addr;

        if (sp == sp->addr) {
            return RP_OK;
        }

#endif

        rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                      "shared zone \"%V\" has no equal addresses: %p vs %p",
                      &zn->shm.name, sp->addr, sp);
        return RP_ERROR;
    }

    sp->end = zn->shm.addr + zn->shm.size;
    sp->min_shift = 3;
    sp->addr = zn->shm.addr;

#if (RP_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = rp_pnalloc(cycle->pool,
                       cycle->lock_file.len + zn->shm.name.len + 1);
    if (file == NULL) {
        return RP_ERROR;
    }

    (void) rp_sprintf(file, "%V%V%Z", &cycle->lock_file, &zn->shm.name);

#endif

    if (rp_shmtx_create(&sp->mutex, &sp->lock, file) != RP_OK) {
        return RP_ERROR;
    }

    rp_slab_init(sp);

    return RP_OK;
}


rp_int_t
rp_create_pidfile(rp_str_t *name, rp_log_t *log)
{
    size_t      len;
    rp_uint_t  create;
    rp_file_t  file;
    u_char      pid[RP_INT64_LEN + 2];

    if (rp_process > RP_PROCESS_MASTER) {
        return RP_OK;
    }

    rp_memzero(&file, sizeof(rp_file_t));

    file.name = *name;
    file.log = log;

    create = rp_test_config ? RP_FILE_CREATE_OR_OPEN : RP_FILE_TRUNCATE;

    file.fd = rp_open_file(file.name.data, RP_FILE_RDWR,
                            create, RP_FILE_DEFAULT_ACCESS);

    if (file.fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      rp_open_file_n " \"%s\" failed", file.name.data);
        return RP_ERROR;
    }

    if (!rp_test_config) {
        len = rp_snprintf(pid, RP_INT64_LEN + 2, "%P%N", rp_pid) - pid;

        if (rp_write_file(&file, pid, len, 0) == RP_ERROR) {
            return RP_ERROR;
        }
    }

    if (rp_close_file(file.fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_close_file_n " \"%s\" failed", file.name.data);
    }

    return RP_OK;
}


void
rp_delete_pidfile(rp_cycle_t *cycle)
{
    u_char           *name;
    rp_core_conf_t  *ccf;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    name = rp_new_binary ? ccf->oldpid.data : ccf->pid.data;

    if (rp_delete_file(name) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      rp_delete_file_n " \"%s\" failed", name);
    }
}


rp_int_t
rp_signal_process(rp_cycle_t *cycle, char *sig)
{
    ssize_t           n;
    rp_pid_t         pid;
    rp_file_t        file;
    rp_core_conf_t  *ccf;
    u_char            buf[RP_INT64_LEN + 2];

    rp_log_error(RP_LOG_NOTICE, cycle->log, 0, "signal process started");

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    rp_memzero(&file, sizeof(rp_file_t));

    file.name = ccf->pid;
    file.log = cycle->log;

    file.fd = rp_open_file(file.name.data, RP_FILE_RDONLY,
                            RP_FILE_OPEN, RP_FILE_DEFAULT_ACCESS);

    if (file.fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_ERR, cycle->log, rp_errno,
                      rp_open_file_n " \"%s\" failed", file.name.data);
        return 1;
    }

    n = rp_read_file(&file, buf, RP_INT64_LEN + 2, 0);

    if (rp_close_file(file.fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", file.name.data);
    }

    if (n == RP_ERROR) {
        return 1;
    }

    while (n-- && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    pid = rp_atoi(buf, ++n);

    if (pid == (rp_pid_t) RP_ERROR) {
        rp_log_error(RP_LOG_ERR, cycle->log, 0,
                      "invalid PID number \"%*s\" in \"%s\"",
                      n, buf, file.name.data);
        return 1;
    }

    return rp_os_signal_process(cycle, sig, pid);

}


static rp_int_t
rp_test_lockfile(u_char *file, rp_log_t *log)
{
#if !(RP_HAVE_ATOMIC_OPS)
    rp_fd_t  fd;

    fd = rp_open_file(file, RP_FILE_RDWR, RP_FILE_CREATE_OR_OPEN,
                       RP_FILE_DEFAULT_ACCESS);

    if (fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      rp_open_file_n " \"%s\" failed", file);
        return RP_ERROR;
    }

    if (rp_close_file(fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_close_file_n " \"%s\" failed", file);
    }

    if (rp_delete_file(file) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      rp_delete_file_n " \"%s\" failed", file);
    }

#endif

    return RP_OK;
}


void
rp_reopen_files(rp_cycle_t *cycle, rp_uid_t user)
{
    rp_fd_t          fd;
    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_open_file_t  *file;

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

        fd = rp_open_file(file[i].name.data, RP_FILE_APPEND,
                           RP_FILE_CREATE_OR_OPEN, RP_FILE_DEFAULT_ACCESS);

        rp_log_debug3(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reopen file \"%s\", old:%d new:%d",
                       file[i].name.data, file[i].fd, fd);

        if (fd == RP_INVALID_FILE) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          rp_open_file_n " \"%s\" failed", file[i].name.data);
            continue;
        }

#if !(RP_WIN32)
        if (user != (rp_uid_t) RP_CONF_UNSET_UINT) {
            rp_file_info_t  fi;

            if (rp_file_info(file[i].name.data, &fi) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              rp_file_info_n " \"%s\" failed",
                              file[i].name.data);

                if (rp_close_file(fd) == RP_FILE_ERROR) {
                    rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                  rp_close_file_n " \"%s\" failed",
                                  file[i].name.data);
                }

                continue;
            }

            if (fi.st_uid != user) {
                if (chown((const char *) file[i].name.data, user, -1) == -1) {
                    rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                  "chown(\"%s\", %d) failed",
                                  file[i].name.data, user);

                    if (rp_close_file(fd) == RP_FILE_ERROR) {
                        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                      rp_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }

            if ((fi.st_mode & (S_IRUSR|S_IWUSR)) != (S_IRUSR|S_IWUSR)) {

                fi.st_mode |= (S_IRUSR|S_IWUSR);

                if (chmod((const char *) file[i].name.data, fi.st_mode) == -1) {
                    rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                  "chmod() \"%s\" failed", file[i].name.data);

                    if (rp_close_file(fd) == RP_FILE_ERROR) {
                        rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                                      rp_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }
        }

        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);

            if (rp_close_file(fd) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                              rp_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#endif

        if (rp_close_file(file[i].fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          rp_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }

        file[i].fd = fd;
    }

    (void) rp_log_redirect_stderr(cycle);
}


rp_shm_zone_t *
rp_shared_memory_add(rp_conf_t *cf, rp_str_t *name, size_t size, void *tag)
{
    rp_uint_t        i;
    rp_shm_zone_t   *shm_zone;
    rp_list_part_t  *part;

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

        if (rp_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                            "the shared memory zone \"%V\" is "
                            "already declared for a different use",
                            &shm_zone[i].shm.name);
            return NULL;
        }

        if (shm_zone[i].shm.size == 0) {
            shm_zone[i].shm.size = size;
        }

        if (size && size != shm_zone[i].shm.size) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                            "the size %uz of shared memory zone \"%V\" "
                            "conflicts with already declared size %uz",
                            size, &shm_zone[i].shm.name, shm_zone[i].shm.size);
            return NULL;
        }

        return &shm_zone[i];
    }

    shm_zone = rp_list_push(&cf->cycle->shared_memory);

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
rp_clean_old_cycles(rp_event_t *ev)
{
    rp_uint_t     i, n, found, live;
    rp_log_t     *log;
    rp_cycle_t  **cycle;

    log = rp_cycle->log;
    rp_temp_pool->log = log;

    rp_log_debug0(RP_LOG_DEBUG_CORE, log, 0, "clean old cycles");

    live = 0;

    cycle = rp_old_cycles.elts;
    for (i = 0; i < rp_old_cycles.nelts; i++) {

        if (cycle[i] == NULL) {
            continue;
        }

        found = 0;

        for (n = 0; n < cycle[i]->connection_n; n++) {
            if (cycle[i]->connections[n].fd != (rp_socket_t) -1) {
                found = 1;

                rp_log_debug1(RP_LOG_DEBUG_CORE, log, 0, "live fd:%ui", n);

                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, log, 0, "clean old cycle: %ui", i);

        rp_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, log, 0, "old cycles status: %ui", live);

    if (live) {
        rp_add_timer(ev, 30000);

    } else {
        rp_destroy_pool(rp_temp_pool);
        rp_temp_pool = NULL;
        rp_old_cycles.nelts = 0;
    }
}


void
rp_set_shutdown_timer(rp_cycle_t *cycle)
{
    rp_core_conf_t  *ccf;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (ccf->shutdown_timeout) {
        rp_shutdown_event.handler = rp_shutdown_timer_handler;
        rp_shutdown_event.data = cycle;
        rp_shutdown_event.log = cycle->log;
        rp_shutdown_event.cancelable = 1;

        rp_add_timer(&rp_shutdown_event, ccf->shutdown_timeout);
    }
}


static void
rp_shutdown_timer_handler(rp_event_t *ev)
{
    rp_uint_t         i;
    rp_cycle_t       *cycle;
    rp_connection_t  *c;

    cycle = ev->data;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        if (c[i].fd == (rp_socket_t) -1
            || c[i].read == NULL
            || c[i].read->accept
            || c[i].read->channel
            || c[i].read->resolver)
        {
            continue;
        }

        rp_log_debug1(RP_LOG_DEBUG_CORE, ev->log, 0,
                       "*%uA shutdown timeout", c[i].number);

        c[i].close = 1;
        c[i].error = 1;

        c[i].read->handler(c[i].read);
    }
}
