
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rap.h>


static void rp_show_version_info(void);
static rp_int_t rp_add_inherited_sockets(rp_cycle_t *cycle);
static void rp_cleanup_environment(void *data);
static rp_int_t rp_get_options(int argc, char *const *argv);
static rp_int_t rp_process_options(rp_cycle_t *cycle);
static rp_int_t rp_save_argv(rp_cycle_t *cycle, int argc, char *const *argv);
static void *rp_core_module_create_conf(rp_cycle_t *cycle);
static char *rp_core_module_init_conf(rp_cycle_t *cycle, void *conf);
static char *rp_set_user(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_set_env(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_set_priority(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_set_cpu_affinity(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_set_worker_processes(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_load_module(rp_conf_t *cf, rp_command_t *cmd, void *conf);
#if (RP_HAVE_DLOPEN)
static void rp_unload_module(void *data);
#endif


static rp_conf_enum_t  rp_debug_points[] = {
    { rp_string("stop"), RP_DEBUG_POINTS_STOP },
    { rp_string("abort"), RP_DEBUG_POINTS_ABORT },
    { rp_null_string, 0 }
};


static rp_command_t  rp_core_commands[] = {

    { rp_string("daemon"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      0,
      offsetof(rp_core_conf_t, daemon),
      NULL },

    { rp_string("master_process"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      0,
      offsetof(rp_core_conf_t, master),
      NULL },

    { rp_string("timer_resolution"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      0,
      offsetof(rp_core_conf_t, timer_resolution),
      NULL },

    { rp_string("pid"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      0,
      offsetof(rp_core_conf_t, pid),
      NULL },

    { rp_string("lock_file"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      0,
      offsetof(rp_core_conf_t, lock_file),
      NULL },

    { rp_string("worker_processes"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_set_worker_processes,
      0,
      0,
      NULL },

    { rp_string("debug_points"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      0,
      offsetof(rp_core_conf_t, debug_points),
      &rp_debug_points },

    { rp_string("user"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE12,
      rp_set_user,
      0,
      0,
      NULL },

    { rp_string("worker_priority"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_set_priority,
      0,
      0,
      NULL },

    { rp_string("worker_cpu_affinity"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_1MORE,
      rp_set_cpu_affinity,
      0,
      0,
      NULL },

    { rp_string("worker_rlimit_nofile"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      0,
      offsetof(rp_core_conf_t, rlimit_nofile),
      NULL },

    { rp_string("worker_rlimit_core"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_off_slot,
      0,
      offsetof(rp_core_conf_t, rlimit_core),
      NULL },

    { rp_string("worker_shutdown_timeout"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      0,
      offsetof(rp_core_conf_t, shutdown_timeout),
      NULL },

    { rp_string("working_directory"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      0,
      offsetof(rp_core_conf_t, working_directory),
      NULL },

    { rp_string("env"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_set_env,
      0,
      0,
      NULL },

    { rp_string("load_module"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_TAKE1,
      rp_load_module,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_core_module_ctx = {
    rp_string("core"),
    rp_core_module_create_conf,
    rp_core_module_init_conf
};


rp_module_t  rp_core_module = {
    RP_MODULE_V1,
    &rp_core_module_ctx,                  /* module context */
    rp_core_commands,                     /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_uint_t   rp_show_help;
static rp_uint_t   rp_show_version;
static rp_uint_t   rp_show_configure;
static u_char      *rp_prefix;
static u_char      *rp_conf_file;
static u_char      *rp_conf_params;
static char        *rp_signal;


static char **rp_os_environ;


int rp_cdecl
main(int argc, char *const *argv)
{
    rp_buf_t        *b;
    rp_log_t        *log;
    rp_uint_t        i;
    rp_cycle_t      *cycle, init_cycle;
    rp_conf_dump_t  *cd;
    rp_core_conf_t  *ccf;

    rp_debug_init();

    if (rp_strerror_init() != RP_OK) {
        return 1;
    }

    if (rp_get_options(argc, argv) != RP_OK) {
        return 1;
    }

    if (rp_show_version) {
        rp_show_version_info();

        if (!rp_test_config) {
            return 0;
        }
    }

    /* TODO */ rp_max_sockets = -1;

    rp_time_init();

#if (RP_PCRE)
    rp_regex_init();
#endif

    rp_pid = rp_getpid();
    rp_parent = rp_getppid();

    log = rp_log_init(rp_prefix);
    if (log == NULL) {
        return 1;
    }

    /* STUB */
#if (RP_OPENSSL)
    rp_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * rp_process_options()
     */

    rp_memzero(&init_cycle, sizeof(rp_cycle_t));
    init_cycle.log = log;
    rp_cycle = &init_cycle;

    init_cycle.pool = rp_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    if (rp_save_argv(&init_cycle, argc, argv) != RP_OK) {
        return 1;
    }

    if (rp_process_options(&init_cycle) != RP_OK) {
        return 1;
    }

    if (rp_os_init(log) != RP_OK) {
        return 1;
    }

    /*
     * rp_crc32_table_init() requires rp_cacheline_size set in rp_os_init()
     */

    if (rp_crc32_table_init() != RP_OK) {
        return 1;
    }

    /*
     * rp_slab_sizes_init() requires rp_pagesize set in rp_os_init()
     */

    rp_slab_sizes_init();

    if (rp_add_inherited_sockets(&init_cycle) != RP_OK) {
        return 1;
    }

    if (rp_preinit_modules() != RP_OK) {
        return 1;
    }

    cycle = rp_init_cycle(&init_cycle);
    if (cycle == NULL) {
        if (rp_test_config) {
            rp_log_stderr(0, "configuration file %s test failed",
                           init_cycle.conf_file.data);
        }

        return 1;
    }

    if (rp_test_config) {
        if (!rp_quiet_mode) {
            rp_log_stderr(0, "configuration file %s test is successful",
                           cycle->conf_file.data);
        }

        if (rp_dump_config) {
            cd = cycle->config_dump.elts;

            for (i = 0; i < cycle->config_dump.nelts; i++) {

                rp_write_stdout("# configuration file ");
                (void) rp_write_fd(rp_stdout, cd[i].name.data,
                                    cd[i].name.len);
                rp_write_stdout(":" RP_LINEFEED);

                b = cd[i].buffer;

                (void) rp_write_fd(rp_stdout, b->pos, b->last - b->pos);
                rp_write_stdout(RP_LINEFEED);
            }
        }

        return 0;
    }

    if (rp_signal) {
        return rp_signal_process(cycle, rp_signal);
    }

    rp_os_status(cycle->log);

    rp_cycle = cycle;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (ccf->master && rp_process == RP_PROCESS_SINGLE) {
        rp_process = RP_PROCESS_MASTER;
    }

#if !(RP_WIN32)

    if (rp_init_signals(cycle->log) != RP_OK) {
        return 1;
    }

    if (!rp_inherited && ccf->daemon) {
        if (rp_daemon(cycle->log) != RP_OK) {
            return 1;
        }

        rp_daemonized = 1;
    }

    if (rp_inherited) {
        rp_daemonized = 1;
    }

#endif

    if (rp_create_pidfile(&ccf->pid, cycle->log) != RP_OK) {
        return 1;
    }

    if (rp_log_redirect_stderr(cycle) != RP_OK) {
        return 1;
    }

    if (log->file->fd != rp_stderr) {
        if (rp_close_file(log->file->fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          rp_close_file_n " built-in log failed");
        }
    }

    rp_use_stderr = 0;

    if (rp_process == RP_PROCESS_SINGLE) {
        rp_single_process_cycle(cycle);

    } else {
        rp_master_process_cycle(cycle);
    }

    return 0;
}


static void
rp_show_version_info(void)
{
    rp_write_stderr("rap version: " RAP_VER_BUILD RP_LINEFEED);

    if (rp_show_help) {
        rp_write_stderr(
            "Usage: rap [-?hvVtTq] [-s signal] [-c filename] "
                         "[-p prefix] [-g directives]" RP_LINEFEED
                         RP_LINEFEED
            "Options:" RP_LINEFEED
            "  -?,-h         : this help" RP_LINEFEED
            "  -v            : show version and exit" RP_LINEFEED
            "  -V            : show version and configure options then exit"
                               RP_LINEFEED
            "  -t            : test configuration and exit" RP_LINEFEED
            "  -T            : test configuration, dump it and exit"
                               RP_LINEFEED
            "  -q            : suppress non-error messages "
                               "during configuration testing" RP_LINEFEED
            "  -s signal     : send signal to a master process: "
                               "stop, quit, reopen, reload" RP_LINEFEED
#ifdef RP_PREFIX
            "  -p prefix     : set prefix path (default: " RP_PREFIX ")"
                               RP_LINEFEED
#else
            "  -p prefix     : set prefix path (default: NONE)" RP_LINEFEED
#endif
            "  -c filename   : set configuration file (default: " RP_CONF_PATH
                               ")" RP_LINEFEED
            "  -g directives : set global directives out of configuration "
                               "file" RP_LINEFEED RP_LINEFEED
        );
    }

    if (rp_show_configure) {

#ifdef RP_COMPILER
        rp_write_stderr("built by " RP_COMPILER RP_LINEFEED);
#endif

#if (RP_SSL)
        if (rp_strcmp(rp_ssl_version(), OPENSSL_VERSION_TEXT) == 0) {
            rp_write_stderr("built with " OPENSSL_VERSION_TEXT RP_LINEFEED);
        } else {
            rp_write_stderr("built with " OPENSSL_VERSION_TEXT
                             " (running with ");
            rp_write_stderr((char *) (uintptr_t) rp_ssl_version());
            rp_write_stderr(")" RP_LINEFEED);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        rp_write_stderr("TLS SNI support enabled" RP_LINEFEED);
#else
        rp_write_stderr("TLS SNI support disabled" RP_LINEFEED);
#endif
#endif

        rp_write_stderr("configure arguments:" RP_CONFIGURE RP_LINEFEED);
    }
}


static rp_int_t
rp_add_inherited_sockets(rp_cycle_t *cycle)
{
    u_char           *p, *v, *inherited;
    rp_int_t         s;
    rp_listening_t  *ls;

    inherited = (u_char *) getenv(RAP_VAR);

    if (inherited == NULL) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_NOTICE, cycle->log, 0,
                  "using inherited sockets from \"%s\"", inherited);

    if (rp_array_init(&cycle->listening, cycle->pool, 10,
                       sizeof(rp_listening_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    for (p = inherited, v = p; *p; p++) {
        if (*p == ':' || *p == ';') {
            s = rp_atoi(v, p - v);
            if (s == RP_ERROR) {
                rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                              "invalid socket number \"%s\" in " RAP_VAR
                              " environment variable, ignoring the rest"
                              " of the variable", v);
                break;
            }

            v = p + 1;

            ls = rp_array_push(&cycle->listening);
            if (ls == NULL) {
                return RP_ERROR;
            }

            rp_memzero(ls, sizeof(rp_listening_t));

            ls->fd = (rp_socket_t) s;
        }
    }

    if (v != p) {
        rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                      "invalid socket number \"%s\" in " RAP_VAR
                      " environment variable, ignoring", v);
    }

    rp_inherited = 1;

    return rp_set_inherited_sockets(cycle);
}


char **
rp_set_environment(rp_cycle_t *cycle, rp_uint_t *last)
{
    char                **p, **env;
    rp_str_t            *var;
    rp_uint_t            i, n;
    rp_core_conf_t      *ccf;
    rp_pool_cleanup_t   *cln;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (last == NULL && ccf->environment) {
        return ccf->environment;
    }

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (rp_strcmp(var[i].data, "TZ") == 0
            || rp_strncmp(var[i].data, "TZ=", 3) == 0)
        {
            goto tz_found;
        }
    }

    var = rp_array_push(&ccf->env);
    if (var == NULL) {
        return NULL;
    }

    var->len = 2;
    var->data = (u_char *) "TZ";

    var = ccf->env.elts;

tz_found:

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            n++;
            continue;
        }

        for (p = rp_os_environ; *p; p++) {

            if (rp_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                n++;
                break;
            }
        }
    }

    if (last) {
        env = rp_alloc((*last + n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        *last = n;

    } else {
        cln = rp_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        env = rp_alloc((n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        cln->handler = rp_cleanup_environment;
        cln->data = env;
    }

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            env[n++] = (char *) var[i].data;
            continue;
        }

        for (p = rp_os_environ; *p; p++) {

            if (rp_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                env[n++] = *p;
                break;
            }
        }
    }

    env[n] = NULL;

    if (last == NULL) {
        ccf->environment = env;
        environ = env;
    }

    return env;
}


static void
rp_cleanup_environment(void *data)
{
    char  **env = data;

    if (environ == env) {

        /*
         * if the environment is still used, as it happens on exit,
         * the only option is to leak it
         */

        return;
    }

    rp_free(env);
}


rp_pid_t
rp_exec_new_binary(rp_cycle_t *cycle, char *const *argv)
{
    char             **env, *var;
    u_char            *p;
    rp_uint_t         i, n;
    rp_pid_t          pid;
    rp_exec_ctx_t     ctx;
    rp_core_conf_t   *ccf;
    rp_listening_t   *ls;

    rp_memzero(&ctx, sizeof(rp_exec_ctx_t));

    ctx.path = argv[0];
    ctx.name = "new binary process";
    ctx.argv = argv;

    n = 2;
    env = rp_set_environment(cycle, &n);
    if (env == NULL) {
        return RP_INVALID_PID;
    }

    var = rp_alloc(sizeof(RAP_VAR)
                    + cycle->listening.nelts * (RP_INT32_LEN + 1) + 2,
                    cycle->log);
    if (var == NULL) {
        rp_free(env);
        return RP_INVALID_PID;
    }

    p = rp_cpymem(var, RAP_VAR "=", sizeof(RAP_VAR));

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        p = rp_sprintf(p, "%ud;", ls[i].fd);
    }

    *p = '\0';

    env[n++] = var;

#if (RP_SETPROCTITLE_USES_ENV)

    /* allocate the spare 300 bytes for the new binary process title */

    env[n++] = "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#endif

    env[n] = NULL;

#if (RP_DEBUG)
    {
    char  **e;
    for (e = env; *e; e++) {
        rp_log_debug1(RP_LOG_DEBUG_CORE, cycle->log, 0, "env: %s", *e);
    }
    }
#endif

    ctx.envp = (char *const *) env;

    ccf = (rp_core_conf_t *) rp_get_conf(cycle->conf_ctx, rp_core_module);

    if (rp_rename_file(ccf->pid.data, ccf->oldpid.data) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                      rp_rename_file_n " %s to %s failed "
                      "before executing new binary process \"%s\"",
                      ccf->pid.data, ccf->oldpid.data, argv[0]);

        rp_free(env);
        rp_free(var);

        return RP_INVALID_PID;
    }

    pid = rp_execute(cycle, &ctx);

    if (pid == RP_INVALID_PID) {
        if (rp_rename_file(ccf->oldpid.data, ccf->pid.data)
            == RP_FILE_ERROR)
        {
            rp_log_error(RP_LOG_ALERT, cycle->log, rp_errno,
                          rp_rename_file_n " %s back to %s failed after "
                          "an attempt to execute new binary process \"%s\"",
                          ccf->oldpid.data, ccf->pid.data, argv[0]);
        }
    }

    rp_free(env);
    rp_free(var);

    return pid;
}


static rp_int_t
rp_get_options(int argc, char *const *argv)
{
    u_char     *p;
    rp_int_t   i;

    for (i = 1; i < argc; i++) {

        p = (u_char *) argv[i];

        if (*p++ != '-') {
            rp_log_stderr(0, "invalid option: \"%s\"", argv[i]);
            return RP_ERROR;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                rp_show_version = 1;
                rp_show_help = 1;
                break;

            case 'v':
                rp_show_version = 1;
                break;

            case 'V':
                rp_show_version = 1;
                rp_show_configure = 1;
                break;

            case 't':
                rp_test_config = 1;
                break;

            case 'T':
                rp_test_config = 1;
                rp_dump_config = 1;
                break;

            case 'q':
                rp_quiet_mode = 1;
                break;

            case 'p':
                if (*p) {
                    rp_prefix = p;
                    goto next;
                }

                if (argv[++i]) {
                    rp_prefix = (u_char *) argv[i];
                    goto next;
                }

                rp_log_stderr(0, "option \"-p\" requires directory name");
                return RP_ERROR;

            case 'c':
                if (*p) {
                    rp_conf_file = p;
                    goto next;
                }

                if (argv[++i]) {
                    rp_conf_file = (u_char *) argv[i];
                    goto next;
                }

                rp_log_stderr(0, "option \"-c\" requires file name");
                return RP_ERROR;

            case 'g':
                if (*p) {
                    rp_conf_params = p;
                    goto next;
                }

                if (argv[++i]) {
                    rp_conf_params = (u_char *) argv[i];
                    goto next;
                }

                rp_log_stderr(0, "option \"-g\" requires parameter");
                return RP_ERROR;

            case 's':
                if (*p) {
                    rp_signal = (char *) p;

                } else if (argv[++i]) {
                    rp_signal = argv[i];

                } else {
                    rp_log_stderr(0, "option \"-s\" requires parameter");
                    return RP_ERROR;
                }

                if (rp_strcmp(rp_signal, "stop") == 0
                    || rp_strcmp(rp_signal, "quit") == 0
                    || rp_strcmp(rp_signal, "reopen") == 0
                    || rp_strcmp(rp_signal, "reload") == 0)
                {
                    rp_process = RP_PROCESS_SIGNALLER;
                    goto next;
                }

                rp_log_stderr(0, "invalid option: \"-s %s\"", rp_signal);
                return RP_ERROR;

            default:
                rp_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
                return RP_ERROR;
            }
        }

    next:

        continue;
    }

    return RP_OK;
}


static rp_int_t
rp_save_argv(rp_cycle_t *cycle, int argc, char *const *argv)
{
#if (RP_FREEBSD)

    rp_os_argv = (char **) argv;
    rp_argc = argc;
    rp_argv = (char **) argv;

#else
    size_t     len;
    rp_int_t  i;

    rp_os_argv = (char **) argv;
    rp_argc = argc;

    rp_argv = rp_alloc((argc + 1) * sizeof(char *), cycle->log);
    if (rp_argv == NULL) {
        return RP_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = rp_strlen(argv[i]) + 1;

        rp_argv[i] = rp_alloc(len, cycle->log);
        if (rp_argv[i] == NULL) {
            return RP_ERROR;
        }

        (void) rp_cpystrn((u_char *) rp_argv[i], (u_char *) argv[i], len);
    }

    rp_argv[i] = NULL;

#endif

    rp_os_environ = environ;

    return RP_OK;
}


static rp_int_t
rp_process_options(rp_cycle_t *cycle)
{
    u_char  *p;
    size_t   len;

    if (rp_prefix) {
        len = rp_strlen(rp_prefix);
        p = rp_prefix;

        if (len && !rp_path_separator(p[len - 1])) {
            p = rp_pnalloc(cycle->pool, len + 1);
            if (p == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(p, rp_prefix, len);
            p[len++] = '/';
        }

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

    } else {

#ifndef RP_PREFIX

        p = rp_pnalloc(cycle->pool, RP_MAX_PATH);
        if (p == NULL) {
            return RP_ERROR;
        }

        if (rp_getcwd(p, RP_MAX_PATH) == 0) {
            rp_log_stderr(rp_errno, "[emerg]: " rp_getcwd_n " failed");
            return RP_ERROR;
        }

        len = rp_strlen(p);

        p[len++] = '/';

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

#else

#ifdef RP_CONF_PREFIX
        rp_str_set(&cycle->conf_prefix, RP_CONF_PREFIX);
#else
        rp_str_set(&cycle->conf_prefix, RP_PREFIX);
#endif
        rp_str_set(&cycle->prefix, RP_PREFIX);

#endif
    }

    if (rp_conf_file) {
        cycle->conf_file.len = rp_strlen(rp_conf_file);
        cycle->conf_file.data = rp_conf_file;

    } else {
        rp_str_set(&cycle->conf_file, RP_CONF_PATH);
    }

    if (rp_conf_full_name(cycle, &cycle->conf_file, 0) != RP_OK) {
        return RP_ERROR;
    }

    for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
         p > cycle->conf_file.data;
         p--)
    {
        if (rp_path_separator(*p)) {
            cycle->conf_prefix.len = p - cycle->conf_file.data + 1;
            cycle->conf_prefix.data = cycle->conf_file.data;
            break;
        }
    }

    if (rp_conf_params) {
        cycle->conf_param.len = rp_strlen(rp_conf_params);
        cycle->conf_param.data = rp_conf_params;
    }

    if (rp_test_config) {
        cycle->log->log_level = RP_LOG_INFO;
    }

    return RP_OK;
}


static void *
rp_core_module_create_conf(rp_cycle_t *cycle)
{
    rp_core_conf_t  *ccf;

    ccf = rp_pcalloc(cycle->pool, sizeof(rp_core_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc()
     *
     *     ccf->pid = NULL;
     *     ccf->oldpid = NULL;
     *     ccf->priority = 0;
     *     ccf->cpu_affinity_auto = 0;
     *     ccf->cpu_affinity_n = 0;
     *     ccf->cpu_affinity = NULL;
     */

    ccf->daemon = RP_CONF_UNSET;
    ccf->master = RP_CONF_UNSET;
    ccf->timer_resolution = RP_CONF_UNSET_MSEC;
    ccf->shutdown_timeout = RP_CONF_UNSET_MSEC;

    ccf->worker_processes = RP_CONF_UNSET;
    ccf->debug_points = RP_CONF_UNSET;

    ccf->rlimit_nofile = RP_CONF_UNSET;
    ccf->rlimit_core = RP_CONF_UNSET;

    ccf->user = (rp_uid_t) RP_CONF_UNSET_UINT;
    ccf->group = (rp_gid_t) RP_CONF_UNSET_UINT;

    if (rp_array_init(&ccf->env, cycle->pool, 1, sizeof(rp_str_t))
        != RP_OK)
    {
        return NULL;
    }

    return ccf;
}


static char *
rp_core_module_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_core_conf_t  *ccf = conf;

    rp_conf_init_value(ccf->daemon, 1);
    rp_conf_init_value(ccf->master, 1);
    rp_conf_init_msec_value(ccf->timer_resolution, 0);
    rp_conf_init_msec_value(ccf->shutdown_timeout, 0);

    rp_conf_init_value(ccf->worker_processes, 1);
    rp_conf_init_value(ccf->debug_points, 0);

#if (RP_HAVE_CPU_AFFINITY)

    if (!ccf->cpu_affinity_auto
        && ccf->cpu_affinity_n
        && ccf->cpu_affinity_n != 1
        && ccf->cpu_affinity_n != (rp_uint_t) ccf->worker_processes)
    {
        rp_log_error(RP_LOG_WARN, cycle->log, 0,
                      "the number of \"worker_processes\" is not equal to "
                      "the number of \"worker_cpu_affinity\" masks, "
                      "using last mask for remaining worker processes");
    }

#endif


    if (ccf->pid.len == 0) {
        rp_str_set(&ccf->pid, RP_PID_PATH);
    }

    if (rp_conf_full_name(cycle, &ccf->pid, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    ccf->oldpid.len = ccf->pid.len + sizeof(RP_OLDPID_EXT);

    ccf->oldpid.data = rp_pnalloc(cycle->pool, ccf->oldpid.len);
    if (ccf->oldpid.data == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memcpy(rp_cpymem(ccf->oldpid.data, ccf->pid.data, ccf->pid.len),
               RP_OLDPID_EXT, sizeof(RP_OLDPID_EXT));


#if !(RP_WIN32)

    if (ccf->user == (uid_t) RP_CONF_UNSET_UINT && geteuid() == 0) {
        struct group   *grp;
        struct passwd  *pwd;

        rp_set_errno(0);
        pwd = getpwnam(RP_USER);
        if (pwd == NULL) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "getpwnam(\"" RP_USER "\") failed");
            return RP_CONF_ERROR;
        }

        ccf->username = RP_USER;
        ccf->user = pwd->pw_uid;

        rp_set_errno(0);
        grp = getgrnam(RP_GROUP);
        if (grp == NULL) {
            rp_log_error(RP_LOG_EMERG, cycle->log, rp_errno,
                          "getgrnam(\"" RP_GROUP "\") failed");
            return RP_CONF_ERROR;
        }

        ccf->group = grp->gr_gid;
    }


    if (ccf->lock_file.len == 0) {
        rp_str_set(&ccf->lock_file, RP_LOCK_PATH);
    }

    if (rp_conf_full_name(cycle, &ccf->lock_file, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    {
    rp_str_t  lock_file;

    lock_file = cycle->old_cycle->lock_file;

    if (lock_file.len) {
        lock_file.len--;

        if (ccf->lock_file.len != lock_file.len
            || rp_strncmp(ccf->lock_file.data, lock_file.data, lock_file.len)
               != 0)
        {
            rp_log_error(RP_LOG_EMERG, cycle->log, 0,
                          "\"lock_file\" could not be changed, ignored");
        }

        cycle->lock_file.len = lock_file.len + 1;
        lock_file.len += sizeof(".accept");

        cycle->lock_file.data = rp_pstrdup(cycle->pool, &lock_file);
        if (cycle->lock_file.data == NULL) {
            return RP_CONF_ERROR;
        }

    } else {
        cycle->lock_file.len = ccf->lock_file.len + 1;
        cycle->lock_file.data = rp_pnalloc(cycle->pool,
                                      ccf->lock_file.len + sizeof(".accept"));
        if (cycle->lock_file.data == NULL) {
            return RP_CONF_ERROR;
        }

        rp_memcpy(rp_cpymem(cycle->lock_file.data, ccf->lock_file.data,
                              ccf->lock_file.len),
                   ".accept", sizeof(".accept"));
    }
    }

#endif

    return RP_CONF_OK;
}


static char *
rp_set_user(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
#if (RP_WIN32)

    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "\"user\" is not supported, ignored");

    return RP_CONF_OK;

#else

    rp_core_conf_t  *ccf = conf;

    char             *group;
    struct passwd    *pwd;
    struct group     *grp;
    rp_str_t        *value;

    if (ccf->user != (uid_t) RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (geteuid() != 0) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "the \"user\" directive makes sense only "
                           "if the master process runs "
                           "with super-user privileges, ignored");
        return RP_CONF_OK;
    }

    value = cf->args->elts;

    ccf->username = (char *) value[1].data;

    rp_set_errno(0);
    pwd = getpwnam((const char *) value[1].data);
    if (pwd == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, rp_errno,
                           "getpwnam(\"%s\") failed", value[1].data);
        return RP_CONF_ERROR;
    }

    ccf->user = pwd->pw_uid;

    group = (char *) ((cf->args->nelts == 2) ? value[1].data : value[2].data);

    rp_set_errno(0);
    grp = getgrnam(group);
    if (grp == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, rp_errno,
                           "getgrnam(\"%s\") failed", group);
        return RP_CONF_ERROR;
    }

    ccf->group = grp->gr_gid;

    return RP_CONF_OK;

#endif
}


static char *
rp_set_env(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_core_conf_t  *ccf = conf;

    rp_str_t   *value, *var;
    rp_uint_t   i;

    var = rp_array_push(&ccf->env);
    if (var == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;
    *var = value[1];

    for (i = 0; i < value[1].len; i++) {

        if (value[1].data[i] == '=') {

            var->len = i;

            return RP_CONF_OK;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_set_priority(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_core_conf_t  *ccf = conf;

    rp_str_t        *value;
    rp_uint_t        n, minus;

    if (ccf->priority != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].data[0] == '-') {
        n = 1;
        minus = 1;

    } else if (value[1].data[0] == '+') {
        n = 1;
        minus = 0;

    } else {
        n = 0;
        minus = 0;
    }

    ccf->priority = rp_atoi(&value[1].data[n], value[1].len - n);
    if (ccf->priority == RP_ERROR) {
        return "invalid number";
    }

    if (minus) {
        ccf->priority = -ccf->priority;
    }

    return RP_CONF_OK;
}


static char *
rp_set_cpu_affinity(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
#if (RP_HAVE_CPU_AFFINITY)
    rp_core_conf_t  *ccf = conf;

    u_char            ch, *p;
    rp_str_t        *value;
    rp_uint_t        i, n;
    rp_cpuset_t     *mask;

    if (ccf->cpu_affinity) {
        return "is duplicate";
    }

    mask = rp_palloc(cf->pool, (cf->args->nelts - 1) * sizeof(rp_cpuset_t));
    if (mask == NULL) {
        return RP_CONF_ERROR;
    }

    ccf->cpu_affinity_n = cf->args->nelts - 1;
    ccf->cpu_affinity = mask;

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "auto") == 0) {

        if (cf->args->nelts > 3) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid number of arguments in "
                               "\"worker_cpu_affinity\" directive");
            return RP_CONF_ERROR;
        }

        ccf->cpu_affinity_auto = 1;

        CPU_ZERO(&mask[0]);
        for (i = 0; i < (rp_uint_t) rp_min(rp_ncpu, CPU_SETSIZE); i++) {
            CPU_SET(i, &mask[0]);
        }

        n = 2;

    } else {
        n = 1;
    }

    for ( /* void */ ; n < cf->args->nelts; n++) {

        if (value[n].len > CPU_SETSIZE) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                         "\"worker_cpu_affinity\" supports up to %d CPUs only",
                         CPU_SETSIZE);
            return RP_CONF_ERROR;
        }

        i = 0;
        CPU_ZERO(&mask[n - 1]);

        for (p = value[n].data + value[n].len - 1;
             p >= value[n].data;
             p--)
        {
            ch = *p;

            if (ch == ' ') {
                continue;
            }

            i++;

            if (ch == '0') {
                continue;
            }

            if (ch == '1') {
                CPU_SET(i - 1, &mask[n - 1]);
                continue;
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                          "invalid character \"%c\" in \"worker_cpu_affinity\"",
                          ch);
            return RP_CONF_ERROR;
        }
    }

#else

    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "\"worker_cpu_affinity\" is not supported "
                       "on this platform, ignored");
#endif

    return RP_CONF_OK;
}


rp_cpuset_t *
rp_get_cpu_affinity(rp_uint_t n)
{
#if (RP_HAVE_CPU_AFFINITY)
    rp_uint_t        i, j;
    rp_cpuset_t     *mask;
    rp_core_conf_t  *ccf;

    static rp_cpuset_t  result;

    ccf = (rp_core_conf_t *) rp_get_conf(rp_cycle->conf_ctx,
                                           rp_core_module);

    if (ccf->cpu_affinity == NULL) {
        return NULL;
    }

    if (ccf->cpu_affinity_auto) {
        mask = &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

        for (i = 0, j = n; /* void */ ; i++) {

            if (CPU_ISSET(i % CPU_SETSIZE, mask) && j-- == 0) {
                break;
            }

            if (i == CPU_SETSIZE && j == n) {
                /* empty mask */
                return NULL;
            }

            /* void */
        }

        CPU_ZERO(&result);
        CPU_SET(i % CPU_SETSIZE, &result);

        return &result;
    }

    if (ccf->cpu_affinity_n > n) {
        return &ccf->cpu_affinity[n];
    }

    return &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

#else

    return NULL;

#endif
}


static char *
rp_set_worker_processes(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_str_t        *value;
    rp_core_conf_t  *ccf;

    ccf = (rp_core_conf_t *) conf;

    if (ccf->worker_processes != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "auto") == 0) {
        ccf->worker_processes = rp_ncpu;
        return RP_CONF_OK;
    }

    ccf->worker_processes = rp_atoi(value[1].data, value[1].len);

    if (ccf->worker_processes == RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


static char *
rp_load_module(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
#if (RP_HAVE_DLOPEN)
    void                *handle;
    char               **names, **order;
    rp_str_t           *value, file;
    rp_uint_t           i;
    rp_module_t        *module, **modules;
    rp_pool_cleanup_t  *cln;

    if (cf->cycle->modules_used) {
        return "is specified too late";
    }

    value = cf->args->elts;

    file = value[1];

    if (rp_conf_full_name(cf->cycle, &file, 0) != RP_OK) {
        return RP_CONF_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->cycle->pool, 0);
    if (cln == NULL) {
        return RP_CONF_ERROR;
    }

    handle = rp_dlopen(file.data);
    if (handle == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           rp_dlopen_n " \"%s\" failed (%s)",
                           file.data, rp_dlerror());
        return RP_CONF_ERROR;
    }

    cln->handler = rp_unload_module;
    cln->data = handle;

    modules = rp_dlsym(handle, "rp_modules");
    if (modules == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           rp_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "rp_modules", rp_dlerror());
        return RP_CONF_ERROR;
    }

    names = rp_dlsym(handle, "rp_module_names");
    if (names == NULL) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           rp_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "rp_module_names", rp_dlerror());
        return RP_CONF_ERROR;
    }

    order = rp_dlsym(handle, "rp_module_order");

    for (i = 0; modules[i]; i++) {
        module = modules[i];
        module->name = names[i];

        if (rp_add_module(cf, &file, module, order) != RP_OK) {
            return RP_CONF_ERROR;
        }

        rp_log_debug2(RP_LOG_DEBUG_CORE, cf->log, 0, "module: %s i:%ui",
                       module->name, module->index);
    }

    return RP_CONF_OK;

#else

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "\"load_module\" is not supported "
                       "on this platform");
    return RP_CONF_ERROR;

#endif
}


#if (RP_HAVE_DLOPEN)

static void
rp_unload_module(void *data)
{
    void  *handle = data;

    if (rp_dlclose(handle) != 0) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, 0,
                      rp_dlclose_n " failed (%s)", rp_dlerror());
    }
}

#endif
