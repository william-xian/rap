
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap.h>


static void rap_show_version_info(void);
static rap_int_t rap_add_inherited_sockets(rap_cycle_t *cycle);
static void rap_cleanup_environment(void *data);
static rap_int_t rap_get_options(int argc, char *const *argv);
static rap_int_t rap_process_options(rap_cycle_t *cycle);
static rap_int_t rap_save_argv(rap_cycle_t *cycle, int argc, char *const *argv);
static void *rap_core_module_create_conf(rap_cycle_t *cycle);
static char *rap_core_module_init_conf(rap_cycle_t *cycle, void *conf);
static char *rap_set_user(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_set_env(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_set_priority(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_set_cpu_affinity(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_set_worker_processes(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_load_module(rap_conf_t *cf, rap_command_t *cmd, void *conf);
#if (RAP_HAVE_DLOPEN)
static void rap_unload_module(void *data);
#endif


static rap_conf_enum_t  rap_debug_points[] = {
    { rap_string("stop"), RAP_DEBUG_POINTS_STOP },
    { rap_string("abort"), RAP_DEBUG_POINTS_ABORT },
    { rap_null_string, 0 }
};


static rap_command_t  rap_core_commands[] = {

    { rap_string("daemon"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      0,
      offsetof(rap_core_conf_t, daemon),
      NULL },

    { rap_string("master_process"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      0,
      offsetof(rap_core_conf_t, master),
      NULL },

    { rap_string("timer_resolution"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      0,
      offsetof(rap_core_conf_t, timer_resolution),
      NULL },

    { rap_string("pid"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      0,
      offsetof(rap_core_conf_t, pid),
      NULL },

    { rap_string("lock_file"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      0,
      offsetof(rap_core_conf_t, lock_file),
      NULL },

    { rap_string("worker_processes"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_set_worker_processes,
      0,
      0,
      NULL },

    { rap_string("debug_points"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      0,
      offsetof(rap_core_conf_t, debug_points),
      &rap_debug_points },

    { rap_string("user"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE12,
      rap_set_user,
      0,
      0,
      NULL },

    { rap_string("worker_priority"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_set_priority,
      0,
      0,
      NULL },

    { rap_string("worker_cpu_affinity"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_1MORE,
      rap_set_cpu_affinity,
      0,
      0,
      NULL },

    { rap_string("worker_rlimit_nofile"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      0,
      offsetof(rap_core_conf_t, rlimit_nofile),
      NULL },

    { rap_string("worker_rlimit_core"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      0,
      offsetof(rap_core_conf_t, rlimit_core),
      NULL },

    { rap_string("worker_shutdown_timeout"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      0,
      offsetof(rap_core_conf_t, shutdown_timeout),
      NULL },

    { rap_string("working_directory"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      0,
      offsetof(rap_core_conf_t, working_directory),
      NULL },

    { rap_string("env"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_set_env,
      0,
      0,
      NULL },

    { rap_string("load_module"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_TAKE1,
      rap_load_module,
      0,
      0,
      NULL },

      rap_null_command
};


static rap_core_module_t  rap_core_module_ctx = {
    rap_string("core"),
    rap_core_module_create_conf,
    rap_core_module_init_conf
};


rap_module_t  rap_core_module = {
    RAP_MODULE_V1,
    &rap_core_module_ctx,                  /* module context */
    rap_core_commands,                     /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_uint_t   rap_show_help;
static rap_uint_t   rap_show_version;
static rap_uint_t   rap_show_configure;
static u_char      *rap_prefix;
static u_char      *rap_conf_file;
static u_char      *rap_conf_params;
static char        *rap_signal;


static char **rap_os_environ;


int rap_cdecl
main(int argc, char *const *argv)
{
    rap_buf_t        *b;
    rap_log_t        *log;
    rap_uint_t        i;
    rap_cycle_t      *cycle, init_cycle;
    rap_conf_dump_t  *cd;
    rap_core_conf_t  *ccf;

    rap_debug_init();

    if (rap_strerror_init() != RAP_OK) {
        return 1;
    }

    if (rap_get_options(argc, argv) != RAP_OK) {
        return 1;
    }

    if (rap_show_version) {
        rap_show_version_info();

        if (!rap_test_config) {
            return 0;
        }
    }

    /* TODO */ rap_max_sockets = -1;

    rap_time_init();

#if (RAP_PCRE)
    rap_regex_init();
#endif

    rap_pid = rap_getpid();
    rap_parent = rap_getppid();

    log = rap_log_init(rap_prefix);
    if (log == NULL) {
        return 1;
    }

    /* STUB */
#if (RAP_OPENSSL)
    rap_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * rap_process_options()
     */

    rap_memzero(&init_cycle, sizeof(rap_cycle_t));
    init_cycle.log = log;
    rap_cycle = &init_cycle;

    init_cycle.pool = rap_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    if (rap_save_argv(&init_cycle, argc, argv) != RAP_OK) {
        return 1;
    }

    if (rap_process_options(&init_cycle) != RAP_OK) {
        return 1;
    }

    if (rap_os_init(log) != RAP_OK) {
        return 1;
    }

    /*
     * rap_crc32_table_init() requires rap_cacheline_size set in rap_os_init()
     */

    if (rap_crc32_table_init() != RAP_OK) {
        return 1;
    }

    /*
     * rap_slab_sizes_init() requires rap_pagesize set in rap_os_init()
     */

    rap_slab_sizes_init();

    if (rap_add_inherited_sockets(&init_cycle) != RAP_OK) {
        return 1;
    }

    if (rap_preinit_modules() != RAP_OK) {
        return 1;
    }

    cycle = rap_init_cycle(&init_cycle);
    if (cycle == NULL) {
        if (rap_test_config) {
            rap_log_stderr(0, "configuration file %s test failed",
                           init_cycle.conf_file.data);
        }

        return 1;
    }

    if (rap_test_config) {
        if (!rap_quiet_mode) {
            rap_log_stderr(0, "configuration file %s test is successful",
                           cycle->conf_file.data);
        }

        if (rap_dump_config) {
            cd = cycle->config_dump.elts;

            for (i = 0; i < cycle->config_dump.nelts; i++) {

                rap_write_stdout("# configuration file ");
                (void) rap_write_fd(rap_stdout, cd[i].name.data,
                                    cd[i].name.len);
                rap_write_stdout(":" RAP_LINEFEED);

                b = cd[i].buffer;

                (void) rap_write_fd(rap_stdout, b->pos, b->last - b->pos);
                rap_write_stdout(RAP_LINEFEED);
            }
        }

        return 0;
    }

    if (rap_signal) {
        return rap_signal_process(cycle, rap_signal);
    }

    rap_os_status(cycle->log);

    rap_cycle = cycle;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (ccf->master && rap_process == RAP_PROCESS_SINGLE) {
        rap_process = RAP_PROCESS_MASTER;
    }

#if !(RAP_WIN32)

    if (rap_init_signals(cycle->log) != RAP_OK) {
        return 1;
    }

    if (!rap_inherited && ccf->daemon) {
        if (rap_daemon(cycle->log) != RAP_OK) {
            return 1;
        }

        rap_daemonized = 1;
    }

    if (rap_inherited) {
        rap_daemonized = 1;
    }

#endif

    if (rap_create_pidfile(&ccf->pid, cycle->log) != RAP_OK) {
        return 1;
    }

    if (rap_log_redirect_stderr(cycle) != RAP_OK) {
        return 1;
    }

    if (log->file->fd != rap_stderr) {
        if (rap_close_file(log->file->fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          rap_close_file_n " built-in log failed");
        }
    }

    rap_use_stderr = 0;

    if (rap_process == RAP_PROCESS_SINGLE) {
        rap_single_process_cycle(cycle);

    } else {
        rap_master_process_cycle(cycle);
    }

    return 0;
}


static void
rap_show_version_info(void)
{
    rap_write_stderr("rap version: " RAP_VER_BUILD RAP_LINEFEED);

    if (rap_show_help) {
        rap_write_stderr(
            "Usage: rap [-?hvVtTq] [-s signal] [-c filename] "
                         "[-p prefix] [-g directives]" RAP_LINEFEED
                         RAP_LINEFEED
            "Options:" RAP_LINEFEED
            "  -?,-h         : this help" RAP_LINEFEED
            "  -v            : show version and exit" RAP_LINEFEED
            "  -V            : show version and configure options then exit"
                               RAP_LINEFEED
            "  -t            : test configuration and exit" RAP_LINEFEED
            "  -T            : test configuration, dump it and exit"
                               RAP_LINEFEED
            "  -q            : suppress non-error messages "
                               "during configuration testing" RAP_LINEFEED
            "  -s signal     : send signal to a master process: "
                               "stop, quit, reopen, reload" RAP_LINEFEED
#ifdef RAP_PREFIX
            "  -p prefix     : set prefix path (default: " RAP_PREFIX ")"
                               RAP_LINEFEED
#else
            "  -p prefix     : set prefix path (default: NONE)" RAP_LINEFEED
#endif
            "  -c filename   : set configuration file (default: " RAP_CONF_PATH
                               ")" RAP_LINEFEED
            "  -g directives : set global directives out of configuration "
                               "file" RAP_LINEFEED RAP_LINEFEED
        );
    }

    if (rap_show_configure) {

#ifdef RAP_COMPILER
        rap_write_stderr("built by " RAP_COMPILER RAP_LINEFEED);
#endif

#if (RAP_SSL)
        if (rap_strcmp(rap_ssl_version(), OPENSSL_VERSION_TEXT) == 0) {
            rap_write_stderr("built with " OPENSSL_VERSION_TEXT RAP_LINEFEED);
        } else {
            rap_write_stderr("built with " OPENSSL_VERSION_TEXT
                             " (running with ");
            rap_write_stderr((char *) (uintptr_t) rap_ssl_version());
            rap_write_stderr(")" RAP_LINEFEED);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        rap_write_stderr("TLS SNI support enabled" RAP_LINEFEED);
#else
        rap_write_stderr("TLS SNI support disabled" RAP_LINEFEED);
#endif
#endif

        rap_write_stderr("configure arguments:" RAP_CONFIGURE RAP_LINEFEED);
    }
}


static rap_int_t
rap_add_inherited_sockets(rap_cycle_t *cycle)
{
    u_char           *p, *v, *inherited;
    rap_int_t         s;
    rap_listening_t  *ls;

    inherited = (u_char *) getenv(RAP_VAR);

    if (inherited == NULL) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_NOTICE, cycle->log, 0,
                  "using inherited sockets from \"%s\"", inherited);

    if (rap_array_init(&cycle->listening, cycle->pool, 10,
                       sizeof(rap_listening_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    for (p = inherited, v = p; *p; p++) {
        if (*p == ':' || *p == ';') {
            s = rap_atoi(v, p - v);
            if (s == RAP_ERROR) {
                rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                              "invalid socket number \"%s\" in " RAP_VAR
                              " environment variable, ignoring the rest"
                              " of the variable", v);
                break;
            }

            v = p + 1;

            ls = rap_array_push(&cycle->listening);
            if (ls == NULL) {
                return RAP_ERROR;
            }

            rap_memzero(ls, sizeof(rap_listening_t));

            ls->fd = (rap_socket_t) s;
        }
    }

    if (v != p) {
        rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                      "invalid socket number \"%s\" in " RAP_VAR
                      " environment variable, ignoring", v);
    }

    rap_inherited = 1;

    return rap_set_inherited_sockets(cycle);
}


char **
rap_set_environment(rap_cycle_t *cycle, rap_uint_t *last)
{
    char                **p, **env;
    rap_str_t            *var;
    rap_uint_t            i, n;
    rap_core_conf_t      *ccf;
    rap_pool_cleanup_t   *cln;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (last == NULL && ccf->environment) {
        return ccf->environment;
    }

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (rap_strcmp(var[i].data, "TZ") == 0
            || rap_strncmp(var[i].data, "TZ=", 3) == 0)
        {
            goto tz_found;
        }
    }

    var = rap_array_push(&ccf->env);
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

        for (p = rap_os_environ; *p; p++) {

            if (rap_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                n++;
                break;
            }
        }
    }

    if (last) {
        env = rap_alloc((*last + n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        *last = n;

    } else {
        cln = rap_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        env = rap_alloc((n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        cln->handler = rap_cleanup_environment;
        cln->data = env;
    }

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            env[n++] = (char *) var[i].data;
            continue;
        }

        for (p = rap_os_environ; *p; p++) {

            if (rap_strncmp(*p, var[i].data, var[i].len) == 0
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
rap_cleanup_environment(void *data)
{
    char  **env = data;

    if (environ == env) {

        /*
         * if the environment is still used, as it happens on exit,
         * the only option is to leak it
         */

        return;
    }

    rap_free(env);
}


rap_pid_t
rap_exec_new_binary(rap_cycle_t *cycle, char *const *argv)
{
    char             **env, *var;
    u_char            *p;
    rap_uint_t         i, n;
    rap_pid_t          pid;
    rap_exec_ctx_t     ctx;
    rap_core_conf_t   *ccf;
    rap_listening_t   *ls;

    rap_memzero(&ctx, sizeof(rap_exec_ctx_t));

    ctx.path = argv[0];
    ctx.name = "new binary process";
    ctx.argv = argv;

    n = 2;
    env = rap_set_environment(cycle, &n);
    if (env == NULL) {
        return RAP_INVALID_PID;
    }

    var = rap_alloc(sizeof(RAP_VAR)
                    + cycle->listening.nelts * (RAP_INT32_LEN + 1) + 2,
                    cycle->log);
    if (var == NULL) {
        rap_free(env);
        return RAP_INVALID_PID;
    }

    p = rap_cpymem(var, RAP_VAR "=", sizeof(RAP_VAR));

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        p = rap_sprintf(p, "%ud;", ls[i].fd);
    }

    *p = '\0';

    env[n++] = var;

#if (RAP_SETPROCTITLE_USES_ENV)

    /* allocate the spare 300 bytes for the new binary process title */

    env[n++] = "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#endif

    env[n] = NULL;

#if (RAP_DEBUG)
    {
    char  **e;
    for (e = env; *e; e++) {
        rap_log_debug1(RAP_LOG_DEBUG_CORE, cycle->log, 0, "env: %s", *e);
    }
    }
#endif

    ctx.envp = (char *const *) env;

    ccf = (rap_core_conf_t *) rap_get_conf(cycle->conf_ctx, rap_core_module);

    if (rap_rename_file(ccf->pid.data, ccf->oldpid.data) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                      rap_rename_file_n " %s to %s failed "
                      "before executing new binary process \"%s\"",
                      ccf->pid.data, ccf->oldpid.data, argv[0]);

        rap_free(env);
        rap_free(var);

        return RAP_INVALID_PID;
    }

    pid = rap_execute(cycle, &ctx);

    if (pid == RAP_INVALID_PID) {
        if (rap_rename_file(ccf->oldpid.data, ccf->pid.data)
            == RAP_FILE_ERROR)
        {
            rap_log_error(RAP_LOG_ALERT, cycle->log, rap_errno,
                          rap_rename_file_n " %s back to %s failed after "
                          "an attempt to execute new binary process \"%s\"",
                          ccf->oldpid.data, ccf->pid.data, argv[0]);
        }
    }

    rap_free(env);
    rap_free(var);

    return pid;
}


static rap_int_t
rap_get_options(int argc, char *const *argv)
{
    u_char     *p;
    rap_int_t   i;

    for (i = 1; i < argc; i++) {

        p = (u_char *) argv[i];

        if (*p++ != '-') {
            rap_log_stderr(0, "invalid option: \"%s\"", argv[i]);
            return RAP_ERROR;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                rap_show_version = 1;
                rap_show_help = 1;
                break;

            case 'v':
                rap_show_version = 1;
                break;

            case 'V':
                rap_show_version = 1;
                rap_show_configure = 1;
                break;

            case 't':
                rap_test_config = 1;
                break;

            case 'T':
                rap_test_config = 1;
                rap_dump_config = 1;
                break;

            case 'q':
                rap_quiet_mode = 1;
                break;

            case 'p':
                if (*p) {
                    rap_prefix = p;
                    goto next;
                }

                if (argv[++i]) {
                    rap_prefix = (u_char *) argv[i];
                    goto next;
                }

                rap_log_stderr(0, "option \"-p\" requires directory name");
                return RAP_ERROR;

            case 'c':
                if (*p) {
                    rap_conf_file = p;
                    goto next;
                }

                if (argv[++i]) {
                    rap_conf_file = (u_char *) argv[i];
                    goto next;
                }

                rap_log_stderr(0, "option \"-c\" requires file name");
                return RAP_ERROR;

            case 'g':
                if (*p) {
                    rap_conf_params = p;
                    goto next;
                }

                if (argv[++i]) {
                    rap_conf_params = (u_char *) argv[i];
                    goto next;
                }

                rap_log_stderr(0, "option \"-g\" requires parameter");
                return RAP_ERROR;

            case 's':
                if (*p) {
                    rap_signal = (char *) p;

                } else if (argv[++i]) {
                    rap_signal = argv[i];

                } else {
                    rap_log_stderr(0, "option \"-s\" requires parameter");
                    return RAP_ERROR;
                }

                if (rap_strcmp(rap_signal, "stop") == 0
                    || rap_strcmp(rap_signal, "quit") == 0
                    || rap_strcmp(rap_signal, "reopen") == 0
                    || rap_strcmp(rap_signal, "reload") == 0)
                {
                    rap_process = RAP_PROCESS_SIGNALLER;
                    goto next;
                }

                rap_log_stderr(0, "invalid option: \"-s %s\"", rap_signal);
                return RAP_ERROR;

            default:
                rap_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
                return RAP_ERROR;
            }
        }

    next:

        continue;
    }

    return RAP_OK;
}


static rap_int_t
rap_save_argv(rap_cycle_t *cycle, int argc, char *const *argv)
{
#if (RAP_FREEBSD)

    rap_os_argv = (char **) argv;
    rap_argc = argc;
    rap_argv = (char **) argv;

#else
    size_t     len;
    rap_int_t  i;

    rap_os_argv = (char **) argv;
    rap_argc = argc;

    rap_argv = rap_alloc((argc + 1) * sizeof(char *), cycle->log);
    if (rap_argv == NULL) {
        return RAP_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = rap_strlen(argv[i]) + 1;

        rap_argv[i] = rap_alloc(len, cycle->log);
        if (rap_argv[i] == NULL) {
            return RAP_ERROR;
        }

        (void) rap_cpystrn((u_char *) rap_argv[i], (u_char *) argv[i], len);
    }

    rap_argv[i] = NULL;

#endif

    rap_os_environ = environ;

    return RAP_OK;
}


static rap_int_t
rap_process_options(rap_cycle_t *cycle)
{
    u_char  *p;
    size_t   len;

    if (rap_prefix) {
        len = rap_strlen(rap_prefix);
        p = rap_prefix;

        if (len && !rap_path_separator(p[len - 1])) {
            p = rap_pnalloc(cycle->pool, len + 1);
            if (p == NULL) {
                return RAP_ERROR;
            }

            rap_memcpy(p, rap_prefix, len);
            p[len++] = '/';
        }

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

    } else {

#ifndef RAP_PREFIX

        p = rap_pnalloc(cycle->pool, RAP_MAX_PATH);
        if (p == NULL) {
            return RAP_ERROR;
        }

        if (rap_getcwd(p, RAP_MAX_PATH) == 0) {
            rap_log_stderr(rap_errno, "[emerg]: " rap_getcwd_n " failed");
            return RAP_ERROR;
        }

        len = rap_strlen(p);

        p[len++] = '/';

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

#else

#ifdef RAP_CONF_PREFIX
        rap_str_set(&cycle->conf_prefix, RAP_CONF_PREFIX);
#else
        rap_str_set(&cycle->conf_prefix, RAP_PREFIX);
#endif
        rap_str_set(&cycle->prefix, RAP_PREFIX);

#endif
    }

    if (rap_conf_file) {
        cycle->conf_file.len = rap_strlen(rap_conf_file);
        cycle->conf_file.data = rap_conf_file;

    } else {
        rap_str_set(&cycle->conf_file, RAP_CONF_PATH);
    }

    if (rap_conf_full_name(cycle, &cycle->conf_file, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
         p > cycle->conf_file.data;
         p--)
    {
        if (rap_path_separator(*p)) {
            cycle->conf_prefix.len = p - cycle->conf_file.data + 1;
            cycle->conf_prefix.data = cycle->conf_file.data;
            break;
        }
    }

    if (rap_conf_params) {
        cycle->conf_param.len = rap_strlen(rap_conf_params);
        cycle->conf_param.data = rap_conf_params;
    }

    if (rap_test_config) {
        cycle->log->log_level = RAP_LOG_INFO;
    }

    return RAP_OK;
}


static void *
rap_core_module_create_conf(rap_cycle_t *cycle)
{
    rap_core_conf_t  *ccf;

    ccf = rap_pcalloc(cycle->pool, sizeof(rap_core_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc()
     *
     *     ccf->pid = NULL;
     *     ccf->oldpid = NULL;
     *     ccf->priority = 0;
     *     ccf->cpu_affinity_auto = 0;
     *     ccf->cpu_affinity_n = 0;
     *     ccf->cpu_affinity = NULL;
     */

    ccf->daemon = RAP_CONF_UNSET;
    ccf->master = RAP_CONF_UNSET;
    ccf->timer_resolution = RAP_CONF_UNSET_MSEC;
    ccf->shutdown_timeout = RAP_CONF_UNSET_MSEC;

    ccf->worker_processes = RAP_CONF_UNSET;
    ccf->debug_points = RAP_CONF_UNSET;

    ccf->rlimit_nofile = RAP_CONF_UNSET;
    ccf->rlimit_core = RAP_CONF_UNSET;

    ccf->user = (rap_uid_t) RAP_CONF_UNSET_UINT;
    ccf->group = (rap_gid_t) RAP_CONF_UNSET_UINT;

    if (rap_array_init(&ccf->env, cycle->pool, 1, sizeof(rap_str_t))
        != RAP_OK)
    {
        return NULL;
    }

    return ccf;
}


static char *
rap_core_module_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_core_conf_t  *ccf = conf;

    rap_conf_init_value(ccf->daemon, 1);
    rap_conf_init_value(ccf->master, 1);
    rap_conf_init_msec_value(ccf->timer_resolution, 0);
    rap_conf_init_msec_value(ccf->shutdown_timeout, 0);

    rap_conf_init_value(ccf->worker_processes, 1);
    rap_conf_init_value(ccf->debug_points, 0);

#if (RAP_HAVE_CPU_AFFINITY)

    if (!ccf->cpu_affinity_auto
        && ccf->cpu_affinity_n
        && ccf->cpu_affinity_n != 1
        && ccf->cpu_affinity_n != (rap_uint_t) ccf->worker_processes)
    {
        rap_log_error(RAP_LOG_WARN, cycle->log, 0,
                      "the number of \"worker_processes\" is not equal to "
                      "the number of \"worker_cpu_affinity\" masks, "
                      "using last mask for remaining worker processes");
    }

#endif


    if (ccf->pid.len == 0) {
        rap_str_set(&ccf->pid, RAP_PID_PATH);
    }

    if (rap_conf_full_name(cycle, &ccf->pid, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    ccf->oldpid.len = ccf->pid.len + sizeof(RAP_OLDPID_EXT);

    ccf->oldpid.data = rap_pnalloc(cycle->pool, ccf->oldpid.len);
    if (ccf->oldpid.data == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memcpy(rap_cpymem(ccf->oldpid.data, ccf->pid.data, ccf->pid.len),
               RAP_OLDPID_EXT, sizeof(RAP_OLDPID_EXT));


#if !(RAP_WIN32)

    if (ccf->user == (uid_t) RAP_CONF_UNSET_UINT && geteuid() == 0) {
        struct group   *grp;
        struct passwd  *pwd;

        rap_set_errno(0);
        pwd = getpwnam(RAP_USER);
        if (pwd == NULL) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "getpwnam(\"" RAP_USER "\") failed");
            return RAP_CONF_ERROR;
        }

        ccf->username = RAP_USER;
        ccf->user = pwd->pw_uid;

        rap_set_errno(0);
        grp = getgrnam(RAP_GROUP);
        if (grp == NULL) {
            rap_log_error(RAP_LOG_EMERG, cycle->log, rap_errno,
                          "getgrnam(\"" RAP_GROUP "\") failed");
            return RAP_CONF_ERROR;
        }

        ccf->group = grp->gr_gid;
    }


    if (ccf->lock_file.len == 0) {
        rap_str_set(&ccf->lock_file, RAP_LOCK_PATH);
    }

    if (rap_conf_full_name(cycle, &ccf->lock_file, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    {
    rap_str_t  lock_file;

    lock_file = cycle->old_cycle->lock_file;

    if (lock_file.len) {
        lock_file.len--;

        if (ccf->lock_file.len != lock_file.len
            || rap_strncmp(ccf->lock_file.data, lock_file.data, lock_file.len)
               != 0)
        {
            rap_log_error(RAP_LOG_EMERG, cycle->log, 0,
                          "\"lock_file\" could not be changed, ignored");
        }

        cycle->lock_file.len = lock_file.len + 1;
        lock_file.len += sizeof(".accept");

        cycle->lock_file.data = rap_pstrdup(cycle->pool, &lock_file);
        if (cycle->lock_file.data == NULL) {
            return RAP_CONF_ERROR;
        }

    } else {
        cycle->lock_file.len = ccf->lock_file.len + 1;
        cycle->lock_file.data = rap_pnalloc(cycle->pool,
                                      ccf->lock_file.len + sizeof(".accept"));
        if (cycle->lock_file.data == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_memcpy(rap_cpymem(cycle->lock_file.data, ccf->lock_file.data,
                              ccf->lock_file.len),
                   ".accept", sizeof(".accept"));
    }
    }

#endif

    return RAP_CONF_OK;
}


static char *
rap_set_user(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#if (RAP_WIN32)

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"user\" is not supported, ignored");

    return RAP_CONF_OK;

#else

    rap_core_conf_t  *ccf = conf;

    char             *group;
    struct passwd    *pwd;
    struct group     *grp;
    rap_str_t        *value;

    if (ccf->user != (uid_t) RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (geteuid() != 0) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "the \"user\" directive makes sense only "
                           "if the master process runs "
                           "with super-user privileges, ignored");
        return RAP_CONF_OK;
    }

    value = cf->args->elts;

    ccf->username = (char *) value[1].data;

    rap_set_errno(0);
    pwd = getpwnam((const char *) value[1].data);
    if (pwd == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                           "getpwnam(\"%s\") failed", value[1].data);
        return RAP_CONF_ERROR;
    }

    ccf->user = pwd->pw_uid;

    group = (char *) ((cf->args->nelts == 2) ? value[1].data : value[2].data);

    rap_set_errno(0);
    grp = getgrnam(group);
    if (grp == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, rap_errno,
                           "getgrnam(\"%s\") failed", group);
        return RAP_CONF_ERROR;
    }

    ccf->group = grp->gr_gid;

    return RAP_CONF_OK;

#endif
}


static char *
rap_set_env(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_core_conf_t  *ccf = conf;

    rap_str_t   *value, *var;
    rap_uint_t   i;

    var = rap_array_push(&ccf->env);
    if (var == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;
    *var = value[1];

    for (i = 0; i < value[1].len; i++) {

        if (value[1].data[i] == '=') {

            var->len = i;

            return RAP_CONF_OK;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_set_priority(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_core_conf_t  *ccf = conf;

    rap_str_t        *value;
    rap_uint_t        n, minus;

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

    ccf->priority = rap_atoi(&value[1].data[n], value[1].len - n);
    if (ccf->priority == RAP_ERROR) {
        return "invalid number";
    }

    if (minus) {
        ccf->priority = -ccf->priority;
    }

    return RAP_CONF_OK;
}


static char *
rap_set_cpu_affinity(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#if (RAP_HAVE_CPU_AFFINITY)
    rap_core_conf_t  *ccf = conf;

    u_char            ch, *p;
    rap_str_t        *value;
    rap_uint_t        i, n;
    rap_cpuset_t     *mask;

    if (ccf->cpu_affinity) {
        return "is duplicate";
    }

    mask = rap_palloc(cf->pool, (cf->args->nelts - 1) * sizeof(rap_cpuset_t));
    if (mask == NULL) {
        return RAP_CONF_ERROR;
    }

    ccf->cpu_affinity_n = cf->args->nelts - 1;
    ccf->cpu_affinity = mask;

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "auto") == 0) {

        if (cf->args->nelts > 3) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid number of arguments in "
                               "\"worker_cpu_affinity\" directive");
            return RAP_CONF_ERROR;
        }

        ccf->cpu_affinity_auto = 1;

        CPU_ZERO(&mask[0]);
        for (i = 0; i < (rap_uint_t) rap_min(rap_ncpu, CPU_SETSIZE); i++) {
            CPU_SET(i, &mask[0]);
        }

        n = 2;

    } else {
        n = 1;
    }

    for ( /* void */ ; n < cf->args->nelts; n++) {

        if (value[n].len > CPU_SETSIZE) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                         "\"worker_cpu_affinity\" supports up to %d CPUs only",
                         CPU_SETSIZE);
            return RAP_CONF_ERROR;
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

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                          "invalid character \"%c\" in \"worker_cpu_affinity\"",
                          ch);
            return RAP_CONF_ERROR;
        }
    }

#else

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"worker_cpu_affinity\" is not supported "
                       "on this platform, ignored");
#endif

    return RAP_CONF_OK;
}


rap_cpuset_t *
rap_get_cpu_affinity(rap_uint_t n)
{
#if (RAP_HAVE_CPU_AFFINITY)
    rap_uint_t        i, j;
    rap_cpuset_t     *mask;
    rap_core_conf_t  *ccf;

    static rap_cpuset_t  result;

    ccf = (rap_core_conf_t *) rap_get_conf(rap_cycle->conf_ctx,
                                           rap_core_module);

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
rap_set_worker_processes(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_str_t        *value;
    rap_core_conf_t  *ccf;

    ccf = (rap_core_conf_t *) conf;

    if (ccf->worker_processes != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "auto") == 0) {
        ccf->worker_processes = rap_ncpu;
        return RAP_CONF_OK;
    }

    ccf->worker_processes = rap_atoi(value[1].data, value[1].len);

    if (ccf->worker_processes == RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


static char *
rap_load_module(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
#if (RAP_HAVE_DLOPEN)
    void                *handle;
    char               **names, **order;
    rap_str_t           *value, file;
    rap_uint_t           i;
    rap_module_t        *module, **modules;
    rap_pool_cleanup_t  *cln;

    if (cf->cycle->modules_used) {
        return "is specified too late";
    }

    value = cf->args->elts;

    file = value[1];

    if (rap_conf_full_name(cf->cycle, &file, 0) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->cycle->pool, 0);
    if (cln == NULL) {
        return RAP_CONF_ERROR;
    }

    handle = rap_dlopen(file.data);
    if (handle == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           rap_dlopen_n " \"%s\" failed (%s)",
                           file.data, rap_dlerror());
        return RAP_CONF_ERROR;
    }

    cln->handler = rap_unload_module;
    cln->data = handle;

    modules = rap_dlsym(handle, "rap_modules");
    if (modules == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           rap_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "rap_modules", rap_dlerror());
        return RAP_CONF_ERROR;
    }

    names = rap_dlsym(handle, "rap_module_names");
    if (names == NULL) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           rap_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "rap_module_names", rap_dlerror());
        return RAP_CONF_ERROR;
    }

    order = rap_dlsym(handle, "rap_module_order");

    for (i = 0; modules[i]; i++) {
        module = modules[i];
        module->name = names[i];

        if (rap_add_module(cf, &file, module, order) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        rap_log_debug2(RAP_LOG_DEBUG_CORE, cf->log, 0, "module: %s i:%ui",
                       module->name, module->index);
    }

    return RAP_CONF_OK;

#else

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "\"load_module\" is not supported "
                       "on this platform");
    return RAP_CONF_ERROR;

#endif
}


#if (RAP_HAVE_DLOPEN)

static void
rap_unload_module(void *data)
{
    void  *handle = data;

    if (rap_dlclose(handle) != 0) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, 0,
                      rap_dlclose_n " failed (%s)", rap_dlerror());
    }
}

#endif
