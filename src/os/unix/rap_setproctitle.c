
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_SETPROCTITLE_USES_ENV)

/*
 * To change the process title in Linux and Solaris we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * and Solaris store argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 *
 * The Solaris's standard /bin/ps does not show the changed process title.
 * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
 * show a new title if its length less than the origin command line length.
 * To avoid it we append to a new title the origin command line in the
 * parenthesis.
 */

extern char **environ;

static char *rap_os_argv_last;

rap_int_t
rap_init_setproctitle(rap_log_t *log)
{
    u_char      *p;
    size_t       size;
    rap_uint_t   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += rap_strlen(environ[i]) + 1;
    }

    p = rap_alloc(size, log);
    if (p == NULL) {
        return RAP_ERROR;
    }

    rap_os_argv_last = rap_os_argv[0];

    for (i = 0; rap_os_argv[i]; i++) {
        if (rap_os_argv_last == rap_os_argv[i]) {
            rap_os_argv_last = rap_os_argv[i] + rap_strlen(rap_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (rap_os_argv_last == environ[i]) {

            size = rap_strlen(environ[i]) + 1;
            rap_os_argv_last = environ[i] + size;

            rap_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    rap_os_argv_last--;

    return RAP_OK;
}


void
rap_setproctitle(char *title)
{
    u_char     *p;

#if (RAP_SOLARIS)

    rap_int_t   i;
    size_t      size;

#endif

    rap_os_argv[1] = NULL;

    p = rap_cpystrn((u_char *) rap_os_argv[0], (u_char *) "rap: ",
                    rap_os_argv_last - rap_os_argv[0]);

    p = rap_cpystrn(p, (u_char *) title, rap_os_argv_last - (char *) p);

#if (RAP_SOLARIS)

    size = 0;

    for (i = 0; i < rap_argc; i++) {
        size += rap_strlen(rap_argv[i]) + 1;
    }

    if (size > (size_t) ((char *) p - rap_os_argv[0])) {

        /*
         * rap_setproctitle() is too rare operation so we use
         * the non-optimized copies
         */

        p = rap_cpystrn(p, (u_char *) " (", rap_os_argv_last - (char *) p);

        for (i = 0; i < rap_argc; i++) {
            p = rap_cpystrn(p, (u_char *) rap_argv[i],
                            rap_os_argv_last - (char *) p);
            p = rap_cpystrn(p, (u_char *) " ", rap_os_argv_last - (char *) p);
        }

        if (*(p - 1) == ' ') {
            *(p - 1) = ')';
        }
    }

#endif

    if (rap_os_argv_last - (char *) p) {
        rap_memset(p, RAP_SETPROCTITLE_PAD, rap_os_argv_last - (char *) p);
    }

    rap_log_debug1(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                   "setproctitle: \"%s\"", rap_os_argv[0]);
}

#endif /* RAP_SETPROCTITLE_USES_ENV */
