
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_SETPROCTITLE_USES_ENV)

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

static char *rp_os_argv_last;

rp_int_t
rp_init_setproctitle(rp_log_t *log)
{
    u_char      *p;
    size_t       size;
    rp_uint_t   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += rp_strlen(environ[i]) + 1;
    }

    p = rp_alloc(size, log);
    if (p == NULL) {
        return RP_ERROR;
    }

    rp_os_argv_last = rp_os_argv[0];

    for (i = 0; rp_os_argv[i]; i++) {
        if (rp_os_argv_last == rp_os_argv[i]) {
            rp_os_argv_last = rp_os_argv[i] + rp_strlen(rp_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (rp_os_argv_last == environ[i]) {

            size = rp_strlen(environ[i]) + 1;
            rp_os_argv_last = environ[i] + size;

            rp_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    rp_os_argv_last--;

    return RP_OK;
}


void
rp_setproctitle(char *title)
{
    u_char     *p;

#if (RP_SOLARIS)

    rp_int_t   i;
    size_t      size;

#endif

    rp_os_argv[1] = NULL;

    p = rp_cpystrn((u_char *) rp_os_argv[0], (u_char *) "rap: ",
                    rp_os_argv_last - rp_os_argv[0]);

    p = rp_cpystrn(p, (u_char *) title, rp_os_argv_last - (char *) p);

#if (RP_SOLARIS)

    size = 0;

    for (i = 0; i < rp_argc; i++) {
        size += rp_strlen(rp_argv[i]) + 1;
    }

    if (size > (size_t) ((char *) p - rp_os_argv[0])) {

        /*
         * rp_setproctitle() is too rare operation so we use
         * the non-optimized copies
         */

        p = rp_cpystrn(p, (u_char *) " (", rp_os_argv_last - (char *) p);

        for (i = 0; i < rp_argc; i++) {
            p = rp_cpystrn(p, (u_char *) rp_argv[i],
                            rp_os_argv_last - (char *) p);
            p = rp_cpystrn(p, (u_char *) " ", rp_os_argv_last - (char *) p);
        }

        if (*(p - 1) == ' ') {
            *(p - 1) = ')';
        }
    }

#endif

    if (rp_os_argv_last - (char *) p) {
        rp_memset(p, RP_SETPROCTITLE_PAD, rp_os_argv_last - (char *) p);
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                   "setproctitle: \"%s\"", rp_os_argv[0]);
}

#endif /* RP_SETPROCTITLE_USES_ENV */
