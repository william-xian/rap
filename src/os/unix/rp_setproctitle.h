
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SETPROCTITLE_H_INCLUDED_
#define _RP_SETPROCTITLE_H_INCLUDED_


#if (RP_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define rp_init_setproctitle(log) RP_OK
#define rp_setproctitle(title)    setproctitle("%s", title)


#else /* !RP_HAVE_SETPROCTITLE */

#if !defined RP_SETPROCTITLE_USES_ENV

#if (RP_SOLARIS)

#define RP_SETPROCTITLE_USES_ENV  1
#define RP_SETPROCTITLE_PAD       ' '

rp_int_t rp_init_setproctitle(rp_log_t *log);
void rp_setproctitle(char *title);

#elif (RP_LINUX) || (RP_DARWIN)

#define RP_SETPROCTITLE_USES_ENV  1
#define RP_SETPROCTITLE_PAD       '\0'

rp_int_t rp_init_setproctitle(rp_log_t *log);
void rp_setproctitle(char *title);

#else

#define rp_init_setproctitle(log) RP_OK
#define rp_setproctitle(title)

#endif /* OSes */

#endif /* RP_SETPROCTITLE_USES_ENV */

#endif /* RP_HAVE_SETPROCTITLE */


#endif /* _RP_SETPROCTITLE_H_INCLUDED_ */
