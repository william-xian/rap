
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SETPROCTITLE_H_INCLUDED_
#define _RAP_SETPROCTITLE_H_INCLUDED_


#if (RAP_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define rap_init_setproctitle(log) RAP_OK
#define rap_setproctitle(title)    setproctitle("%s", title)


#else /* !RAP_HAVE_SETPROCTITLE */

#if !defined RAP_SETPROCTITLE_USES_ENV

#if (RAP_SOLARIS)

#define RAP_SETPROCTITLE_USES_ENV  1
#define RAP_SETPROCTITLE_PAD       ' '

rap_int_t rap_init_setproctitle(rap_log_t *log);
void rap_setproctitle(char *title);

#elif (RAP_LINUX) || (RAP_DARWIN)

#define RAP_SETPROCTITLE_USES_ENV  1
#define RAP_SETPROCTITLE_PAD       '\0'

rap_int_t rap_init_setproctitle(rap_log_t *log);
void rap_setproctitle(char *title);

#else

#define rap_init_setproctitle(log) RAP_OK
#define rap_setproctitle(title)

#endif /* OSes */

#endif /* RAP_SETPROCTITLE_USES_ENV */

#endif /* RAP_HAVE_SETPROCTITLE */


#endif /* _RAP_SETPROCTITLE_H_INCLUDED_ */
