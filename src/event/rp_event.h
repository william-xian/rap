
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_H_INCLUDED_
#define _RP_EVENT_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_INVALID_INDEX  0xd0d0d0d0


#if (RP_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    rp_event_t     *event;
    int              error;
} rp_event_ovlp_t;

#endif


struct rp_event_s {
    void            *data;

    unsigned         write:1;

    unsigned         accept:1;

    /* used to detect the stale events in kqueue and epoll */
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    unsigned         active:1;

    unsigned         disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    unsigned         ready:1;

    unsigned         oneshot:1;

    /* aio operation is complete */
    unsigned         complete:1;

    unsigned         eof:1;
    unsigned         error:1;

    unsigned         timedout:1;
    unsigned         timer_set:1;

    unsigned         delayed:1;

    unsigned         deferred_accept:1;

    /* the pending eof reported by kqueue, epoll or in aio chain operation */
    unsigned         pending_eof:1;

    unsigned         posted:1;

    unsigned         closed:1;

    /* to test on worker exit */
    unsigned         channel:1;
    unsigned         resolver:1;

    unsigned         cancelable:1;

#if (RP_HAVE_KQUEUE)
    unsigned         kq_vnode:1;

    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with RP_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with RP_LOWAT_EVENT flag
     *
     * iocp: TODO
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     *   read:       bytes to read when event is ready, -1 if not known
     */

    int              available;

    rp_event_handler_pt  handler;


#if (RP_HAVE_IOCP)
    rp_event_ovlp_t ovlp;
#endif

    rp_uint_t       index;

    rp_log_t       *log;

    rp_rbtree_node_t   timer;

    /* the posted queue */
    rp_queue_t      queue;

#if 0

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */

    void            *thr_ctx;

#if (RP_EVENT_T_PADDING)

    /* event should not cross cache line in SMP */

    uint32_t         padding[RP_EVENT_T_PADDING];
#endif
#endif
};


#if (RP_HAVE_FILE_AIO)

struct rp_event_aio_s {
    void                      *data;
    rp_event_handler_pt       handler;
    rp_file_t                *file;

    rp_fd_t                   fd;

#if (RP_HAVE_AIO_SENDFILE || RP_COMPAT)
    ssize_t                  (*preload_handler)(rp_buf_t *file);
#endif

#if (RP_HAVE_EVENTFD)
    int64_t                    res;
#endif

#if !(RP_HAVE_EVENTFD) || (RP_TEST_BUILD_EPOLL)
    rp_err_t                  err;
    size_t                     nbytes;
#endif

    rp_aiocb_t                aiocb;
    rp_event_t                event;
};

#endif


typedef struct {
    rp_int_t  (*add)(rp_event_t *ev, rp_int_t event, rp_uint_t flags);
    rp_int_t  (*del)(rp_event_t *ev, rp_int_t event, rp_uint_t flags);

    rp_int_t  (*enable)(rp_event_t *ev, rp_int_t event, rp_uint_t flags);
    rp_int_t  (*disable)(rp_event_t *ev, rp_int_t event, rp_uint_t flags);

    rp_int_t  (*add_conn)(rp_connection_t *c);
    rp_int_t  (*del_conn)(rp_connection_t *c, rp_uint_t flags);

    rp_int_t  (*notify)(rp_event_handler_pt handler);

    rp_int_t  (*process_events)(rp_cycle_t *cycle, rp_msec_t timer,
                                 rp_uint_t flags);

    rp_int_t  (*init)(rp_cycle_t *cycle, rp_msec_t timer);
    void       (*done)(rp_cycle_t *cycle);
} rp_event_actions_t;


extern rp_event_actions_t   rp_event_actions;
#if (RP_HAVE_EPOLLRDHUP)
extern rp_uint_t            rp_use_epoll_rdhup;
#endif


/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define RP_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define RP_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
#define RP_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define RP_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define RP_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll.
 */
#define RP_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
#define RP_USE_EPOLL_EVENT      0x00000040

/*
 * Obsolete.
 */
#define RP_USE_RTSIG_EVENT      0x00000080

/*
 * Obsolete.
 */
#define RP_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 */
#define RP_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll.
 */
#define RP_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define RP_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define RP_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define RP_USE_VNODE_EVENT      0x00002000


/*
 * The event filter is deleted just before the closing file.
 * Has no meaning for select and poll.
 * kqueue, epoll, eventport:         allows to avoid explicit delete,
 *                                   because filter automatically is deleted
 *                                   on file close,
 *
 * /dev/poll:                        we need to flush POLLREMOVE event
 *                                   before closing file.
 */
#define RP_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define RP_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define RP_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define RP_LOWAT_EVENT    0
#define RP_VNODE_EVENT    0


#if (RP_HAVE_EPOLL) && !(RP_HAVE_EPOLLRDHUP)
#define EPOLLRDHUP         0
#endif


#if (RP_HAVE_KQUEUE)

#define RP_READ_EVENT     EVFILT_READ
#define RP_WRITE_EVENT    EVFILT_WRITE

#undef  RP_VNODE_EVENT
#define RP_VNODE_EVENT    EVFILT_VNODE

/*
 * RP_CLOSE_EVENT, RP_LOWAT_EVENT, and RP_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  RP_CLOSE_EVENT
#define RP_CLOSE_EVENT    EV_EOF

#undef  RP_LOWAT_EVENT
#define RP_LOWAT_EVENT    EV_FLAG1

#undef  RP_FLUSH_EVENT
#define RP_FLUSH_EVENT    EV_ERROR

#define RP_LEVEL_EVENT    0
#define RP_ONESHOT_EVENT  EV_ONESHOT
#define RP_CLEAR_EVENT    EV_CLEAR

#undef  RP_DISABLE_EVENT
#define RP_DISABLE_EVENT  EV_DISABLE


#elif (RP_HAVE_DEVPOLL && !(RP_TEST_BUILD_DEVPOLL)) \
      || (RP_HAVE_EVENTPORT && !(RP_TEST_BUILD_EVENTPORT))

#define RP_READ_EVENT     POLLIN
#define RP_WRITE_EVENT    POLLOUT

#define RP_LEVEL_EVENT    0
#define RP_ONESHOT_EVENT  1


#elif (RP_HAVE_EPOLL) && !(RP_TEST_BUILD_EPOLL)

#define RP_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define RP_WRITE_EVENT    EPOLLOUT

#define RP_LEVEL_EVENT    0
#define RP_CLEAR_EVENT    EPOLLET
#define RP_ONESHOT_EVENT  0x70000000
#if 0
#define RP_ONESHOT_EVENT  EPOLLONESHOT
#endif

#if (RP_HAVE_EPOLLEXCLUSIVE)
#define RP_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#endif

#elif (RP_HAVE_POLL)

#define RP_READ_EVENT     POLLIN
#define RP_WRITE_EVENT    POLLOUT

#define RP_LEVEL_EVENT    0
#define RP_ONESHOT_EVENT  1


#else /* select */

#define RP_READ_EVENT     0
#define RP_WRITE_EVENT    1

#define RP_LEVEL_EVENT    0
#define RP_ONESHOT_EVENT  1

#endif /* RP_HAVE_KQUEUE */


#if (RP_HAVE_IOCP)
#define RP_IOCP_ACCEPT      0
#define RP_IOCP_IO          1
#define RP_IOCP_CONNECT     2
#endif


#if (RP_TEST_BUILD_EPOLL)
#define RP_EXCLUSIVE_EVENT  0
#endif


#ifndef RP_CLEAR_EVENT
#define RP_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define rp_process_events   rp_event_actions.process_events
#define rp_done_events      rp_event_actions.done

#define rp_add_event        rp_event_actions.add
#define rp_del_event        rp_event_actions.del
#define rp_add_conn         rp_event_actions.add_conn
#define rp_del_conn         rp_event_actions.del_conn

#define rp_notify           rp_event_actions.notify

#define rp_add_timer        rp_event_add_timer
#define rp_del_timer        rp_event_del_timer


extern rp_os_io_t  rp_io;

#define rp_recv             rp_io.recv
#define rp_recv_chain       rp_io.recv_chain
#define rp_udp_recv         rp_io.udp_recv
#define rp_send             rp_io.send
#define rp_send_chain       rp_io.send_chain
#define rp_udp_send         rp_io.udp_send
#define rp_udp_send_chain   rp_io.udp_send_chain


#define RP_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define RP_EVENT_CONF        0x02000000


typedef struct {
    rp_uint_t    connections;
    rp_uint_t    use;

    rp_flag_t    multi_accept;
    rp_flag_t    accept_mutex;

    rp_msec_t    accept_mutex_delay;

    u_char       *name;

#if (RP_DEBUG)
    rp_array_t   debug_connection;
#endif
} rp_event_conf_t;


typedef struct {
    rp_str_t              *name;

    void                 *(*create_conf)(rp_cycle_t *cycle);
    char                 *(*init_conf)(rp_cycle_t *cycle, void *conf);

    rp_event_actions_t     actions;
} rp_event_module_t;


extern rp_atomic_t          *rp_connection_counter;

extern rp_atomic_t          *rp_accept_mutex_ptr;
extern rp_shmtx_t            rp_accept_mutex;
extern rp_uint_t             rp_use_accept_mutex;
extern rp_uint_t             rp_accept_events;
extern rp_uint_t             rp_accept_mutex_held;
extern rp_msec_t             rp_accept_mutex_delay;
extern rp_int_t              rp_accept_disabled;


#if (RP_STAT_STUB)

extern rp_atomic_t  *rp_stat_accepted;
extern rp_atomic_t  *rp_stat_handled;
extern rp_atomic_t  *rp_stat_requests;
extern rp_atomic_t  *rp_stat_active;
extern rp_atomic_t  *rp_stat_reading;
extern rp_atomic_t  *rp_stat_writing;
extern rp_atomic_t  *rp_stat_waiting;

#endif


#define RP_UPDATE_TIME         1
#define RP_POST_EVENTS         2


extern sig_atomic_t           rp_event_timer_alarm;
extern rp_uint_t             rp_event_flags;
extern rp_module_t           rp_events_module;
extern rp_module_t           rp_event_core_module;


#define rp_event_get_conf(conf_ctx, module)                                  \
             (*(rp_get_conf(conf_ctx, rp_events_module))) [module.ctx_index]



void rp_event_accept(rp_event_t *ev);
#if !(RP_WIN32)
void rp_event_recvmsg(rp_event_t *ev);
void rp_udp_rbtree_insert_value(rp_rbtree_node_t *temp,
    rp_rbtree_node_t *node, rp_rbtree_node_t *sentinel);
#endif
void rp_delete_udp_connection(void *data);
rp_int_t rp_trylock_accept_mutex(rp_cycle_t *cycle);
rp_int_t rp_enable_accept_events(rp_cycle_t *cycle);
u_char *rp_accept_log_error(rp_log_t *log, u_char *buf, size_t len);
#if (RP_DEBUG)
void rp_debug_accepted_connection(rp_event_conf_t *ecf, rp_connection_t *c);
#endif


void rp_process_events_and_timers(rp_cycle_t *cycle);
rp_int_t rp_handle_read_event(rp_event_t *rev, rp_uint_t flags);
rp_int_t rp_handle_write_event(rp_event_t *wev, size_t lowat);


#if (RP_WIN32)
void rp_event_acceptex(rp_event_t *ev);
rp_int_t rp_event_post_acceptex(rp_listening_t *ls, rp_uint_t n);
u_char *rp_acceptex_log_error(rp_log_t *log, u_char *buf, size_t len);
#endif


rp_int_t rp_send_lowat(rp_connection_t *c, size_t lowat);


/* used in rp_log_debugX() */
#define rp_event_ident(p)  ((rp_connection_t *) (p))->fd


#include <rp_event_timer.h>
#include <rp_event_posted.h>

#if (RP_WIN32)
#include <rp_iocp_module.h>
#endif


#endif /* _RP_EVENT_H_INCLUDED_ */
