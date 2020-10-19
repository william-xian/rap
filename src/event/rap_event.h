
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_H_INCLUDED_
#define _RAP_EVENT_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_INVALID_INDEX  0xd0d0d0d0


#if (RAP_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    rap_event_t     *event;
    int              error;
} rap_event_ovlp_t;

#endif


struct rap_event_s {
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

#if (RAP_HAVE_KQUEUE)
    unsigned         kq_vnode:1;

    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with RAP_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with RAP_LOWAT_EVENT flag
     *
     * iocp: TODO
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     *   read:       bytes to read when event is ready, -1 if not known
     */

    int              available;

    rap_event_handler_pt  handler;


#if (RAP_HAVE_IOCP)
    rap_event_ovlp_t ovlp;
#endif

    rap_uint_t       index;

    rap_log_t       *log;

    rap_rbtree_node_t   timer;

    /* the posted queue */
    rap_queue_t      queue;

#if 0

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */

    void            *thr_ctx;

#if (RAP_EVENT_T_PADDING)

    /* event should not cross cache line in SMP */

    uint32_t         padding[RAP_EVENT_T_PADDING];
#endif
#endif
};


#if (RAP_HAVE_FILE_AIO)

struct rap_event_aio_s {
    void                      *data;
    rap_event_handler_pt       handler;
    rap_file_t                *file;

    rap_fd_t                   fd;

#if (RAP_HAVE_AIO_SENDFILE || RAP_COMPAT)
    ssize_t                  (*preload_handler)(rap_buf_t *file);
#endif

#if (RAP_HAVE_EVENTFD)
    int64_t                    res;
#endif

#if !(RAP_HAVE_EVENTFD) || (RAP_TEST_BUILD_EPOLL)
    rap_err_t                  err;
    size_t                     nbytes;
#endif

    rap_aiocb_t                aiocb;
    rap_event_t                event;
};

#endif


typedef struct {
    rap_int_t  (*add)(rap_event_t *ev, rap_int_t event, rap_uint_t flags);
    rap_int_t  (*del)(rap_event_t *ev, rap_int_t event, rap_uint_t flags);

    rap_int_t  (*enable)(rap_event_t *ev, rap_int_t event, rap_uint_t flags);
    rap_int_t  (*disable)(rap_event_t *ev, rap_int_t event, rap_uint_t flags);

    rap_int_t  (*add_conn)(rap_connection_t *c);
    rap_int_t  (*del_conn)(rap_connection_t *c, rap_uint_t flags);

    rap_int_t  (*notify)(rap_event_handler_pt handler);

    rap_int_t  (*process_events)(rap_cycle_t *cycle, rap_msec_t timer,
                                 rap_uint_t flags);

    rap_int_t  (*init)(rap_cycle_t *cycle, rap_msec_t timer);
    void       (*done)(rap_cycle_t *cycle);
} rap_event_actions_t;


extern rap_event_actions_t   rap_event_actions;
#if (RAP_HAVE_EPOLLRDHUP)
extern rap_uint_t            rap_use_epoll_rdhup;
#endif


/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
#define RAP_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define RAP_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
#define RAP_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define RAP_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define RAP_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll.
 */
#define RAP_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
#define RAP_USE_EPOLL_EVENT      0x00000040

/*
 * Obsolete.
 */
#define RAP_USE_RTSIG_EVENT      0x00000080

/*
 * Obsolete.
 */
#define RAP_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 */
#define RAP_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll.
 */
#define RAP_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define RAP_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define RAP_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define RAP_USE_VNODE_EVENT      0x00002000


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
#define RAP_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define RAP_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define RAP_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define RAP_LOWAT_EVENT    0
#define RAP_VNODE_EVENT    0


#if (RAP_HAVE_EPOLL) && !(RAP_HAVE_EPOLLRDHUP)
#define EPOLLRDHUP         0
#endif


#if (RAP_HAVE_KQUEUE)

#define RAP_READ_EVENT     EVFILT_READ
#define RAP_WRITE_EVENT    EVFILT_WRITE

#undef  RAP_VNODE_EVENT
#define RAP_VNODE_EVENT    EVFILT_VNODE

/*
 * RAP_CLOSE_EVENT, RAP_LOWAT_EVENT, and RAP_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  RAP_CLOSE_EVENT
#define RAP_CLOSE_EVENT    EV_EOF

#undef  RAP_LOWAT_EVENT
#define RAP_LOWAT_EVENT    EV_FLAG1

#undef  RAP_FLUSH_EVENT
#define RAP_FLUSH_EVENT    EV_ERROR

#define RAP_LEVEL_EVENT    0
#define RAP_ONESHOT_EVENT  EV_ONESHOT
#define RAP_CLEAR_EVENT    EV_CLEAR

#undef  RAP_DISABLE_EVENT
#define RAP_DISABLE_EVENT  EV_DISABLE


#elif (RAP_HAVE_DEVPOLL && !(RAP_TEST_BUILD_DEVPOLL)) \
      || (RAP_HAVE_EVENTPORT && !(RAP_TEST_BUILD_EVENTPORT))

#define RAP_READ_EVENT     POLLIN
#define RAP_WRITE_EVENT    POLLOUT

#define RAP_LEVEL_EVENT    0
#define RAP_ONESHOT_EVENT  1


#elif (RAP_HAVE_EPOLL) && !(RAP_TEST_BUILD_EPOLL)

#define RAP_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define RAP_WRITE_EVENT    EPOLLOUT

#define RAP_LEVEL_EVENT    0
#define RAP_CLEAR_EVENT    EPOLLET
#define RAP_ONESHOT_EVENT  0x70000000
#if 0
#define RAP_ONESHOT_EVENT  EPOLLONESHOT
#endif

#if (RAP_HAVE_EPOLLEXCLUSIVE)
#define RAP_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#endif

#elif (RAP_HAVE_POLL)

#define RAP_READ_EVENT     POLLIN
#define RAP_WRITE_EVENT    POLLOUT

#define RAP_LEVEL_EVENT    0
#define RAP_ONESHOT_EVENT  1


#else /* select */

#define RAP_READ_EVENT     0
#define RAP_WRITE_EVENT    1

#define RAP_LEVEL_EVENT    0
#define RAP_ONESHOT_EVENT  1

#endif /* RAP_HAVE_KQUEUE */


#if (RAP_HAVE_IOCP)
#define RAP_IOCP_ACCEPT      0
#define RAP_IOCP_IO          1
#define RAP_IOCP_CONNECT     2
#endif


#if (RAP_TEST_BUILD_EPOLL)
#define RAP_EXCLUSIVE_EVENT  0
#endif


#ifndef RAP_CLEAR_EVENT
#define RAP_CLEAR_EVENT    0    /* dummy declaration */
#endif


#define rap_process_events   rap_event_actions.process_events
#define rap_done_events      rap_event_actions.done

#define rap_add_event        rap_event_actions.add
#define rap_del_event        rap_event_actions.del
#define rap_add_conn         rap_event_actions.add_conn
#define rap_del_conn         rap_event_actions.del_conn

#define rap_notify           rap_event_actions.notify

#define rap_add_timer        rap_event_add_timer
#define rap_del_timer        rap_event_del_timer


extern rap_os_io_t  rap_io;

#define rap_recv             rap_io.recv
#define rap_recv_chain       rap_io.recv_chain
#define rap_udp_recv         rap_io.udp_recv
#define rap_send             rap_io.send
#define rap_send_chain       rap_io.send_chain
#define rap_udp_send         rap_io.udp_send
#define rap_udp_send_chain   rap_io.udp_send_chain


#define RAP_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define RAP_EVENT_CONF        0x02000000


typedef struct {
    rap_uint_t    connections;
    rap_uint_t    use;

    rap_flag_t    multi_accept;
    rap_flag_t    accept_mutex;

    rap_msec_t    accept_mutex_delay;

    u_char       *name;

#if (RAP_DEBUG)
    rap_array_t   debug_connection;
#endif
} rap_event_conf_t;


typedef struct {
    rap_str_t              *name;

    void                 *(*create_conf)(rap_cycle_t *cycle);
    char                 *(*init_conf)(rap_cycle_t *cycle, void *conf);

    rap_event_actions_t     actions;
} rap_event_module_t;


extern rap_atomic_t          *rap_connection_counter;

extern rap_atomic_t          *rap_accept_mutex_ptr;
extern rap_shmtx_t            rap_accept_mutex;
extern rap_uint_t             rap_use_accept_mutex;
extern rap_uint_t             rap_accept_events;
extern rap_uint_t             rap_accept_mutex_held;
extern rap_msec_t             rap_accept_mutex_delay;
extern rap_int_t              rap_accept_disabled;


#if (RAP_STAT_STUB)

extern rap_atomic_t  *rap_stat_accepted;
extern rap_atomic_t  *rap_stat_handled;
extern rap_atomic_t  *rap_stat_requests;
extern rap_atomic_t  *rap_stat_active;
extern rap_atomic_t  *rap_stat_reading;
extern rap_atomic_t  *rap_stat_writing;
extern rap_atomic_t  *rap_stat_waiting;

#endif


#define RAP_UPDATE_TIME         1
#define RAP_POST_EVENTS         2


extern sig_atomic_t           rap_event_timer_alarm;
extern rap_uint_t             rap_event_flags;
extern rap_module_t           rap_events_module;
extern rap_module_t           rap_event_core_module;


#define rap_event_get_conf(conf_ctx, module)                                  \
             (*(rap_get_conf(conf_ctx, rap_events_module))) [module.ctx_index]



void rap_event_accept(rap_event_t *ev);
#if !(RAP_WIN32)
void rap_event_recvmsg(rap_event_t *ev);
void rap_udp_rbtree_insert_value(rap_rbtree_node_t *temp,
    rap_rbtree_node_t *node, rap_rbtree_node_t *sentinel);
#endif
void rap_delete_udp_connection(void *data);
rap_int_t rap_trylock_accept_mutex(rap_cycle_t *cycle);
rap_int_t rap_enable_accept_events(rap_cycle_t *cycle);
u_char *rap_accept_log_error(rap_log_t *log, u_char *buf, size_t len);
#if (RAP_DEBUG)
void rap_debug_accepted_connection(rap_event_conf_t *ecf, rap_connection_t *c);
#endif


void rap_process_events_and_timers(rap_cycle_t *cycle);
rap_int_t rap_handle_read_event(rap_event_t *rev, rap_uint_t flags);
rap_int_t rap_handle_write_event(rap_event_t *wev, size_t lowat);


#if (RAP_WIN32)
void rap_event_acceptex(rap_event_t *ev);
rap_int_t rap_event_post_acceptex(rap_listening_t *ls, rap_uint_t n);
u_char *rap_acceptex_log_error(rap_log_t *log, u_char *buf, size_t len);
#endif


rap_int_t rap_send_lowat(rap_connection_t *c, size_t lowat);


/* used in rap_log_debugX() */
#define rap_event_ident(p)  ((rap_connection_t *) (p))->fd


#include <rap_event_timer.h>
#include <rap_event_posted.h>

#if (RAP_WIN32)
#include <rap_iocp_module.h>
#endif


#endif /* _RAP_EVENT_H_INCLUDED_ */
