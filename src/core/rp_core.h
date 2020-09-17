
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CORE_H_INCLUDED_
#define _RP_CORE_H_INCLUDED_


#include <rp_config.h>


typedef struct rp_module_s          rp_module_t;
typedef struct rp_conf_s            rp_conf_t;
typedef struct rp_cycle_s           rp_cycle_t;
typedef struct rp_pool_s            rp_pool_t;
typedef struct rp_chain_s           rp_chain_t;
typedef struct rp_log_s             rp_log_t;
typedef struct rp_open_file_s       rp_open_file_t;
typedef struct rp_command_s         rp_command_t;
typedef struct rp_file_s            rp_file_t;
typedef struct rp_event_s           rp_event_t;
typedef struct rp_event_aio_s       rp_event_aio_t;
typedef struct rp_connection_s      rp_connection_t;
typedef struct rp_thread_task_s     rp_thread_task_t;
typedef struct rp_ssl_s             rp_ssl_t;
typedef struct rp_proxy_protocol_s  rp_proxy_protocol_t;
typedef struct rp_ssl_connection_s  rp_ssl_connection_t;
typedef struct rp_udp_connection_s  rp_udp_connection_t;

typedef void (*rp_event_handler_pt)(rp_event_t *ev);
typedef void (*rp_connection_handler_pt)(rp_connection_t *c);


#define  RP_OK          0
#define  RP_ERROR      -1
#define  RP_AGAIN      -2
#define  RP_BUSY       -3
#define  RP_DONE       -4
#define  RP_DECLINED   -5
#define  RP_ABORT      -6


#include <rp_errno.h>
#include <rp_atomic.h>
#include <rp_thread.h>
#include <rp_rbtree.h>
#include <rp_time.h>
#include <rp_socket.h>
#include <rp_string.h>
#include <rp_files.h>
#include <rp_shmem.h>
#include <rp_process.h>
#include <rp_user.h>
#include <rp_dlopen.h>
#include <rp_parse.h>
#include <rp_parse_time.h>
#include <rp_log.h>
#include <rp_alloc.h>
#include <rp_palloc.h>
#include <rp_buf.h>
#include <rp_queue.h>
#include <rp_array.h>
#include <rp_list.h>
#include <rp_hash.h>
#include <rp_file.h>
#include <rp_crc.h>
#include <rp_crc32.h>
#include <rp_murmurhash.h>
#if (RP_PCRE)
#include <rp_regex.h>
#endif
#include <rp_radix_tree.h>
#include <rp_times.h>
#include <rp_rwlock.h>
#include <rp_shmtx.h>
#include <rp_slab.h>
#include <rp_inet.h>
#include <rp_cycle.h>
#include <rp_resolver.h>
#if (RP_OPENSSL)
#include <rp_event_openssl.h>
#endif
#include <rp_process_cycle.h>
#include <rp_conf_file.h>
#include <rp_module.h>
#include <rp_open_file_cache.h>
#include <rp_os.h>
#include <rp_connection.h>
#include <rp_syslog.h>
#include <rp_proxy_protocol.h>


#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"


#define rp_abs(value)       (((value) >= 0) ? (value) : - (value))
#define rp_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define rp_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))

void rp_cpuinfo(void);

#if (RP_HAVE_OPENAT)
#define RP_DISABLE_SYMLINKS_OFF        0
#define RP_DISABLE_SYMLINKS_ON         1
#define RP_DISABLE_SYMLINKS_NOTOWNER   2
#endif

#endif /* _RP_CORE_H_INCLUDED_ */
