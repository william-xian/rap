
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CORE_H_INCLUDED_
#define _RAP_CORE_H_INCLUDED_


#include <rap_config.h>


typedef struct rap_module_s          rap_module_t;
typedef struct rap_conf_s            rap_conf_t;
typedef struct rap_cycle_s           rap_cycle_t;
typedef struct rap_pool_s            rap_pool_t;
typedef struct rap_chain_s           rap_chain_t;
typedef struct rap_log_s             rap_log_t;
typedef struct rap_open_file_s       rap_open_file_t;
typedef struct rap_command_s         rap_command_t;
typedef struct rap_file_s            rap_file_t;
typedef struct rap_event_s           rap_event_t;
typedef struct rap_event_aio_s       rap_event_aio_t;
typedef struct rap_connection_s      rap_connection_t;
typedef struct rap_thread_task_s     rap_thread_task_t;
typedef struct rap_ssl_s             rap_ssl_t;
typedef struct rap_proxy_protocol_s  rap_proxy_protocol_t;
typedef struct rap_ssl_connection_s  rap_ssl_connection_t;
typedef struct rap_udp_connection_s  rap_udp_connection_t;

typedef void (*rap_event_handler_pt)(rap_event_t *ev);
typedef void (*rap_connection_handler_pt)(rap_connection_t *c);


#define  RAP_OK          0
#define  RAP_ERROR      -1
#define  RAP_AGAIN      -2
#define  RAP_BUSY       -3
#define  RAP_DONE       -4
#define  RAP_DECLINED   -5
#define  RAP_ABORT      -6


#include <rap_errno.h>
#include <rap_atomic.h>
#include <rap_thread.h>
#include <rap_rbtree.h>
#include <rap_time.h>
#include <rap_socket.h>
#include <rap_string.h>
#include <rap_files.h>
#include <rap_shmem.h>
#include <rap_process.h>
#include <rap_user.h>
#include <rap_dlopen.h>
#include <rap_parse.h>
#include <rap_parse_time.h>
#include <rap_log.h>
#include <rap_alloc.h>
#include <rap_palloc.h>
#include <rap_buf.h>
#include <rap_queue.h>
#include <rap_array.h>
#include <rap_list.h>
#include <rap_hash.h>
#include <rap_file.h>
#include <rap_crc.h>
#include <rap_crc32.h>
#include <rap_murmurhash.h>
#if (RAP_PCRE)
#include <rap_regex.h>
#endif
#include <rap_radix_tree.h>
#include <rap_times.h>
#include <rap_rwlock.h>
#include <rap_shmtx.h>
#include <rap_slab.h>
#include <rap_inet.h>
#include <rap_cycle.h>
#include <rap_resolver.h>
#if (RAP_OPENSSL)
#include <rap_event_openssl.h>
#endif
#include <rap_process_cycle.h>
#include <rap_conf_file.h>
#include <rap_module.h>
#include <rap_open_file_cache.h>
#include <rap_os.h>
#include <rap_connection.h>
#include <rap_syslog.h>
#include <rap_proxy_protocol.h>


#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"


#define rap_abs(value)       (((value) >= 0) ? (value) : - (value))
#define rap_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define rap_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))

void rap_cpuinfo(void);

#if (RAP_HAVE_OPENAT)
#define RAP_DISABLE_SYMLINKS_OFF        0
#define RAP_DISABLE_SYMLINKS_ON         1
#define RAP_DISABLE_SYMLINKS_NOTOWNER   2
#endif

#endif /* _RAP_CORE_H_INCLUDED_ */
