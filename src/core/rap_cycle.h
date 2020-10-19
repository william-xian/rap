
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CYCLE_H_INCLUDED_
#define _RAP_CYCLE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#ifndef RAP_CYCLE_POOL_SIZE
#define RAP_CYCLE_POOL_SIZE     RAP_DEFAULT_POOL_SIZE
#endif


#define RAP_DEBUG_POINTS_STOP   1
#define RAP_DEBUG_POINTS_ABORT  2


typedef struct rap_shm_zone_s  rap_shm_zone_t;

typedef rap_int_t (*rap_shm_zone_init_pt) (rap_shm_zone_t *zone, void *data);

struct rap_shm_zone_s {
    void                     *data;
    rap_shm_t                 shm;
    rap_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    rap_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct rap_cycle_s {
    void                  ****conf_ctx;
    rap_pool_t               *pool;

    rap_log_t                *log;
    rap_log_t                 new_log;

    rap_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    rap_connection_t        **files;
    rap_connection_t         *free_connections;
    rap_uint_t                free_connection_n;

    rap_module_t            **modules;
    rap_uint_t                modules_n;
    rap_uint_t                modules_used;    /* unsigned  modules_used:1; */

    rap_queue_t               reusable_connections_queue;
    rap_uint_t                reusable_connections_n;

    rap_array_t               listening;
    rap_array_t               paths;

    rap_array_t               config_dump;
    rap_rbtree_t              config_dump_rbtree;
    rap_rbtree_node_t         config_dump_sentinel;

    rap_list_t                open_files;
    rap_list_t                shared_memory;

    rap_uint_t                connection_n;
    rap_uint_t                files_n;

    rap_connection_t         *connections;
    rap_event_t              *read_events;
    rap_event_t              *write_events;

    rap_cycle_t              *old_cycle;

    rap_str_t                 conf_file;
    rap_str_t                 conf_param;
    rap_str_t                 conf_prefix;
    rap_str_t                 prefix;
    rap_str_t                 lock_file;
    rap_str_t                 hostname;
};


typedef struct {
    rap_flag_t                daemon;
    rap_flag_t                master;

    rap_msec_t                timer_resolution;
    rap_msec_t                shutdown_timeout;

    rap_int_t                 worker_processes;
    rap_int_t                 debug_points;

    rap_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    rap_uint_t                cpu_affinity_auto;
    rap_uint_t                cpu_affinity_n;
    rap_cpuset_t             *cpu_affinity;

    char                     *username;
    rap_uid_t                 user;
    rap_gid_t                 group;

    rap_str_t                 working_directory;
    rap_str_t                 lock_file;

    rap_str_t                 pid;
    rap_str_t                 oldpid;

    rap_array_t               env;
    char                    **environment;

    rap_uint_t                transparent;  /* unsigned  transparent:1; */
} rap_core_conf_t;


#define rap_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


rap_cycle_t *rap_init_cycle(rap_cycle_t *old_cycle);
rap_int_t rap_create_pidfile(rap_str_t *name, rap_log_t *log);
void rap_delete_pidfile(rap_cycle_t *cycle);
rap_int_t rap_signal_process(rap_cycle_t *cycle, char *sig);
void rap_reopen_files(rap_cycle_t *cycle, rap_uid_t user);
char **rap_set_environment(rap_cycle_t *cycle, rap_uint_t *last);
rap_pid_t rap_exec_new_binary(rap_cycle_t *cycle, char *const *argv);
rap_cpuset_t *rap_get_cpu_affinity(rap_uint_t n);
rap_shm_zone_t *rap_shared_memory_add(rap_conf_t *cf, rap_str_t *name,
    size_t size, void *tag);
void rap_set_shutdown_timer(rap_cycle_t *cycle);


extern volatile rap_cycle_t  *rap_cycle;
extern rap_array_t            rap_old_cycles;
extern rap_module_t           rap_core_module;
extern rap_uint_t             rap_test_config;
extern rap_uint_t             rap_dump_config;
extern rap_uint_t             rap_quiet_mode;


#endif /* _RAP_CYCLE_H_INCLUDED_ */
