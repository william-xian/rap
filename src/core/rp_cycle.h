
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CYCLE_H_INCLUDED_
#define _RP_CYCLE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#ifndef RP_CYCLE_POOL_SIZE
#define RP_CYCLE_POOL_SIZE     RP_DEFAULT_POOL_SIZE
#endif


#define RP_DEBUG_POINTS_STOP   1
#define RP_DEBUG_POINTS_ABORT  2


typedef struct rp_shm_zone_s  rp_shm_zone_t;

typedef rp_int_t (*rp_shm_zone_init_pt) (rp_shm_zone_t *zone, void *data);

struct rp_shm_zone_s {
    void                     *data;
    rp_shm_t                 shm;
    rp_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    rp_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


struct rp_cycle_s {
    void                  ****conf_ctx;
    rp_pool_t               *pool;

    rp_log_t                *log;
    rp_log_t                 new_log;

    rp_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    rp_connection_t        **files;
    rp_connection_t         *free_connections;
    rp_uint_t                free_connection_n;

    rp_module_t            **modules;
    rp_uint_t                modules_n;
    rp_uint_t                modules_used;    /* unsigned  modules_used:1; */

    rp_queue_t               reusable_connections_queue;
    rp_uint_t                reusable_connections_n;

    rp_array_t               listening;
    rp_array_t               paths;

    rp_array_t               config_dump;
    rp_rbtree_t              config_dump_rbtree;
    rp_rbtree_node_t         config_dump_sentinel;

    rp_list_t                open_files;
    rp_list_t                shared_memory;

    rp_uint_t                connection_n;
    rp_uint_t                files_n;

    rp_connection_t         *connections;
    rp_event_t              *read_events;
    rp_event_t              *write_events;

    rp_cycle_t              *old_cycle;

    rp_str_t                 conf_file;
    rp_str_t                 conf_param;
    rp_str_t                 conf_prefix;
    rp_str_t                 prefix;
    rp_str_t                 lock_file;
    rp_str_t                 hostname;
};


typedef struct {
    rp_flag_t                daemon;
    rp_flag_t                master;

    rp_msec_t                timer_resolution;
    rp_msec_t                shutdown_timeout;

    rp_int_t                 worker_processes;
    rp_int_t                 debug_points;

    rp_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    rp_uint_t                cpu_affinity_auto;
    rp_uint_t                cpu_affinity_n;
    rp_cpuset_t             *cpu_affinity;

    char                     *username;
    rp_uid_t                 user;
    rp_gid_t                 group;

    rp_str_t                 working_directory;
    rp_str_t                 lock_file;

    rp_str_t                 pid;
    rp_str_t                 oldpid;

    rp_array_t               env;
    char                    **environment;

    rp_uint_t                transparent;  /* unsigned  transparent:1; */
} rp_core_conf_t;


#define rp_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


rp_cycle_t *rp_init_cycle(rp_cycle_t *old_cycle);
rp_int_t rp_create_pidfile(rp_str_t *name, rp_log_t *log);
void rp_delete_pidfile(rp_cycle_t *cycle);
rp_int_t rp_signal_process(rp_cycle_t *cycle, char *sig);
void rp_reopen_files(rp_cycle_t *cycle, rp_uid_t user);
char **rp_set_environment(rp_cycle_t *cycle, rp_uint_t *last);
rp_pid_t rp_exec_new_binary(rp_cycle_t *cycle, char *const *argv);
rp_cpuset_t *rp_get_cpu_affinity(rp_uint_t n);
rp_shm_zone_t *rp_shared_memory_add(rp_conf_t *cf, rp_str_t *name,
    size_t size, void *tag);
void rp_set_shutdown_timer(rp_cycle_t *cycle);


extern volatile rp_cycle_t  *rp_cycle;
extern rp_array_t            rp_old_cycles;
extern rp_module_t           rp_core_module;
extern rp_uint_t             rp_test_config;
extern rp_uint_t             rp_dump_config;
extern rp_uint_t             rp_quiet_mode;


#endif /* _RP_CYCLE_H_INCLUDED_ */
