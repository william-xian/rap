
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_FILE_H_INCLUDED_
#define _RP_FILE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


struct rp_file_s {
    rp_fd_t                   fd;
    rp_str_t                  name;
    rp_file_info_t            info;

    off_t                      offset;
    off_t                      sys_offset;

    rp_log_t                 *log;

#if (RP_THREADS || RP_COMPAT)
    rp_int_t                (*thread_handler)(rp_thread_task_t *task,
                                               rp_file_t *file);
    void                      *thread_ctx;
    rp_thread_task_t         *thread_task;
#endif

#if (RP_HAVE_FILE_AIO || RP_COMPAT)
    rp_event_aio_t           *aio;
#endif

    unsigned                   valid_info:1;
    unsigned                   directio:1;
};


#define RP_MAX_PATH_LEVEL  3


typedef rp_msec_t (*rp_path_manager_pt) (void *data);
typedef rp_msec_t (*rp_path_purger_pt) (void *data);
typedef void (*rp_path_loader_pt) (void *data);


typedef struct {
    rp_str_t                  name;
    size_t                     len;
    size_t                     level[RP_MAX_PATH_LEVEL];

    rp_path_manager_pt        manager;
    rp_path_purger_pt         purger;
    rp_path_loader_pt         loader;
    void                      *data;

    u_char                    *conf_file;
    rp_uint_t                 line;
} rp_path_t;


typedef struct {
    rp_str_t                  name;
    size_t                     level[RP_MAX_PATH_LEVEL];
} rp_path_init_t;


typedef struct {
    rp_file_t                 file;
    off_t                      offset;
    rp_path_t                *path;
    rp_pool_t                *pool;
    char                      *warn;

    rp_uint_t                 access;

    unsigned                   log_level:8;
    unsigned                   persistent:1;
    unsigned                   clean:1;
    unsigned                   thread_write:1;
} rp_temp_file_t;


typedef struct {
    rp_uint_t                 access;
    rp_uint_t                 path_access;
    time_t                     time;
    rp_fd_t                   fd;

    unsigned                   create_path:1;
    unsigned                   delete_file:1;

    rp_log_t                 *log;
} rp_ext_rename_file_t;


typedef struct {
    off_t                      size;
    size_t                     buf_size;

    rp_uint_t                 access;
    time_t                     time;

    rp_log_t                 *log;
} rp_copy_file_t;


typedef struct rp_tree_ctx_s  rp_tree_ctx_t;

typedef rp_int_t (*rp_tree_init_handler_pt) (void *ctx, void *prev);
typedef rp_int_t (*rp_tree_handler_pt) (rp_tree_ctx_t *ctx, rp_str_t *name);

struct rp_tree_ctx_s {
    off_t                      size;
    off_t                      fs_size;
    rp_uint_t                 access;
    time_t                     mtime;

    rp_tree_init_handler_pt   init_handler;
    rp_tree_handler_pt        file_handler;
    rp_tree_handler_pt        pre_tree_handler;
    rp_tree_handler_pt        post_tree_handler;
    rp_tree_handler_pt        spec_handler;

    void                      *data;
    size_t                     alloc;

    rp_log_t                 *log;
};


rp_int_t rp_get_full_name(rp_pool_t *pool, rp_str_t *prefix,
    rp_str_t *name);

ssize_t rp_write_chain_to_temp_file(rp_temp_file_t *tf, rp_chain_t *chain);
rp_int_t rp_create_temp_file(rp_file_t *file, rp_path_t *path,
    rp_pool_t *pool, rp_uint_t persistent, rp_uint_t clean,
    rp_uint_t access);
void rp_create_hashed_filename(rp_path_t *path, u_char *file, size_t len);
rp_int_t rp_create_path(rp_file_t *file, rp_path_t *path);
rp_err_t rp_create_full_path(u_char *dir, rp_uint_t access);
rp_int_t rp_add_path(rp_conf_t *cf, rp_path_t **slot);
rp_int_t rp_create_paths(rp_cycle_t *cycle, rp_uid_t user);
rp_int_t rp_ext_rename_file(rp_str_t *src, rp_str_t *to,
    rp_ext_rename_file_t *ext);
rp_int_t rp_copy_file(u_char *from, u_char *to, rp_copy_file_t *cf);
rp_int_t rp_walk_tree(rp_tree_ctx_t *ctx, rp_str_t *tree);

rp_atomic_uint_t rp_next_temp_number(rp_uint_t collision);

char *rp_conf_set_path_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_merge_path_value(rp_conf_t *cf, rp_path_t **path,
    rp_path_t *prev, rp_path_init_t *init);
char *rp_conf_set_access_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);


extern rp_atomic_t      *rp_temp_number;
extern rp_atomic_int_t   rp_random_number;


#endif /* _RP_FILE_H_INCLUDED_ */
