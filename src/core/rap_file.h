
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_FILE_H_INCLUDED_
#define _RAP_FILE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


struct rap_file_s {
    rap_fd_t                   fd;
    rap_str_t                  name;
    rap_file_info_t            info;

    off_t                      offset;
    off_t                      sys_offset;

    rap_log_t                 *log;

#if (RAP_THREADS || RAP_COMPAT)
    rap_int_t                (*thread_handler)(rap_thread_task_t *task,
                                               rap_file_t *file);
    void                      *thread_ctx;
    rap_thread_task_t         *thread_task;
#endif

#if (RAP_HAVE_FILE_AIO || RAP_COMPAT)
    rap_event_aio_t           *aio;
#endif

    unsigned                   valid_info:1;
    unsigned                   directio:1;
};


#define RAP_MAX_PATH_LEVEL  3


typedef rap_msec_t (*rap_path_manager_pt) (void *data);
typedef rap_msec_t (*rap_path_purger_pt) (void *data);
typedef void (*rap_path_loader_pt) (void *data);


typedef struct {
    rap_str_t                  name;
    size_t                     len;
    size_t                     level[RAP_MAX_PATH_LEVEL];

    rap_path_manager_pt        manager;
    rap_path_purger_pt         purger;
    rap_path_loader_pt         loader;
    void                      *data;

    u_char                    *conf_file;
    rap_uint_t                 line;
} rap_path_t;


typedef struct {
    rap_str_t                  name;
    size_t                     level[RAP_MAX_PATH_LEVEL];
} rap_path_init_t;


typedef struct {
    rap_file_t                 file;
    off_t                      offset;
    rap_path_t                *path;
    rap_pool_t                *pool;
    char                      *warn;

    rap_uint_t                 access;

    unsigned                   log_level:8;
    unsigned                   persistent:1;
    unsigned                   clean:1;
    unsigned                   thread_write:1;
} rap_temp_file_t;


typedef struct {
    rap_uint_t                 access;
    rap_uint_t                 path_access;
    time_t                     time;
    rap_fd_t                   fd;

    unsigned                   create_path:1;
    unsigned                   delete_file:1;

    rap_log_t                 *log;
} rap_ext_rename_file_t;


typedef struct {
    off_t                      size;
    size_t                     buf_size;

    rap_uint_t                 access;
    time_t                     time;

    rap_log_t                 *log;
} rap_copy_file_t;


typedef struct rap_tree_ctx_s  rap_tree_ctx_t;

typedef rap_int_t (*rap_tree_init_handler_pt) (void *ctx, void *prev);
typedef rap_int_t (*rap_tree_handler_pt) (rap_tree_ctx_t *ctx, rap_str_t *name);

struct rap_tree_ctx_s {
    off_t                      size;
    off_t                      fs_size;
    rap_uint_t                 access;
    time_t                     mtime;

    rap_tree_init_handler_pt   init_handler;
    rap_tree_handler_pt        file_handler;
    rap_tree_handler_pt        pre_tree_handler;
    rap_tree_handler_pt        post_tree_handler;
    rap_tree_handler_pt        spec_handler;

    void                      *data;
    size_t                     alloc;

    rap_log_t                 *log;
};


rap_int_t rap_get_full_name(rap_pool_t *pool, rap_str_t *prefix,
    rap_str_t *name);

ssize_t rap_write_chain_to_temp_file(rap_temp_file_t *tf, rap_chain_t *chain);
rap_int_t rap_create_temp_file(rap_file_t *file, rap_path_t *path,
    rap_pool_t *pool, rap_uint_t persistent, rap_uint_t clean,
    rap_uint_t access);
void rap_create_hashed_filename(rap_path_t *path, u_char *file, size_t len);
rap_int_t rap_create_path(rap_file_t *file, rap_path_t *path);
rap_err_t rap_create_full_path(u_char *dir, rap_uint_t access);
rap_int_t rap_add_path(rap_conf_t *cf, rap_path_t **slot);
rap_int_t rap_create_paths(rap_cycle_t *cycle, rap_uid_t user);
rap_int_t rap_ext_rename_file(rap_str_t *src, rap_str_t *to,
    rap_ext_rename_file_t *ext);
rap_int_t rap_copy_file(u_char *from, u_char *to, rap_copy_file_t *cf);
rap_int_t rap_walk_tree(rap_tree_ctx_t *ctx, rap_str_t *tree);

rap_atomic_uint_t rap_next_temp_number(rap_uint_t collision);

char *rap_conf_set_path_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_merge_path_value(rap_conf_t *cf, rap_path_t **path,
    rap_path_t *prev, rap_path_init_t *init);
char *rap_conf_set_access_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);


extern rap_atomic_t      *rap_temp_number;
extern rap_atomic_int_t   rap_random_number;


#endif /* _RAP_FILE_H_INCLUDED_ */
