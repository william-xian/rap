
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CONF_FILE_H_INCLUDED_
#define _RAP_CONF_FILE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define RAP_CONF_NOARGS      0x00000001
#define RAP_CONF_TAKE1       0x00000002
#define RAP_CONF_TAKE2       0x00000004
#define RAP_CONF_TAKE3       0x00000008
#define RAP_CONF_TAKE4       0x00000010
#define RAP_CONF_TAKE5       0x00000020
#define RAP_CONF_TAKE6       0x00000040
#define RAP_CONF_TAKE7       0x00000080

#define RAP_CONF_MAX_ARGS    8

#define RAP_CONF_TAKE12      (RAP_CONF_TAKE1|RAP_CONF_TAKE2)
#define RAP_CONF_TAKE13      (RAP_CONF_TAKE1|RAP_CONF_TAKE3)

#define RAP_CONF_TAKE23      (RAP_CONF_TAKE2|RAP_CONF_TAKE3)

#define RAP_CONF_TAKE123     (RAP_CONF_TAKE1|RAP_CONF_TAKE2|RAP_CONF_TAKE3)
#define RAP_CONF_TAKE1234    (RAP_CONF_TAKE1|RAP_CONF_TAKE2|RAP_CONF_TAKE3   \
                              |RAP_CONF_TAKE4)

#define RAP_CONF_ARGS_NUMBER 0x000000ff
#define RAP_CONF_BLOCK       0x00000100
#define RAP_CONF_FLAG        0x00000200
#define RAP_CONF_ANY         0x00000400
#define RAP_CONF_1MORE       0x00000800
#define RAP_CONF_2MORE       0x00001000

#define RAP_DIRECT_CONF      0x00010000

#define RAP_MAIN_CONF        0x01000000
#define RAP_ANY_CONF         0xFF000000



#define RAP_CONF_UNSET       -1
#define RAP_CONF_UNSET_UINT  (rap_uint_t) -1
#define RAP_CONF_UNSET_PTR   (void *) -1
#define RAP_CONF_UNSET_SIZE  (size_t) -1
#define RAP_CONF_UNSET_MSEC  (rap_msec_t) -1


#define RAP_CONF_OK          NULL
#define RAP_CONF_ERROR       (void *) -1

#define RAP_CONF_BLOCK_START 1
#define RAP_CONF_BLOCK_DONE  2
#define RAP_CONF_FILE_DONE   3

#define RAP_CORE_MODULE      0x45524F43  /* "CORE" */
#define RAP_CONF_MODULE      0x464E4F43  /* "CONF" */


#define RAP_MAX_CONF_ERRSTR  1024


struct rap_command_s {
    rap_str_t             name;
    rap_uint_t            type;
    char               *(*set)(rap_conf_t *cf, rap_command_t *cmd, void *conf);
    rap_uint_t            conf;
    rap_uint_t            offset;
    void                 *post;
};

#define rap_null_command  { rap_null_string, 0, NULL, 0, 0, NULL }


struct rap_open_file_s {
    rap_fd_t              fd;
    rap_str_t             name;

    void                (*flush)(rap_open_file_t *file, rap_log_t *log);
    void                 *data;
};


typedef struct {
    rap_file_t            file;
    rap_buf_t            *buffer;
    rap_buf_t            *dump;
    rap_uint_t            line;
} rap_conf_file_t;


typedef struct {
    rap_str_t             name;
    rap_buf_t            *buffer;
} rap_conf_dump_t;


typedef char *(*rap_conf_handler_pt)(rap_conf_t *cf,
    rap_command_t *dummy, void *conf);


struct rap_conf_s {
    char                 *name;
    rap_array_t          *args;

    rap_cycle_t          *cycle;
    rap_pool_t           *pool;
    rap_pool_t           *temp_pool;
    rap_conf_file_t      *conf_file;
    rap_log_t            *log;

    void                 *ctx;
    rap_uint_t            module_type;
    rap_uint_t            cmd_type;

    rap_conf_handler_pt   handler;
    void                 *handler_conf;
};


typedef char *(*rap_conf_post_handler_pt) (rap_conf_t *cf,
    void *data, void *conf);

typedef struct {
    rap_conf_post_handler_pt  post_handler;
} rap_conf_post_t;


typedef struct {
    rap_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} rap_conf_deprecated_t;


typedef struct {
    rap_conf_post_handler_pt  post_handler;
    rap_int_t                 low;
    rap_int_t                 high;
} rap_conf_num_bounds_t;


typedef struct {
    rap_str_t                 name;
    rap_uint_t                value;
} rap_conf_enum_t;


#define RAP_CONF_BITMASK_SET  1

typedef struct {
    rap_str_t                 name;
    rap_uint_t                mask;
} rap_conf_bitmask_t;



char * rap_conf_deprecated(rap_conf_t *cf, void *post, void *data);
char *rap_conf_check_num_bounds(rap_conf_t *cf, void *post, void *data);


#define rap_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define rap_conf_init_value(conf, default)                                   \
    if (conf == RAP_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define rap_conf_init_ptr_value(conf, default)                               \
    if (conf == RAP_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define rap_conf_init_uint_value(conf, default)                              \
    if (conf == RAP_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define rap_conf_init_size_value(conf, default)                              \
    if (conf == RAP_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define rap_conf_init_msec_value(conf, default)                              \
    if (conf == RAP_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define rap_conf_merge_value(conf, prev, default)                            \
    if (conf == RAP_CONF_UNSET) {                                            \
        conf = (prev == RAP_CONF_UNSET) ? default : prev;                    \
    }

#define rap_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == RAP_CONF_UNSET_PTR) {                                        \
        conf = (prev == RAP_CONF_UNSET_PTR) ? default : prev;                \
    }

#define rap_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == RAP_CONF_UNSET_UINT) {                                       \
        conf = (prev == RAP_CONF_UNSET_UINT) ? default : prev;               \
    }

#define rap_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == RAP_CONF_UNSET_MSEC) {                                       \
        conf = (prev == RAP_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define rap_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == RAP_CONF_UNSET) {                                            \
        conf = (prev == RAP_CONF_UNSET) ? default : prev;                    \
    }

#define rap_conf_merge_size_value(conf, prev, default)                       \
    if (conf == RAP_CONF_UNSET_SIZE) {                                       \
        conf = (prev == RAP_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define rap_conf_merge_off_value(conf, prev, default)                        \
    if (conf == RAP_CONF_UNSET) {                                            \
        conf = (prev == RAP_CONF_UNSET) ? default : prev;                    \
    }

#define rap_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define rap_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define rap_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *rap_conf_param(rap_conf_t *cf);
char *rap_conf_parse(rap_conf_t *cf, rap_str_t *filename);
char *rap_conf_include(rap_conf_t *cf, rap_command_t *cmd, void *conf);


rap_int_t rap_conf_full_name(rap_cycle_t *cycle, rap_str_t *name,
    rap_uint_t conf_prefix);
rap_open_file_t *rap_conf_open_file(rap_cycle_t *cycle, rap_str_t *name);
void rap_cdecl rap_conf_log_error(rap_uint_t level, rap_conf_t *cf,
    rap_err_t err, const char *fmt, ...);


char *rap_conf_set_flag_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_str_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_str_array_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
char *rap_conf_set_keyval_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_num_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_size_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_off_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_msec_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_sec_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_bufs_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_enum_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);
char *rap_conf_set_bitmask_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf);


#endif /* _RAP_CONF_FILE_H_INCLUDED_ */
