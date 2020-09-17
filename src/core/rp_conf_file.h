
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CONF_FILE_H_INCLUDED_
#define _RP_CONF_FILE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define RP_CONF_NOARGS      0x00000001
#define RP_CONF_TAKE1       0x00000002
#define RP_CONF_TAKE2       0x00000004
#define RP_CONF_TAKE3       0x00000008
#define RP_CONF_TAKE4       0x00000010
#define RP_CONF_TAKE5       0x00000020
#define RP_CONF_TAKE6       0x00000040
#define RP_CONF_TAKE7       0x00000080

#define RP_CONF_MAX_ARGS    8

#define RP_CONF_TAKE12      (RP_CONF_TAKE1|RP_CONF_TAKE2)
#define RP_CONF_TAKE13      (RP_CONF_TAKE1|RP_CONF_TAKE3)

#define RP_CONF_TAKE23      (RP_CONF_TAKE2|RP_CONF_TAKE3)

#define RP_CONF_TAKE123     (RP_CONF_TAKE1|RP_CONF_TAKE2|RP_CONF_TAKE3)
#define RP_CONF_TAKE1234    (RP_CONF_TAKE1|RP_CONF_TAKE2|RP_CONF_TAKE3   \
                              |RP_CONF_TAKE4)

#define RP_CONF_ARGS_NUMBER 0x000000ff
#define RP_CONF_BLOCK       0x00000100
#define RP_CONF_FLAG        0x00000200
#define RP_CONF_ANY         0x00000400
#define RP_CONF_1MORE       0x00000800
#define RP_CONF_2MORE       0x00001000

#define RP_DIRECT_CONF      0x00010000

#define RP_MAIN_CONF        0x01000000
#define RP_ANY_CONF         0xFF000000



#define RP_CONF_UNSET       -1
#define RP_CONF_UNSET_UINT  (rp_uint_t) -1
#define RP_CONF_UNSET_PTR   (void *) -1
#define RP_CONF_UNSET_SIZE  (size_t) -1
#define RP_CONF_UNSET_MSEC  (rp_msec_t) -1


#define RP_CONF_OK          NULL
#define RP_CONF_ERROR       (void *) -1

#define RP_CONF_BLOCK_START 1
#define RP_CONF_BLOCK_DONE  2
#define RP_CONF_FILE_DONE   3

#define RP_CORE_MODULE      0x45524F43  /* "CORE" */
#define RP_CONF_MODULE      0x464E4F43  /* "CONF" */


#define RP_MAX_CONF_ERRSTR  1024


struct rp_command_s {
    rp_str_t             name;
    rp_uint_t            type;
    char               *(*set)(rp_conf_t *cf, rp_command_t *cmd, void *conf);
    rp_uint_t            conf;
    rp_uint_t            offset;
    void                 *post;
};

#define rp_null_command  { rp_null_string, 0, NULL, 0, 0, NULL }


struct rp_open_file_s {
    rp_fd_t              fd;
    rp_str_t             name;

    void                (*flush)(rp_open_file_t *file, rp_log_t *log);
    void                 *data;
};


typedef struct {
    rp_file_t            file;
    rp_buf_t            *buffer;
    rp_buf_t            *dump;
    rp_uint_t            line;
} rp_conf_file_t;


typedef struct {
    rp_str_t             name;
    rp_buf_t            *buffer;
} rp_conf_dump_t;


typedef char *(*rp_conf_handler_pt)(rp_conf_t *cf,
    rp_command_t *dummy, void *conf);


struct rp_conf_s {
    char                 *name;
    rp_array_t          *args;

    rp_cycle_t          *cycle;
    rp_pool_t           *pool;
    rp_pool_t           *temp_pool;
    rp_conf_file_t      *conf_file;
    rp_log_t            *log;

    void                 *ctx;
    rp_uint_t            module_type;
    rp_uint_t            cmd_type;

    rp_conf_handler_pt   handler;
    void                 *handler_conf;
};


typedef char *(*rp_conf_post_handler_pt) (rp_conf_t *cf,
    void *data, void *conf);

typedef struct {
    rp_conf_post_handler_pt  post_handler;
} rp_conf_post_t;


typedef struct {
    rp_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} rp_conf_deprecated_t;


typedef struct {
    rp_conf_post_handler_pt  post_handler;
    rp_int_t                 low;
    rp_int_t                 high;
} rp_conf_num_bounds_t;


typedef struct {
    rp_str_t                 name;
    rp_uint_t                value;
} rp_conf_enum_t;


#define RP_CONF_BITMASK_SET  1

typedef struct {
    rp_str_t                 name;
    rp_uint_t                mask;
} rp_conf_bitmask_t;



char * rp_conf_deprecated(rp_conf_t *cf, void *post, void *data);
char *rp_conf_check_num_bounds(rp_conf_t *cf, void *post, void *data);


#define rp_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define rp_conf_init_value(conf, default)                                   \
    if (conf == RP_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define rp_conf_init_ptr_value(conf, default)                               \
    if (conf == RP_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define rp_conf_init_uint_value(conf, default)                              \
    if (conf == RP_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define rp_conf_init_size_value(conf, default)                              \
    if (conf == RP_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define rp_conf_init_msec_value(conf, default)                              \
    if (conf == RP_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define rp_conf_merge_value(conf, prev, default)                            \
    if (conf == RP_CONF_UNSET) {                                            \
        conf = (prev == RP_CONF_UNSET) ? default : prev;                    \
    }

#define rp_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == RP_CONF_UNSET_PTR) {                                        \
        conf = (prev == RP_CONF_UNSET_PTR) ? default : prev;                \
    }

#define rp_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == RP_CONF_UNSET_UINT) {                                       \
        conf = (prev == RP_CONF_UNSET_UINT) ? default : prev;               \
    }

#define rp_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == RP_CONF_UNSET_MSEC) {                                       \
        conf = (prev == RP_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define rp_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == RP_CONF_UNSET) {                                            \
        conf = (prev == RP_CONF_UNSET) ? default : prev;                    \
    }

#define rp_conf_merge_size_value(conf, prev, default)                       \
    if (conf == RP_CONF_UNSET_SIZE) {                                       \
        conf = (prev == RP_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define rp_conf_merge_off_value(conf, prev, default)                        \
    if (conf == RP_CONF_UNSET) {                                            \
        conf = (prev == RP_CONF_UNSET) ? default : prev;                    \
    }

#define rp_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define rp_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define rp_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *rp_conf_param(rp_conf_t *cf);
char *rp_conf_parse(rp_conf_t *cf, rp_str_t *filename);
char *rp_conf_include(rp_conf_t *cf, rp_command_t *cmd, void *conf);


rp_int_t rp_conf_full_name(rp_cycle_t *cycle, rp_str_t *name,
    rp_uint_t conf_prefix);
rp_open_file_t *rp_conf_open_file(rp_cycle_t *cycle, rp_str_t *name);
void rp_cdecl rp_conf_log_error(rp_uint_t level, rp_conf_t *cf,
    rp_err_t err, const char *fmt, ...);


char *rp_conf_set_flag_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_str_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_str_array_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
char *rp_conf_set_keyval_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_num_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_size_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_off_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_msec_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_sec_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_bufs_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_enum_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);
char *rp_conf_set_bitmask_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf);


#endif /* _RP_CONF_FILE_H_INCLUDED_ */
