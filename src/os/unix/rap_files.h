
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_FILES_H_INCLUDED_
#define _RAP_FILES_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef int                      rap_fd_t;
typedef struct stat              rap_file_info_t;
typedef ino_t                    rap_file_uniq_t;


typedef struct {
    u_char                      *name;
    size_t                       size;
    void                        *addr;
    rap_fd_t                     fd;
    rap_log_t                   *log;
} rap_file_mapping_t;


typedef struct {
    DIR                         *dir;
    struct dirent               *de;
    struct stat                  info;

    unsigned                     type:8;
    unsigned                     valid_info:1;
} rap_dir_t;


typedef struct {
    size_t                       n;
    glob_t                       pglob;
    u_char                      *pattern;
    rap_log_t                   *log;
    rap_uint_t                   test;
} rap_glob_t;


#define RAP_INVALID_FILE         -1
#define RAP_FILE_ERROR           -1



#ifdef __CYGWIN__

#ifndef RAP_HAVE_CASELESS_FILESYSTEM
#define RAP_HAVE_CASELESS_FILESYSTEM  1
#endif

#define rap_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create|O_BINARY, access)

#else

#define rap_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create, access)

#endif

#define rap_open_file_n          "open()"

#define RAP_FILE_RDONLY          O_RDONLY
#define RAP_FILE_WRONLY          O_WRONLY
#define RAP_FILE_RDWR            O_RDWR
#define RAP_FILE_CREATE_OR_OPEN  O_CREAT
#define RAP_FILE_OPEN            0
#define RAP_FILE_TRUNCATE        (O_CREAT|O_TRUNC)
#define RAP_FILE_APPEND          (O_WRONLY|O_APPEND)
#define RAP_FILE_NONBLOCK        O_NONBLOCK

#if (RAP_HAVE_OPENAT)
#define RAP_FILE_NOFOLLOW        O_NOFOLLOW

#if defined(O_DIRECTORY)
#define RAP_FILE_DIRECTORY       O_DIRECTORY
#else
#define RAP_FILE_DIRECTORY       0
#endif

#if defined(O_SEARCH)
#define RAP_FILE_SEARCH          (O_SEARCH|RAP_FILE_DIRECTORY)

#elif defined(O_EXEC)
#define RAP_FILE_SEARCH          (O_EXEC|RAP_FILE_DIRECTORY)

#elif (RAP_HAVE_O_PATH)
#define RAP_FILE_SEARCH          (O_PATH|O_RDONLY|RAP_FILE_DIRECTORY)

#else
#define RAP_FILE_SEARCH          (O_RDONLY|RAP_FILE_DIRECTORY)
#endif

#endif /* RAP_HAVE_OPENAT */

#define RAP_FILE_DEFAULT_ACCESS  0644
#define RAP_FILE_OWNER_ACCESS    0600


#define rap_close_file           close
#define rap_close_file_n         "close()"


#define rap_delete_file(name)    unlink((const char *) name)
#define rap_delete_file_n        "unlink()"


rap_fd_t rap_open_tempfile(u_char *name, rap_uint_t persistent,
    rap_uint_t access);
#define rap_open_tempfile_n      "open()"


ssize_t rap_read_file(rap_file_t *file, u_char *buf, size_t size, off_t offset);
#if (RAP_HAVE_PREAD)
#define rap_read_file_n          "pread()"
#else
#define rap_read_file_n          "read()"
#endif

ssize_t rap_write_file(rap_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t rap_write_chain_to_file(rap_file_t *file, rap_chain_t *ce,
    off_t offset, rap_pool_t *pool);


#define rap_read_fd              read
#define rap_read_fd_n            "read()"

/*
 * we use inlined function instead of simple #define
 * because glibc 2.3 sets warn_unused_result attribute for write()
 * and in this case gcc 4.3 ignores (void) cast
 */
static rap_inline ssize_t
rap_write_fd(rap_fd_t fd, void *buf, size_t n)
{
    return write(fd, buf, n);
}

#define rap_write_fd_n           "write()"


#define rap_write_console        rap_write_fd


#define rap_linefeed(p)          *p++ = LF;
#define RAP_LINEFEED_SIZE        1
#define RAP_LINEFEED             "\x0a"


#define rap_rename_file(o, n)    rename((const char *) o, (const char *) n)
#define rap_rename_file_n        "rename()"


#define rap_change_file_access(n, a) chmod((const char *) n, a)
#define rap_change_file_access_n "chmod()"


rap_int_t rap_set_file_time(u_char *name, rap_fd_t fd, time_t s);
#define rap_set_file_time_n      "utimes()"


#define rap_file_info(file, sb)  stat((const char *) file, sb)
#define rap_file_info_n          "stat()"

#define rap_fd_info(fd, sb)      fstat(fd, sb)
#define rap_fd_info_n            "fstat()"

#define rap_link_info(file, sb)  lstat((const char *) file, sb)
#define rap_link_info_n          "lstat()"

#define rap_is_dir(sb)           (S_ISDIR((sb)->st_mode))
#define rap_is_file(sb)          (S_ISREG((sb)->st_mode))
#define rap_is_link(sb)          (S_ISLNK((sb)->st_mode))
#define rap_is_exec(sb)          (((sb)->st_mode & S_IXUSR) == S_IXUSR)
#define rap_file_access(sb)      ((sb)->st_mode & 0777)
#define rap_file_size(sb)        (sb)->st_size
#define rap_file_fs_size(sb)     rap_max((sb)->st_size, (sb)->st_blocks * 512)
#define rap_file_mtime(sb)       (sb)->st_mtime
#define rap_file_uniq(sb)        (sb)->st_ino


rap_int_t rap_create_file_mapping(rap_file_mapping_t *fm);
void rap_close_file_mapping(rap_file_mapping_t *fm);


#define rap_realpath(p, r)       (u_char *) realpath((char *) p, (char *) r)
#define rap_realpath_n           "realpath()"
#define rap_getcwd(buf, size)    (getcwd((char *) buf, size) != NULL)
#define rap_getcwd_n             "getcwd()"
#define rap_path_separator(c)    ((c) == '/')


#if defined(PATH_MAX)

#define RAP_HAVE_MAX_PATH        1
#define RAP_MAX_PATH             PATH_MAX

#else

#define RAP_MAX_PATH             4096

#endif


rap_int_t rap_open_dir(rap_str_t *name, rap_dir_t *dir);
#define rap_open_dir_n           "opendir()"


#define rap_close_dir(d)         closedir((d)->dir)
#define rap_close_dir_n          "closedir()"


rap_int_t rap_read_dir(rap_dir_t *dir);
#define rap_read_dir_n           "readdir()"


#define rap_create_dir(name, access) mkdir((const char *) name, access)
#define rap_create_dir_n         "mkdir()"


#define rap_delete_dir(name)     rmdir((const char *) name)
#define rap_delete_dir_n         "rmdir()"


#define rap_dir_access(a)        (a | (a & 0444) >> 2)


#define rap_de_name(dir)         ((u_char *) (dir)->de->d_name)
#if (RAP_HAVE_D_NAMLEN)
#define rap_de_namelen(dir)      (dir)->de->d_namlen
#else
#define rap_de_namelen(dir)      rap_strlen((dir)->de->d_name)
#endif

static rap_inline rap_int_t
rap_de_info(u_char *name, rap_dir_t *dir)
{
    dir->type = 0;
    return stat((const char *) name, &dir->info);
}

#define rap_de_info_n            "stat()"
#define rap_de_link_info(name, dir)  lstat((const char *) name, &(dir)->info)
#define rap_de_link_info_n       "lstat()"

#if (RAP_HAVE_D_TYPE)

/*
 * some file systems (e.g. XFS on Linux and CD9660 on FreeBSD)
 * do not set dirent.d_type
 */

#define rap_de_is_dir(dir)                                                   \
    (((dir)->type) ? ((dir)->type == DT_DIR) : (S_ISDIR((dir)->info.st_mode)))
#define rap_de_is_file(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_REG) : (S_ISREG((dir)->info.st_mode)))
#define rap_de_is_link(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_LNK) : (S_ISLNK((dir)->info.st_mode)))

#else

#define rap_de_is_dir(dir)       (S_ISDIR((dir)->info.st_mode))
#define rap_de_is_file(dir)      (S_ISREG((dir)->info.st_mode))
#define rap_de_is_link(dir)      (S_ISLNK((dir)->info.st_mode))

#endif

#define rap_de_access(dir)       (((dir)->info.st_mode) & 0777)
#define rap_de_size(dir)         (dir)->info.st_size
#define rap_de_fs_size(dir)                                                  \
    rap_max((dir)->info.st_size, (dir)->info.st_blocks * 512)
#define rap_de_mtime(dir)        (dir)->info.st_mtime


rap_int_t rap_open_glob(rap_glob_t *gl);
#define rap_open_glob_n          "glob()"
rap_int_t rap_read_glob(rap_glob_t *gl, rap_str_t *name);
void rap_close_glob(rap_glob_t *gl);


rap_err_t rap_trylock_fd(rap_fd_t fd);
rap_err_t rap_lock_fd(rap_fd_t fd);
rap_err_t rap_unlock_fd(rap_fd_t fd);

#define rap_trylock_fd_n         "fcntl(F_SETLK, F_WRLCK)"
#define rap_lock_fd_n            "fcntl(F_SETLKW, F_WRLCK)"
#define rap_unlock_fd_n          "fcntl(F_SETLK, F_UNLCK)"


#if (RAP_HAVE_F_READAHEAD)

#define RAP_HAVE_READ_AHEAD      1

#define rap_read_ahead(fd, n)    fcntl(fd, F_READAHEAD, (int) n)
#define rap_read_ahead_n         "fcntl(fd, F_READAHEAD)"

#elif (RAP_HAVE_POSIX_FADVISE)

#define RAP_HAVE_READ_AHEAD      1

rap_int_t rap_read_ahead(rap_fd_t fd, size_t n);
#define rap_read_ahead_n         "posix_fadvise(POSIX_FADV_SEQUENTIAL)"

#else

#define rap_read_ahead(fd, n)    0
#define rap_read_ahead_n         "rap_read_ahead_n"

#endif


#if (RAP_HAVE_O_DIRECT)

rap_int_t rap_directio_on(rap_fd_t fd);
#define rap_directio_on_n        "fcntl(O_DIRECT)"

rap_int_t rap_directio_off(rap_fd_t fd);
#define rap_directio_off_n       "fcntl(!O_DIRECT)"

#elif (RAP_HAVE_F_NOCACHE)

#define rap_directio_on(fd)      fcntl(fd, F_NOCACHE, 1)
#define rap_directio_on_n        "fcntl(F_NOCACHE, 1)"

#elif (RAP_HAVE_DIRECTIO)

#define rap_directio_on(fd)      directio(fd, DIRECTIO_ON)
#define rap_directio_on_n        "directio(DIRECTIO_ON)"

#else

#define rap_directio_on(fd)      0
#define rap_directio_on_n        "rap_directio_on_n"

#endif

size_t rap_fs_bsize(u_char *name);


#if (RAP_HAVE_OPENAT)

#define rap_openat_file(fd, name, mode, create, access)                      \
    openat(fd, (const char *) name, mode|create, access)

#define rap_openat_file_n        "openat()"

#define rap_file_at_info(fd, name, sb, flag)                                 \
    fstatat(fd, (const char *) name, sb, flag)

#define rap_file_at_info_n       "fstatat()"

#define RAP_AT_FDCWD             (rap_fd_t) AT_FDCWD

#endif


#define rap_stdout               STDOUT_FILENO
#define rap_stderr               STDERR_FILENO
#define rap_set_stderr(fd)       dup2(fd, STDERR_FILENO)
#define rap_set_stderr_n         "dup2(STDERR_FILENO)"


#if (RAP_HAVE_FILE_AIO)

rap_int_t rap_file_aio_init(rap_file_t *file, rap_pool_t *pool);
ssize_t rap_file_aio_read(rap_file_t *file, u_char *buf, size_t size,
    off_t offset, rap_pool_t *pool);

extern rap_uint_t  rap_file_aio;

#endif

#if (RAP_THREADS)
ssize_t rap_thread_read(rap_file_t *file, u_char *buf, size_t size,
    off_t offset, rap_pool_t *pool);
ssize_t rap_thread_write_chain_to_file(rap_file_t *file, rap_chain_t *cl,
    off_t offset, rap_pool_t *pool);
#endif


#endif /* _RAP_FILES_H_INCLUDED_ */
