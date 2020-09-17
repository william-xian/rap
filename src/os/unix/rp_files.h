
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_FILES_H_INCLUDED_
#define _RP_FILES_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef int                      rp_fd_t;
typedef struct stat              rp_file_info_t;
typedef ino_t                    rp_file_uniq_t;


typedef struct {
    u_char                      *name;
    size_t                       size;
    void                        *addr;
    rp_fd_t                     fd;
    rp_log_t                   *log;
} rp_file_mapping_t;


typedef struct {
    DIR                         *dir;
    struct dirent               *de;
    struct stat                  info;

    unsigned                     type:8;
    unsigned                     valid_info:1;
} rp_dir_t;


typedef struct {
    size_t                       n;
    glob_t                       pglob;
    u_char                      *pattern;
    rp_log_t                   *log;
    rp_uint_t                   test;
} rp_glob_t;


#define RP_INVALID_FILE         -1
#define RP_FILE_ERROR           -1



#ifdef __CYGWIN__

#ifndef RP_HAVE_CASELESS_FILESYSTEM
#define RP_HAVE_CASELESS_FILESYSTEM  1
#endif

#define rp_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create|O_BINARY, access)

#else

#define rp_open_file(name, mode, create, access)                            \
    open((const char *) name, mode|create, access)

#endif

#define rp_open_file_n          "open()"

#define RP_FILE_RDONLY          O_RDONLY
#define RP_FILE_WRONLY          O_WRONLY
#define RP_FILE_RDWR            O_RDWR
#define RP_FILE_CREATE_OR_OPEN  O_CREAT
#define RP_FILE_OPEN            0
#define RP_FILE_TRUNCATE        (O_CREAT|O_TRUNC)
#define RP_FILE_APPEND          (O_WRONLY|O_APPEND)
#define RP_FILE_NONBLOCK        O_NONBLOCK

#if (RP_HAVE_OPENAT)
#define RP_FILE_NOFOLLOW        O_NOFOLLOW

#if defined(O_DIRECTORY)
#define RP_FILE_DIRECTORY       O_DIRECTORY
#else
#define RP_FILE_DIRECTORY       0
#endif

#if defined(O_SEARCH)
#define RP_FILE_SEARCH          (O_SEARCH|RP_FILE_DIRECTORY)

#elif defined(O_EXEC)
#define RP_FILE_SEARCH          (O_EXEC|RP_FILE_DIRECTORY)

#elif (RP_HAVE_O_PATH)
#define RP_FILE_SEARCH          (O_PATH|O_RDONLY|RP_FILE_DIRECTORY)

#else
#define RP_FILE_SEARCH          (O_RDONLY|RP_FILE_DIRECTORY)
#endif

#endif /* RP_HAVE_OPENAT */

#define RP_FILE_DEFAULT_ACCESS  0644
#define RP_FILE_OWNER_ACCESS    0600


#define rp_close_file           close
#define rp_close_file_n         "close()"


#define rp_delete_file(name)    unlink((const char *) name)
#define rp_delete_file_n        "unlink()"


rp_fd_t rp_open_tempfile(u_char *name, rp_uint_t persistent,
    rp_uint_t access);
#define rp_open_tempfile_n      "open()"


ssize_t rp_read_file(rp_file_t *file, u_char *buf, size_t size, off_t offset);
#if (RP_HAVE_PREAD)
#define rp_read_file_n          "pread()"
#else
#define rp_read_file_n          "read()"
#endif

ssize_t rp_write_file(rp_file_t *file, u_char *buf, size_t size,
    off_t offset);

ssize_t rp_write_chain_to_file(rp_file_t *file, rp_chain_t *ce,
    off_t offset, rp_pool_t *pool);


#define rp_read_fd              read
#define rp_read_fd_n            "read()"

/*
 * we use inlined function instead of simple #define
 * because glibc 2.3 sets warn_unused_result attribute for write()
 * and in this case gcc 4.3 ignores (void) cast
 */
static rp_inline ssize_t
rp_write_fd(rp_fd_t fd, void *buf, size_t n)
{
    return write(fd, buf, n);
}

#define rp_write_fd_n           "write()"


#define rp_write_console        rp_write_fd


#define rp_linefeed(p)          *p++ = LF;
#define RP_LINEFEED_SIZE        1
#define RP_LINEFEED             "\x0a"


#define rp_rename_file(o, n)    rename((const char *) o, (const char *) n)
#define rp_rename_file_n        "rename()"


#define rp_change_file_access(n, a) chmod((const char *) n, a)
#define rp_change_file_access_n "chmod()"


rp_int_t rp_set_file_time(u_char *name, rp_fd_t fd, time_t s);
#define rp_set_file_time_n      "utimes()"


#define rp_file_info(file, sb)  stat((const char *) file, sb)
#define rp_file_info_n          "stat()"

#define rp_fd_info(fd, sb)      fstat(fd, sb)
#define rp_fd_info_n            "fstat()"

#define rp_link_info(file, sb)  lstat((const char *) file, sb)
#define rp_link_info_n          "lstat()"

#define rp_is_dir(sb)           (S_ISDIR((sb)->st_mode))
#define rp_is_file(sb)          (S_ISREG((sb)->st_mode))
#define rp_is_link(sb)          (S_ISLNK((sb)->st_mode))
#define rp_is_exec(sb)          (((sb)->st_mode & S_IXUSR) == S_IXUSR)
#define rp_file_access(sb)      ((sb)->st_mode & 0777)
#define rp_file_size(sb)        (sb)->st_size
#define rp_file_fs_size(sb)     rp_max((sb)->st_size, (sb)->st_blocks * 512)
#define rp_file_mtime(sb)       (sb)->st_mtime
#define rp_file_uniq(sb)        (sb)->st_ino


rp_int_t rp_create_file_mapping(rp_file_mapping_t *fm);
void rp_close_file_mapping(rp_file_mapping_t *fm);


#define rp_realpath(p, r)       (u_char *) realpath((char *) p, (char *) r)
#define rp_realpath_n           "realpath()"
#define rp_getcwd(buf, size)    (getcwd((char *) buf, size) != NULL)
#define rp_getcwd_n             "getcwd()"
#define rp_path_separator(c)    ((c) == '/')


#if defined(PATH_MAX)

#define RP_HAVE_MAX_PATH        1
#define RP_MAX_PATH             PATH_MAX

#else

#define RP_MAX_PATH             4096

#endif


rp_int_t rp_open_dir(rp_str_t *name, rp_dir_t *dir);
#define rp_open_dir_n           "opendir()"


#define rp_close_dir(d)         closedir((d)->dir)
#define rp_close_dir_n          "closedir()"


rp_int_t rp_read_dir(rp_dir_t *dir);
#define rp_read_dir_n           "readdir()"


#define rp_create_dir(name, access) mkdir((const char *) name, access)
#define rp_create_dir_n         "mkdir()"


#define rp_delete_dir(name)     rmdir((const char *) name)
#define rp_delete_dir_n         "rmdir()"


#define rp_dir_access(a)        (a | (a & 0444) >> 2)


#define rp_de_name(dir)         ((u_char *) (dir)->de->d_name)
#if (RP_HAVE_D_NAMLEN)
#define rp_de_namelen(dir)      (dir)->de->d_namlen
#else
#define rp_de_namelen(dir)      rp_strlen((dir)->de->d_name)
#endif

static rp_inline rp_int_t
rp_de_info(u_char *name, rp_dir_t *dir)
{
    dir->type = 0;
    return stat((const char *) name, &dir->info);
}

#define rp_de_info_n            "stat()"
#define rp_de_link_info(name, dir)  lstat((const char *) name, &(dir)->info)
#define rp_de_link_info_n       "lstat()"

#if (RP_HAVE_D_TYPE)

/*
 * some file systems (e.g. XFS on Linux and CD9660 on FreeBSD)
 * do not set dirent.d_type
 */

#define rp_de_is_dir(dir)                                                   \
    (((dir)->type) ? ((dir)->type == DT_DIR) : (S_ISDIR((dir)->info.st_mode)))
#define rp_de_is_file(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_REG) : (S_ISREG((dir)->info.st_mode)))
#define rp_de_is_link(dir)                                                  \
    (((dir)->type) ? ((dir)->type == DT_LNK) : (S_ISLNK((dir)->info.st_mode)))

#else

#define rp_de_is_dir(dir)       (S_ISDIR((dir)->info.st_mode))
#define rp_de_is_file(dir)      (S_ISREG((dir)->info.st_mode))
#define rp_de_is_link(dir)      (S_ISLNK((dir)->info.st_mode))

#endif

#define rp_de_access(dir)       (((dir)->info.st_mode) & 0777)
#define rp_de_size(dir)         (dir)->info.st_size
#define rp_de_fs_size(dir)                                                  \
    rp_max((dir)->info.st_size, (dir)->info.st_blocks * 512)
#define rp_de_mtime(dir)        (dir)->info.st_mtime


rp_int_t rp_open_glob(rp_glob_t *gl);
#define rp_open_glob_n          "glob()"
rp_int_t rp_read_glob(rp_glob_t *gl, rp_str_t *name);
void rp_close_glob(rp_glob_t *gl);


rp_err_t rp_trylock_fd(rp_fd_t fd);
rp_err_t rp_lock_fd(rp_fd_t fd);
rp_err_t rp_unlock_fd(rp_fd_t fd);

#define rp_trylock_fd_n         "fcntl(F_SETLK, F_WRLCK)"
#define rp_lock_fd_n            "fcntl(F_SETLKW, F_WRLCK)"
#define rp_unlock_fd_n          "fcntl(F_SETLK, F_UNLCK)"


#if (RP_HAVE_F_READAHEAD)

#define RP_HAVE_READ_AHEAD      1

#define rp_read_ahead(fd, n)    fcntl(fd, F_READAHEAD, (int) n)
#define rp_read_ahead_n         "fcntl(fd, F_READAHEAD)"

#elif (RP_HAVE_POSIX_FADVISE)

#define RP_HAVE_READ_AHEAD      1

rp_int_t rp_read_ahead(rp_fd_t fd, size_t n);
#define rp_read_ahead_n         "posix_fadvise(POSIX_FADV_SEQUENTIAL)"

#else

#define rp_read_ahead(fd, n)    0
#define rp_read_ahead_n         "rp_read_ahead_n"

#endif


#if (RP_HAVE_O_DIRECT)

rp_int_t rp_directio_on(rp_fd_t fd);
#define rp_directio_on_n        "fcntl(O_DIRECT)"

rp_int_t rp_directio_off(rp_fd_t fd);
#define rp_directio_off_n       "fcntl(!O_DIRECT)"

#elif (RP_HAVE_F_NOCACHE)

#define rp_directio_on(fd)      fcntl(fd, F_NOCACHE, 1)
#define rp_directio_on_n        "fcntl(F_NOCACHE, 1)"

#elif (RP_HAVE_DIRECTIO)

#define rp_directio_on(fd)      directio(fd, DIRECTIO_ON)
#define rp_directio_on_n        "directio(DIRECTIO_ON)"

#else

#define rp_directio_on(fd)      0
#define rp_directio_on_n        "rp_directio_on_n"

#endif

size_t rp_fs_bsize(u_char *name);


#if (RP_HAVE_OPENAT)

#define rp_openat_file(fd, name, mode, create, access)                      \
    openat(fd, (const char *) name, mode|create, access)

#define rp_openat_file_n        "openat()"

#define rp_file_at_info(fd, name, sb, flag)                                 \
    fstatat(fd, (const char *) name, sb, flag)

#define rp_file_at_info_n       "fstatat()"

#define RP_AT_FDCWD             (rp_fd_t) AT_FDCWD

#endif


#define rp_stdout               STDOUT_FILENO
#define rp_stderr               STDERR_FILENO
#define rp_set_stderr(fd)       dup2(fd, STDERR_FILENO)
#define rp_set_stderr_n         "dup2(STDERR_FILENO)"


#if (RP_HAVE_FILE_AIO)

rp_int_t rp_file_aio_init(rp_file_t *file, rp_pool_t *pool);
ssize_t rp_file_aio_read(rp_file_t *file, u_char *buf, size_t size,
    off_t offset, rp_pool_t *pool);

extern rp_uint_t  rp_file_aio;

#endif

#if (RP_THREADS)
ssize_t rp_thread_read(rp_file_t *file, u_char *buf, size_t size,
    off_t offset, rp_pool_t *pool);
ssize_t rp_thread_write_chain_to_file(rp_file_t *file, rp_chain_t *cl,
    off_t offset, rp_pool_t *pool);
#endif


#endif /* _RP_FILES_H_INCLUDED_ */
