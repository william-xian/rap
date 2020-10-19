
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_CRYPT)

#if (RAP_HAVE_GNU_CRYPT_R)

rap_int_t
rap_libc_crypt(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    cd.initialized = 0;

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = rap_strlen(value) + 1;

        *encrypted = rap_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return RAP_ERROR;
        }

        rap_memcpy(*encrypted, value, len);
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_CRIT, pool->log, rap_errno, "crypt_r() failed");

    return RAP_ERROR;
}

#else

rap_int_t
rap_libc_crypt(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    rap_err_t   err;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = rap_strlen(value) + 1;

        *encrypted = rap_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return RAP_ERROR;
        }

        rap_memcpy(*encrypted, value, len);
        return RAP_OK;
    }

    err = rap_errno;

    rap_log_error(RAP_LOG_CRIT, pool->log, err, "crypt() failed");

    return RAP_ERROR;
}

#endif

#endif /* RAP_CRYPT */
