
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_CRYPT)

#if (RP_HAVE_GNU_CRYPT_R)

rp_int_t
rp_libc_crypt(rp_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    cd.initialized = 0;

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = rp_strlen(value) + 1;

        *encrypted = rp_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return RP_ERROR;
        }

        rp_memcpy(*encrypted, value, len);
        return RP_OK;
    }

    rp_log_error(RP_LOG_CRIT, pool->log, rp_errno, "crypt_r() failed");

    return RP_ERROR;
}

#else

rp_int_t
rp_libc_crypt(rp_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    rp_err_t   err;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = rp_strlen(value) + 1;

        *encrypted = rp_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return RP_ERROR;
        }

        rp_memcpy(*encrypted, value, len);
        return RP_OK;
    }

    err = rp_errno;

    rp_log_error(RP_LOG_CRIT, pool->log, err, "crypt() failed");

    return RP_ERROR;
}

#endif

#endif /* RP_CRYPT */
