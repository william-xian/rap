
/*
 * Copyright (C) Maxim Dounin
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_crypt.h>
#include <rap_md5.h>
#include <rap_sha1.h>


#if (RAP_CRYPT)

static rap_int_t rap_crypt_apr1(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static rap_int_t rap_crypt_plain(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static rap_int_t rap_crypt_ssha(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static rap_int_t rap_crypt_sha(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


static u_char *rap_crypt_to64(u_char *p, uint32_t v, size_t n);


rap_int_t
rap_crypt(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    if (rap_strncmp(salt, "$apr1$", sizeof("$apr1$") - 1) == 0) {
        return rap_crypt_apr1(pool, key, salt, encrypted);

    } else if (rap_strncmp(salt, "{PLAIN}", sizeof("{PLAIN}") - 1) == 0) {
        return rap_crypt_plain(pool, key, salt, encrypted);

    } else if (rap_strncmp(salt, "{SSHA}", sizeof("{SSHA}") - 1) == 0) {
        return rap_crypt_ssha(pool, key, salt, encrypted);

    } else if (rap_strncmp(salt, "{SHA}", sizeof("{SHA}") - 1) == 0) {
        return rap_crypt_sha(pool, key, salt, encrypted);
    }

    /* fallback to libc crypt() */

    return rap_libc_crypt(pool, key, salt, encrypted);
}


static rap_int_t
rap_crypt_apr1(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    rap_int_t          n;
    rap_uint_t         i;
    u_char            *p, *last, final[16];
    size_t             saltlen, keylen;
    rap_md5_t          md5, ctx1;

    /* Apache's apr1 crypt is Poul-Henning Kamp's md5 crypt with $apr1$ magic */

    keylen = rap_strlen(key);

    /* true salt: no magic, max 8 chars, stop at first $ */

    salt += sizeof("$apr1$") - 1;
    last = salt + 8;
    for (p = salt; *p && *p != '$' && p < last; p++) { /* void */ }
    saltlen = p - salt;

    /* hash key and salt */

    rap_md5_init(&md5);
    rap_md5_update(&md5, key, keylen);
    rap_md5_update(&md5, (u_char *) "$apr1$", sizeof("$apr1$") - 1);
    rap_md5_update(&md5, salt, saltlen);

    rap_md5_init(&ctx1);
    rap_md5_update(&ctx1, key, keylen);
    rap_md5_update(&ctx1, salt, saltlen);
    rap_md5_update(&ctx1, key, keylen);
    rap_md5_final(final, &ctx1);

    for (n = keylen; n > 0; n -= 16) {
        rap_md5_update(&md5, final, n > 16 ? 16 : n);
    }

    rap_memzero(final, sizeof(final));

    for (i = keylen; i; i >>= 1) {
        if (i & 1) {
            rap_md5_update(&md5, final, 1);

        } else {
            rap_md5_update(&md5, key, 1);
        }
    }

    rap_md5_final(final, &md5);

    for (i = 0; i < 1000; i++) {
        rap_md5_init(&ctx1);

        if (i & 1) {
            rap_md5_update(&ctx1, key, keylen);

        } else {
            rap_md5_update(&ctx1, final, 16);
        }

        if (i % 3) {
            rap_md5_update(&ctx1, salt, saltlen);
        }

        if (i % 7) {
            rap_md5_update(&ctx1, key, keylen);
        }

        if (i & 1) {
            rap_md5_update(&ctx1, final, 16);

        } else {
            rap_md5_update(&ctx1, key, keylen);
        }

        rap_md5_final(final, &ctx1);
    }

    /* output */

    *encrypted = rap_pnalloc(pool, sizeof("$apr1$") - 1 + saltlen + 1 + 22 + 1);
    if (*encrypted == NULL) {
        return RAP_ERROR;
    }

    p = rap_cpymem(*encrypted, "$apr1$", sizeof("$apr1$") - 1);
    p = rap_copy(p, salt, saltlen);
    *p++ = '$';

    p = rap_crypt_to64(p, (final[ 0]<<16) | (final[ 6]<<8) | final[12], 4);
    p = rap_crypt_to64(p, (final[ 1]<<16) | (final[ 7]<<8) | final[13], 4);
    p = rap_crypt_to64(p, (final[ 2]<<16) | (final[ 8]<<8) | final[14], 4);
    p = rap_crypt_to64(p, (final[ 3]<<16) | (final[ 9]<<8) | final[15], 4);
    p = rap_crypt_to64(p, (final[ 4]<<16) | (final[10]<<8) | final[ 5], 4);
    p = rap_crypt_to64(p, final[11], 2);
    *p = '\0';

    return RAP_OK;
}


static u_char *
rap_crypt_to64(u_char *p, uint32_t v, size_t n)
{
    static u_char   itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (n--) {
        *p++ = itoa64[v & 0x3f];
        v >>= 6;
    }

    return p;
}


static rap_int_t
rap_crypt_plain(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t   len;
    u_char  *p;

    len = rap_strlen(key);

    *encrypted = rap_pnalloc(pool, sizeof("{PLAIN}") - 1 + len + 1);
    if (*encrypted == NULL) {
        return RAP_ERROR;
    }

    p = rap_cpymem(*encrypted, "{PLAIN}", sizeof("{PLAIN}") - 1);
    rap_memcpy(p, key, len + 1);

    return RAP_OK;
}


static rap_int_t
rap_crypt_ssha(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t       len;
    rap_int_t    rc;
    rap_str_t    encoded, decoded;
    rap_sha1_t   sha1;

    /* "{SSHA}" base64(SHA1(key salt) salt) */

    /* decode base64 salt to find out true salt */

    encoded.data = salt + sizeof("{SSHA}") - 1;
    encoded.len = rap_strlen(encoded.data);

    len = rap_max(rap_base64_decoded_length(encoded.len), 20);

    decoded.data = rap_pnalloc(pool, len);
    if (decoded.data == NULL) {
        return RAP_ERROR;
    }

    rc = rap_decode_base64(&decoded, &encoded);

    if (rc != RAP_OK || decoded.len < 20) {
        decoded.len = 20;
    }

    /* update SHA1 from key and salt */

    rap_sha1_init(&sha1);
    rap_sha1_update(&sha1, key, rap_strlen(key));
    rap_sha1_update(&sha1, decoded.data + 20, decoded.len - 20);
    rap_sha1_final(decoded.data, &sha1);

    /* encode it back to base64 */

    len = sizeof("{SSHA}") - 1 + rap_base64_encoded_length(decoded.len) + 1;

    *encrypted = rap_pnalloc(pool, len);
    if (*encrypted == NULL) {
        return RAP_ERROR;
    }

    encoded.data = rap_cpymem(*encrypted, "{SSHA}", sizeof("{SSHA}") - 1);
    rap_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    return RAP_OK;
}


static rap_int_t
rap_crypt_sha(rap_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t      len;
    rap_str_t   encoded, decoded;
    rap_sha1_t  sha1;
    u_char      digest[20];

    /* "{SHA}" base64(SHA1(key)) */

    decoded.len = sizeof(digest);
    decoded.data = digest;

    rap_sha1_init(&sha1);
    rap_sha1_update(&sha1, key, rap_strlen(key));
    rap_sha1_final(digest, &sha1);

    len = sizeof("{SHA}") - 1 + rap_base64_encoded_length(decoded.len) + 1;

    *encrypted = rap_pnalloc(pool, len);
    if (*encrypted == NULL) {
        return RAP_ERROR;
    }

    encoded.data = rap_cpymem(*encrypted, "{SHA}", sizeof("{SHA}") - 1);
    rap_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    return RAP_OK;
}

#endif /* RAP_CRYPT */
