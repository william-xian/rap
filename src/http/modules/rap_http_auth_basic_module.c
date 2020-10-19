
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_crypt.h>


#define RAP_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
    rap_http_complex_value_t  *realm;
    rap_http_complex_value_t   user_file;
} rap_http_auth_basic_loc_conf_t;


static rap_int_t rap_http_auth_basic_handler(rap_http_request_t *r);
static rap_int_t rap_http_auth_basic_crypt_handler(rap_http_request_t *r,
    rap_str_t *passwd, rap_str_t *realm);
static rap_int_t rap_http_auth_basic_set_realm(rap_http_request_t *r,
    rap_str_t *realm);
static void *rap_http_auth_basic_create_loc_conf(rap_conf_t *cf);
static char *rap_http_auth_basic_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_auth_basic_init(rap_conf_t *cf);
static char *rap_http_auth_basic_user_file(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_auth_basic_commands[] = {

    { rap_string("auth_basic"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LMT_CONF
                        |RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_auth_basic_loc_conf_t, realm),
      NULL },

    { rap_string("auth_basic_user_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LMT_CONF
                        |RAP_CONF_TAKE1,
      rap_http_auth_basic_user_file,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_auth_basic_loc_conf_t, user_file),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_auth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_auth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_auth_basic_create_loc_conf,   /* create location configuration */
    rap_http_auth_basic_merge_loc_conf     /* merge location configuration */
};


rap_module_t  rap_http_auth_basic_module = {
    RAP_MODULE_V1,
    &rap_http_auth_basic_module_ctx,       /* module context */
    rap_http_auth_basic_commands,          /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_http_auth_basic_handler(rap_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    rap_fd_t                         fd;
    rap_int_t                        rc;
    rap_err_t                        err;
    rap_str_t                        pwd, realm, user_file;
    rap_uint_t                       i, level, login, left, passwd;
    rap_file_t                       file;
    rap_http_auth_basic_loc_conf_t  *alcf;
    u_char                           buf[RAP_HTTP_AUTH_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    alcf = rap_http_get_module_loc_conf(r, rap_http_auth_basic_module);

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return RAP_DECLINED;
    }

    if (rap_http_complex_value(r, alcf->realm, &realm) != RAP_OK) {
        return RAP_ERROR;
    }

    if (realm.len == 3 && rap_strncmp(realm.data, "off", 3) == 0) {
        return RAP_DECLINED;
    }

    rc = rap_http_auth_basic_user(r);

    if (rc == RAP_DECLINED) {

        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return rap_http_auth_basic_set_realm(r, &realm);
    }

    if (rc == RAP_ERROR) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_http_complex_value(r, &alcf->user_file, &user_file) != RAP_OK) {
        return RAP_ERROR;
    }

    fd = rap_open_file(user_file.data, RAP_FILE_RDONLY, RAP_FILE_OPEN, 0);

    if (fd == RAP_INVALID_FILE) {
        err = rap_errno;

        if (err == RAP_ENOENT) {
            level = RAP_LOG_ERR;
            rc = RAP_HTTP_FORBIDDEN;

        } else {
            level = RAP_LOG_CRIT;
            rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rap_log_error(level, r->connection->log, err,
                      rap_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    rap_memzero(&file, sizeof(rap_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    login = 0;
    left = 0;
    offset = 0;

    for ( ;; ) {
        i = left;

        n = rap_read_file(&file, buf + left, RAP_HTTP_AUTH_BUF_SIZE - left,
                          offset);

        if (n == RAP_ERROR) {
            rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
            goto cleanup;
        }

        if (n == 0) {
            break;
        }

        for (i = left; i < left + n; i++) {
            switch (state) {

            case sw_login:
                if (login == 0) {

                    if (buf[i] == '#' || buf[i] == CR) {
                        state = sw_skip;
                        break;
                    }

                    if (buf[i] == LF) {
                        break;
                    }
                }

                if (buf[i] != r->headers_in.user.data[login]) {
                    state = sw_skip;
                    break;
                }

                if (login == r->headers_in.user.len) {
                    state = sw_passwd;
                    passwd = i + 1;
                }

                login++;

                break;

            case sw_passwd:
                if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
                    buf[i] = '\0';

                    pwd.len = i - passwd;
                    pwd.data = &buf[passwd];

                    rc = rap_http_auth_basic_crypt_handler(r, &pwd, &realm);
                    goto cleanup;
                }

                break;

            case sw_skip:
                if (buf[i] == LF) {
                    state = sw_login;
                    login = 0;
                }

                break;
            }
        }

        if (state == sw_passwd) {
            left = left + n - passwd;
            rap_memmove(buf, &buf[passwd], left);
            passwd = 0;

        } else {
            left = 0;
        }

        offset += n;
    }

    if (state == sw_passwd) {
        pwd.len = i - passwd;
        pwd.data = rap_pnalloc(r->pool, pwd.len + 1);
        if (pwd.data == NULL) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rap_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);

        rc = rap_http_auth_basic_crypt_handler(r, &pwd, &realm);
        goto cleanup;
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" was not found in \"%s\"",
                  &r->headers_in.user, user_file.data);

    rc = rap_http_auth_basic_set_realm(r, &realm);

cleanup:

    if (rap_close_file(file.fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", user_file.data);
    }

    rap_explicit_memzero(buf, RAP_HTTP_AUTH_BUF_SIZE);

    return rc;
}


static rap_int_t
rap_http_auth_basic_crypt_handler(rap_http_request_t *r, rap_str_t *passwd,
    rap_str_t *realm)
{
    rap_int_t   rc;
    u_char     *encrypted;

    rc = rap_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
                   &encrypted);

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &r->headers_in.user, passwd->data);

    if (rc != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_strcmp(encrypted, passwd->data) == 0) {
        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted: \"%s\"", encrypted);

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "user \"%V\": password mismatch",
                  &r->headers_in.user);

    return rap_http_auth_basic_set_realm(r, realm);
}


static rap_int_t
rap_http_auth_basic_set_realm(rap_http_request_t *r, rap_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = rap_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = rap_pnalloc(r->pool, len);
    if (basic == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = rap_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = rap_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    rap_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return RAP_HTTP_UNAUTHORIZED;
}


static void *
rap_http_auth_basic_create_loc_conf(rap_conf_t *cf)
{
    rap_http_auth_basic_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_auth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rap_http_auth_basic_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_auth_basic_loc_conf_t  *prev = parent;
    rap_http_auth_basic_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_auth_basic_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_auth_basic_handler;

    return RAP_OK;
}


static char *
rap_http_auth_basic_user_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_auth_basic_loc_conf_t *alcf = conf;

    rap_str_t                         *value;
    rap_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
