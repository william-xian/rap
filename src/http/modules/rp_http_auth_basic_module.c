
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_crypt.h>


#define RP_HTTP_AUTH_BUF_SIZE  2048


typedef struct {
    rp_http_complex_value_t  *realm;
    rp_http_complex_value_t   user_file;
} rp_http_auth_basic_loc_conf_t;


static rp_int_t rp_http_auth_basic_handler(rp_http_request_t *r);
static rp_int_t rp_http_auth_basic_crypt_handler(rp_http_request_t *r,
    rp_str_t *passwd, rp_str_t *realm);
static rp_int_t rp_http_auth_basic_set_realm(rp_http_request_t *r,
    rp_str_t *realm);
static void *rp_http_auth_basic_create_loc_conf(rp_conf_t *cf);
static char *rp_http_auth_basic_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_auth_basic_init(rp_conf_t *cf);
static char *rp_http_auth_basic_user_file(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_auth_basic_commands[] = {

    { rp_string("auth_basic"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LMT_CONF
                        |RP_CONF_TAKE1,
      rp_http_set_complex_value_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_auth_basic_loc_conf_t, realm),
      NULL },

    { rp_string("auth_basic_user_file"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LMT_CONF
                        |RP_CONF_TAKE1,
      rp_http_auth_basic_user_file,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_auth_basic_loc_conf_t, user_file),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_auth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_auth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_auth_basic_create_loc_conf,   /* create location configuration */
    rp_http_auth_basic_merge_loc_conf     /* merge location configuration */
};


rp_module_t  rp_http_auth_basic_module = {
    RP_MODULE_V1,
    &rp_http_auth_basic_module_ctx,       /* module context */
    rp_http_auth_basic_commands,          /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_http_auth_basic_handler(rp_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    rp_fd_t                         fd;
    rp_int_t                        rc;
    rp_err_t                        err;
    rp_str_t                        pwd, realm, user_file;
    rp_uint_t                       i, level, login, left, passwd;
    rp_file_t                       file;
    rp_http_auth_basic_loc_conf_t  *alcf;
    u_char                           buf[RP_HTTP_AUTH_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    alcf = rp_http_get_module_loc_conf(r, rp_http_auth_basic_module);

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return RP_DECLINED;
    }

    if (rp_http_complex_value(r, alcf->realm, &realm) != RP_OK) {
        return RP_ERROR;
    }

    if (realm.len == 3 && rp_strncmp(realm.data, "off", 3) == 0) {
        return RP_DECLINED;
    }

    rc = rp_http_auth_basic_user(r);

    if (rc == RP_DECLINED) {

        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        return rp_http_auth_basic_set_realm(r, &realm);
    }

    if (rc == RP_ERROR) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_complex_value(r, &alcf->user_file, &user_file) != RP_OK) {
        return RP_ERROR;
    }

    fd = rp_open_file(user_file.data, RP_FILE_RDONLY, RP_FILE_OPEN, 0);

    if (fd == RP_INVALID_FILE) {
        err = rp_errno;

        if (err == RP_ENOENT) {
            level = RP_LOG_ERR;
            rc = RP_HTTP_FORBIDDEN;

        } else {
            level = RP_LOG_CRIT;
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rp_log_error(level, r->connection->log, err,
                      rp_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    rp_memzero(&file, sizeof(rp_file_t));

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

        n = rp_read_file(&file, buf + left, RP_HTTP_AUTH_BUF_SIZE - left,
                          offset);

        if (n == RP_ERROR) {
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
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

                    rc = rp_http_auth_basic_crypt_handler(r, &pwd, &realm);
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
            rp_memmove(buf, &buf[passwd], left);
            passwd = 0;

        } else {
            left = 0;
        }

        offset += n;
    }

    if (state == sw_passwd) {
        pwd.len = i - passwd;
        pwd.data = rp_pnalloc(r->pool, pwd.len + 1);
        if (pwd.data == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        rp_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);

        rc = rp_http_auth_basic_crypt_handler(r, &pwd, &realm);
        goto cleanup;
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" was not found in \"%s\"",
                  &r->headers_in.user, user_file.data);

    rc = rp_http_auth_basic_set_realm(r, &realm);

cleanup:

    if (rp_close_file(file.fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", user_file.data);
    }

    rp_explicit_memzero(buf, RP_HTTP_AUTH_BUF_SIZE);

    return rc;
}


static rp_int_t
rp_http_auth_basic_crypt_handler(rp_http_request_t *r, rp_str_t *passwd,
    rp_str_t *realm)
{
    rp_int_t   rc;
    u_char     *encrypted;

    rc = rp_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
                   &encrypted);

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &r->headers_in.user, passwd->data);

    if (rc != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_strcmp(encrypted, passwd->data) == 0) {
        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted: \"%s\"", encrypted);

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "user \"%V\": password mismatch",
                  &r->headers_in.user);

    return rp_http_auth_basic_set_realm(r, realm);
}


static rp_int_t
rp_http_auth_basic_set_realm(rp_http_request_t *r, rp_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = rp_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = rp_pnalloc(r->pool, len);
    if (basic == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = rp_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = rp_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    rp_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return RP_HTTP_UNAUTHORIZED;
}


static void *
rp_http_auth_basic_create_loc_conf(rp_conf_t *cf)
{
    rp_http_auth_basic_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_auth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
rp_http_auth_basic_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_auth_basic_loc_conf_t  *prev = parent;
    rp_http_auth_basic_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_auth_basic_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_auth_basic_handler;

    return RP_OK;
}


static char *
rp_http_auth_basic_user_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_auth_basic_loc_conf_t *alcf = conf;

    rp_str_t                         *value;
    rp_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
