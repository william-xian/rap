
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static char *rap_http_empty_gif(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

static rap_command_t  rap_http_empty_gif_commands[] = {

    { rap_string("empty_gif"),
      RAP_HTTP_LOC_CONF|RAP_CONF_NOARGS,
      rap_http_empty_gif,
      0,
      0,
      NULL },

      rap_null_command
};


/* the minimal single pixel transparent GIF, 43 bytes */

static u_char  rap_empty_gif[] = {

    'G', 'I', 'F', '8', '9', 'a',  /* header                                 */

                                   /* logical screen descriptor              */
    0x01, 0x00,                    /* logical screen width                   */
    0x01, 0x00,                    /* logical screen height                  */
    0x80,                          /* global 1-bit color table               */
    0x01,                          /* background color #1                    */
    0x00,                          /* no aspect ratio                        */

                                   /* global color table                     */
    0x00, 0x00, 0x00,              /* #0: black                              */
    0xff, 0xff, 0xff,              /* #1: white                              */

                                   /* graphic control extension              */
    0x21,                          /* extension introducer                   */
    0xf9,                          /* graphic control label                  */
    0x04,                          /* block size                             */
    0x01,                          /* transparent color is given,            */
                                   /*     no disposal specified,             */
                                   /*     user input is not expected         */
    0x00, 0x00,                    /* delay time                             */
    0x01,                          /* transparent color #1                   */
    0x00,                          /* block terminator                       */

                                   /* image descriptor                       */
    0x2c,                          /* image separator                        */
    0x00, 0x00,                    /* image left position                    */
    0x00, 0x00,                    /* image top position                     */
    0x01, 0x00,                    /* image width                            */
    0x01, 0x00,                    /* image height                           */
    0x00,                          /* no local color table, no interlaced    */

                                   /* table based image data                 */
    0x02,                          /* LZW minimum code size,                 */
                                   /*     must be at least 2-bit             */
    0x02,                          /* block size                             */
    0x4c, 0x01,                    /* compressed bytes 01_001_100, 0000000_1 */
                                   /* 100: clear code                        */
                                   /* 001: 1                                 */
                                   /* 101: end of information code           */
    0x00,                          /* block terminator                       */

    0x3B                           /* trailer                                */
};


static rap_http_module_t  rap_http_empty_gif_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


rap_module_t  rap_http_empty_gif_module = {
    RAP_MODULE_V1,
    &rap_http_empty_gif_module_ctx, /* module context */
    rap_http_empty_gif_commands,   /* module directives */
    RAP_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_str_t  rap_http_gif_type = rap_string("image/gif");


static rap_int_t
rap_http_empty_gif_handler(rap_http_request_t *r)
{
    rap_http_complex_value_t  cv;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    rap_memzero(&cv, sizeof(rap_http_complex_value_t));

    cv.value.len = sizeof(rap_empty_gif);
    cv.value.data = rap_empty_gif;
    r->headers_out.last_modified_time = 23349600;

    return rap_http_send_response(r, RAP_HTTP_OK, &rap_http_gif_type, &cv);
}


static char *
rap_http_empty_gif(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);
    clcf->handler = rap_http_empty_gif_handler;

    return RAP_CONF_OK;
}
