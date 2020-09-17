
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static char *rp_http_empty_gif(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

static rp_command_t  rp_http_empty_gif_commands[] = {

    { rp_string("empty_gif"),
      RP_HTTP_LOC_CONF|RP_CONF_NOARGS,
      rp_http_empty_gif,
      0,
      0,
      NULL },

      rp_null_command
};


/* the minimal single pixel transparent GIF, 43 bytes */

static u_char  rp_empty_gif[] = {

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


static rp_http_module_t  rp_http_empty_gif_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


rp_module_t  rp_http_empty_gif_module = {
    RP_MODULE_V1,
    &rp_http_empty_gif_module_ctx, /* module context */
    rp_http_empty_gif_commands,   /* module directives */
    RP_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t  rp_http_gif_type = rp_string("image/gif");


static rp_int_t
rp_http_empty_gif_handler(rp_http_request_t *r)
{
    rp_http_complex_value_t  cv;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    rp_memzero(&cv, sizeof(rp_http_complex_value_t));

    cv.value.len = sizeof(rp_empty_gif);
    cv.value.data = rp_empty_gif;
    r->headers_out.last_modified_time = 23349600;

    return rp_http_send_response(r, RP_HTTP_OK, &rp_http_gif_type, &cv);
}


static char *
rp_http_empty_gif(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_empty_gif_handler;

    return RP_CONF_OK;
}
