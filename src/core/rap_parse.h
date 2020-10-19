
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PARSE_H_INCLUDED_
#define _RAP_PARSE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


ssize_t rap_parse_size(rap_str_t *line);
off_t rap_parse_offset(rap_str_t *line);
rap_int_t rap_parse_time(rap_str_t *line, rap_uint_t is_sec);


#endif /* _RAP_PARSE_H_INCLUDED_ */
