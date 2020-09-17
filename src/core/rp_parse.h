
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PARSE_H_INCLUDED_
#define _RP_PARSE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


ssize_t rp_parse_size(rp_str_t *line);
off_t rp_parse_offset(rp_str_t *line);
rp_int_t rp_parse_time(rp_str_t *line, rp_uint_t is_sec);


#endif /* _RP_PARSE_H_INCLUDED_ */
