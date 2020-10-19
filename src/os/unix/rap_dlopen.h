
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_DLOPEN_H_INCLUDED_
#define _RAP_DLOPEN_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define rap_dlopen(path)           dlopen((char *) path, RTLD_NOW | RTLD_GLOBAL)
#define rap_dlopen_n               "dlopen()"

#define rap_dlsym(handle, symbol)  dlsym(handle, symbol)
#define rap_dlsym_n                "dlsym()"

#define rap_dlclose(handle)        dlclose(handle)
#define rap_dlclose_n              "dlclose()"


#if (RAP_HAVE_DLOPEN)
char *rap_dlerror(void);
#endif


#endif /* _RAP_DLOPEN_H_INCLUDED_ */
