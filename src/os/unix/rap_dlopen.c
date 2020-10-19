
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_DLOPEN)

char *
rap_dlerror(void)
{
    char  *err;

    err = (char *) dlerror();

    if (err == NULL) {
        return "";
    }

    return err;
}

#endif
