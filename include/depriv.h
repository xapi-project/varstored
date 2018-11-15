/*
 * Copyright (C) Citrix Systems, Inc
 */

#ifndef DEPRIV_H
#define DEPRIV_H

#include <stdbool.h>
#include <sys/types.h>

bool drop_privileges(const char *opt_chroot, bool opt_depriv, gid_t opt_gid,
                     uid_t opt_uid);

#endif
