/*
 * Copyright (C) Citrix Systems, Inc
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <backend.h>
#include <debug.h>
#include <xapidb.h>

static bool
xapidb_cmdline_parse_arg(const char *name, const char *val)
{
    if (!strcmp(name, "uuid"))
        xapidb_arg_uuid = strdup(val);
    else if (!strcmp(name, "socket"))
        xapidb_arg_socket = strdup(val);
    else
        return false;

    return true;
}

static bool
xapidb_cmdline_check_args(void)
{
    if (!xapidb_arg_uuid) {
        ERR("VM UUID must be specified\n");
        return false;
    }

    return true;
}

const struct backend xapidb_cmdline = {
    .parse_arg = xapidb_cmdline_parse_arg,
    .check_args = xapidb_cmdline_check_args,
    .init = xapidb_init,
    .set_variable = xapidb_set_variable,
};
