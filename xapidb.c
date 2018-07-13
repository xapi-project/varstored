#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "backend.h"
#include "option.h"


/* Path to the file containing the initial data from XAPI. */
static char *arg_init;
/* Path to the file used for saving / resuming. */
static char *arg_save;
/* The VM's uuid. Used for saving to the XAPI db. */
static char *arg_uuid;

static bool
xapidb_parse_arg(const char *name, const char *val)
{
    if (!strcmp(name, "init"))
        arg_init = strdup(val);
    else if (!strcmp(name, "save"))
        arg_save = strdup(val);
    else if (!strcmp(name, "uuid"))
        arg_uuid = strdup(val);
    else
        return false;

    return true;
}

static bool
xapidb_check_args(void)
{
    if (opt_resume && arg_init) {
        fprintf(stderr, "Backend arg 'init' is invalid when resuming\n");
        return false;
    }

    return true;
}

static bool
xapidb_init(void)
{
    /* Unimplemented */
    return 0;
}

static bool
xapidb_save(void)
{
    /* Unimplemented */
    return 0;
}

static bool
xapidb_resume(void)
{
    /* Unimplemented */
    return 0;
}

static bool
xapidb_set_variable(void)
{
    /* Unimplemented */
    return 0;
}

struct backend xapidb = {
    .parse_arg = xapidb_parse_arg,
    .check_args = xapidb_check_args,
    .init = xapidb_init,
    .save = xapidb_save,
    .resume = xapidb_resume,
    .set_variable = xapidb_set_variable,
};
