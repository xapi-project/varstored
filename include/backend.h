/*
 * Copyright (C) Citrix Systems, Inc
 */

#ifndef  BACKEND_H
#define  BACKEND_H

#include <stdbool.h>

enum backend_init_status {
    BACKEND_INIT_FAILURE,
    BACKEND_INIT_SUCCESS,
    BACKEND_INIT_FIRSTBOOT,
};

struct backend {
    /* Called to handle arguments specific to the backend. */
    bool (*parse_arg)(const char *name, const char *val);
    /* Called after argument parsing to verify arguments. */
    bool (*check_args)(void);
    /* Called at startup when not resuming to load the initial data. */
    enum backend_init_status (*init)(void);
    /* Called to save state when exiting. */
    bool (*save)(void);
    /* Called to resume from previously saved state. */
    bool (*resume)(void);
    /* Called when set_variable updates an NV variable. */
    bool (*set_variable)(void);
    /* Called when a Secure Boot verification failure occurs. */
    bool (*sb_notify)(void);
};

extern struct backend *db;
extern struct backend xapidb;
extern struct backend xapidb_cmdline;

#endif
