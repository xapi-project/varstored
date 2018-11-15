/*
 * Copyright (C) Citrix Systems, Inc
 */

#ifndef LIB_PROG_H
#define LIB_PROG_H

#include <efi.h>

#define GUID_STR_LEN (strlen("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"))

/*
 * These macros are used by all the tools to implement the common deprivileging
 * behaviour. Macros are used because it is non-trivial with getopt to
 * implement common parsing of deprivileging options while still allowing each
 * tool to have its own options.
 */

#define DEPRIV_VARS \
    char *end; \
    bool opt_depriv = false; \
    const char *opt_chroot = NULL; \
    const char *opt_socket = NULL; \
    uid_t opt_uid = 0; \
    gid_t opt_gid = 0;

#define DEPRIV_OPTS "r:dg:s:u:"

#define DEPRIV_CASES \
    case 'd': \
        opt_depriv = true; \
        break; \
    case 'g': \
        opt_gid = (gid_t)strtol(optarg, &end, 0); \
        if (*end != '\0') { \
            fprintf(stderr, "invalid uid '%s'\n", optarg); \
            exit(1); \
        } \
        break; \
    case 'r': \
        opt_chroot = optarg; \
        break; \
    case 's': \
        opt_socket = optarg; \
        break; \
    case 'u': \
        opt_uid = (uid_t)strtol(optarg, &end, 0); \
        if (*end != '\0') { \
            fprintf(stderr, "invalid uid '%s'\n", optarg); \
            exit(1); \
        } \
        break;

bool tool_init(void);
void print_efi_error(EFI_STATUS status);
bool parse_guid(EFI_GUID *guid, const char *guid_str);
size_t parse_name(const char *in, uint8_t *name);
void print_depriv_options(void);

#endif
