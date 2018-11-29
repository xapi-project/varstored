/*
 * Copyright (c) Citrix Systems, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
bool do_rm(const EFI_GUID *guid, const char *name);

#endif
