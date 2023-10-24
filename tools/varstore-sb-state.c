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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <backend.h>
#include <debug.h>
#include <depriv.h>
#include <guid.h>
#include <serialize.h>

#include "tool-lib.h"

const struct backend *db = &xapidb_cmdline;
const enum log_level log_level = LOG_LVL_INFO;

static void
usage(const char *progname)
{
    printf("usage: %s [-h] [depriv options] <vm-uuid> setup|user\n\n",
           progname);
    printf("If setup is given, clears a VM's EFI variables related to Secure Boot\n"
           "and places it into Setup Mode.\n"
           "If user is given, resets a VM's EFI variables related to Secure Boot\n"
           "to the defaults, placing it into User Mode.\n");
    print_depriv_options();
}

int main(int argc, char **argv)
{
    DEPRIV_VARS

    for (;;) {
        int c = getopt(argc, argv, "h" DEPRIV_OPTS);

        if (c == -1)
            break;

        switch (c) {
        DEPRIV_CASES
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if ((argc - optind != 2) ||
            (strcmp(argv[optind + 1], "setup") &&
             strcmp(argv[optind + 1], "user"))) {
        usage(argv[0]);
        exit(1);
    }

    db->parse_arg("uuid", argv[optind]);

    if (opt_socket)
        db->parse_arg("socket", opt_socket);

    if (!strcmp(argv[optind + 1], "user"))
        load_auth_data();

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        exit(1);

    if (!tool_init())
        exit(1);

    /* Ignore errors in case the variables are missing. */
    printf("Removing PK...\n");
    do_rm(&gEfiGlobalVariableGuid, "PK");
    printf("Removing KEK...\n");
    do_rm(&gEfiGlobalVariableGuid, "KEK");
    printf("Removing db...\n");
    do_rm(&gEfiImageSecurityDatabaseGuid, "db");
    printf("Removing dbx...\n");
    do_rm(&gEfiImageSecurityDatabaseGuid, "dbx");

    if (!strcmp(argv[optind + 1], "user"))
        return (setup_keys() ? 0 : 1);
    else
        return 0;
}
