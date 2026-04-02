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
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <backend.h>
#include <debug.h>
#include <depriv.h>
#include <xapidb.h>
#include <handler.h>

#include "tool-lib.h"

const struct backend *db = &xapidb_cmdline;
const enum log_level log_level = LOG_LVL_INFO;

static const struct {
    enum certificate_current_state state;
    const char *name;
} cert_state_map[] = {
    { CERT_STATE_UPDATE_OK,       "update_ok" },
    { CERT_STATE_UPDATE_REQUIRED, "update_required" },
    { CERT_STATE_UNKNOWN, "unknown" },
};

static const char *
cert_state_to_string(enum certificate_current_state state)
{
    size_t i;

    for (i = 0; i < sizeof(cert_state_map) / sizeof(cert_state_map[0]); i++) {
        if (cert_state_map[i].state == state)
            return cert_state_map[i].name;
    }

    return "unknown";
}

static void
usage(const char *progname)
{
    printf("usage: %s [-hvs] [depriv options] <vm-uuid>\n\n", progname);
    printf("Checks the VM's NVRAM Secure Boot certificate status.\n"
           "Outputs one of:\n"
           "  1. upadte_ok        - certificates include latest certs\n"
           "  2. update_required  - certificates only contain legacy certs\n"
           "  3. unknown\n"
           "\n"
           "  [-f] - if latest certs are present, flag secureboot_certificates_state to 'ok'\n"
           "  [-v] - enables debug logging\n");
    print_depriv_options();
}

int main(int argc, char **argv)
{
    int verbose = 0;
    int opt_flag = 0;
    enum certificate_current_state state;

    DEPRIV_VARS

    for (;;) {
        int c = getopt(argc, argv, "hvf" DEPRIV_OPTS);

        if (c == -1)
            break;

        switch (c) {
        DEPRIV_CASES
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'v':
            verbose = 1;
            break;
        case 'f':
            opt_flag = 1;
            break;
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (argc - optind != 1) {
        usage(argv[0]);
        exit(1);
    }

    db->parse_arg("uuid", argv[optind]);

    if (!drop_privileges(opt_chroot, opt_depriv, opt_gid, opt_uid))
        exit(1);

    if (!tool_init())
        exit(1);

    state = check_nvram_certs_state(verbose);
    printf("%s\n", cert_state_to_string(state));

#if 0
    if (opt_flag) {
        if (state == CERT_STATE_UPDATE_OK) {
            if (!xapidb_set_secureboot_certs_state(xapidb_get_uuid(),
                                                SECUREBOOT_CERT_STATE_OK)) {
                fprintf(stderr, "Failed to set secureboot_certificates_state\n");
                exit(1);
            } else {
                fprintf(stderr, "Now secureboot_certificates_state is ok\n");
            }
        } else if (state == CERT_STATE_UPDATE_REQUIRED) {
            if (!xapidb_set_secureboot_certs_state(xapidb_get_uuid(),
                                                SECUREBOOT_CERT_STATE_UPDATE_AVAILABLE)) {
                fprintf(stderr, "Failed to set secureboot_certificates_state\n");
                exit(1);
            } else {
                fprintf(stderr, "Now secureboot_certificates_state is update_available\n");
            }
        } else {
            fprintf(stderr, "secureboot_certificates_state is unknown\n");
        }
    }
#endif

    return 0;
}
