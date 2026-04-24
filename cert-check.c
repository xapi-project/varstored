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
#include <stdint.h>
#include <string.h>

#include <backend.h>
#include <debug.h>
#include <efi.h>
#include <guid.h>
#include <handler.h>

#include <cert-check.h>

/*
 * Classify the certificate state based on the parsed cert_info array.
 * Returns:
 *   CERT_STATE_UPDATE_OK       - at least one certificate satisfies NOT_EXPIRE
 *   CERT_STATE_UPDATE_REQUIRED - only legacy/expiring certificates present
 *   CERT_STATE_UNKNOWN         - no recognisable certificates
 */
enum certificate_current_state
classify_certs_state(const struct cert_info *certs, int count)
{
    bool saw_legacy_cert = false;
    int i;

    for (i = 0; i < count && i < MAX_CERTS_IN_SIGLIST; i++) {
        if (NOT_EXPIRE(certs[i].not_before_year, certs[i].not_after_year)) {
            return CERT_STATE_UPDATE_OK;
        } else if (EXPIRE_SOON(certs[i].not_before_year, certs[i].not_after_year)) {
            saw_legacy_cert = true;
        } else if (EXPIRE_PAST(certs[i].not_before_year, certs[i].not_after_year)) {
            saw_legacy_cert = true;
        }
    }

    if (saw_legacy_cert)
        return CERT_STATE_UPDATE_REQUIRED;

    return CERT_STATE_UNKNOWN;
}

/*
 * Check the loaded variable store's KEK certificate state.
 * The backend must have been initialised (var_list populated) before calling.
 * Returns:
 *   CERT_STATE_UNKNOWN          - no KEK variable or no X.509 certs found
 *   CERT_STATE_UPDATE_REQUIRED  - only 2011-era certificate(s) present
 *   CERT_STATE_UPDATE_OK        - 2023-era certificate(s) present
 */
enum certificate_current_state
check_nvram_certs_state(int verbose)
{
    uint8_t *data = NULL;
    UINTN data_len = 0;
    EFI_STATUS status;
    struct cert_info certs[MAX_CERTS_IN_SIGLIST];
    int count;

    status = internal_get_variable(EFI_KEY_EXCHANGE_KEY_NAME,
                                   EFI_KEY_EXCHANGE_KEY_NAME_LEN,
                                   &gEfiGlobalVariableGuid,
                                   &data, &data_len);
    if (status != EFI_SUCCESS)
        return CERT_STATE_UNKNOWN;

    count = parse_certs_from_siglist(data, data_len, certs,
                                     MAX_CERTS_IN_SIGLIST, verbose);
    free(data);

    if (count <= 0)
        return CERT_STATE_UNKNOWN;

    return classify_certs_state(certs, count);
}
