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

#ifndef  HANDLER_H
#define  HANDLER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "efi.h"

#define NAME_LIMIT 4096 /* Maximum length of name */
#define DATA_LIMIT 57344 /* Maximum length of a single variable */
#define TOTAL_LIMIT 131072 /* Maximum total storage */

/*
 * A single variable takes up a minimum number of bytes.
 * This ensures a suitably low limit on the number of variables that can be
 * stored.
 */
#define VARIABLE_SIZE_OVERHEAD 128
#define MAX_VARIABLE_COUNT (TOTAL_LIMIT / VARIABLE_SIZE_OVERHEAD)

#define PAGE_SIZE 4096
#define SHMEM_PAGES 16
#define SHMEM_SIZE (SHMEM_PAGES * PAGE_SIZE)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

enum command_t {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
    COMMAND_NOTIFY_SB_FAILURE,
};

struct efi_variable {
    uint8_t *name;
    UINTN name_len;
    uint8_t *data;
    UINTN data_len;
    EFI_GUID guid;
    UINT32 attributes;
    EFI_TIME timestamp;
    uint8_t cert[SHA256_DIGEST_SIZE];
    struct efi_variable *next;
};

extern struct efi_variable *var_list;

void dispatch_command(uint8_t *comm_buf);
bool setup_crypto(void);
bool setup_variables(void);
bool setup_keys(void);
bool setup_keys_for_cert_update(void);
bool load_auth_data(void);
void free_auth_data(void);
void get_kek_auth_data(const uint8_t **data, off_t *len);

EFI_STATUS
internal_set_variable(const uint8_t *name, UINTN name_len, const EFI_GUID *guid,
                      const uint8_t *data, UINTN data_len, UINT32 attr);
EFI_STATUS
internal_get_variable(const uint8_t *name, UINTN name_len, const EFI_GUID *guid,
                      uint8_t **data, UINTN *data_len);

extern const uint8_t TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME[];
extern const size_t TCG2_PHYSICAL_PRESENCEFLAGSLOCK_NAME_SIZE;
extern const uint8_t EFI_KEY_EXCHANGE_KEY_NAME[];
#define EFI_KEY_EXCHANGE_KEY_NAME_LEN 6

extern bool secure_boot_enable;
extern bool auth_enforce;
extern bool persistent;

#define MAX_CERT_SUBJECT 256
#define MAX_CERTS_IN_SIGLIST 32

struct cert_info {
    char subject[MAX_CERT_SUBJECT];
    int not_before_year;
    int not_before_month;
    int not_before_day;
    int not_after_year;
    int not_after_month;
    int not_after_day;
};

int parse_certs_from_siglist(const uint8_t *data, UINTN data_len,
                             struct cert_info *certs, int max_certs,
                             int verbose);
bool siglist_has_latest_cert(const uint8_t *data, UINTN data_len, int verbose);
bool check_kek_and_db_uptodate(void);

#endif
