#ifndef  HANDLER_H
#define  HANDLER_H

#include <stdint.h>

#include "efi.h"

#define NAME_LIMIT 4096 /* Maximum length of name */
#define DATA_LIMIT 57344 /* Maximum length of a single variable */
#define TOTAL_LIMIT 65536 /* Maximum total storage */

#define SHMEM_SIZE (16 * 4096)

enum command_t {
    COMMAND_GET_VARIABLE,
    COMMAND_SET_VARIABLE,
    COMMAND_GET_NEXT_VARIABLE,
    COMMAND_QUERY_VARIABLE_INFO,
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
void load_list();
bool setup_variables(void);
bool setup_keys(void);

extern bool secure_boot_enable;

#endif
