#ifndef LIB_PROG_H
#define LIB_PROG_H

#include <efi.h>

bool tool_init(void);
void print_efi_error(EFI_STATUS status);
bool parse_guid(EFI_GUID *guid, const char *guid_str);
size_t parse_name(const char *in, uint8_t *name);

#endif
