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


#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <efi.h>
#include <handler.h>
#include <mor.h>

#define MOR_CONTROL_LEN 1
#define MOR_ACTION_VALID_MASK 0x11

/* MemoryOverwriteRequestControl values */
#define MOR_UNLOCKED 0
#define MOR_LOCKED_WITHOUT_KEY 1
#define MOR_LOCKED_WITH_KEY 2

#define MOR_LOCK_REV1_UNLOCK 0
#define MOR_LOCK_REV1_LOCK 1
#define MOR_LOCK_REV1_LEN 1

uint8_t mor_key[MOR_LOCK_REV2_LEN];

static const uint8_t MOR_CONTROL_NAME[] = {'M',0,'e',0,'m',0,'o',0,'r',0,'y',0,'O',0,'v',0,'e',0,'r',0,'w',0,'r',0,'i',0,'t',0,'e',0,'R',0,'e',0,'q',0,'u',0,'e',0,'s',0,'t',0,'C',0,'o',0,'n',0,'t',0,'r',0,'o',0,'l',0};
static const uint8_t MOR_CONTROL_LOCK_NAME[] = {'M',0,'e',0,'m',0,'o',0,'r',0,'y',0,'O',0,'v',0,'e',0,'r',0,'w',0,'r',0,'i',0,'t',0,'e',0,'R',0,'e',0,'q',0,'u',0,'e',0,'s',0,'t',0,'C',0,'o',0,'n',0,'t',0,'r',0,'o',0,'l',0,'L',0,'o',0,'c',0,'k',0};
const EFI_GUID morControlGuid =
    {{0xbe, 0x39, 0x09, 0xe2, 0xd4, 0x32, 0xbe, 0x41, 0xa1, 0x50, 0x89, 0x7f, 0x85, 0xd4, 0x98, 0x29}};
const EFI_GUID morControlLockGuid =
    {{0xcf, 0x3c, 0x98, 0xbb, 0x1d, 0x15, 0xe1, 0x40, 0xa0, 0x7b, 0x4a, 0x17, 0xbe, 0x16, 0x82, 0x92}};

bool
setup_mor_variables(void)
{
    EFI_STATUS status;
    uint8_t mor_control = 0, mor_control_lock = 0;
    /*
     * Initialize the MemoryOverwriteRequestControl variable to 0 at boot. The
     * firmware never needs to clear the memory under Xen since bootup always
     * takes place in a new domain with zeroed memory.
     */
    status = internal_set_variable(MOR_CONTROL_NAME,
                                   sizeof(MOR_CONTROL_NAME),
                                   &morControlGuid,
                                   &mor_control,
                                   sizeof(mor_control),
                                   ATTR_BRNV);
    if (status != EFI_SUCCESS)
        return false;

    /*
     * Initialize the MemoryOverwriteRequestControlLock variable to 0
     * (unlocked) at boot.
     */
    status = internal_set_variable(MOR_CONTROL_LOCK_NAME,
                                   sizeof(MOR_CONTROL_LOCK_NAME),
                                   &morControlLockGuid,
                                   &mor_control_lock,
                                   sizeof(mor_control_lock),
                                   ATTR_BRNV);
    if (status != EFI_SUCCESS)
        return false;

    return true;
}

bool
is_mor_control(uint8_t *name, UINTN name_len, EFI_GUID *guid)
{
    return name_len == sizeof(MOR_CONTROL_NAME) &&
           !memcmp(name, MOR_CONTROL_NAME, name_len) &&
           !memcmp(guid, &morControlGuid, GUID_LEN);
}

bool
is_mor_control_lock(uint8_t *name, UINTN name_len, EFI_GUID *guid)
{
    return name_len == sizeof(MOR_CONTROL_LOCK_NAME) &&
           !memcmp(name, MOR_CONTROL_LOCK_NAME, name_len) &&
           !memcmp(guid, &morControlLockGuid, GUID_LEN);
}

EFI_STATUS
do_set_mor_control(uint8_t *data, UINTN data_len, UINT32 attr, BOOLEAN append)
{
    EFI_STATUS status;
    uint8_t mor_locked_state;
    uint8_t *buf;
    UINTN buf_len;

    if (attr != ATTR_BRNV || append || data_len != MOR_CONTROL_LEN)
        return EFI_INVALID_PARAMETER;

    if (*data != (*data & MOR_ACTION_VALID_MASK))
        return EFI_INVALID_PARAMETER;

    status = internal_get_variable(MOR_CONTROL_LOCK_NAME,
                                   sizeof(MOR_CONTROL_LOCK_NAME),
                                   &morControlLockGuid, &buf, &buf_len);
    if (status != EFI_SUCCESS)
        return status;

    assert(buf_len == 1);
    mor_locked_state = buf[0];
    free(buf);

    if (mor_locked_state == MOR_LOCKED_WITH_KEY ||
            mor_locked_state == MOR_LOCKED_WITHOUT_KEY)
        return EFI_WRITE_PROTECTED;

    return internal_set_variable(MOR_CONTROL_NAME,
                                 sizeof(MOR_CONTROL_NAME),
                                 &morControlGuid,
                                 data,
                                 MOR_CONTROL_LEN,
                                 ATTR_BRNV);
}

EFI_STATUS
do_set_mor_control_lock(uint8_t *data, UINTN data_len,
                        UINT32 attr, BOOLEAN append)
{
    EFI_STATUS status;
    uint8_t mor_locked_state;
    uint8_t *buf;
    UINTN buf_len;

    if (attr == 0 || data_len == 0)
        return EFI_WRITE_PROTECTED;

    if (attr != ATTR_BRNV || append ||
            (data_len != MOR_LOCK_REV1_LEN && data_len != MOR_LOCK_REV2_LEN))
        return EFI_INVALID_PARAMETER;

    status = internal_get_variable(MOR_CONTROL_LOCK_NAME,
                                   sizeof(MOR_CONTROL_LOCK_NAME),
                                   &morControlLockGuid, &buf, &buf_len);
    if (status != EFI_SUCCESS)
        return status;

    assert(buf_len == 1);
    mor_locked_state = buf[0];
    free(buf);

    if (data_len == MOR_LOCK_REV1_LEN) {
        if (*data == MOR_LOCK_REV1_UNLOCK) {
            if (mor_locked_state == MOR_UNLOCKED)
                return EFI_SUCCESS; /* no-op */
            else
                return EFI_ACCESS_DENIED;
        } else if (*data == MOR_LOCK_REV1_LOCK) {
            if (mor_locked_state == MOR_UNLOCKED) {
                mor_locked_state = MOR_LOCKED_WITHOUT_KEY;
            } else {
                return EFI_ACCESS_DENIED;
            }
        } else {
            return EFI_INVALID_PARAMETER;
        }
    } else { /* data_len == MOR_LOCK_REV2_LEN */
        if (mor_locked_state == MOR_UNLOCKED) {
            memcpy(mor_key, data, data_len);
            mor_locked_state = MOR_LOCKED_WITH_KEY;
        } else if (mor_locked_state == MOR_LOCKED_WITHOUT_KEY) {
            return EFI_ACCESS_DENIED;
        } else {
            if (memcmp(mor_key, data, data_len)) {
                mor_locked_state = MOR_LOCKED_WITHOUT_KEY;
                internal_set_variable(MOR_CONTROL_LOCK_NAME,
                                      sizeof(MOR_CONTROL_LOCK_NAME),
                                      &morControlLockGuid,
                                      &mor_locked_state,
                                      sizeof(mor_locked_state),
                                      ATTR_BRNV);
                return EFI_ACCESS_DENIED;
            } else {
                mor_locked_state = MOR_UNLOCKED;
            }
        }
    }

    return internal_set_variable(MOR_CONTROL_LOCK_NAME,
                                 sizeof(MOR_CONTROL_LOCK_NAME),
                                 &morControlLockGuid,
                                 &mor_locked_state,
                                 sizeof(mor_locked_state),
                                 ATTR_BRNV);
}
