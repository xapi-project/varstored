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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <handler.h>
#include <backend.h>
#include <debug.h>
#include <ppi.h>
#include <efi.h>
#include "io_port.h"

static const uint8_t PPI_NAME[] = {'P',0,'P',0,'I',0,'B',0,'u',0,'f',0,'f',0,'e',0,'r',0};
const EFI_GUID ppiBufferGuid =
    {{0xbe, 0x39, 0x09, 0xe2, 0xd4, 0x32, 0xbe, 0x41, 0xa1, 0x50, 0x89, 0x7f, 0x85, 0xd4, 0x98, 0x29}};

#define PPI_IDX_ADDRESS  0x0104
#define PPI_DATA_ADDRESS 0x0108


#define PPI_VOLATILE_SIZE 0x100
#define PPI_NONVOLITILE_SIZE 48
#define PPI_BUFF_SIZE (PPI_NONVOLITILE_SIZE + PPI_VOLATILE_SIZE)

bool
setup_ppi_variables(void)
{
    EFI_STATUS status;
    UINTN data_len;
    uint8_t *data;

    status = internal_get_variable(PPI_NAME,
                                   sizeof(PPI_NAME),
                                   &ppiBufferGuid, &data, &data_len);
    if (status == EFI_NOT_FOUND) {
        uint8_t buf[PPI_NONVOLITILE_SIZE] = {0};

        status = internal_set_variable(PPI_NAME,
                                       sizeof(PPI_NAME),
                                       &ppiBufferGuid,
                                       buf,
                                       sizeof(buf),
                                       ATTR_BRNV);
        if (status != EFI_SUCCESS) {
            ERR("internal_set_variable returned 0x%016lx\n", status);
            return false;
        }
    } else {
        if (status != EFI_SUCCESS) {
           ERR("internal_get_variable returned 0x%016lx\n", status);
           return false;
        }
        free(data);
    }

    return true;
}

static void
ppi_idx_port_writel(uint64_t offset, uint64_t size, uint32_t val)
{
    if (offset != 0 || size != sizeof(uint32_t)) {
        DBG("Bad PPI IDX write offset 0x%" PRIx64 ", size 0x%" PRIx64", val 0x%" PRIx32 "\n", offset, size, val);
        return;
    }
    ppi_vdata.idx = val;
}

static uint32_t
ppi_data_readl(uint64_t offset, uint64_t size)
{
    uint32_t ret = 0;
    EFI_STATUS status;

    if (ppi_vdata.idx + size > PPI_BUFF_SIZE) {
       INFO("PPI IDX out of range. 0x%" PRIx32 "+ %" PRIx64 "\n", ppi_vdata.idx, size);
       return 0;
    }

    if (ppi_vdata.idx >= PPI_VOLATILE_SIZE) {
        uint8_t *data;
        UINTN data_len;
        status = internal_get_variable(PPI_NAME,
                                       sizeof(PPI_NAME),
                                       &ppiBufferGuid, &data, &data_len);

        if (status == EFI_SUCCESS) {
            memcpy(&ret, data + offset + (ppi_vdata.idx - PPI_VOLATILE_SIZE), size);
            free(data);
            return ret;
        } else {
            ERR("ppi read failure 0x%016lx!\n", status);
            return 0;
        }
    } else {
        memcpy(&ret, ppi_vdata.func + offset + ppi_vdata.idx, size);
        return ret;
    }
    return 0;
}

static void
ppi_data_port_writel(uint64_t offset, uint64_t size, uint32_t val)
{
    EFI_STATUS status;

    if (ppi_vdata.idx + size> PPI_BUFF_SIZE) {
       INFO("PP IDX out of range. 0x%" PRIx32 "+ %" PRIx64 "\n", ppi_vdata.idx, size);
       return;
    }

    if (ppi_vdata.idx >= PPI_VOLATILE_SIZE) {
            uint8_t *data;
            UINTN data_len;
            status = internal_get_variable(PPI_NAME,
                                           sizeof(PPI_NAME),
                                           &ppiBufferGuid, &data, &data_len);

            if (status == EFI_SUCCESS) {
                memcpy(data + (ppi_vdata.idx - PPI_VOLATILE_SIZE), &val, size);
                status = internal_set_variable(PPI_NAME,
                                              sizeof(PPI_NAME),
                                              &ppiBufferGuid,
                                              data,
                                              data_len,
                                              ATTR_BRNV);
                free(data);
                if (status == EFI_SUCCESS) {
                    db->set_variable();
                } else {
                    ERR("Set variable failure 0x%016lx!\n", status);
                }

            } else {
                ERR("Get variable failure 0x%016lx!\n", status);
            }
    } else {
        memcpy(ppi_vdata.func + ppi_vdata.idx + offset, &val, size);
    }
}

bool
setup_ppi_port(void) {
     bool r = true;
     r &= register_io_port_writel_handler(PPI_IDX_ADDRESS, ppi_idx_port_writel);
     r &= register_io_port_writel_handler(PPI_DATA_ADDRESS, ppi_data_port_writel);
     r &= register_io_port_readl_handler(PPI_DATA_ADDRESS, ppi_data_readl);
     return r;
}

