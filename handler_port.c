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
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <debug.h>
#include <handler_port.h>

#include "io_port.h"

#define HANDLER_PORT_ADDRESS 0x0100

static struct {
    xenforeignmemory_handle *fmem;
    domid_t domid;
} io_info;

static void
io_port_writel(uint64_t offset, uint64_t size, uint32_t val)
{
    xen_pfn_t pfns[SHMEM_PAGES];
    void *shmem;
    int i;

    if (offset != 0 || size != sizeof(uint32_t)) {
        DBG("Expected size 4, offset 0.  Got %" PRIu64 ", %" PRIu64 ".\n", size, offset);
        return;
    }

    for (i = 0; i < SHMEM_PAGES; i++)
        pfns[i] = val + i;
    DBG("io_port write\n");

    shmem = xenforeignmemory_map(io_info.fmem,
                                 io_info.domid,
                                 PROT_READ | PROT_WRITE,
                                 SHMEM_PAGES, pfns, NULL);
    if (!shmem) {
        DBG("map foreign range failed: %d\n", errno);
        return;
    }

    dispatch_command(shmem);

    xenforeignmemory_unmap(io_info.fmem, shmem, SHMEM_PAGES);

}

bool
setup_handler_io_port(domid_t domid, xenforeignmemory_handle *fmem) {
    io_info.domid = domid;
    io_info.fmem = fmem;
    DBG("port setup for %d\n", domid);

    return register_io_port_writel_handler(HANDLER_PORT_ADDRESS, io_port_writel);
}

