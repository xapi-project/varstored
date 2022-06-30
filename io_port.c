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

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <xenctrl.h>

#include <debug.h>
#include <handler.h>
#include <ppi.h>

#include "io_port.h"


typedef struct io_port {
    writel_callback_t *writel;
    readl_callback_t  *readl;
    xendevicemodel_handle *dmod;
    domid_t         domid;
    ioservid_t      ioservid;
    uint64_t        addr;
    uint64_t        size;
    int             enable;
} io_port_t;

static io_port_t io_port = { .addr = IO_PORT_UNMAPPED };

void
io_port_deregister(void)
{
    DBG("Deregistering port\n");

    if (io_port.addr == IO_PORT_UNMAPPED)
        return;

    (void) xendevicemodel_unmap_io_range_from_ioreq_server(
               io_port.dmod,
               io_port.domid,
               io_port.ioservid,
               0,
               io_port.addr,
               io_port.addr + io_port.size - 1);

    io_port.addr = IO_PORT_UNMAPPED;

    free(io_port.readl);
    free(io_port.writel);
}

void
io_port_write(uint64_t addr, uint64_t size, uint32_t val)
{
    uint64_t port_index;
    uint64_t alignment;

    assert(io_port.enable && io_port.addr <= addr
           && addr < (io_port.addr + io_port.size));

    addr -= io_port.addr;
    alignment = addr % sizeof(uint32_t);

    if (size == 0) {
       DBG("Zero sized write to %" PRIu64 "\n", addr);
       return;
    }

    if (size + alignment <= sizeof(uint32_t)) {
        port_index = addr / sizeof(uint32_t);
        if (io_port.writel[port_index] != NULL)
           io_port.writel[port_index](addr - port_index * sizeof(uint32_t), size, val);
        else
           DBG("Write to offset %" PRIu64 " not supported.\n", addr);
    } else {
        DBG("Write misaligned with ports. Address %" PRIu64 " Size %" PRIu64 ".\n", addr, size);
    }
}

uint64_t
io_port_read(uint64_t addr, uint64_t size)
{
    uint32_t port_index;
    uint64_t alignment;

    assert(io_port.enable && io_port.addr <= addr
           && addr < (io_port.addr + io_port.size));

    addr -= io_port.addr;
    alignment = addr % sizeof(uint32_t);

    if (size == 0) {
       DBG("Zero sized read from %" PRIu64 "\n", addr);
       return 0;
    }

    if (size + alignment <= sizeof(uint32_t)) {
        port_index = addr / sizeof(uint32_t);

        if (io_port.readl[port_index] != NULL) {
            return (uint64_t) io_port.readl[port_index](addr - port_index * sizeof(uint32_t), size);
        } else {
            DBG("Read from offset %" PRIu64 "not supported.\n", addr);
            return 0;
        }
    } else {
        DBG("Read misaligned with ports. Address %" PRIu64 " Size %" PRIu64 ".\n", addr, size);
    }

    return 0;
}


static bool
get_port(uint64_t address, uint32_t *port) {

    if (address < io_port.addr  || address > io_port.addr + io_port.size - sizeof(uint32_t)) {
        ERR("Failed to register io port handler, address out of range: %016"PRIx64"\n", address);
        return false;
    }
    if ((address - io_port.addr) & 0x3) {
        ERR("Failed to register io port handler, address not aligned: %016"PRIx64"\n", address);
        return false;
    }
    *port = (address - io_port.addr) >> 2;
    return true;
}

bool
register_io_port_readl_handler(uint64_t address, readl_callback_t callback) {
    uint32_t port;
    bool r;
    r = get_port(address, &port);
    if (!r)
       return false;
    if (io_port.readl[port]) {
       ERR("Failed to register io_port_handler, handler already exits. address: %016"PRIx64"\n", address);
       return false;
    }
    DBG("Registering read callback at %016"PRIx64"\n", address);
    io_port.readl[port] = callback;
    return true;
}

bool
register_io_port_writel_handler(uint64_t address, writel_callback_t callback) {
    uint32_t port;
    bool r;
    r = get_port(address, &port);
    if (!r)
       return false;
    if (io_port.readl[port]) {
       ERR("Failed to register io_port_handler, handler already exits. address: %016"PRIx64"\n", address);
       return false;
    }
    DBG("Registering write callback at %016"PRIx64"\n", address);
    io_port.writel[port] = callback;
    return true;
}

int
io_port_initialize(xendevicemodel_handle *dmod,
                   domid_t domid, ioservid_t ioservid,
                   uint64_t addr, uint64_t size)
{
    int rc;
    size_t num_32bit_ports = size / sizeof(uint32_t);

    assert(num_32bit_ports < UINT32_MAX);

    io_port.dmod = dmod;
    io_port.domid = domid;
    io_port.ioservid = ioservid;

    if (io_port.enable) {
        ERR("Cannot initialize already enable ioport!\n");
        return -1;
    }

    io_port.writel = calloc(num_32bit_ports, sizeof(*io_port.writel));
    io_port.readl = calloc(num_32bit_ports, sizeof(*io_port.readl));

    io_port.size = size;
    io_port.enable = 1;
    io_port.addr = addr;

    rc = xendevicemodel_map_io_range_to_ioreq_server(
             dmod,
             domid,
             ioservid,
             0,
             io_port.addr,
             io_port.addr + io_port.size - 1);

    if (rc < 0) {
        ERR("Failed to map io range to ioreq server: %d, %s\n",
            errno, strerror(errno));
        return -1;
    }

    DBG("map IO port: %016"PRIx64" - %016"PRIx64"\n", io_port.addr,
        io_port.addr + io_port.size - 1);

    return 0;
}
