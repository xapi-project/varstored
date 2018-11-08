/*
 * Copyright (C) Citrix Systems, Inc
*/
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <xenctrl.h>

#include <debug.h>
#include <handler.h>

#include "io_port.h"

typedef struct io_port {
    void            (*writel)(uint64_t offset, uint32_t val);

    xc_interface    *xch;
    domid_t         domid;
    ioservid_t      ioservid;
    uint32_t        addr;
    uint32_t        size;
    int             enable;
} io_port_t;

static io_port_t io_port;

static void
io_port_writel(uint64_t offset, uint32_t val)
{
    void *shmem = xc_map_foreign_range(io_port.xch,
                                       io_port.domid,
                                       SHMEM_SIZE,
                                       PROT_READ | PROT_WRITE,
                                       val);
    if (!shmem) {
        DBG("map foreign range failed: %d\n", errno);
        return;
    }

    dispatch_command(shmem);

    munmap(shmem, XC_PAGE_SIZE);
}

void
io_port_deregister(void)
{
    DBG("Deregistering port\n");

    if (io_port.addr == IO_PORT_UNMAPPED)
        return;

    (void) xc_hvm_unmap_io_range_from_ioreq_server(io_port.xch,
                                                   io_port.domid,
                                                   io_port.ioservid,
                                                   0,
                                                   io_port.addr,
                                                   io_port.addr + io_port.size - 1);

    io_port.addr = IO_PORT_UNMAPPED;
}

void
io_port_write(uint64_t addr, uint64_t size, uint32_t val)
{
    assert(io_port.enable && io_port.addr <= addr
           && addr < (io_port.addr + io_port.size));

    addr -= io_port.addr;

    if (size == 4)
        io_port.writel(addr, val);
    else
        DBG("Expected size 4. Got %" PRIu64 ".\n", size);
}

int
io_port_initialize(xc_interface *xch, domid_t domid, ioservid_t ioservid)
{
    int rc;

    io_port.xch = xch;
    io_port.domid = domid;
    io_port.ioservid = ioservid;

    if (io_port.enable)
        return -1;

    io_port.writel = io_port_writel;

    /* Large enough for accepting 32-bit write. */
    io_port.size = 4;

    io_port.enable = 1;
    io_port.addr = IO_PORT_ADDRESS;

    rc = xc_hvm_map_io_range_to_ioreq_server(xch,
                                            domid,
                                            ioservid,
                                            0,
                                            io_port.addr,
                                            io_port.addr + io_port.size - 1);

    if (rc < 0) {
        ERR("xc_hvm_map_io_range_to_ioreq_server failed: rc %d\n", rc);
        return -1;
    }

    DBG("map IO port: %016"PRIx32" - %016"PRIx32"\n", io_port.addr,
        io_port.addr + io_port.size - 1);

    return 0;
}
