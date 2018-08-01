#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <xenctrl.h>

#include <debug.h>
#include <handler.h>

#include "pci.h"
#include "device.h"

typedef struct _device_io_state {
    unsigned int    index;
    unsigned int    order;
    domid_t domid;
    xc_interface *xch;
} device_io_state_t;

static  device_io_state_t   device_io_state;

static void
device_io_map(void *priv, uint64_t addr)
{
    device_io_state_t   *state = priv;

    DBG("map %d: %016"PRIx64" - %016"PRIx64"\n",
        state->index,
        addr,
        addr + (1 << state->order) - 1);
}

static void
device_io_unmap(void *priv)
{
    device_io_state_t   *state = priv;

    DBG("unmap %d\n", state->index);
}

static uint8_t
device_io_readb(void *priv, uint64_t offset)
{
    return 0;
}

static void
device_io_writeb(void *priv, uint64_t offset, uint8_t val)
{
}

static void
device_io_writel(void *priv, uint64_t offset, uint32_t val)
{
    void *shmem;
    device_io_state_t *state = priv;

    shmem = xc_map_foreign_range(state->xch,
                                 state->domid,
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

static bar_ops_t device_io_ops = {
    .map = device_io_map,
    .unmap = device_io_unmap,
    .readb = device_io_readb,
    .writeb = device_io_writeb,
    .writel = device_io_writel,
};

typedef struct _device_memory_state {
    unsigned int    index;
    unsigned int    order;
    domid_t domid;
    xc_interface *xch;
} device_memory_state_t;

int
device_initialize(xc_interface *xch, domid_t domid, ioservid_t ioservid,
                  unsigned int bus, unsigned int device, unsigned int function)
{
    pci_info_t  info;
    int         rc;

    info.bus = bus;
    info.device = device;
    info.function = function;

    info.vendor_id = 0x5853;
    info.device_id = 0x0003;
    info.subvendor_id = 0x5853;
    info.subdevice_id = 0x0003;
    info.revision = 0x01;
    info.class = 0x01;
    info.subclass = 0x00;
    info.prog_if = 0x00;
    info.header_type = 0;
    info.command = PCI_COMMAND_IO;
    info.interrupt_pin = 1;

    rc = pci_device_register(xch, domid, ioservid, &info);
    if (rc < 0)
        goto fail1;

    device_io_state.index = 0;
    device_io_state.order = 8;
    device_io_state.domid = domid;
    device_io_state.xch = xch;

    rc = pci_bar_register(device_io_state.index,
                          PCI_BASE_ADDRESS_SPACE_IO,
                          device_io_state.order,
                          &device_io_ops,
                          &device_io_state);
    if (rc < 0)
        goto fail2;

    return 0;

fail2:
    DBG("fail2\n");

    pci_device_deregister();

fail1:
    DBG("fail1\n");

    warn("fail");
    return -1;
}

void
device_teardown(void)
{
    pci_bar_deregister(0);
    pci_device_deregister();
}
