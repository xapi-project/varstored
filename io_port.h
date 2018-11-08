/*
 * Copyright (C) Citrix Systems, Inc
 */

#ifndef _IO_PORT_H
#define _IO_PORT_H

#include <xenctrl.h>

#define IO_PORT_UNMAPPED (~(0u))
#define IO_PORT_ADDRESS 0x0100

void io_port_deregister(void);

void io_port_write(uint64_t addr, uint64_t sizem, uint32_t val);
int  io_port_initialize(xc_interface *xch, domid_t domid, ioservid_t ioservid);

#endif /* _IO_PORT_H */
