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

#ifndef _IO_PORT_H
#define _IO_PORT_H

#include <xendevicemodel.h>
#include <xenforeignmemory.h>

#define IO_PORT_UNMAPPED (~(0u))

typedef void (*writel_callback_t)(uint64_t offset, uint64_t size, uint32_t val);
typedef uint32_t (*readl_callback_t)(uint64_t offset, uint64_t size);

bool register_io_port_readl_handler(uint64_t address, readl_callback_t callback);
bool register_io_port_writel_handler(uint64_t address, writel_callback_t callback);


void io_port_deregister(void);

void io_port_write(uint64_t addr, uint64_t sizem, uint32_t val);
uint64_t io_port_read(uint64_t addr, uint64_t size);
int  io_port_initialize(xendevicemodel_handle *dmod,
                        domid_t domid,
                        ioservid_t ioservid,
                        uint64_t addr, uint64_t size);

#endif /* _IO_PORT_H */
