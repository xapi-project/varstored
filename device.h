#ifndef  _DEVICE_H
#define  _DEVICE_H

int     device_initialize(xc_interface *xch, domid_t domid, ioservid_t ioservid,
                          unsigned int bus, unsigned int device,
                          unsigned int function);

void    device_teardown(void);

#endif  /* _DEVICE_H */

