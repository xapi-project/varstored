#ifndef  HANDLER_H
#define  HANDLER_H

#include <stdint.h>

void dispatch_command(uint8_t *comm_buf);
void load_list();

#endif
