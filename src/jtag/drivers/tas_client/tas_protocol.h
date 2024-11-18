#ifndef OPENOCD_JTAG_DRIVERS_TAS_CLIENT_TAS_PROTOCOL_H
#define OPENOCD_JTAG_DRIVERS_TAS_CLIENT_TAS_PROTOCOL_H

#include <stdio.h>

#include "tas_pkt.h"

int tas_client_connect(int sock);
int tas_client_device_connect(int sock, tas_dev_con_feat_et dev_con_feat);
int tas_client_get_targets(int sock, tas_target_info_st **targets,
                           size_t *target_num);
int tas_client_session_start(int sock, const char *device, uint8_t con_id,
                             tas_con_info_st *con_info);
int tas_client_send_pl0(int sock, uint8_t con_id, uint32_t *buffer, size_t len,
                        size_t elements);

#endif // !OPENOCD_JTAG_DRIVERS_TAS_CLIENT_TAS_PROTOCOL_H
