#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "helper/log.h"
#include "tas_pkt.h"

int tas_client_connect(int sock) {
  tas_pl1rq_server_connect_st rq_server_connect;
  tas_pl1rsp_server_connect_st rsp_server_connect;
  uint32_t packet_size;

  packet_size = 4 + sizeof(tas_pl1rq_server_connect_st);
  rq_server_connect.wl = sizeof(tas_pl1rq_server_connect_st) / 4 - 1;
  rq_server_connect.cmd = TAS_PL1_CMD_SERVER_CONNECT;
  rq_server_connect.reserved = 0;
  snprintf(rq_server_connect.client_name, TAS_NAME_LEN32, "openocd");
  getlogin_r(rq_server_connect.user_name, TAS_NAME_LEN16);
  rq_server_connect.client_pid = getpid();

  if (send(sock, &packet_size, 4, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_server_connect, sizeof(tas_pl1rq_server_connect_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (recv(sock, &packet_size, 4, 0) != 4) {
    return ERROR_FAIL;
  }
  if (recv(sock, &rsp_server_connect, sizeof(tas_pl1rsp_server_connect_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (rsp_server_connect.cmd != TAS_PL1_CMD_SERVER_CONNECT ||
      rsp_server_connect.err != TAS_PL_ERR_NO_ERROR) {
    return ERROR_FAIL;
  }

  return 0;
}

int tas_client_session_start(int sock, const char *device, uint8_t con_id,
                             tas_con_info_st *con_info) {
  tas_pl1rq_session_start_st rq_session_start;
  tas_pl1rsp_session_start_st rsp_session_start;
  uint32_t packet_size;

  packet_size = 4 + sizeof(tas_pl1rq_session_start_st);
  rq_session_start.wl = sizeof(tas_pl1rq_session_start_st) / 4 - 1;
  rq_session_start.cmd = TAS_PL1_CMD_SESSION_START;
  rq_session_start.con_id = con_id;
  rq_session_start.client_type = TAS_CLIENT_TYPE_RW;
  strncpy(rq_session_start.identifier, device, TAS_NAME_LEN64);
  snprintf(rq_session_start.session_name, TAS_NAME_LEN16, "openocd%u", con_id);
  rq_session_start.session_pw[0] = 0;

  if (send(sock, &packet_size, 4, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_session_start, sizeof(tas_pl1rq_session_start_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (recv(sock, &packet_size, 4, 0) != 4) {
    return ERROR_FAIL;
  }
  if (recv(sock, &rsp_session_start, sizeof(tas_pl1rsp_session_start_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (rsp_session_start.cmd != TAS_PL1_CMD_SESSION_START ||
      rsp_session_start.con_id != con_id ||
      rsp_session_start.err != TAS_PL_ERR_NO_ERROR) {
    return ERROR_FAIL;
  }

  if (rsp_session_start.num_instances > 0) {
    return ERROR_FAIL;
  }
  *con_info = rsp_session_start.con_info;

  return 0;
}

int tas_client_device_connect(int sock, tas_dev_con_feat_et dev_con_feat) {
  tas_pl1rq_device_connect_st rq_device_connect;
  tas_pl1rsp_device_connect_st rsp_device_connect;
  uint32_t packet_size;

  packet_size = 4 + sizeof(tas_pl1rq_device_connect_st);
  rq_device_connect.wl = sizeof(tas_pl1rq_device_connect_st) / 4 - 1;
  rq_device_connect.cmd = TAS_PL1_CMD_DEVICE_CONNECT;
  rq_device_connect.con_id = 0xFF;
  rq_device_connect.reserved = 0;
  rq_device_connect.option = dev_con_feat;
  rq_device_connect.reserved1 = 0;

  if (send(sock, &packet_size, 4, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_device_connect, sizeof(tas_pl1rq_device_connect_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (recv(sock, &packet_size, 4, 0) != 4) {
    return ERROR_FAIL;
  }
  if (recv(sock, &rsp_device_connect, sizeof(tas_pl1rsp_device_connect_st), 0) <
      0) {
    return ERROR_FAIL;
  }

  if (rsp_device_connect.cmd != TAS_PL1_CMD_DEVICE_CONNECT ||
      rsp_device_connect.err != TAS_PL_ERR_NO_ERROR) {
    return ERROR_FAIL;
  }

  if (rsp_device_connect.feat_used != dev_con_feat) {
    return ERROR_FAIL;
  }

  return 0;
}

int tas_client_get_targets(int sock, tas_target_info_st **targets,
                           size_t *target_num) {
  tas_pl1rq_get_targets_st rq_get_targets;
  tas_pl1rsp_get_targets_st rsp_get_targets;
  uint32_t packet_size;
  if (targets == NULL) {
    return ERROR_FAIL;
  }

  packet_size = 4 + sizeof(tas_pl1rq_get_targets_st);
  rq_get_targets.cmd = TAS_PL1_CMD_GET_TARGETS;
  rq_get_targets.wl = 0;
  rq_get_targets.start_index = 0;

  if (send(sock, &packet_size, 4, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_get_targets, sizeof(tas_pl1rq_get_targets_st), 0) < 0) {
    return ERROR_FAIL;
  }

  if (recv(sock, &packet_size, 4, 0) != 4) {
    return ERROR_FAIL;
  }
  if (recv(sock, &rsp_get_targets, sizeof(tas_pl1rsp_get_targets_st), 0) < 0) {
    return ERROR_FAIL;
  }

  if (rsp_get_targets.cmd != TAS_PL1_CMD_GET_TARGETS ||
      rsp_get_targets.err != TAS_PL_ERR_NO_ERROR) {
    return ERROR_FAIL;
  }

  *target_num = rsp_get_targets.num_target;
  /* Limit number of targets supported */
  if (*target_num > 32) {
    return ERROR_FAIL;
  }
  if (*target_num > 0) {
    *targets = calloc(*target_num, sizeof(tas_target_info_st));
    if (*targets == NULL) {
      return ERROR_FAIL;
    }
    if (recv(sock, *targets, *target_num * sizeof(tas_target_info_st), 0) < 0) {
      return ERROR_FAIL;
    }
  }

  return ERROR_OK;
}

enum {
  PROTOC_VER = 0 //!< \brief TasPkt protocol version implemented in this class
};

static uint16_t pl1_count = 0;

struct tas_client_pl0_req {
  uint32_t addr;
  uint8_t *buffer;
  uint8_t cmd;
};

int tas_client_send_pl0(int sock, uint8_t con_id, uint32_t *pl0_buffer,
                        size_t pl0_len, size_t pl0_elements) {

  uint32_t packet_size = 4 + sizeof(tas_pl1rq_pl0_start_st) +
                         sizeof(tas_pl1rq_pl0_end_st) + pl0_len;
  tas_pl1rq_pl0_start_st rq_start = {
      .cmd = TAS_PL1_CMD_PL0_START,
      .wl = 0,
      .con_id = con_id,
      .pl0_addr_map_mask = 1,
      .pl1_cnt = pl1_count++,
      .protoc_ver = PROTOC_VER,

  };
  tas_pl1rq_pl0_end_st rq_end = {
      .wl = 0, .cmd = TAS_PL1_CMD_PL0_END, .num_pl0_rw = pl0_elements};
  tas_pl1rsp_pl0_start_st rsp_start;
  tas_pl1rsp_pl0_end_st rsp_end;

  if (send(sock, &packet_size, 4, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_start, sizeof(tas_pl1rq_pl0_start_st), MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, pl0_buffer, pl0_len, MSG_MORE) < 0) {
    return ERROR_FAIL;
  }
  if (send(sock, &rq_end, sizeof(tas_pl1rq_pl0_end_st), 0) < 0) {
    return ERROR_FAIL;
  }

  if (recv(sock, &packet_size, 4, 0) != 4) {
    return ERROR_FAIL;
  }
  if (recv(sock, &rsp_start, sizeof(tas_pl1rsp_pl0_start_st), 0) < 0) {
    return ERROR_FAIL;
  }

  if (rsp_start.cmd != TAS_PL1_CMD_PL0_START ||
      (rsp_start.err != TAS_PL_ERR_NO_ERROR &&
       rsp_start.err != TAS_PL_ERR_PROTOCOL)) {
    uint8_t buf[packet_size - 4 - sizeof(tas_pl1rsp_pl0_start_st)];
    recv(sock, buf, packet_size - 4 - sizeof(tas_pl1rsp_pl0_start_st), 0);
    return ERROR_FAIL;
  }
  pl0_len = packet_size - 4 - sizeof(tas_pl1rsp_pl0_start_st) -
            sizeof(tas_pl1rsp_pl0_end_st);
  int err = recv(sock, pl0_buffer, MIN(pl0_len, 256 * 4), 0);
  if (err < 0) {
    return ERROR_FAIL;
  };
  pl0_len -= err;

  /* Don't overflow pl0 buffer in case of error */
  while (pl0_len) {
    uint8_t buf[1024];
    err = recv(sock, buf, MIN(1024, pl0_len), 0);
    if (err < 0) {
      return ERROR_FAIL;
    };
    pl0_len -= err;
  }

  if (recv(sock, &rsp_end, sizeof(tas_pl1rsp_pl0_end_st), 0) < 0) {
    return ERROR_FAIL;
  }
  if (rsp_end.cmd != TAS_PL1_CMD_PL0_END ||
      rsp_end.pl1_cnt != rq_start.pl1_cnt) {
    return ERROR_FAIL;
  }

  return ERROR_OK;
}