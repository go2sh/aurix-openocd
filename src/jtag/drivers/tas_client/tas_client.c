#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "helper/command.h"
#include "helper/list.h"
#include "helper/log.h"
#include "jtag/drivers/tas_client/tas_pkt.h"
#include "jtag/jtag.h"
#include "jtag/tas.h"
#include "server/server.h"
#include <jtag/interface.h>

#include "target/aurix/aurix_ocds.h"
#include "target/target.h"
#include "tas_protocol.h"

struct tas_client_pl0_req {
  uint32_t addr;
  uint8_t cmd;
  uint32_t count;
  union {
    void *buffer;
    uint64_t data;
  };
};
struct tas_client_con_queue {
  uint32_t max_pkt_size;
  uint32_t reqs_count;
  uint32_t reqs_size;
  struct tas_client_pl0_req *reqs;
};
struct tas_client_state {
  int sock;
  bool connected;
  const char *ip_addr;
  tas_target_info_st *targets;
  size_t target_num;
  struct tas_client_con_queue con_queues[32];
};

static struct tas_client_state client_state;

static int tas_client_init(void) {
  struct sockaddr_in ipv4_sock_addr;

  if (client_state.ip_addr == NULL) {
    client_state.ip_addr = "127.0.0.1";
  }
  if (inet_aton(client_state.ip_addr, &ipv4_sock_addr.sin_addr) == 0) {
    LOG_ERROR("Invalid ip addr: %s", client_state.ip_addr);
    return ERROR_INVALID_NUMBER;
  }
  ipv4_sock_addr.sin_family = AF_INET;
  ipv4_sock_addr.sin_port = htons(24817);

  LOG_INFO("Connecting to TAS server %s:%u", client_state.ip_addr, 24817);
  client_state.sock = socket(AF_INET, SOCK_STREAM, 0);
  if (client_state.sock == -1) {
    return ERROR_FAIL;
  }

  if (connect(client_state.sock, (struct sockaddr *)&ipv4_sock_addr,
              sizeof(struct sockaddr_in))) {
    LOG_ERROR("Failed to connect to tas server %s: %s", client_state.ip_addr,
              strerror(errno));
    return ERROR_CONNECTION_REJECTED;
  }

  if (tas_client_connect(client_state.sock) != 0) {
    LOG_ERROR("Failed to connect to TAS server");
    return ERROR_CONNECTION_REJECTED;
  }
  client_state.connected = true;

  if (tas_client_get_targets(client_state.sock, &client_state.targets,
                             &client_state.target_num) != 0) {
    LOG_ERROR("Failed to receive targets");
    return ERROR_FAIL;
  }

  return ERROR_OK;
}

static int tas_client_quit(void) {

  close(client_state.sock);
  return 0;
}

static int tas_client_reset(int trst, int srst) {
  if (trst != 0) {
    return ERROR_NOT_IMPLEMENTED;
  }
  if (!client_state.connected) {
    return ERROR_FAIL;
  }
  if (srst) {
    return tas_client_device_connect(client_state.sock,
                                     TAS_DEV_CON_FEAT_RESET_AND_HALT);
  }

  return 0;
}

static int tas_client_op_run(struct aurix_ocds *ocds) {

  uint32_t base_address = 0xFFFFFFFF;
  uint32_t i;
  uint32_t pl0_buffer[client_state.con_queues[ocds->con_id].max_pkt_size / 4];
  size_t pl0_size = 0;

  for (i = 0; i < client_state.con_queues[ocds->con_id].reqs_count; i++) {
    struct tas_client_pl0_req *req =
        &client_state.con_queues[ocds->con_id].reqs[i];

    if ((req->addr & 0xFFFF0000) != base_address) {
      tas_pl0rq_base_addr32_st base_addr = {
          .wl = 0,
          .cmd = TAS_PL0_CMD_BASE_ADDR32,
          .ba31to16 = req->addr >> 16,
      };
      memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), &base_addr,
             sizeof(tas_pl0rq_base_addr32_st));
      pl0_size += sizeof(tas_pl0rq_base_addr32_st);
      base_address = req->addr & 0xFFFF0000;
    }

    if ((req->cmd & 0x1) == 1 || req->cmd == TAS_PL0_CMD_RDBLK) {
      if (req->cmd < TAS_PL0_CMD_RDBLK) {
        tas_pl0rq_rd_st read_addr = {
            .wl = 0,
            .cmd = req->cmd,
            .a15to0 = req->addr & 0xFFFF,
        };
        memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), &read_addr,
               sizeof(tas_pl0rq_rd_st));
        pl0_size += sizeof(tas_pl0rq_rd_st);
      } else {
        tas_pl0rq_rdblk_st read_addr = {
            .wl = 1,
            .cmd = req->cmd,
            .wlrd = req->count,
            .a15to0 = req->addr & 0xFFFF,
        };
        memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), &read_addr,
               sizeof(tas_pl0rq_rdblk_st));
        pl0_size += sizeof(tas_pl0rq_rdblk_st);
      }
    } else {
      if (req->cmd < TAS_PL0_CMD_WRBLK) {
        tas_pl0rq_wr_st write_addr = {
            .wl = 1,
            .cmd = req->cmd,
            .a15to0 = req->addr & 0xFFFF,
            .data = req->data,
        };
        memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), &write_addr,
               sizeof(tas_pl0rq_wr_st));
        pl0_size += sizeof(tas_pl0rq_wr_st);
      } else {
        tas_pl0rq_wrblk_st write_addr = {
            .wl = req->count,
            .cmd = req->cmd,
            .a15to0 = req->addr & 0xFFFF,
        };
        memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), &write_addr,
               sizeof(tas_pl0rq_wrblk_st));
        pl0_size += sizeof(tas_pl0rq_wrblk_st);
        memcpy(pl0_buffer + pl0_size / sizeof(uint32_t), req->buffer,
               req->count * sizeof(uint32_t));
        pl0_size += req->count * 4;
      }
    }
  }

  int err =
      tas_client_send_pl0(client_state.sock, ocds->con_id, pl0_buffer, pl0_size,
                          client_state.con_queues[ocds->con_id].reqs_count);
  if (err) {
    client_state.con_queues[ocds->con_id].reqs_count = 0;
    return err;
  }

  size_t pl0_offset = 0;
  for (i = 0; i < client_state.con_queues[ocds->con_id].reqs_count; i++) {
    struct tas_client_pl0_req *req =
        &client_state.con_queues[ocds->con_id].reqs[i];
    tas_pl0rsp_rd_st rsp_rd;
    tas_pl0rsp_wr_st rsp_wr;

    switch (req->cmd) {
    case TAS_PL0_CMD_RD8:
    case TAS_PL0_CMD_RD16:
    case TAS_PL0_CMD_RD32:
    case TAS_PL0_CMD_RDBLK:
    case TAS_PL0_CMD_RDBLK1KB:
      memcpy(&rsp_rd, pl0_buffer + pl0_offset, sizeof(tas_pl0rsp_rd_st));
      pl0_offset++;
      if (rsp_rd.cmd != req->cmd || rsp_rd.err != TAS_PL0_ERR_NO_ERROR ||
          rsp_rd.wlrd != req->count) {
        client_state.con_queues[ocds->con_id].reqs_count = 0;
        return ERROR_FAIL;
      }
      uint32_t size = req->cmd == TAS_PL0_CMD_RD8    ? 1
                      : req->cmd == TAS_PL0_CMD_RD16 ? 2
                                                     : 4;
      memcpy(req->buffer, pl0_buffer + pl0_offset, req->count * size);
      pl0_offset += (req->count + 3) / 4;
      break;
    case TAS_PL0_CMD_WR8:
    case TAS_PL0_CMD_WR16:
    case TAS_PL0_CMD_WR32:
    case TAS_PL0_CMD_WR64:
    case TAS_PL0_CMD_WRBLK:
      memcpy(&rsp_wr, pl0_buffer + pl0_offset, sizeof(tas_pl0rsp_wr_st));
      pl0_offset++;
      if (rsp_wr.cmd != req->cmd || rsp_wr.err != TAS_PL0_ERR_NO_ERROR ||
          rsp_wr.wlwr != (req->count + 3) / 4) {
        client_state.con_queues[ocds->con_id].reqs_count = 0;
        return ERROR_FAIL;
      }
      break;
    }
  }

  client_state.con_queues[ocds->con_id].reqs_count = 0;
  return ERROR_OK;
}

static int tas_client_op_queue_soc_read(struct aurix_ocds *ocds, uint32_t addr,
                                        uint32_t size, uint32_t count,
                                        void *buffer) {
  if (ocds->con_id > 32 || !client_state.con_queues[ocds->con_id].reqs) {
    return ERROR_FAIL;
  }

  if (size == 4 && count > 1) {
    uint32_t i;
    for (i = 0; i < count; i += 256) {
      if (client_state.con_queues[ocds->con_id].reqs_count > 0) {
        int ret = tas_client_op_run(ocds);
        if (ret) {
          return ret;
        }
      }
      client_state.con_queues[ocds->con_id]
          .reqs[client_state.con_queues[ocds->con_id].reqs_count++] =
          (struct tas_client_pl0_req){.addr = addr,
                                      .count = MIN(256, count - i),
                                      .cmd = TAS_PL0_CMD_RDBLK,
                                      .buffer = buffer};
    }
  } else {
    uint32_t i;
    for (i = 0; i < count; i++) {
      if (client_state.con_queues[ocds->con_id].reqs_count >=
          client_state.con_queues[ocds->con_id].reqs_size) {
        int ret = tas_client_op_run(ocds);
        if (ret) {
          return ret;
        }
      }
      client_state.con_queues[ocds->con_id]
          .reqs[client_state.con_queues[ocds->con_id].reqs_count++] =
          (struct tas_client_pl0_req){.addr = addr,
                                      .count = 1,
                                      .cmd = size == 4   ? TAS_PL0_CMD_RD32
                                             : size == 2 ? TAS_PL0_CMD_RD16
                                                         : TAS_PL0_CMD_RD8,
                                      .buffer = buffer};
    }
  }
  return ERROR_OK;
}

static int tas_client_op_queue_soc_write(struct aurix_ocds *ocds, uint32_t addr,
                                         uint32_t size, uint32_t count,
                                         const void *buffer) {
  if (ocds->con_id > 32 || !client_state.con_queues[ocds->con_id].reqs) {
    return ERROR_FAIL;
  }

  if (size == 4 && count > 1) {
    uint32_t i;
    for (i = 0; i < count; i += 256) {
      if (client_state.con_queues[ocds->con_id].reqs_count > 0) {
        int ret = tas_client_op_run(ocds);
        if (ret) {
          return ret;
        }
      }

      client_state.con_queues[ocds->con_id]
          .reqs[client_state.con_queues[ocds->con_id].reqs_count++] =
          (struct tas_client_pl0_req){.addr = addr,
                                      .count = count,
                                      .cmd = TAS_PL0_CMD_WRBLK,
                                      .buffer = (void *)buffer};
    }
  } else {
    uint32_t i;
    for (i = 0; i < count; i++) {
      uint64_t data;

      if (client_state.con_queues[ocds->con_id].reqs_count >=
          client_state.con_queues[ocds->con_id].reqs_size) {
        int ret = tas_client_op_run(ocds);
        if (ret) {
          return ret;
        }
      }

      memcpy(&data, buffer, size);
      client_state.con_queues[ocds->con_id]
          .reqs[client_state.con_queues[ocds->con_id].reqs_count++] =
          (struct tas_client_pl0_req){.addr = addr,
                                      .count = 1,
                                      .cmd = size == 4   ? TAS_PL0_CMD_WR32
                                             : size == 2 ? TAS_PL0_CMD_WR16
                                                         : TAS_PL0_CMD_WR8,
                                      .data = data};
    }
  }

  return ERROR_OK;
}

static uint16_t con_id = 0;

static int tas_client_op_connect(struct aurix_ocds *ocds) {
  uint32_t i, j;
  tas_target_info_st *target = NULL;
  tas_con_info_st con_info;
  for (i = 0; i < client_state.target_num; i++) {
    for (j = 0; j < ocds->tap->expected_ids_cnt; j++) {
      if (client_state.targets[i].device_type == ocds->tap->expected_ids[j]) {
        target = &client_state.targets[i];
        goto out;
      }
    }
  }

out:
  if (target == NULL) {
    LOG_ERROR("No matching target for OCDS %s found", ocds->name);
    return ERROR_COMMAND_ARGUMENT_INVALID;
  }
  ocds->con_id = con_id++;

  int err = tas_client_session_start(client_state.sock, target->identifier,
                                     ocds->con_id, &con_info);
  if (err) {
    LOG_ERROR("Failed to start session for target %s", target->identifier);
    return ERROR_FAIL;
  }

  if (client_state.con_queues[ocds->con_id].reqs) {
    free(client_state.con_queues[ocds->con_id].reqs);
  }
  client_state.con_queues[ocds->con_id].max_pkt_size =
      con_info.max_pl2rq_pkt_size - 4 - sizeof(tas_pl1rq_pl0_start_st) -
      sizeof(tas_pl1rq_pl0_end_st);
  client_state.con_queues[ocds->con_id].reqs_size =
      MIN(256, con_info.pl0_max_num_rw);
  client_state.con_queues[ocds->con_id].reqs =
      malloc(sizeof(struct tas_client_pl0_req) *
             client_state.con_queues[ocds->con_id].reqs_size);
  client_state.con_queues[ocds->con_id].reqs_count = 0;
  if (!client_state.con_queues[ocds->con_id].reqs) {
    return ERROR_FAIL;
  }

  enum reset_types jtag_reset_config = jtag_get_reset_config();

  if (jtag_reset_config & RESET_CNCT_UNDER_SRST) {
    err = tas_client_device_connect(client_state.sock,
                                    TAS_DEV_CON_FEAT_RESET_AND_HALT);
  } else {
    err = tas_client_device_connect(client_state.sock, TAS_DEV_CON_FEAT_NONE);
  }
  if (err) {
    LOG_ERROR("Failed to connect to device %s", target->identifier);
    return ERROR_FAIL;
  }

  return ERROR_OK;
}

static const struct aurix_ocds_ops tas_ops_interface = {
    .connect = tas_client_op_connect,
    .queue_soc_read = tas_client_op_queue_soc_read,
    .queue_soc_write = tas_client_op_queue_soc_write,
    .run = tas_client_op_run,
};

static const char *const tas_client_transports[] = {"tas", NULL};

struct adapter_driver tas_client_adapter_driver = {
    .name = "tas_client",
    .transports = tas_client_transports,
    .tas_ops = &tas_ops_interface,
    .init = tas_client_init,
    .quit = tas_client_quit,
    .reset = tas_client_reset,
};