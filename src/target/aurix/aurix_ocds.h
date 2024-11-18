#ifndef OPENOCD_TARGET_AURIX_AURIX_OCDS_H
#define OPENOCD_TARGET_AURIX_AURIX_OCDS_H

#include "helper/list.h"
#include "helper/log.h"
#include <jtag/jtag.h>
#include <stdatomic.h>

struct aurix_ocds {
  const char *name;
  struct list_head lh;
  struct jtag_tap *tap;
  atomic_bool used;
  uint8_t con_id;

  const struct aurix_ocds_ops *ops;
  uint8_t *queue_buffer;
};

struct aurix_ocds_ops {
  int (*connect)(struct aurix_ocds *ocds);
  int (*queue_soc_read)(struct aurix_ocds *ocds, uint32_t addr, uint32_t size,
                        uint32_t count, void *buffer);
  int (*queue_soc_write)(struct aurix_ocds *ocds, uint32_t addr, uint32_t size,
                         uint32_t count, const void *buffer);
  int (*run)(struct aurix_ocds *ocds);
};

struct aurix_ocds *aurix_ocds_by_jim_obj(Jim_Interp *interp, Jim_Obj *o);
int ocds_register_commands(struct command_context *cmd_ctx);

static inline int aurix_ocds_get(struct aurix_ocds *ocds) {
  return atomic_exchange(&ocds->used, 1) ? ERROR_FAIL : ERROR_OK;
}

static inline void aurix_ocds_put(struct aurix_ocds *ocds) {
  atomic_store(&ocds->used, 0);
}

static inline int aurix_ocds_queue_soc_read(struct aurix_ocds *ocds,
                                            uint32_t addr, uint32_t size,
                                            uint32_t count, void *data) {
  assert(ocds->ops);
  if (!ocds->used) {
    LOG_ERROR("BUG: refcount OCDS %s used without get", ocds->name);
    if (atomic_exchange(&ocds->used, 1)) {
      return ERROR_FAIL;
    }
  }
  return ocds->ops->queue_soc_read(ocds, addr, size, count, data);
}

static inline int aurix_ocds_queue_soc_read_u8(struct aurix_ocds *ocds,
                                               uint32_t addr, uint8_t *data) {
  return aurix_ocds_queue_soc_read(ocds, addr, 1, 1, data);
}
static inline int aurix_ocds_queue_soc_read_u16(struct aurix_ocds *ocds,
                                                uint32_t addr, uint16_t *data) {
  return aurix_ocds_queue_soc_read(ocds, addr, 2, 1, data);
}
static inline int aurix_ocds_queue_soc_read_u32(struct aurix_ocds *ocds,
                                                uint32_t addr, uint32_t *data) {
  return aurix_ocds_queue_soc_read(ocds, addr, 4, 1, data);
}

static inline int aurix_ocds_queue_soc_write(struct aurix_ocds *ocds,
                                             uint32_t addr, uint32_t size,
                                             uint32_t count, const void *data) {
  assert(ocds->ops);
  if (!ocds->used) {
    LOG_ERROR("BUG: refcount OCDS %s used without get", ocds->name);
    if (atomic_exchange(&ocds->used, 1)) {
      return ERROR_FAIL;
    }
  }
  return ocds->ops->queue_soc_write(ocds, addr, size, count, data);
}
static inline int aurix_ocds_queue_soc_write_u8(struct aurix_ocds *ocds,
                                                uint32_t addr, uint8_t data) {
  return aurix_ocds_queue_soc_write(ocds, addr, 1, 1, &data);
}
static inline int aurix_ocds_queue_soc_write_u16(struct aurix_ocds *ocds,
                                                 uint32_t addr, uint16_t data) {
  return aurix_ocds_queue_soc_write(ocds, addr, 2, 1, &data);
}
static inline int aurix_ocds_queue_soc_write_u32(struct aurix_ocds *ocds,
                                                 uint32_t addr, uint32_t data) {
  return aurix_ocds_queue_soc_write(ocds, addr, 4, 1, &data);
}

static inline int aurix_ocds_run(struct aurix_ocds *ocds) {
  assert(ocds->ops);
  if (!ocds->used) {
    LOG_ERROR("BUG: refcount OCDS %s used without get", ocds->name);
    if (atomic_exchange(&ocds->used, 1)) {
      return ERROR_FAIL;
    }
  }
  return ocds->ops->run(ocds);
}

#endif