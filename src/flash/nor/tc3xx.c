#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "target/aurix/aurix.h"
#include "target/aurix/aurix_ocds.h"
#include <flash/common.h>
#include <flash/nor/core.h>
#include <flash/nor/driver.h>
#include <helper/log.h>
#include <target/target.h>

struct tc3xx_flash_bank {
  bool probed;
};

#define SCU_CHIPID 0xF0036140
#define SCU_CHIPID_CHREV 0x3F
#define SCU_CHIPID_CHTEC 0xC0
#define SCU_CHIPID_FSIZE 0x0F000000

static int tc3xx_probe(struct flash_bank *bank) {
  struct tc3xx_flash_bank *tc3xx_bank = bank->driver_priv;
  uint32_t flash_addr = bank->base;
  uint32_t chipid;
  int retval;

  if (tc3xx_bank->probed)
    return ERROR_OK;

  retval = target_read_u32(bank->target, SCU_CHIPID, &chipid);
  if (retval != ERROR_OK) {
    LOG_ERROR("Cannot read CHIPID register.");
    return retval;
  }

  if ((chipid & SCU_CHIPID_CHTEC) != 0x80) {
    LOG_ERROR("CHIPID register does not match tc3xx.");
    return ERROR_FAIL;
  }

  LOG_DEBUG("IDCHIP = %08" PRIx32, chipid);

  /* TODO: Check size / DFLASH / UCB */

  bank->num_sectors = bank->size / 16 / 1024;
  bank->sectors = calloc(bank->num_sectors, sizeof(struct flash_sector));
  for (unsigned int i = 0; i < bank->num_sectors; i++) {
    bank->sectors[i].size = 0x4000;
    bank->sectors[i].offset = flash_addr - bank->base;
    flash_addr += 0x4000;
    /* TOOD: Check erased */
    bank->sectors[i].is_erased = -1;
    /* TODO: Check UCB for protection*/
    bank->sectors[i].is_protected = -1;
  }

  tc3xx_bank->probed = true;

  return ERROR_OK;
}

static int tc3xx_auto_probe(struct flash_bank *bank) {
  struct tc3xx_flash_bank *tc3xx_bank = bank->driver_priv;

  if (tc3xx_bank->probed)
    return ERROR_OK;

  return tc3xx_probe(bank);
}

int tc3xx_erase(struct flash_bank *bank, unsigned int first,
                unsigned int last) {

  struct aurix_ocds *ocds = target_to_aurix(bank->target)->ocds;
  int err;

  while (first <= last) {
    uint32_t addr = bank->base + bank->sectors[first].offset;
    /* Align sector count to physical sector boundary (64 sectors) */
    uint32_t sector_count = MIN(last - first + 1, 64 - (first % 64));
    first += sector_count;

    err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA50, addr);
    if (err) {
      goto err;
    }
    err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA58, sector_count);
    if (err) {
      goto err;
    }
    err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0x80);
    if (err) {
      goto err;
    }
    err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0x50);
    if (err) {
      goto err;
    }

    err = aurix_ocds_run(ocds);
    if (err) {
      goto err;
    }

    uint32_t flash_err = 0;
    uint32_t flash_busy = 0xFFFFFFFF;
    while (flash_err == 0 && (flash_busy & (1 << (0 + 2)))) {
      err = aurix_ocds_queue_soc_read_u32(ocds, 0xF8040034, &flash_err);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_read_u32(ocds, 0xF8040010, &flash_busy);
      if (err) {
        goto err;
      }
      err = aurix_ocds_run(ocds);
      if (err) {
        goto err;
      }
    }

    if (flash_err) {
      LOG_ERROR("Flash operation failed: %x", flash_err);
      return ERROR_FLASH_OPERATION_FAILED;
    }
  }

  return ERROR_OK;

err:
  LOG_ERROR("Failed to execute flash erase sequence");
  return ERROR_FLASH_OPERATION_FAILED;
}

static int tc3xx_write(struct flash_bank *bank, const uint8_t *buffer,
                       uint32_t offset, uint32_t count) {
  struct aurix_ocds *ocds = target_to_aurix(bank->target)->ocds;
  int err;
  uint32_t page_offset = 0;

  if (offset & 0x1F) {
    return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
  }


  while (page_offset < count) {
    /* Enter page mode*/
    err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF005554, 0x50);
    if (err) {
      goto err;
    }
    
    /* Check for burst sequence*/
    if (count - page_offset >= 256) {
      uint32_t i;
      for (i = 0; i < 256; i += 4) {
        uint32_t data;
        memcpy(&data, buffer + page_offset + i, 4);
        err = aurix_ocds_queue_soc_write_u32(
            ocds, 0xAF0055F0 + ((i % 8) == 0 ? 0 : 4), data);
        if (err) {
          goto err;
        }
      }
      /* Executing Write Burst sequnce */
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA50,
                                           bank->base + offset + page_offset);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA58, 0);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0xA0);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0xA6);
      if (err) {
        goto err;
      }
      page_offset += 256;
    } else {
      uint32_t i;
      for (i = 0; i < 32 && page_offset + i + 3 < count; i += 4) {
        uint32_t data;
        memcpy(&data, buffer + page_offset + i, 4);
        err = aurix_ocds_queue_soc_write_u32(
            ocds, 0xAF0055F0 + ((i % 8) == 0 ? 0 : 4), data);
        if (err) {
          goto err;
        }
      }

      /* Write unaligned data to page */
      if ((count - i - page_offset) < 4) {
        uint32_t data;
        memcpy(&data, buffer + page_offset + i, count - i - page_offset);
        err = aurix_ocds_queue_soc_write_u32(
            ocds, 0xAF0055F0 + ((i % 8) == 0 ? 0 : 4), data);
        if (err) {
          goto err;
        }
        i += 4;
      }
      /* Fill up to page boundary */
      for (; i < 32; i += 4) {
        err = aurix_ocds_queue_soc_write_u32(
            ocds, 0xAF0055F0 + ((i % 8) == 0 ? 0 : 4), 0xFFFFFFFF);
        if (err) {
          goto err;
        }
      }

      /* Execute page write sequence */
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA50,
                                           bank->base + offset + page_offset);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AA58, 0);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0xA0);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_write_u32(ocds, 0xAF00AAA8, 0xAA);
      if (err) {
        goto err;
      }
      page_offset += 32;
    }

    err = aurix_ocds_run(ocds);
    if (err) {
      goto err;
    }

    uint32_t flash_err = 0;
    uint32_t flash_busy = 0xFFFFFFFF;
    while (flash_err == 0 && (flash_busy & (1 << (0 + 2)))) {
      err = aurix_ocds_queue_soc_read_u32(ocds, 0xF8040034, &flash_err);
      if (err) {
        goto err;
      }
      err = aurix_ocds_queue_soc_read_u32(ocds, 0xF8040010, &flash_busy);
      if (err) {
        goto err;
      }
      err = aurix_ocds_run(ocds);
      if (err) {
        goto err;
      }
    }

    if (flash_err) {
      LOG_ERROR("Flash operation failed: %x", flash_err);
      return ERROR_FLASH_OPERATION_FAILED;
    }
  }

  return ERROR_OK;

err:
  LOG_ERROR("Failed to execute flash erase sequence");
  return ERROR_FLASH_OPERATION_FAILED;
}

static int tc3xx_read(struct flash_bank *bank, uint8_t *buffer, uint32_t offset,
                      uint32_t count) {

  return target_read_buffer(bank->target, bank->base + offset, count, buffer);
}

FLASH_BANK_COMMAND_HANDLER(tc3xx_flash_bank_command) {
  struct tc3xx_flash_bank *tc3xx_bank;

  tc3xx_bank = malloc(sizeof(struct tc3xx_flash_bank));
  if (!tc3xx_bank)
    return ERROR_FLASH_OPERATION_FAILED;

  tc3xx_bank->probed = false;

  bank->driver_priv = tc3xx_bank;

  return ERROR_OK;
}

const struct flash_driver tc3xx_flash = {
    .name = "tc3xx",
    .flash_bank_command = tc3xx_flash_bank_command,
    .probe = tc3xx_probe,
    .auto_probe = tc3xx_auto_probe,
    .erase = tc3xx_erase,
    .write = tc3xx_write,
    .read = tc3xx_read,
};