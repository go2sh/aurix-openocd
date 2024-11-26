#include <stdio.h>
#include <string.h>

#include <helper/command.h>
#include <helper/list.h>

#include "aurix_ocds.h"
#include "helper/jim-nvp.h"
#include "jim.h"
#include <jtag/adapter.h>
#include "jtag/interface.h"
#include "jtag/tas.h"
#include "transport/transport.h"

static LIST_HEAD(all_ocds);

extern struct adapter_driver *adapter_driver;

/**
 * Synchronous read of a word from memory or a system register.
 * As a side effect, this flushes any queued transactions.
 *
 * @param ap The MEM-AP to access.
 * @param address Address of the 32-bit word to read; it must be
 *	readable by the currently selected MEM-AP.
 * @param value points to where the result will be stored.
 *
 * @return ERROR_OK for success; *value holds the result.
 * Otherwise a fault code.
 */
int aurix_ocds_atomic_read_u32(struct aurix_ocds *ocds, target_addr_t address,
		uint32_t *value)
{
	int retval;

	retval = aurix_ocds_queue_soc_read_u32(ocds, address, value);
	if (retval != ERROR_OK)
		return retval;

	return aurix_ocds_run(ocds);
}


struct aurix_ocds *aurix_ocds_by_jim_obj(Jim_Interp *interp, Jim_Obj *o) {
  struct aurix_ocds *ocds;
  const char *name = Jim_GetString(o, NULL);

  list_for_each_entry(ocds, &all_ocds, lh) {
    if (strcmp(name, ocds->name) == 0) {
      return ocds;
    }
  }

  return NULL;
}

enum dap_cfg_param {
  CFG_CHAIN_POSITION,
};

static const struct jim_nvp nvp_config_opts[] = {
    {.name = "-chain-position", .value = CFG_CHAIN_POSITION},
    {.name = NULL, .value = -1}};

static int aurix_ocds_configure(struct jim_getopt_info *goi,
                                struct aurix_ocds *ocds) {
  struct jim_nvp *n;
  int e;
  const char *name;

  jim_getopt_string(goi, &name, NULL);
  ocds->name = strdup(name);

  /* parse config ... */
  while (goi->argc > 0) {
    Jim_SetEmptyResult(goi->interp);

    e = jim_getopt_nvp(goi, nvp_config_opts, &n);
    if (e != JIM_OK) {
      jim_getopt_nvp_unknown(goi, nvp_config_opts, 0);
      return e;
    }
    switch (n->value) {
    case CFG_CHAIN_POSITION: {
      Jim_Obj *o_t;
      e = jim_getopt_obj(goi, &o_t);
      if (e != JIM_OK)
        return e;

      struct jtag_tap *tap;
      tap = jtag_tap_by_jim_obj(goi->interp, o_t);
      if (!tap) {
        Jim_SetResultString(goi->interp, "-chain-position is invalid", -1);
        return JIM_ERR;
      }
      ocds->tap = tap;
      /* loop for more */
      break;
    }
    default:
      break;
    }
  }

  return JIM_OK;
}

static int aurix_ocds_create(Jim_Interp *interp, int argc,
                             Jim_Obj *const *argv) {
  struct jim_getopt_info goi;
  jim_getopt_setup(&goi, interp, argc - 1, argv + 1);
  if (goi.argc < 2) {
    Jim_WrongNumArgs(goi.interp, goi.argc, goi.argv,
                     "<name> [<ocds_options> ...]");
    return JIM_ERR;
  }
  struct aurix_ocds *ocds = calloc(1, sizeof(struct aurix_ocds));
  if (!ocds) {
    return JIM_ERR;
  }

  aurix_ocds_configure(&goi, ocds);

  list_add_tail(&ocds->lh, &all_ocds);

  return 0;
}

COMMAND_HANDLER(aurix_ocds_init) {
  struct aurix_ocds *ocds;

  list_for_each_entry(ocds, &all_ocds, lh) {
    /* skip taps that are disabled */
    if (!ocds->tap->enabled)
      continue;

    if (transport_is_tas()) {
      ocds->ops = adapter_driver->tas_ops;
      int err = ocds->ops->connect(ocds);
      if (err) {
        return err;
      }
    }
  }

  return JIM_OK;
}

static const struct command_registration ocds_subcommand_handlers[] = {
    {
        .name = "init",
        .mode = COMMAND_ANY,
        .handler = aurix_ocds_init,
        .usage = "",
        .help = "Initialize all OCDS systems",
    },
    {
        .name = "create",
        .mode = COMMAND_ANY,
        .jim_handler = aurix_ocds_create,
        .usage = "name '-chain-position' name",
        .help = "Creates a new DAP instance",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration ocds_commands[] = {
    {
        .name = "ocds",
        .mode = COMMAND_CONFIG,
        .help = "OCDS commands",
        .chain = ocds_subcommand_handlers,
        .usage = "",
    },
    COMMAND_REGISTRATION_DONE};

int ocds_register_commands(struct command_context *cmd_ctx) {
  return register_commands(cmd_ctx, NULL, ocds_commands);
}