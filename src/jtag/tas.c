#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <transport/transport.h>
#include <jtag/interface.h>

static const struct command_registration tas_transport_subcommand_handlers[] = {
	{
		.name = "newtap",
		.handler = handle_jtag_newtap,
		.mode = COMMAND_CONFIG,
		.help = "declare a new TAP",
		.usage = "basename tap_type '-irlen' count "
			"['-enable'|'-disable'] "
			"['-expected_id' number] "
			"['-ignore-version'] "
			"['-ignore-bypass'] "
			"['-ircapture' number] "
			"['-ir-bypass' number] "
			"['-mask' number]",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration tas_transport_command_handlers[] = {
	{
		.name = "tas",
		.mode = COMMAND_ANY,
		.help = "perform tas adapter actions",
		.usage = "",
		.chain = tas_transport_subcommand_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

static int tas_transport_select(struct command_context *cmd_ctx)
{
	LOG_DEBUG(__func__);

	return register_commands(cmd_ctx, NULL, tas_transport_command_handlers);
}

static int tas_transport_init(struct command_context *cmd_ctx)
{
	return ERROR_OK;
}

static struct transport tas_transport = {
	.name = "tas",
	.select = tas_transport_select,
	.init = tas_transport_init,
};

static void tas_constructor(void) __attribute__ ((constructor));
static void tas_constructor(void)
{
	transport_register(&tas_transport);
}

bool transport_is_tas(void)
{
	return get_current_transport() == &tas_transport;
}
