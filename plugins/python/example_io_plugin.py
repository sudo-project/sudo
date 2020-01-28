import sudo

from os import path
import errno
import signal
import sys
import json
from typing import Tuple, Dict


VERSION = 1.0


class SudoIOPlugin(sudo.Plugin):
    """Example sudo input/output plugin

    Demonstrates how to use the sudo IO plugin API. All functions are added as
    an example on their syntax, but note that all of them are optional. Also
    typing annotations are just here for the help on the syntax (requires
    python >= 3.5).

    On detailed description of the functions refer to sudo_plugin manual (man
    sudo_plugin).

    Most functions can express error or reject through their "int" return value
    as documented in the manual. The sudo module also has constants for these:
        sudo.RC_ACCEPT / sudo.RC_OK  1
        sudo.RC_REJECT               0
        sudo.RC_ERROR               -1
        sudo.RC_USAGE_ERROR         -2

    If the function returns "None" (for example does not call return), it will
    be considered sudo.RC_OK. If an exception is raised, its backtrace will be
    shown to the user and the plugin function returns sudo.RC_ERROR. If that is
    not acceptable, catch it.
    """

    # -- Plugin API functions --

    def __init__(self, version: str, plugin_options: Tuple[str, ...], **kwargs):
        """The constructor of the IO plugin.

        Other variables you can currently use as arguments are:
            user_env: Tuple[str, ...]
            settings: Tuple[str, ...]
            user_info: Tuple[str, ...]

        For their detailed description, see the open() call of the C plugin API
        in the sudo manual ("man sudo").
        """
        if not version.startswith("1."):
            raise sudo.SudoException(
                "This plugin plugin is not compatible with python plugin"
                "API version {}".format(version))

        # convert tuple of "key=value"s to dict
        plugin_options = sudo.options_as_dict(plugin_options)

        log_path = plugin_options.get("LogPath", "/tmp")
        self._open_log_file(path.join(log_path, "sudo.log"))
        self._log("", "-- Plugin STARTED --")

    def __del__(self):
        if hasattr(self, "_log_file"):
            self._log("", "-- Plugin DESTROYED --")
            self._log_file.close()

    def open(self, argv: Tuple[str, ...], command_info: Tuple[str, ...]) -> int:
        """Receives the command the user wishes to run.

        This function works the same as open() call of the C IO plugin API (see
        sudo manual), except that:
         - It only gets called before the user would execute some command (and
           not for a version query for example).
         - Other arguments of the C open() call are received through the
           constructor.
        """
        self._log("EXEC", " ".join(argv))
        self._log("EXEC info", json.dumps(command_info, indent=4))

        return sudo.RC_ACCEPT

    def log_ttyout(self, buf: str) -> int:
        return self._log("TTY OUT", buf.strip())

    def log_ttyin(self, buf: str) -> int:
        return self._log("TTY IN", buf.strip())

    def log_stdin(self, buf: str) -> int:
        return self._log("STD IN", buf.strip())

    def log_stdout(self, buf: str) -> int:
        return self._log("STD OUT", buf.strip())

    def log_stderr(self, buf: str) -> int:
        return self._log("STD ERR", buf.strip())

    def change_winsize(self, line: int, cols: int) -> int:
        self._log("WINSIZE", "{}x{}".format(line, cols))

    def log_suspend(self, signo: int) -> int:
        try:
            signal_description = signal.Signals(signo).name
        except (AttributeError, ValueError):
            signal_description = "signal {}".format(signo)

        self._log("SUSPEND", signal_description)

    def show_version(self, is_verbose: int) -> int:
        sudo.log_info("Python Example IO Plugin version: {}".format(VERSION))
        if is_verbose:
            sudo.log_info("Python interpreter version:", sys.version)

    def close(self, exit_status: int, error: int) -> None:
        """Called when a command execution finished.

        Works the same as close() from C API (see sudo_plugin manual), except
        that it only gets called if there was a command execution trial (open()
        returned with sudo.RC_ACCEPT).
        """
        if error == 0:
            self._log("CLOSE", "Command returned {}".format(exit_status))
        else:
            error_name = errno.errorcode.get(error, "???")
            self._log("CLOSE", "Failed to execute, execve returned {} ({})"
                               .format(error, error_name))

    # -- Helper functions --

    def _open_log_file(self, log_path):
        sudo.log_info("Example sudo python plugin will log to", log_path)
        self._log_file = open(log_path, "a")

    def _log(self, type, message):
        print(type, message, file=self._log_file)
        return sudo.RC_ACCEPT
