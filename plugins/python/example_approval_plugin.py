import sudo

from datetime import datetime
from typing import Tuple


class BusinessHoursApprovalPlugin(sudo.Plugin):
    def check(self, command_info: Tuple[str, ...], run_argv: Tuple[str, ...],
              run_env: Tuple[str, ...]) -> int:
        error_msg = ""
        now = datetime.now()
        if now.weekday() >= 5:
            error_msg = "That is not allowed on the weekend!"
        if now.hour < 8 or now.hour > 17:
            error_msg = "That is not allowed outside the business hours!"

        if error_msg:
            sudo.log_info(error_msg)
            raise sudo.PluginReject(error_msg)
