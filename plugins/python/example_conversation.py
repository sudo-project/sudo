import sudo
import signal

class ReasonLoggerIOPlugin(sudo.Plugin):
    """
    An example sudo plugin demonstrating how to use the sudo conversation API.

    From the python plugin, you can ask something from the user using the
    "sudo.conv" function. It expects one or more "sudo.ConvMessage" instances
    which specifies how the interaction has to look like.

    sudo.ConvMessage has the following fields (see help(sudo.ConvMessage)):
        msg_type: int  Specifies the type of the conversation.
                       See sudo.CONV_* constants below.
        timeout: int   The maximum amount of time for the conversation in seconds.
                       After the timeout exceeds, the "sudo.conv" function will
                       raise sudo.ConversationInterrupted exception.
        msg: str       The message to display for the user.

    To specify the conversion type you can use the following constants:
        sudo.CONV_PROMPT_ECHO_OFF
        sudo.CONV_PROMPT_ECHO_ON
        sudo.CONV_ERROR_MSG
        sudo.CONV_INFO_MSG
        sudo.CONV_PROMPT_MASK
        sudo.CONV_PROMPT_ECHO_OK
        sudo.CONV_PREFER_TTY
    """
    def open(self, argv, command_info):
        try:
            conv_timeout = 120  # in seconds
            sudo.log_info("Please provide your reason for executing {}".format(argv))

            # We ask two questions, the second is not visible on screen, so the user
            # can hide a hidden message in case of criminals are forcing him for
            # running the command.
            # You can either specify the arguments in strict order (timeout being optional), or use named arguments.
            message1 = sudo.ConvMessage(sudo.CONV_PROMPT_ECHO_ON, "Reason: ", conv_timeout)
            message2 = sudo.ConvMessage(msg="Secret reason: ", timeout=conv_timeout, msg_type=sudo.CONV_PROMPT_MASK)
            reply1, reply2 = sudo.conv(message1, message2,
                                       on_suspend=self.on_conversation_suspend,
                                       on_resume=self.on_conversation_resume)

            with open("/tmp/sudo_reasons.txt", "a") as file:
                print("Executed", ' '.join(argv), file=file)
                print("Reason:", reply1, file=file)
                print("Hidden reason:", reply2, file=file)

        except sudo.ConversationInterrupted:
            sudo.log_error("You did not answer in time")
            return sudo.RC_REJECT

    def on_conversation_suspend(self, signum):
        # This is just an example of how to do something on conversation suspend.
        # You can skip specifying 'on_suspend' argument if there is no need
        sudo.log_info("conversation suspend: signal", self._signal_name(signum))

    def on_conversation_resume(self, signum):
        # This is just an example of how to do something on conversation resume.
        # You can skip specifying 'on_resume' argument if there is no need
        sudo.log_info("conversation resume: signal was", self._signal_name(signum))

    # helper functions:
    @classmethod
    def _signal_name(cls, signum):
        try:
            return "{} ({})".format(signal.Signals(signum).name, signum)
        except Exception:
            return "{}".format(signum)
