/* public domain */

my_sys_signame[0] = "Signal 0";
#ifdef SIGHUP
    if (my_sys_signame[SIGHUP] == NULL)
	my_sys_signame[SIGHUP] = "HUP";
#endif
#ifdef SIGINT
    if (my_sys_signame[SIGINT] == NULL)
	my_sys_signame[SIGINT] = "INT";
#endif
#ifdef SIGQUIT
    if (my_sys_signame[SIGQUIT] == NULL)
	my_sys_signame[SIGQUIT] = "QUIT";
#endif
#ifdef SIGILL
    if (my_sys_signame[SIGILL] == NULL)
	my_sys_signame[SIGILL] = "ILL";
#endif
#ifdef SIGTRAP
    if (my_sys_signame[SIGTRAP] == NULL)
	my_sys_signame[SIGTRAP] = "TRAP";
#endif
#ifdef SIGABRT
    if (my_sys_signame[SIGABRT] == NULL)
	my_sys_signame[SIGABRT] = "ABRT";
#endif
#ifdef SIGIOT
    if (my_sys_signame[SIGIOT] == NULL)
	my_sys_signame[SIGIOT] = "IOT";
#endif
#ifdef SIGEMT
    if (my_sys_signame[SIGEMT] == NULL)
	my_sys_signame[SIGEMT] = "EMT";
#endif
#ifdef SIGFPE
    if (my_sys_signame[SIGFPE] == NULL)
	my_sys_signame[SIGFPE] = "FPE";
#endif
#ifdef SIGKILL
    if (my_sys_signame[SIGKILL] == NULL)
	my_sys_signame[SIGKILL] = "KILL";
#endif
#ifdef SIGUNUSED
    if (my_sys_signame[SIGUNUSED] == NULL)
	my_sys_signame[SIGUNUSED] = "UNUSED";
#endif
#ifdef SIGBUS
    if (my_sys_signame[SIGBUS] == NULL)
	my_sys_signame[SIGBUS] = "BUS";
#endif
#ifdef SIGSEGV
    if (my_sys_signame[SIGSEGV] == NULL)
	my_sys_signame[SIGSEGV] = "SEGV";
#endif
#ifdef SIGSYS
    if (my_sys_signame[SIGSYS] == NULL)
	my_sys_signame[SIGSYS] = "SYS";
#endif
#ifdef SIGPIPE
    if (my_sys_signame[SIGPIPE] == NULL)
	my_sys_signame[SIGPIPE] = "PIPE";
#endif
#ifdef SIGALRM
    if (my_sys_signame[SIGALRM] == NULL)
	my_sys_signame[SIGALRM] = "ALRM";
#endif
#ifdef SIGTERM
    if (my_sys_signame[SIGTERM] == NULL)
	my_sys_signame[SIGTERM] = "TERM";
#endif
#ifdef SIGSTKFLT
    if (my_sys_signame[SIGSTKFLT] == NULL)
	my_sys_signame[SIGSTKFLT] = "STKFLT";
#endif
#ifdef SIGIO
    if (my_sys_signame[SIGIO] == NULL)
	my_sys_signame[SIGIO] = "IO";
#endif
#ifdef SIGXCPU
    if (my_sys_signame[SIGXCPU] == NULL)
	my_sys_signame[SIGXCPU] = "XCPU";
#endif
#ifdef SIGXFSZ
    if (my_sys_signame[SIGXFSZ] == NULL)
	my_sys_signame[SIGXFSZ] = "XFSZ";
#endif
#ifdef SIGVTALRM
    if (my_sys_signame[SIGVTALRM] == NULL)
	my_sys_signame[SIGVTALRM] = "VTALRM";
#endif
#ifdef SIGPROF
    if (my_sys_signame[SIGPROF] == NULL)
	my_sys_signame[SIGPROF] = "PROF";
#endif
#ifdef SIGWINCH
    if (my_sys_signame[SIGWINCH] == NULL)
	my_sys_signame[SIGWINCH] = "WINCH";
#endif
#ifdef SIGLOST
    if (my_sys_signame[SIGLOST] == NULL)
	my_sys_signame[SIGLOST] = "LOST";
#endif
#ifdef SIGUSR1
    if (my_sys_signame[SIGUSR1] == NULL)
	my_sys_signame[SIGUSR1] = "USR1";
#endif
#ifdef SIGUSR2
    if (my_sys_signame[SIGUSR2] == NULL)
	my_sys_signame[SIGUSR2] = "USR2";
#endif
#ifdef SIGPWR
    if (my_sys_signame[SIGPWR] == NULL)
	my_sys_signame[SIGPWR] = "PWR";
#endif
#ifdef SIGPOLL
    if (my_sys_signame[SIGPOLL] == NULL)
	my_sys_signame[SIGPOLL] = "POLL";
#endif
#ifdef SIGSTOP
    if (my_sys_signame[SIGSTOP] == NULL)
	my_sys_signame[SIGSTOP] = "STOP";
#endif
#ifdef SIGTSTP
    if (my_sys_signame[SIGTSTP] == NULL)
	my_sys_signame[SIGTSTP] = "TSTP";
#endif
#ifdef SIGCONT
    if (my_sys_signame[SIGCONT] == NULL)
	my_sys_signame[SIGCONT] = "CONT";
#endif
#ifdef SIGCHLD
    if (my_sys_signame[SIGCHLD] == NULL)
	my_sys_signame[SIGCHLD] = "CHLD";
#endif
#ifdef SIGCLD
    if (my_sys_signame[SIGCLD] == NULL)
	my_sys_signame[SIGCLD] = "CLD";
#endif
#ifdef SIGTTIN
    if (my_sys_signame[SIGTTIN] == NULL)
	my_sys_signame[SIGTTIN] = "TTIN";
#endif
#ifdef SIGTTOU
    if (my_sys_signame[SIGTTOU] == NULL)
	my_sys_signame[SIGTTOU] = "TTOU";
#endif
#ifdef SIGINFO
    if (my_sys_signame[SIGINFO] == NULL)
	my_sys_signame[SIGINFO] = "INFO";
#endif
#ifdef SIGURG
    if (my_sys_signame[SIGURG] == NULL)
	my_sys_signame[SIGURG] = "URG";
#endif
#ifdef SIGWAITING
    if (my_sys_signame[SIGWAITING] == NULL)
	my_sys_signame[SIGWAITING] = "WAITING";
#endif
#ifdef SIGLWP
    if (my_sys_signame[SIGLWP] == NULL)
	my_sys_signame[SIGLWP] = "LWP";
#endif
#ifdef SIGFREEZE
    if (my_sys_signame[SIGFREEZE] == NULL)
	my_sys_signame[SIGFREEZE] = "FREEZE";
#endif
#ifdef SIGTHAW
    if (my_sys_signame[SIGTHAW] == NULL)
	my_sys_signame[SIGTHAW] = "THAW";
#endif
#ifdef SIGCANCEL
    if (my_sys_signame[SIGCANCEL] == NULL)
	my_sys_signame[SIGCANCEL] = "CANCEL";
#endif
