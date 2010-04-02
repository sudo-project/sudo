/* public domain */

#ifdef SIGHUP
    if (my_sys_siglist[SIGHUP] == NULL)
	my_sys_siglist[SIGHUP] = "Hangup";
#endif
#ifdef SIGINT
    if (my_sys_siglist[SIGINT] == NULL)
	my_sys_siglist[SIGINT] = "Interrupt";
#endif
#ifdef SIGQUIT
    if (my_sys_siglist[SIGQUIT] == NULL)
	my_sys_siglist[SIGQUIT] = "Quit";
#endif
#ifdef SIGILL
    if (my_sys_siglist[SIGILL] == NULL)
	my_sys_siglist[SIGILL] = "Illegal instruction";
#endif
#ifdef SIGTRAP
    if (my_sys_siglist[SIGTRAP] == NULL)
	my_sys_siglist[SIGTRAP] = "Trace trap";
#endif
#ifdef SIGABRT
    if (my_sys_siglist[SIGABRT] == NULL)
	my_sys_siglist[SIGABRT] = "Abort";
#endif
#ifdef SIGIOT
    if (my_sys_siglist[SIGIOT] == NULL)
	my_sys_siglist[SIGIOT] = "IOT instruction";
#endif
#ifdef SIGEMT
    if (my_sys_siglist[SIGEMT] == NULL)
	my_sys_siglist[SIGEMT] = "EMT trap";
#endif
#ifdef SIGFPE
    if (my_sys_siglist[SIGFPE] == NULL)
	my_sys_siglist[SIGFPE] = "Floating point exception";
#endif
#ifdef SIGKILL
    if (my_sys_siglist[SIGKILL] == NULL)
	my_sys_siglist[SIGKILL] = "Killed";
#endif
#ifdef SIGUNUSED
    if (my_sys_siglist[SIGUNUSED] == NULL)
	my_sys_siglist[SIGUNUSED] = "Unused";
#endif
#ifdef SIGBUS
    if (my_sys_siglist[SIGBUS] == NULL)
	my_sys_siglist[SIGBUS] = "Bus error";
#endif
#ifdef SIGSEGV
    if (my_sys_siglist[SIGSEGV] == NULL)
	my_sys_siglist[SIGSEGV] = "Memory fault";
#endif
#ifdef SIGSYS
    if (my_sys_siglist[SIGSYS] == NULL)
	my_sys_siglist[SIGSYS] = "Bad system call";
#endif
#ifdef SIGPIPE
    if (my_sys_siglist[SIGPIPE] == NULL)
	my_sys_siglist[SIGPIPE] = "Broken pipe";
#endif
#ifdef SIGALRM
    if (my_sys_siglist[SIGALRM] == NULL)
	my_sys_siglist[SIGALRM] = "Alarm clock";
#endif
#ifdef SIGTERM
    if (my_sys_siglist[SIGTERM] == NULL)
	my_sys_siglist[SIGTERM] = "Terminated";
#endif
#ifdef SIGSTKFLT
    if (my_sys_siglist[SIGSTKFLT] == NULL)
	my_sys_siglist[SIGSTKFLT] = "Stack fault";
#endif
#ifdef SIGIO
    if (my_sys_siglist[SIGIO] == NULL)
	my_sys_siglist[SIGIO] = "I/O possible";
#endif
#ifdef SIGXCPU
    if (my_sys_siglist[SIGXCPU] == NULL)
	my_sys_siglist[SIGXCPU] = "CPU time limit exceeded";
#endif
#ifdef SIGXFSZ
    if (my_sys_siglist[SIGXFSZ] == NULL)
	my_sys_siglist[SIGXFSZ] = "File size limit exceeded";
#endif
#ifdef SIGVTALRM
    if (my_sys_siglist[SIGVTALRM] == NULL)
	my_sys_siglist[SIGVTALRM] = "Virtual timer expired";
#endif
#ifdef SIGPROF
    if (my_sys_siglist[SIGPROF] == NULL)
	my_sys_siglist[SIGPROF] = "Profiling timer expired";
#endif
#ifdef SIGWINCH
    if (my_sys_siglist[SIGWINCH] == NULL)
	my_sys_siglist[SIGWINCH] = "Window size change";
#endif
#ifdef SIGLOST
    if (my_sys_siglist[SIGLOST] == NULL)
	my_sys_siglist[SIGLOST] = "File lock lost";
#endif
#ifdef SIGUSR1
    if (my_sys_siglist[SIGUSR1] == NULL)
	my_sys_siglist[SIGUSR1] = "User defined signal 1";
#endif
#ifdef SIGUSR2
    if (my_sys_siglist[SIGUSR2] == NULL)
	my_sys_siglist[SIGUSR2] = "User defined signal 2";
#endif
#ifdef SIGPWR
    if (my_sys_siglist[SIGPWR] == NULL)
	my_sys_siglist[SIGPWR] = "Power-fail/Restart";
#endif
#ifdef SIGPOLL
    if (my_sys_siglist[SIGPOLL] == NULL)
	my_sys_siglist[SIGPOLL] = "Pollable event occurred";
#endif
#ifdef SIGSTOP
    if (my_sys_siglist[SIGSTOP] == NULL)
	my_sys_siglist[SIGSTOP] = "Stopped (signal)";
#endif
#ifdef SIGTSTP
    if (my_sys_siglist[SIGTSTP] == NULL)
	my_sys_siglist[SIGTSTP] = "Stopped";
#endif
#ifdef SIGCONT
    if (my_sys_siglist[SIGCONT] == NULL)
	my_sys_siglist[SIGCONT] = "Continued";
#endif
#ifdef SIGCHLD
    if (my_sys_siglist[SIGCHLD] == NULL)
	my_sys_siglist[SIGCHLD] = "Child exited";
#endif
#ifdef SIGCLD
    if (my_sys_siglist[SIGCLD] == NULL)
	my_sys_siglist[SIGCLD] = "Child exited";
#endif
#ifdef SIGTTIN
    if (my_sys_siglist[SIGTTIN] == NULL)
	my_sys_siglist[SIGTTIN] = "Stopped (tty input)";
#endif
#ifdef SIGTTOU
    if (my_sys_siglist[SIGTTOU] == NULL)
	my_sys_siglist[SIGTTOU] = "Stopped (tty output)";
#endif
#ifdef SIGINFO
    if (my_sys_siglist[SIGINFO] == NULL)
	my_sys_siglist[SIGINFO] = "Information request";
#endif
#ifdef SIGURG
    if (my_sys_siglist[SIGURG] == NULL)
	my_sys_siglist[SIGURG] = "Urgent I/O condition";
#endif
#ifdef SIGWAITING
    if (my_sys_siglist[SIGWAITING] == NULL)
	my_sys_siglist[SIGWAITING] = "No runnable LWPs";
#endif
#ifdef SIGLWP
    if (my_sys_siglist[SIGLWP] == NULL)
	my_sys_siglist[SIGLWP] = "Inter-LWP signal";
#endif
#ifdef SIGFREEZE
    if (my_sys_siglist[SIGFREEZE] == NULL)
	my_sys_siglist[SIGFREEZE] = "Checkpoint freeze";
#endif
#ifdef SIGTHAW
    if (my_sys_siglist[SIGTHAW] == NULL)
	my_sys_siglist[SIGTHAW] = "Checkpoint thaw";
#endif
#ifdef SIGCANCEL
    if (my_sys_siglist[SIGCANCEL] == NULL)
	my_sys_siglist[SIGCANCEL] = "Thread cancellation";
#endif
