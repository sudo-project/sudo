%set
	if test -n "$SUDO_FLAVOR"; then
		name="sudo-$SUDO_FLAVOR"
	else
		name="sudo"
	fi
	summary="Provide limited super-user priveleges to specific users"
	description="Sudo is a program designed to allow a sysadmin to give \
limited root privileges to users and log root activity.  \
The basic philosophy is to give as few privileges as possible but \
still allow people to get their work done."
	vendor="Todd C. Miller"
	copyright="(c) 1993-1996,1998-2010 Todd C. Miller"
	pp_rpm_release="1"
	pp_rpm_license="BSD"
	pp_rpm_url="http://www.sudo.ws/"
	pp_rpm_group="Applications/System"
	pp_rpm_packager="Todd.Miller@courtesan.com"
	pp_deb_maintainer="Todd.Miller@courtesan.com"
	pp_sd_vendor_tag="TCM"
	pp_solaris_name="TCMsudo"

%set [rpm]
	# Add distro info to release
	case "$pp_rpm_distro" in
	centos*|rhel*)
		d=`echo "$pp_rpm_distro" | sed -e 's/^[^0-9]*//' -e 's/[^0-9].*$//'`
		if test -n "$d"; then
		    pp_rpm_release="$pp_rpm_release.el$d"
		fi
		;;
	sles*)
		d=`echo "$pp_rpm_distro" | sed -e 's/^[^0-9]*//' -e 's/[^0-9].*$//'`
		if test -n "$d"; then
		    pp_rpm_release="$pp_rpm_release.sles$d"
		fi
		;;
	esac

	# Uncomment some Defaults in sudoers.dist
	# Note that the order must match that of sudoers.
	case "$pp_rpm_distro" in
	centos*|rhel*)
		# Uncomment some Defaults in sudoers.dist, must be tab indented.
		# Note that the order must match that of sudoers.
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers.dist <<-'EOF'
		/Locale settings/+1,s/^# //
		/Desktop path settings/+1,s/^# //
		w
		q
		EOF
		;;
	sles*)
		# Uncomment some Defaults in sudoers.dist, must be tab indented.
		# Note that the order must match that of sudoers.
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers.dist <<-'EOF'
		/Locale settings/+1,s/^# //
		/ConsoleKit session/+1,s/^# //
		w
		q
		EOF
		;;
	esac

	# For RedHat the doc dir is expected to include version and release
	case "$pp_rpm_distro" in
	centos*|rhel*)
		mv ${pp_destdir}/${docdir} ${pp_destdir}/${docdir}-${version}-1
		docdir=${docdir}-${version}-1
		;;
	esac

	# Choose the correct PAM file by distro, must be tab indented for "<<-"
	case "$pp_rpm_distro" in
	centos[0-4].*|rhel[0-4].*)
		mkdir -p ${pp_destdir}/etc/pam.d
		cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
		#%PAM-1.0
		auth       required	pam_stack.so service=system-auth
		account    required	pam_stack.so service=system-auth
		password   required	pam_stack.so service=system-auth
		session    required	pam_limits.so
		EOF
		;;
	centos*|rhel*)
		mkdir -p ${pp_destdir}/etc/pam.d
		cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
		#%PAM-1.0
		auth       include	system-auth
		account    include	system-auth
		password   include	system-auth
		session    optional	pam_keyinit.so revoke
		session    required	pam_limits.so
		EOF
		cat > ${pp_destdir}/etc/pam.d/sudo-i <<-EOF
		#%PAM-1.0
		auth       include	sudo
		account    include	sudo
		password   include	sudo
		session    optional	pam_keyinit.so force revoke
		session    required	pam_limits.so
		EOF
		;;
	  sles9.*)
		mkdir -p ${pp_destdir}/etc/pam.d
		cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
		#%PAM-1.0
		auth     required       pam_unix2.so
		session  required       pam_limits.so
		EOF
		;;
	  sles*)
		mkdir -p ${pp_destdir}/etc/pam.d
		cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
		#%PAM-1.0
		auth     include	common-auth
		account  include	common-account
		password include	common-password
		session  include	common-session
		# session  optional	pam_xauth.so
		EOF
		;;
	esac

%set [deb]
	# Uncomment some Defaults and the %sudo rule in sudoers.dist
	# Note that the order must match that of sudoers and be tab-indented.
	/bin/ed - ${pp_destdir}${sudoersdir}/sudoers.dist <<-'EOF'
	/Locale settings/+1,s/^# //
	/X11 resource/+1,s/^# //
	/^# \%sudo/,s/^# //
	w
	q
	EOF
	mkdir -p ${pp_destdir}/etc/pam.d
	cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
	#%PAM-1.0

	@include common-auth
	@include common-account

	session required pam_permit.so
	session required pam_limits.so
	EOF

%set [aix]
	pp_aix_version=`echo $version | sed -e 's,\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)p\([0-9][0-9]*\)q\([0-9][0-9]*\),\1.\2.\3.\4,'`
	summary="Configurable super-user privileges"

%files
	$bindir/sudo        4111 root:
	$bindir/sudoedit    4111 root:
	$sbindir/visudo     0111
	$bindir/sudoreplay  0111
	$includedir/sudo_plugin.h
	$libexecdir/*
	$sudoersdir/sudoers.dist $sudoers_mode $sudoers_uid:$sudoers_gid volatile
	$sudoersdir/sudoers.d/	0750 $sudoers_uid:$sudoers_gid
	$timedir/		0700 root:
	$docdir/
	$docdir/*
	/etc/pam.d/*		volatile,optional

%files [!aix]
	$mandir/man*/*

%files [aix]
	# Some versions use catpages, some use manpages.
	$mandir/cat*/* optional
	$mandir/man*/* optional

%post
	# Don't overwrite an existing sudoers file
	sudoersdir=%{sudoersdir}
	if test ! -r $sudoersdir/sudoers; then
		cp -p $sudoersdir/sudoers.dist $sudoersdir/sudoers
	fi

%post [deb]
	# dpkg-deb does not maintain the mode on the sudoers file, and
	# installs it 0640 when sudo requires 0440
	chmod %{sudoers_mode} %{sudoersdir}/sudoers

	# create symlink to ease transition to new path for ldap config
	# if old config file exists and new one doesn't
	if test X"%{SUDO_FLAVOR}" = X"ldap" -a \
	    -r /etc/ldap/ldap.conf -a ! -r /etc/sudo-ldap.conf; then
		ln -s /etc/ldap/ldap.conf /etc/sudo-ldap.conf
	fi

	# Debian uses a sudo group in its default sudoers file
	perl -e '
		exit 0 if getgrnam("sudo");
		$gid = 27; # default debian sudo gid
		setgrent();
		while (getgrgid($gid)) { $gid++; }
		if ($gid != 27) {
			print "On Debian we normally use gid 27 for \"sudo\".\n";
			$gname = getgrgid(27);
			print "However, on your system gid 27 is group \"$gname\".\n\n";
			print "Would you like me to stop configuring sudo so that you can change this? [n] "; 
			$ans = <STDIN>;
			if ($ans =~ /^[yY]/) {
				print "\"dpkg --pending --configure\" will restart the configuration.\n\n";
				exit 1;
			}
		}
		print "Creating group \"sudo\" with gid = $gid\n";
		system("groupadd -g $gid sudo");
		exit 0;
	'

%preun [deb]
	# Remove the /etc/ldap/ldap.conf -> /etc/sudo-ldap.conf symlink if
	# it matches what we created in the postinstall script.
	if test X"%{SUDO_FLAVOR}" = X"ldap" -a \
	    X"`readlink /etc/sudo-ldap.conf 2>/dev/null`" = X"/etc/ldap/ldap.conf"; then
		rm -f /etc/sudo-ldap.conf
	fi
