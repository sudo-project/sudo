%set
	if test -n "$flavor"; then
		name="sudo-$flavor"
		pp_kit_package="sudo_$flavor"
	else
		name="sudo"
		pp_kit_package="sudo"
	fi
	summary="Provide limited super-user priveleges to specific users"
	description="Sudo is a program designed to allow a sysadmin to give \
limited root privileges to users and log root activity.  \
The basic philosophy is to give as few privileges as possible but \
still allow people to get their work done."
	vendor="Todd C. Miller"
	copyright="(c) 1993-1996,1998-2010 Todd C. Miller"

	# Convert to 4 part version for AIX, including patch level
	pp_aix_version=`echo $version|sed -e 's/\([0-9]*\.[0-9]*\.[0-9]*\)$/\1.0/' -e 's/[^0-9]*\([0-9]*\)$/.\1/'`

	# Strip of patchlevel for kit which only supports x.y.z versions
	pp_kit_version="`echo $version|sed -e 's/\.//g' -e 's/p[0-9]*$//'`"
	pp_kit_name="TCM"

	pp_sd_vendor_tag="TCM"
	pp_solaris_name="TCM${name}"
%if [rpm,deb]
	# Convert patch level into release and remove from version
	pp_rpm_release="`echo $version|sed 's/^[0-9]*\.[0-9]*\.[0-9]*[^0-9]*//'`"
	pp_rpm_release="`expr $pp_rpm_release + 1`"
	pp_rpm_version="`echo $version|sed 's/p[0-9]*$//'`"
	pp_rpm_license="BSD"
	pp_rpm_url="http://www.sudo.ws/"
	pp_rpm_group="Applications/System"
	pp_rpm_packager="Todd.Miller@courtesan.com"

	pp_deb_maintainer="$pp_rpm_packager"
	pp_deb_release="$pp_rpm_release"
	pp_deb_version="$pp_rpm_version"
%else
	# For all but RPM and Debian we need to install sudoers with a different
	# name and make a copy of it if there is no existing file.
	mv ${pp_destdir}$sudoersdir/sudoers ${pp_destdir}$sudoersdir/sudoers.dist
%endif

%set [rpm]
	# Add distro info to release
	osrelease=`echo "$pp_rpm_distro" | sed -e 's/^[^0-9]*//' -e 's/-.*$//'`
	case "$pp_rpm_distro" in
	centos*|rhel*)
		pp_rpm_release="$pp_rpm_release.el${osrelease%%[0-9]}"
		;;
	sles*)
		pp_rpm_release="$pp_rpm_release.sles$osrelease"
		;;
	esac

	# Uncomment some Defaults in sudoers
	# Note that the order must match that of sudoers.
	case "$pp_rpm_distro" in
	centos*|rhel*)
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
		/Locale settings/+1,s/^# //
		/Desktop path settings/+1,s/^# //
		w
		q
		EOF
		;;
	sles*)
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
		/Locale settings/+1,s/^# //
		/ConsoleKit session/+1,s/^# //
		/allow any user to run sudo if they know the password/+2,s/^# //
		/allow any user to run sudo if they know the password/+3,s/^# //
		w
		q
		EOF
		;;
	esac

	# For RedHat the doc dir is expected to include version and release
	case "$pp_rpm_distro" in
	centos*|rhel*)
		mv ${pp_destdir}/${docdir} ${pp_destdir}/${docdir}-${version}-${pp_rpm_release}
		docdir=${docdir}-${version}-${pp_rpm_release}
		;;
	esac

	# Choose the correct PAM file by distro, must be tab indented for "<<-"
	case "$pp_rpm_distro" in
	centos*|rhel*)
		mkdir -p ${pp_destdir}/etc/pam.d
		if test $osrelease -lt 50; then
			cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
			#%PAM-1.0
			auth       required	pam_stack.so service=system-auth
			account    required	pam_stack.so service=system-auth
			password   required	pam_stack.so service=system-auth
			session    required	pam_limits.so
			EOF
		else
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
		fi
		;;
	  sles*)
		mkdir -p ${pp_destdir}/etc/pam.d
		if test $osrelease -lt 10; then
			cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
			#%PAM-1.0
			auth     required       pam_unix2.so
			session  required       pam_limits.so
			EOF
		else
			cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
			#%PAM-1.0
			auth     include	common-auth
			account  include	common-account
			password include	common-password
			session  include	common-session
			# session  optional	pam_xauth.so
			EOF
		fi
		;;
	esac

%set [deb]
	# Uncomment some Defaults and the %sudo rule in sudoers
	# Note that the order must match that of sudoers and be tab-indented.
	/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
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
	summary="Configurable super-user privileges"

%files
	$bindir/sudo        4111 root:
	$bindir/sudoedit    4111 root:
	$sbindir/visudo     0111
	$bindir/sudoreplay  0111
	$libexecdir/*
	$sudoersdir/sudoers.d/	0750 $sudoers_uid:$sudoers_gid
	$timedir/		0700 root:
	$docdir/
	$docdir/*
	/etc/pam.d/*		volatile,optional
%if [rpm,deb]
	$sudoersdir/sudoers $sudoers_mode $sudoers_uid:$sudoers_gid volatile
%else
	$sudoersdir/sudoers.dist $sudoers_mode $sudoers_uid:$sudoers_gid volatile
%endif

%files [!aix]
	$mandir/man*/*

%files [aix]
	# Some versions use catpages, some use manpages.
	$mandir/cat*/* optional
	$mandir/man*/* optional

%post [!rpm,deb]
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
	if test X"%{flavor}" = X"ldap" -a \
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
	if test X"%{flavor}" = X"ldap" -a \
	    X"`readlink /etc/sudo-ldap.conf 2>/dev/null`" = X"/etc/ldap/ldap.conf"; then
		rm -f /etc/sudo-ldap.conf
	fi
