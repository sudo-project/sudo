%set
  name="sudo"
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

  # For RedHat the doc dir is expected to include version and release
  case "$pp_rpm_distro" in
    centos*|rhel*)
      mv ${pp_destdir}/${docdir} ${pp_destdir}/${docdir}-${version}-1
      docdir=${docdir}-${version}-1
      ;;
  esac

  # Choose the correct PAM file by distro
  case "$pp_rpm_distro" in
    centos4.*|rhel4.*)
        mkdir -p ${pp_destdir}/etc/pam.d
	cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
	#%PAM-1.0
	auth       required	pam_stack.so service=system-auth
	account    required	pam_stack.so service=system-auth
	password   required	pam_stack.so service=system-auth
	session    required	pam_limits.so
	EOF
	;;
    centos5.*|rhel5.*)
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
    sles10.*|sles11.*)
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
  # Choose the correct PAM file by distro
  case "$pp_deb_distro" in
    deb[456].*)
        mkdir -p ${pp_destdir}/etc/pam.d
	cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
	#%PAM-1.0

	@include common-auth
	@include common-account

	session required pam_permit.so
	session required pam_limits.so
	EOF
	;;
  esac

%set [aix]
  pp_aix_version=`echo $version | sed -e 's,\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)p\([0-9][0-9]*\)q\([0-9][0-9]*\),\1.\2.\3.\4,'`
  summary="Configurable super-user privileges"

%files
  $bindir/sudo        4111 root:
  $bindir/sudoedit    4111 root:
  $sbindir/visudo     0111
  $bindir/sudoreplay  0111
  $libexecdir/*
  $sudoersdir/sudoers.dist $sudoers_mode $sudoers_uid:$sudoers_gid volatile
  $sudoersdir/sudoers.d/ 0750 $sudoers_uid:$sudoers_gid
  $timedir/	      0700 root:
  $docdir/
  $docdir/*
  $includedir/sudo_plugin.h

%files [!aix]
  $mandir/man*/*

%files [aix]
  # Some versions use catpages, some use manpages.
  $mandir/cat*/* optional
  $mandir/man*/* optional

%files [rpm]
  /etc/pam.d/* volatile,optional

%post
  # Don't overwrite an existing sudoers file
  sysconfdir=%{sysconfdir}
  if test ! -r $sysconfdir/sudoers; then
    cp -p $sysconfdir/sudoers.dist $sysconfdir/sudoers
  fi

%post [deb]
  # dpkg-deb does not maintain the mode on the sudoers file, and
  # installs it 0640 when sudo requires 0440
  chmod %{sudoers_mode} %{sudoersdir}/sudoers

# vim:ts=2:sw=2:et
