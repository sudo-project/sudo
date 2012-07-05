%set
	if test -n "$flavor"; then
		name="sudo-$flavor"
		pp_kit_package="sudo_$flavor"
	else
		name="sudo"
		pp_kit_package="sudo"
	fi
	summary="Provide limited super-user privileges to specific users"
	description="Sudo is a program designed to allow a sysadmin to give \
limited root privileges to users and log root activity.  \
The basic philosophy is to give as few privileges as possible but \
still allow people to get their work done."
	vendor="Todd C. Miller"
	copyright="(c) 1993-1996,1998-2012 Todd C. Miller"
	sudoedit_man=`echo ${pp_destdir}$mandir/*/sudoedit.*|sed "s:^${pp_destdir}::"`
	sudoedit_man_target=`basename $sudoedit_man | sed 's/edit//'`

%if [aix]
	# AIX package summary is limited to 40 characters
	summary="Configurable super-user privileges"

	# Convert to 4 part version for AIX, including patch level
	pp_aix_version=`echo $version|sed -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\)p\([0-9]*\)$/\1.\2/' -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\)[^0-9\.].*$/\1/' -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\)$/\1.0/'`
%endif

%if [kit]
	# Strip off patchlevel for kit which only supports xyz versions
	pp_kit_version="`echo $version|sed -e 's/\.//g' -e 's/[^0-9][^0-9]*[0-9][0-9]*$//'`"
	pp_kit_name="TCM"
%endif

%if [sd]
	pp_sd_vendor_tag="TCM"
%endif

%if [solaris]
	pp_solaris_name="TCM${name}"
	pp_solaris_pstamp=`/usr/bin/date "+%B %d, %Y"`
%endif

%if [rpm,deb]
	# Convert patch level into release and remove from version
	pp_rpm_release="`expr \( $version : '.*p\([0-9][0-9]*\)' \| 0 \) + 1`"
	pp_rpm_version="`expr $version : '\(.*\)p[0-9][0-9]*'`"
	pp_rpm_license="BSD"
	pp_rpm_url="http://www.sudo.ws/"
	pp_rpm_group="Applications/System"
	pp_rpm_packager="Todd C. Miller <Todd.Miller@courtesan.com>"
	if test -n "$linux_audit"; then
		pp_rpm_requires="audit-libs >= $linux_audit"
	fi
%else
	# For all but RPM and Debian we need to install sudoers with a different
	# name and make a copy of it if there is no existing file.
	mv ${pp_destdir}$sudoersdir/sudoers ${pp_destdir}$sudoersdir/sudoers.dist
%endif

%if [deb]
	pp_deb_maintainer="$pp_rpm_packager"
	pp_deb_release="$pp_rpm_release"
	pp_deb_version="$pp_rpm_version"
	pp_deb_section=admin
	install -D -m 644 ${pp_destdir}$docdir/LICENSE ${pp_wrkdir}/${name}/usr/share/doc/${name}/copyright
	install -D -m 644 ${pp_destdir}$docdir/ChangeLog ${pp_wrkdir}/${name}/usr/share/doc/${name}/changelog
	gzip -9f ${pp_wrkdir}/${name}/usr/share/doc/${name}/changelog
	printf "$name ($pp_deb_version-$pp_deb_release) admin; urgency=low\n\n  * see upstream changelog\n\n -- $pp_deb_maintainer  `date '+%a, %d %b %Y %T %z'`\n" > ${pp_wrkdir}/${name}/usr/share/doc/${name}/changelog.Debian
	chmod 644 ${pp_wrkdir}/${name}/usr/share/doc/${name}/changelog.Debian
	gzip -9f ${pp_wrkdir}/${name}/usr/share/doc/${name}/changelog.Debian
	# Create lintian override file
	mkdir -p ${pp_wrkdir}/${name}/usr/share/lintian/overrides
	cat >${pp_wrkdir}/${name}/usr/share/lintian/overrides/${name} <<-EOF
	# The sudo binary must be setuid root
	$name: setuid-binary usr/bin/sudo 4755 root/root
	# Sudo configuration and data dirs must not be world-readable
	$name: non-standard-file-perm etc/sudoers 0440 != 0644
	$name: non-standard-dir-perm etc/sudoers.d/ 0750 != 0755
	$name: non-standard-dir-perm var/lib/sudo/ 0700 != 0755
	# Sudo ships with debugging symbols
	$name: unstripped-binary-or-object
	EOF
	chmod 644 ${pp_wrkdir}/${name}/usr/share/lintian/overrides/${name}
%endif

%if [rpm]
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
		chmod u+w ${pp_destdir}${sudoersdir}/sudoers
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
		/Locale settings/+1,s/^# //
		/Desktop path settings/+1,s/^# //
		w
		q
		EOF
		chmod u-w ${pp_destdir}${sudoersdir}/sudoers
		;;
	sles*)
		chmod u+w ${pp_destdir}${sudoersdir}/sudoers
		/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
		/Locale settings/+1,s/^# //
		/ConsoleKit session/+1,s/^# //
		/allow any user to run sudo if they know the password/+2,s/^# //
		/allow any user to run sudo if they know the password/+3,s/^# //
		w
		q
		EOF
		chmod u-w ${pp_destdir}${sudoersdir}/sudoers
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
%endif

%if [deb]
	# Uncomment some Defaults and the %sudo rule in sudoers
	# Note that the order must match that of sudoers and be tab-indented.
	chmod u+w ${pp_destdir}${sudoersdir}/sudoers
	/bin/ed - ${pp_destdir}${sudoersdir}/sudoers <<-'EOF'
	/Locale settings/+1,s/^# //
	/X11 resource/+1,s/^# //
	/^# \%sudo/,s/^# //
	w
	q
	EOF
	chmod u-w ${pp_destdir}${sudoersdir}/sudoers
	mkdir -p ${pp_destdir}/etc/pam.d
	cat > ${pp_destdir}/etc/pam.d/sudo <<-EOF
	#%PAM-1.0

	@include common-auth
	@include common-account

	session required pam_permit.so
	session required pam_limits.so
	EOF
%endif

%if [macos]
	pp_macos_pkg_type=flat
	pp_macos_bundle_id=ws.sudo.pkg.sudo
	pp_macos_pkg_license=LICENSE
	pp_macos_pkg_readme=${pp_wrkdir}/ReadMe.txt
	perl -pe 'last if (/^What/i && $seen++)' NEWS > ${pp_wrkdir}/ReadMe.txt
%endif

%if X"$aix_freeware" = X"true"
	# Create links from /opt/freeware/{bin,sbin} -> /usr/{bin.sbin}
	mkdir -p ${pp_destdir}/usr/bin ${pp_destdir}/usr/sbin
	ln -s -f ${bindir}/sudo ${pp_destdir}/usr/bin
	ln -s -f ${bindir}/sudoedit ${pp_destdir}/usr/bin
	ln -s -f ${bindir}/sudoreplay ${pp_destdir}/usr/bin
	ln -s -f ${sbindir}/visudo ${pp_destdir}/usr/sbin
%endif

	# OS-level directories that should generally exist but might not.
	extradirs=`echo ${pp_destdir}/${mandir}/[mc]* | sed "s#${pp_destdir}/##g"`
	extradirs="$extradirs `dirname $docdir` `dirname $timedir`"
	test -d ${pp_destdir}/etc/pam.d && extradirs="${extradirs} /etc/pam.d"
	for dir in $bindir $sbindir $libexecdir $extradirs; do
		while test "$dir" != "/"; do
			osdirs="${osdirs}${osdirs+ }$dir/"
			dir=`dirname $dir`
		done
	done
	osdirs=`echo $osdirs | tr " " "\n" | sort -u`

%depend [deb]
	libc6, libpam0g, libpam-modules, zlib1g, libselinux1

%fixup [deb]
	# Add Conflicts, Replaces headers and add libldap depedency as needed.
	if test -z "%{flavor}"; then
	    echo "Conflicts: sudo-ldap" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	    echo "Replaces: sudo-ldap" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	elif test "%{flavor}" = "ldap"; then
	    echo "Conflicts: sudo" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	    echo "Replaces: sudo" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	    echo "Provides: sudo" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	    cp -p %{pp_wrkdir}/%{name}/DEBIAN/control %{pp_wrkdir}/%{name}/DEBIAN/control.$$
	    sed 's/^\(Depends:.*\) *$/\1, libldap-2.4-2/' %{pp_wrkdir}/%{name}/DEBIAN/control.$$ > %{pp_wrkdir}/%{name}/DEBIAN/control
	    rm -f %{pp_wrkdir}/%{name}/DEBIAN/control.$$
	fi
	echo "Homepage: http://www.sudo.ws/sudo/" >> %{pp_wrkdir}/%{name}/DEBIAN/control
	echo "Bugs: http://www.sudo.ws/bugs/" >> %{pp_wrkdir}/%{name}/DEBIAN/control

%files
	$osdirs			-
	$bindir/sudo        	4755 root:
	$bindir/sudoedit    	0755 root: symlink sudo
	$sbindir/visudo     	0755
	$bindir/sudoreplay  	0755
	$libexecdir/*		$shlib_mode optional
	$sudoersdir/sudoers.d/	0750 $sudoers_uid:$sudoers_gid
	$timedir/		0700 root:
	$docdir/		0755
	$docdir/sudoers2ldif	0755 optional,ignore-others
%if [deb]
	$docdir/LICENSE		ignore,ignore-others
	$docdir/ChangeLog	ignore,ignore-others
%endif
	$docdir/*		0644
	/etc/pam.d/*		0644 volatile,optional
%if [rpm,deb]
	$sudoersdir/sudoers $sudoers_mode $sudoers_uid:$sudoers_gid volatile
%else
	$sudoersdir/sudoers.dist $sudoers_mode $sudoers_uid:$sudoers_gid volatile
%endif
%if X"$aix_freeware" = X"true"
	# Links for binaries from /opt/freeware to /usr
	/usr/bin/sudo    	0755 root: symlink $bindir/sudo
	/usr/bin/sudoedit    	0755 root: symlink $bindir/sudoedit
	/usr/bin/sudoreplay    	0755 root: symlink $bindir/sudoreplay
	/usr/sbin/visudo    	0755 root: symlink $sbindir/visudo
%endif

%files [!aix]
	$sudoedit_man		0644 symlink,ignore-others $sudoedit_man_target
	$mandir/man*/*		0644

%files [aix]
	# Some versions use catpages, some use manpages.
	$sudoedit_man		0644 symlink,ignore-others $sudoedit_man_target
	$mandir/cat*/*		0644 optional
	$mandir/man*/*		0644 optional

%pre [aix]
	if rpm -q %{name} >/dev/null 2>&1; then
		echo "Another version of sudo is currently installed via rpm." 2>&1
		echo "Please either uninstall the rpm version of sudo by running \"rpm -e sudo\"" 2>&1
		echo "or upgrade the existing version of sudo using the .rpm packagae instead" 2>&1
		echo "instead of the .bff package." 2>&1
		echo "" 2>&1
		echo "Note that you may need to pass rpm the --oldpackage flag when upgrading" 2>&1
		echo "the AIX Toolbox version of sudo to the latest sudo rpm from sudo.ws." 2>&1
		echo "" 2>&1
		exit 1
	fi

%post [!rpm,deb]
	# Don't overwrite an existing sudoers file
%if [solaris]
	sudoersdir=${PKG_INSTALL_ROOT}%{sudoersdir}
%else
	sudoersdir=%{sudoersdir}
%endif
	if test ! -r $sudoersdir/sudoers; then
		cp $sudoersdir/sudoers.dist $sudoersdir/sudoers
		chmod %{sudoers_mode} $sudoersdir/sudoers
		chown %{sudoers_uid} $sudoersdir/sudoers
		chgrp %{sudoers_gid} $sudoersdir/sudoers
	fi

%post [deb]
	set -e

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
	set -e

	# Remove the /etc/ldap/ldap.conf -> /etc/sudo-ldap.conf symlink if
	# it matches what we created in the postinstall script.
	if test X"%{flavor}" = X"ldap" -a \
	    X"`readlink /etc/sudo-ldap.conf 2>/dev/null`" = X"/etc/ldap/ldap.conf"; then
		rm -f /etc/sudo-ldap.conf
	fi
