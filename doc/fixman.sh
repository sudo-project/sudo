#!/bin/sh

OUTFILE="$1"
rm -f "$OUTFILE"
> "$OUTFILE"

# HP-UX friendly header/footer for all man pages
if [ X"`uname 2>&1`" = X"HP-UX" ]; then
    cat >>"$OUTFILE" <<-'EOF'
	s/^\.TH \("[^"]*"\) \("[^"]*"\) "\([^"]*\)" "\([^"]*\)" \("[^"]*"\)/.TH \1 \2\
	.ds )H \4\
	.ds ]W \3/
EOF
fi

# Page specific hacks
case "$OUTFILE" in
    sudo.man.sed)
	# Replace "0 minutes" with "unlimited"
	cat >>"$OUTFILE" <<-'EOF'
		/^\\fR0\\fR$/ {
			N
			s/^\\fR0\\fR\nminutes\.$/unlimited./
		}
	EOF

	# BSD auth
	if [ X"$BAMAN" != X"1" ]; then
	cat >>"$OUTFILE" <<-'EOF'
		/^\[\\fB\\-a\\fR\\ \\fIauth_type\\fR/d
		/^\\fB\\-a\\fR \\fItype\\fR$/,/^\.TP 12n$/ {
			/^\.PD$/!d
		}
	EOF
	fi

	# BSD login class
	if [ X"$LCMAN" != X"1" ]; then
	cat >>"$OUTFILE" <<-'EOF'
		/^\[\\fB\\-c\\fR\\ \\fIclass\\fR/d
		/^\\fB\\-c\\fR \\fIclass\\fR$/,/^\.TP 12n$/ {
			/^\.PD$/!d
		}
		/^login_cap(3),$/d
		/^BSD login class$/ {
			N
			N
			/^BSD login class\n\.TP 4n\n\\fBo\\fR$/d
		}
	EOF
	fi

	# SELinux
	if [ X"$SEMAN" != X"1" ]; then
	cat >>"$OUTFILE" <<-'EOF'
		/^\[\\fB\\-[rt]\\fR\\ \\fI[rt][oy][lp]e\\fR/d
		/^\\fB\\-[rt]\\fR \\fI[rt][oy][lp]e\\fR$/,/^\.TP 12n$/ {
			/^\.PD$/!d
		}
		/^SELinux role and type$/ {
			N
			N
			/^SELinux role and type\n\.TP 4n\n\\fBo\\fR$/d
		}
	EOF
	fi

	# Solaris privileges
	if [ X"$PSMAN" != X"1" ]; then
	cat >>"$OUTFILE" <<-'EOF'
		/^Solaris project$/ {
			N
			N
			N
			N
			N
			/^Solaris project\n\.TP 4n\n\\fBo\\fR\nSolaris privileges\n\.TP 4n\n\\fBo\\fR$/d
		}
	EOF
	fi
		;;
    sudoers.man.sed)
	# Subsections to remove (SELinux and Solaris are adjacent)
	RM_SS=
	if [ X"$PSMAN" != X"1" ]; then
	    if [ X"$SEMAN" != X"1" ]; then
		RM_SS='/^\.SS "SELinux_Spec"/,/^\.SS "[^S]/{;/^\.SS "[^S][^o][^l]/!d;};'
	    else
		RM_SS='/^\.SS "Solaris_Priv_Spec"/,/^\.SS/{;/^\.SS "[^S][^o][^l]/!d;};'
	    fi
	elif [ X"$SEMAN" != X"1" ]; then
		RM_SS='/^\.SS "SELinux_Spec"/,/^\.SS/{;/^\.SS "[^S][^E][^L]/!d;};'
	fi
	if [ -n "$RM_SS" ]; then
		cat >>"$OUTFILE" <<-EOF
			$RM_SS
		EOF
	fi

	# BSD login class
	if [ X"$LCMAN" != X"1" ]; then
		cat >>"$OUTFILE" <<-EOF
			/^On BSD systems/,/\.$/ {
				d
			}
			/^use_loginclass$/,/^\.TP 18n$/ {
				/^\.PD$/!d
			}
		EOF
	fi

	# Solaris PrivSpec
	if [ X"$PSMAN" != X"1" ]; then
		cat >>"$OUTFILE" <<-EOF
			s/Solaris_Priv_Spec? //
			/^Solaris_Priv_Spec ::=/ {
				N
				d
			}
			/^l*i*m*i*t*privs$/,/^\.TP 18n$/ {
				/^\.PD$/!d
			}
			/^On Solaris 10/,/^\.[sP][pP]/ {
				d
			}
		EOF
	fi

	# SELinux
	if [ X"$SEMAN" != X"1" ]; then
		cat >>"$OUTFILE" <<-EOF
			s/SELinux_Spec? //
			/^SELinux_Spec ::=/ {
				N
				d
			}
			/^[rt][oy][lp]e$/,/^\.TP 18n$/ {
				/^\.PD$/!d
			}
		EOF
	fi
	;;
esac
