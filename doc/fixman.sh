#!/bin/sh

OUTFILE="$1"
rm -f "$OUTFILE"
> "$OUTFILE"

# HP-UX friendly header/footer for all man pages
if [ X"`uname 2>&1`" = X"HP-UX" ]; then
    cat >>"$OUTFILE" <<-'EOF'
	s/^\.TH \("[^"]*"\) \("[^"]*"\) "\([^"]*\)" "\([^"]*\)" \("[^"]*"\)/.TH \1 \2 "" \5\
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
			s/^\\fR0\\fR\
			minutes\.$/unlimited./
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
	EOF
	fi

	# SELinux
	if [ X"$SEMAN" != X"1" ]; then
	cat >>"$OUTFILE" <<-'EOF'
		/^\[\\fB\\-[rt]\\fR\\ \\fI[rt][oy][lp]e\\fR/d
		/^\\fB\\-[rt]\\fR \\fI[rt][oy][lp]e\\fR$/,/^\.TP 12n$/ {
			/^\.PD$/!d
		}
	EOF
	fi
		;;
    sudoers.man.sed)
	;;
esac
