s/^\(.TH .*\)/.nr SL @SEMAN@\
\1/

/^\.TP 6n$/ {
	N
	/^.TP 6n\nsesh$/ {
		i\
.if \\n(SL \\{\\
	}
}

/^\\fI@sesh_file@\\fR\.$/ {
	a\
.\\}
}
