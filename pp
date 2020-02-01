#!/bin/sh
# Copyright 2019 One Identity LLC. ALL RIGHTS RESERVED
pp_revision="20190919"
 # Copyright 2018 One Identity LLC.  ALL RIGHTS RESERVED.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions
 # are met:
 #
 # 1. Redistributions of source code must retain the above copyright
 #    notice, this list of conditions and the following disclaimer.
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 # 3. Neither the name of One Identity LLC. nor the names of its
 #    contributors may be used to endorse or promote products derived from
 #    this software without specific prior written permission.
 #
 # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 # "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 # LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 # A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 # OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 # SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 # TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 # PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 # LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 # NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 # SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 # Please see <http://rc.quest.com/topics/polypkg/> for more information

pp_version="1.0.0.$pp_revision"
pp_copyright="Copyright 2018, One Identity LLC. ALL RIGHTS RESERVED."

pp_opt_debug=false
pp_opt_destdir="$DESTDIR"
pp_opt_install_script=
pp_opt_list=false
pp_opt_no_clean=false
pp_opt_no_package=false
pp_opt_only_front=false
pp_opt_platform=
pp_opt_probe=false
pp_opt_strip=false
pp_opt_save_unstripped=false
pp_opt_vas_platforms=false
pp_opt_wrkdir="`pwd`/pp.work.$$"
pp_opt_verbose=false
pp_opt_version=false
pp_opt_input="-"
pp_opt_init_vars=""
pp_opt_eval=

test -n "$PP_NO_CLEAN" && pp_opt_no_clean=true
test -n "$PP_DEBUG" && pp_opt_debug=true
test -n "$PP_VERBOSE" && pp_opt_verbose=true

pp_main_cleanup () {
	pp_debug "main_cleanup"
        pp_remove_later_now
	if $pp_opt_no_clean || test x"$pp_platform" = x"unknown"; then
	    : no cleanup
	else
	    pp_backend_${pp_platform}_cleanup
	    $pp_errors && pp_die "Errors during cleanup"
	    if test -d "$pp_wrkdir"; then
		if $pp_opt_debug; then
		    pp_debug "not removing $pp_wrkdir"
		else
		    pp_verbose rm -rf "$pp_wrkdir"
		fi
	    fi
	fi
}

pp_parseopts () {
        typeset a n _var _val
	while test $# -gt 0; do

	  # convert -[dilpv] to --long-options
	  case "$1" in
	    --?*=?*) n=`echo "$1" | sed -ne 's/^--\([^=]*\)=.*/\1/p'`
	           a=`echo "$1" | sed -ne 's/^--[^=]*=\(.*\)/\1/p'`
		   shift
		   set -- "--$n" "$a" "$@";;
	    --?*) : ;;

	    -d)  shift; set -- "--debug" "$@";;
	    -d*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--debug" "$@";;

	    -i) shift; set -- "--install-script" "$@";;
	    -i*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--install-script" "$a" "$@";;

	    -l)  shift; set -- "--list" "$@";;
	    -l*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--list" "$@";;

	    -p) shift; set -- "--platform" "$@";;
	    -p*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--platform" "$a" "$@";;

	    -v)  shift; set -- "--verbose" "$@";;
	    -v*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--verbose" "$@";;

	    -\?)  shift; set -- "--help" "$@";;
	    -\?*) a=`echo "$1" | sed -ne 's/^-.//'`
		 shift; set -- "--help" "$@";;
	  esac

	  case "$1" in
	    --destdir|--eval|--install-script|--platform|--wrkdir)
		test $# -ge 2 || pp_error "missing argument to $1";;
	  esac

	  case "$1" in
	    --) 				       shift;break;;
	    --debug)           pp_opt_debug=true;      shift;;
	    --destdir)         pp_opt_destdir="$2";    shift;shift;;
	    --eval)            pp_opt_eval="$2";       shift;shift;; # undoc
	    --install-script)  pp_opt_install_script="$2"; shift;shift;;
	    --list)            pp_opt_list=true;       shift;;
	    --no-clean)        pp_opt_no_clean=true;   shift;;
	    --no-package)      pp_opt_no_package=true; shift;;
	    --only-front)      pp_opt_only_front=true; shift;;
	    --platform)        pp_opt_platform="$2";   shift;shift;;
	    --probe)           pp_opt_probe=true;      shift;;
	    --strip)           pp_opt_strip=true;      shift;;
	    --save-unstripped) pp_opt_save_unstripped=true; shift;;
	    --wrkdir)          pp_opt_wrkdir="$2";     shift;shift;;
	    --vas-platforms)   pp_opt_vas_platforms=true; shift;;
	    --verbose)         pp_opt_verbose=true;    shift;;
	    --version)         pp_opt_version=true;    shift;;
	    --help)            pp_errors=true;         shift;;
	    -) break;;
	    -*) pp_error "unknown option $1"; shift;;
	    *) break;;
	  esac

	done

	pp_opt_input=-
	if test $# -gt 0; then
	    pp_opt_input="$1"
	    shift
	fi

        #-- extra arguments of the form Foo=bar alter *global* vars
        while test $# -gt 0; do
            case "$1" in
		-*)	pp_error "unexpected option '$1'"
			shift;;
                *=*)    _val="${1#*=}"
                        _var=${1%="$_val"}
                        _val=`echo "$_val"|sed -e 's/[$"\\]/\\&/g'`
                        pp_debug "setting $_var = \"$_val\""
                        pp_opt_init_vars="$pp_opt_init_vars$_var=\"$_val\";"
                        shift;;
                *)      pp_error "unexpected argument $1'"
			shift;;
            esac
        done

	test $# -gt 0 &&
            pp_error "unknown argument $1"

	if $pp_errors; then
	    cat <<. >&2
polypkg $pp_version $pp_copyright
usage: $0 [options] [input.pp] [var=value ...]
    -d --debug                  -- write copious info to stderr
       --destdir=path           -- file root, defaults to \$DESTDIR
    -? --help                   -- display this information
    -i --install-script=path    -- create an install helper script
    -l --list                   -- write package filenames to stdout
       --no-clean               -- don't remove temporary files
       --no-package             -- do everything but create packages
       --only-front             -- only perform front-end actions
    -p --platform=platform      -- defaults to local platform
       --probe                  -- print local system identifier, then exit
       --strip                  -- strip debug symbols from binaries before
                                   packaging (modifies files in destdir)
       --save-unstripped        -- save unstripped binaries to
                                   \$name-\$version-unstripped.tar.gz
       --wrkdir=path            -- defaults to subdirectory of \$TMPDIR or /tmp
    -v --verbose                -- write info to stderr
       --version                -- display version and quit
.
	    exit 1
	fi
}

pp_drive () {
	# initialise the front and back ends
        pp_model_init
	pp_frontend_init
	$pp_opt_only_front || pp_backend_init

	# run the front-end to generate the intermediate files
        # set $pp_input_dir to be the 'include dir' if needed
	pp_debug "calling frontend on $pp_opt_input"
	case "$pp_opt_input" in
	    -)   pp_input_dir=.
		 test -t 1<&0 &&
		    pp_warn "reading directives from standard input"
                 pp_frontend
                 ;;
            */*) pp_input_dir=${pp_opt_input%/*}
	         pp_frontend <"$pp_opt_input"
                 ;;
            *)   pp_input_dir=.
	         pp_frontend <"$pp_opt_input"
                 ;;
	esac

        pp_files_ignore_others
        pp_service_scan_groups

	# some sanity checks after front-end processing
        if test x"$pp_platform" != x"null"; then
	    pp_debug "sanity checks"
	    test -n "$pp_components" || pp_error "No components?"
	    pp_check_var_is_defined  "name"
	    pp_check_var_is_defined  "version"
            pp_files_check_duplicates
            pp_files_check_coverage
	    pp_die_if_errors "Errors during sanity checks"
        fi

	# stop now if we're only running the front
	$pp_opt_only_front && return

	if test x"$pp_opt_strip" = x"true"; then
	    pp_strip_binaries
	fi

	# run the back-end to generate the package
	pp_debug "calling backend"
	pp_backend
	pp_die_if_errors "Errors during backend processing"

	# copy the resulting package files to PP_PKGDESTDIR or .
	for f in `pp_backend_names` -; do
           test x"$f" = x"-" && continue
	   pp_debug "copying: $f to `pwd`"
	   if pp_verbose cp -r $pp_wrkdir/$f ${PP_PKGDESTDIR:-.}; then
               echo "${PP_PKGDESTDIR:+$PP_PKGDESTDIR/}$f"
           else
               pp_error "$f: missing package"
           fi
	done
	pp_die_if_errors "Errors during package copying"
}

pp_install_script () {
        pp_debug "writing install script to $pp_opt_install_script"
        rm -f $pp_opt_install_script
        pp_backend_install_script > $pp_opt_install_script
	pp_die_if_errors "Errors during package install script"
        chmod +x $pp_opt_install_script
}

pp_main () {
	# If PP_DEV_PATH is set, then jump to that script.
	# (Useful when working on polypkg source that isn't installed)
	if test -n "$PP_DEV_PATH" -a x"$PP_DEV_PATH" != x"$0"; then
	    pp_warn "switching from $0 to $PP_DEV_PATH ..."
	    exec "$PP_DEV_PATH" "$@" || exit 1
	fi

	pp_set_expand_converter_or_reexec "$@"
	pp_parseopts "$@"

        if $pp_opt_version; then
            #-- print version and exit
            echo "polypkg $pp_version"
            exit 0
        fi

	pp_set_platform

	trap 'pp_main_cleanup' 0

	pp_wrkdir="$pp_opt_wrkdir"
	pp_debug "pp_wrkdir = $pp_wrkdir"
	rm -rf "$pp_wrkdir"
	mkdir -p "$pp_wrkdir"

	pp_destdir="$pp_opt_destdir"
	pp_debug "pp_destdir = $pp_destdir"

        if $pp_opt_probe; then
	    pp_backend_init
            pp_backend_probe
        elif $pp_opt_vas_platforms; then
	    pp_backend_init
            pp_backend_vas_platforms
	elif test -n "$pp_opt_eval"; then
	    #-- execute a shell command
	    eval "$pp_opt_eval" || exit
	else
	    pp_drive
	    if test -n "$pp_opt_install_script"; then
		pp_install_script
	    fi
        fi

	exit 0
}


pp_errors=false

if test -n "$TERM" -a -t 1 && (tput op) >/dev/null 2>/dev/null; then
   pp_col_redfg=`tput setf 4` 2>/dev/null
   pp_col_bluefg=`tput setf 1` 2>/dev/null
   pp_col_reset=`tput op` 2>/dev/null
else
   pp_col_redfg='['
   pp_col_bluefg='['
   pp_col_reset=']'
fi

pp__warn () {
	if test x"" = x"$pp_lineno"; then
	    echo "$1 $2" >&2
	else
	    echo "$1 line $pp_lineno: $2" >&2
	fi
}

pp_warn () {
	pp__warn "pp: ${pp_col_redfg}warning${pp_col_reset}" "$*"
}

pp_error () {
	pp__warn "pp: ${pp_col_redfg}error${pp_col_reset}" "$*"
	pp_errors=true
}

pp_die () {
	pp_error "$@"
	exit 1
}

pp_die_if_errors () {
	$pp_errors && pp_die "$@"
}

pp_debug () {
	$pp_opt_debug && echo "${pp_col_bluefg}debug${pp_col_reset} $*" >&2
}

pp_verbose () {
	$pp_opt_verbose && echo "pp: ${pp_col_bluefg}info${pp_col_reset} $*" >&2
	"$@";
}

pp_substitute () {
  sed -e 's,%(\([^)]*\)),`\1`,g' \
      -e 's,%{\([^}]*\)},${\1},g' \
      -e 's,$,,' |
  tr '' '\012' |
  sed -e '/^[^]/s/["$`\\]/\\&/g' \
      -e 's/^//' \
      -e '1s/^/echo "/' \
      -e '$s,$,",' \
      -e 's,,"echo ",g' |
  tr -d '\012' |
  tr '' '\012'
  echo
}

pp_incr () {
    eval "$1=\`expr \$$1 + 1\`"
}

pp_decr () {
    eval "$1=\`expr \$$1 - 1\`"
}

pp_check_var_is_defined () {
    if eval test -z "\"\$$1\""; then
	pp_error "\$$1: not set"
	eval "$1=undefined"
    fi
}

pp_contains () {
    case " $1 " in
       *" $2 "*) return 0;;
       *) return 1;;
    esac
}

pp_contains_all () {
    typeset _s _c
    _l="$1"; shift
    for _w
    do
	pp_contains "$_l" "$_w" || return 1
    done
    return 0
}

pp_contains_any () {
    typeset _s _c
    _l="$1"; shift
    for _w
    do
	pp_contains "$_l" "$_w" && return 0
    done
    return 1
}

pp_add_to_list () {
    if eval test -z \"\$$1\"; then
	eval $1='"$2"'
    elif eval pp_contains '"$'$1'"' '"$2"'; then
	: already there
    else
	eval $1='"$'$1' $2"'
    fi
}

pp_unique () {
    typeset result element
    result=
    for element
    do
	pp_add_to_list result $element
    done
    echo $result
}

pp_mode_strip_altaccess () {
    case "$1" in
	??????????[+.])
	    echo `echo "$1" | cut -b -10`;;
	*)
	    echo "$1";;
    esac
}

pp_mode_from_ls () {
   typeset umode gmode omode smode

   set -- `pp_mode_strip_altaccess "$1"`

   case "$1" in
	?--[-X]??????) umode=0;;
	?--[xs]??????) umode=1;;
	?-w[-X]??????) umode=2;;
	?-w[xs]??????) umode=3;;
	?r-[-X]??????) umode=4;;
	?r-[xs]??????) umode=5;;
	?rw[-X]??????) umode=6;;
	?rw[xs]??????) umode=7;;
	*) pp_error "bad user mode $1";;
   esac

   case "$1" in
	????--[-S]???) gmode=0;;
	????--[xs]???) gmode=1;;
	????-w[-S]???) gmode=2;;
	????-w[xs]???) gmode=3;;
	????r-[-X]???) gmode=4;;
	????r-[xs]???) gmode=5;;
	????rw[-X]???) gmode=6;;
	????rw[xs]???) gmode=7;;
	*) pp_error "bad group mode $1";;
   esac

   case "$1" in
	???????--[-T]) omode=0;;
	???????--[xt]) omode=1;;
	???????-w[-T]) omode=2;;
	???????-w[xt]) omode=3;;
	???????r-[-T]) omode=4;;
	???????r-[xt]) omode=5;;
	???????rw[-T]) omode=6;;
	???????rw[xt]) omode=7;;
	*) pp_error "bad other mode $1";;
   esac

   case "$1" in
	???[-x]??[-x]??[-x]) smode=;;
	???[-x]??[-x]??[tT]) smode=1;;
	???[-x]??[Ss]??[-x]) smode=2;;
	???[-x]??[Ss]??[tT]) smode=3;;
	???[Ss]??[-x]??[-x]) smode=4;;
	???[Ss]??[-x]??[tT]) smode=5;;
	???[Ss]??[Ss]??[-x]) smode=6;;
	???[Ss]??[Ss]??[tT]) smode=7;;
	*) pp_error "bad set-id mode $1";;
   esac

   echo "$smode$umode$gmode$omode"
}

pp_find_recurse () {
  pp_debug "find: ${1#$pp_destdir}/"
  for f in "$1"/.* "$1"/*; do
    case "$f" in */.|*/..) continue;; esac  # should never happen!
    if test -d "$f" -o -f "$f" -o -h "$f"; then
        if test -d "$f" -a ! -h "$f"; then
            echo "${f#$pp_destdir}/"
            pp_find_recurse "$f"
        else
            echo "${f#$pp_destdir}"
        fi
    fi
  done
}

pp_prepend () {
    #test -t && pp_warn "pp_prepend: stdin is a tty?"
    if test -f $1; then
        pp_debug "prepending to $1"
        mv $1 $1._prepend
        cat - $1._prepend >$1
        rm -f $1._prepend
    else
        pp_debug "prepend: creating $1"
        cat >$1
    fi
}

pp_note_file_used() {
    echo "$1" >> $pp_wrkdir/all.files
}

pp_create_dir_if_missing () {
    case "$1" in
        */) pp_error "pp_create_dir_if_missing: trailing / forbidden";;
	"") return 0;;
	*)  if test ! -d "$pp_destdir$1"; then
                pp_debug "fabricating directory $1/"
		pp_create_dir_if_missing "${1%/*}"
		mkdir "$pp_destdir$1" &&
                    pp_note_file_used "$1/"
		pp_remove_later "$1" &&
		chmod ${2:-755} "$pp_destdir$1"
	    fi;;
    esac
}

pp_add_file_if_missing () {
    typeset dir
    #-- check that the file isn't already declared in the component
    if test -s $pp_wrkdir/%files.${2:-run}; then
      awk "\$6 == \"$1\" {exit 1}" < $pp_wrkdir/%files.${2:-run} || return 1
    fi

    pp_create_dir_if_missing "${1%/*}"
    pp_debug "fabricating file $1"
    echo "f ${3:-755} - - ${4:--} $1" >> $pp_wrkdir/%files.${2:-run}
    pp_note_file_used "$1"
    pp_remove_later "$1"
    return 0
}

pp_add_transient_file () {
    test -f "$pp_destdir$1" && pp_die "$pp_destdir$1: exists"
    pp_create_dir_if_missing "${1%/*}"
    pp_debug "transient file $1"
    pp_note_file_used "$1"
    pp_remove_later "$1"
}

pp_remove_later () {
   {
	echo "$1"
	test -s $pp_wrkdir/pp_cleanup && cat $pp_wrkdir/pp_cleanup
   } > $pp_wrkdir/pp_cleanup.new
   mv $pp_wrkdir/pp_cleanup.new $pp_wrkdir/pp_cleanup
}

pp_ls_readlink () {
    if test -h "$1"; then
        ls -1ld "$1" | sed -ne 's,.* -> ,,p'
    else
        echo "$1: not a symbolic link" >&2
        return 1
    fi
}

pp_remove_later_now () {
    typeset f
    if test -s $pp_wrkdir/pp_cleanup; then
        pp_debug "pp_remove_later_now"
        while read f; do
            pp_debug "removing $pp_destdir$f"
	    if test -d $pp_destdir$f; then
		rmdir $pp_destdir$f
	    else
		rm $pp_destdir$f
	    fi
        done < $pp_wrkdir/pp_cleanup
        rm $pp_wrkdir/pp_cleanup
    fi
}

pp_readlink() {

pp_debug "&& pp_readlink_fn=$pp_readlink_fn"

    if test -n "$pp_readlink_fn"; then
pp_debug "&& calling $pp_readlink_fn $*"
        "$pp_readlink_fn" "$@"
    else
        readlink "$@"
    fi
}


pp_install_script_common () {
        cat <<-.

            # Automatically generated for
            #    $name $version ($pp_platform)
            # by PolyPackage $pp_version

            usage () {
              case "$1" in
              "list-services")
                echo "usage: \$0 list-services" ;;
              "list-components")
                echo "usage: \$0 list-components" ;;
              "list-files")
                echo "usage: \$0 list-files {cpt...|all}" ;;
              "install")
                echo "usage: \$0 install {cpt...|all}" ;;
              "uninstall")
                echo "usage: \$0 uninstall {cpt...|all}" ;;
              "start")
                echo "usage: \$0 start {svc...}" ;;
              "stop")
                echo "usage: \$0 stop {svc...}" ;;
              "print-platform")
                echo "usage: \$0 print-platform" ;;
              *)
                echo "usage: \$0 [-q] command [args]"
                echo "   list-services"
                echo "   list-components"
                echo "   list-files {cpt...|all}"
                echo "   install {cpt...|all}"
                echo "   uninstall {cpt...|all}"
                echo "   start {svc...}"
                echo "   stop {svc...}"
                echo "   print-platform"
                ;;
              esac >&2
              exit 1
            }

            if test x"\$1" = x"-q"; then
                shift
                verbose () { "\$@"; }
                verbosemsg () { : ; }
            else
                verbose () { echo "+ \$*"; "\$@"; }
                verbosemsg () { echo "\$*"; }
            fi
.
}


pp_functions () {
    typeset func deps allfuncs
    allfuncs=
    while test $# -gt 0; do
	pp_add_to_list allfuncs "$1"
	deps=`pp_backend_function "$1:depends"`
	shift
	set -- `pp_unique "$@" $deps`
    done

    for func in $allfuncs
    do
        pp_debug "generating function code for '$1'"
        echo ""
        echo "$func () {"
	case "$func" in
	    pp_mkgroup|pp_mkuser|pp_havelib) echo <<.;;
		if test \$# -lt 1; then
		    echo "$func: not enough arguments" >&2
		    return 1
		fi
.
	esac
        pp_backend_function "$func" || cat <<.
		echo "$func: not implemented" >&2
		return 1
.
        echo "}"
    done
}

pp_function () {
    pp_functions "$1"
}

pp_makevar () {
    #-- convert all non alpha/digits to underscores
    echo "$*" | tr -c '[a-z][A-Z][0-9]\012' '[_*]'
}

pp_getpwuid () {
    awk -F: '$3 == uid { if (!found) print $1; found=1; } END { if (!found) exit 1; }' uid="$1" \
	< /etc/passwd || pp_error "no local username for uid $1"
}

pp_getgrgid () {
    awk -F: '$3 == gid { if (!found) print $1; found=1; } END { if (!found) exit 1; }' gid="$1" \
	< /etc/group || pp_error "no local group for gid $1"
}

pp_backend_function_getopt () {
    cat <<'..'
pp_getopt () {
     _pp_optstring="$1"; shift; eval `_pp_getopt "$_pp_optstring"`
}
_pp_getopt_meta=s,[\\\\\"\'\`\$\&\;\(\)\{\}\#\%\ \	],\\\\\&,g
_pp_protect () {
    sed "$_pp_getopt_meta" <<. | tr '\012' ' '
$*
.
}
_pp_protect2 () {
    sed "s,^..,,$pp_getopt_meta" <<. | tr '\012' ' '
$*
.
}
_pp_nonl () {
    tr '\012' ' ' <<.
$*
.
}
_pp_getopt () {
    _pp_nonl '_pp_nonl set --; while test $# -gt 0; do case "$1" in "--") shift; break;;'
    sed 's/\([^: 	]:*\)/<@<\1>@>/g;
	 s/<@<\(.\):>@>/"-\1")  _pp_nonl -"\1"; _pp_protect "$2"; shift; shift;; "-\1"*) _pp_nonl -"\1"; _pp_protect2 "$1"; shift;;/g;s/<@<\(.\)>@>/ "-\1")  _pp_nonl -"\1"; shift;; "-\1"*) _pp_nonl -"\1"; _pp_tmp="$1"; shift; set -- -`_pp_protect2 "$_pp_tmp"` "$@";;/g' <<.
$1
.
    _pp_nonl '-*) echo "$1: unknown option">&2; return 1;; *) break;; esac; done; _pp_nonl --; while test $# -gt 0; do _pp_nonl "$1"; shift; done; echo'
    echo
}
..
}

pp_copy_unstripped () {
    typeset filedir realdir
    filedir="`dirname ${1#$pp_destdir}`"
    realdir="$pp_wrkdir/unstripped/$filedir"

    mkdir -p "$realdir"
    # Can't use hardlinks because `strip` modifies the original file in-place
    cp "$1" "$realdir"
}

pp_package_stripped_binaries () {
    (cd "$pp_wrkdir/unstripped" && tar -c .) \
     | gzip > "$name-dbg-$version.tar.gz"
    rm -rf "$pp_wrkdir/unstripped"
}

pp_strip_binaries () {
    if test x"$pp_opt_save_unstripped" = x"true"; then
	rm  -rf "$pp_wrkdir/unstripped"
	mkdir "$pp_wrkdir/unstripped"
    fi

    for f in `find "$pp_destdir" -type f`; do
	if file "$f" | awk '{print $2}' | grep ^ELF >/dev/null 2>&1; then
	    if test x"$pp_opt_save_unstripped" = x"true"; then
		if file "$f" | LC_MESSAGES=C grep 'not stripped' >/dev/null 2>&1; then
		    pp_debug "Saving unstripped binary $f"
		    pp_copy_unstripped "$f"
		else
		    pp_debug "$f is already stripped; not saving a copy"
		fi
	    fi
	    pp_debug "Stripping unnecessary symbols from $f"
	    strip "$f"
	fi
    done

    if test x"$pp_opt_save_unstripped" = x"true"; then
	pp_package_stripped_binaries
    fi
}

pp_if_true=0
pp_if_false=0

pp_frontend_init () {
    name=
    version=
    build_number=
    summary="no summary"
    description="No description"
    copyright="Copyright 2018 One Identity LLC. ALL RIGHTS RESERVED."

    #-- if the user supplied extra arguments on the command line
    #   then load them now.
    pp_debug "pp_opt_init_vars=$pp_opt_init_vars"
    test -n "$pp_opt_init_vars" && eval "$pp_opt_init_vars"
}

pp_is_qualifier () {
    typeset ret

    case "$1" in
        "["*"]") ret=true;;
        *)       ret=false;;
    esac
    pp_debug "is_qualifier: $* -> $ret"
    test $ret = true
}

pp_eval_qualifier () {
    typeset ret

    case "$1" in
        "[!$pp_platform]"| \
         "[!"*",$pp_platform]"| \
         "[!$pp_platform,"*"]"| \
         "[!"*",$pp_platform,"*"]") ret=false;;
        "[!"*"]") ret=true;;
        "[$pp_platform]"| \
         "["*",$pp_platform]"| \
         "[$pp_platform,"*"]"| \
         "["*",$pp_platform,"*"]") ret=true;;
        "["*"]") ret=false;;
        *) pp_die "pp_eval_qualifier: bad qualifier '$1'"
    esac
    pp_debug "eval: $* -> $ret"
    test true = $ret
}

pp_frontend_if () {
    typeset ifcmd ifret
    ifcmd="$1";
    shift
    case "$ifcmd" in
	%if) if test 0 = $pp_if_false; then
		case "$*" in
		    true |1) pp_incr pp_if_true;;
		    false|0) pp_incr pp_if_false;;
                    *)
			ifret=true
                        if pp_is_qualifier "$*"; then
                            pp_eval_qualifier "$*" || ifret=false
                        else
			    eval test "$@" || ifret=false
			    pp_debug "evaluating test $* -> $ifret"
			fi
			pp_incr pp_if_$ifret
                        ;;
		esac
	     else
		pp_incr pp_if_false
	     fi;;
	%else)  test $# = 0 || pp_warn "ignoring argument to %else"
		if test $pp_if_false -gt 1; then
		  : no change
		elif test $pp_if_false = 1; then
		  pp_incr pp_if_true
		  pp_decr pp_if_false
		elif test $pp_if_true = 0; then
		  pp_die "unmatched %else"
		else
		  pp_incr pp_if_false
		  pp_decr pp_if_true
		fi;;
	%endif) test $# = 0 || pp_warn "ignoring argument to %endif"
		if test $pp_if_false -gt 0; then
		  pp_decr pp_if_false
		elif test $pp_if_true -gt 0; then
		  pp_decr pp_if_true
		else
		  pp_die "unmatched %endif"
		fi;;
	*) pp_die "frontend_if: unknown cmd $ifcmd";;
    esac
}


pp_frontend () {
  typeset section newsection sed_word sed_ws line cpt svc
  typeset section_enabled newsection_enabled s sed sed_candidate

  section='%_initial'
  newsection='%_initial'
  section_enabled=:
  newsection_enabled=:
  sed_word="[a-zA-Z_][a-zA-Z_0-9]*"
  sed_ws="[ 	]"

  #-- not all seds are created equal
  sed=
  for sed_candidate in ${PP_SED:-sed} /usr/xpg4/bin/sed; do
      if echo 'foo' | $sed_candidate -ne '/^\(x\)*foo/p' | grep foo > /dev/null
      then
        sed="$sed_candidate"
        break
      fi
  done
  test -z "$sed" &&
        pp_die "sed is broken on this system"

  pp_lineno=0

  #-- Note: this sed script should perform similar to pp_eval_qualifier()
  $sed -e "/^#/s/.*//" \
       -e "/^\\[!\\($sed_word,\\)*$pp_platform\\(,$sed_word\\)*\\]/s/.*//" \
       -e "s/^\\[\\($sed_word,\\)*$pp_platform\\(,$sed_word\\)*\\]$sed_ws*//" \
       -e "s/^\\[!\\($sed_word,\\)*$sed_word\\]$sed_ws*//" \
       -e "/^\\[\\($sed_word,\\)*$sed_word\\]/s/.*//" \
       -e "s/^%$sed_ws*/%/" \
       -e "s/^$sed_ws/%\\\\&/" \
     > $pp_wrkdir/frontend.tmp

  #-- add an ignore section at the end to force section completion
  echo '%ignore' >> $pp_wrkdir/frontend.tmp
  echo  >> $pp_wrkdir/frontend.tmp

  exec 0<$pp_wrkdir/frontend.tmp
  : > $pp_wrkdir/tmp
  : > $pp_wrkdir/%fixup
  while read -r line; do
     #-- Convert leading double-% to single-%, or switch sections
     pp_incr pp_lineno

     pp_debug "line $pp_lineno: $line"
     set -f
     set -- $line
     set +f
     #pp_debug "line $pp_lineno: $*"

     case "$line" in %*)
        case "$1" in
	   %if|%else|%endif)
                pp_debug "processing if directive $1"
	   	pp_frontend_if "$@"
		continue;;
	esac
	test 0 -ne $pp_if_false && continue	# ignore lines %if'd out

        case "$1" in
	  %set|%fixup|%ignore)
             pp_debug "processing new section $1"
	     newsection="$1"; shift
             newsection_enabled=:
             if pp_is_qualifier "$1"; then
                pp_eval_qualifier "$1" || newsection_enabled=false
                shift
             fi
	     test $# -eq 0 || pp_warn "ignoring extra arguments: $line"
	     continue;;
	  %pre|%post|%preun|%postup|%preup|%postun|%files|%depend|%check|%conflict)
             pp_debug "processing new component section $*"
             s="$1"; shift
             if test $# -eq 0 || pp_is_qualifier "$1"; then
                cpt=run
             else
                cpt="$1"
                shift
             fi
             newsection="$s.$cpt"
             newsection_enabled=:
             if test $# -gt 0 && pp_is_qualifier "$1"; then
                pp_eval_qualifier "$1" || newsection_enabled=false
                shift
             fi
             test $# -eq 0 ||
                pp_warn "ignoring extra arguments: $line"
             case "$cpt" in
                run|dbg|doc|dev)
                    $newsection_enabled && pp_add_component "$cpt";;
                x-*) :;;    # useful for discarding stuff
                *) pp_error "unknown component: $1 $cpt";;
             esac
	     continue;;
          %pp)
            newsection="%ignore"; shift
            if test $# -gt 0; then
                pp_set_api_version "$1"
                shift
            else
                pp_error "%pp: missing version"
            fi
            test $# -gt 0 &&
                pp_error "%pp: too many arguments"
            continue;;
	  %service)
             pp_debug "processing new service section $1 $2"
             s="$1"; shift
             if test $# -eq 0 || pp_is_qualifier "$1"; then
                pp_error "$s: service name required"
                svc=unknown
             else
                svc="$1"; shift
             fi

	     newsection="$s.$svc"
             newsection_enabled=:
	     if test $# -gt 0 && pp_is_qualifier "$1"; then
                pp_eval_qualifier "$1" || newsection_enabled=false
                shift
             fi
             test $# -eq 0 ||
                pp_warn "ignoring extra arguments: $line"
	     $newsection_enabled && pp_add_service "$svc"
	     continue;;
	  %\\*)
             pp_debug "removing leading %\\"
	     line="${line#??}"
             pp_debug "  result is <$line>"
             set -f
             set -- $line
             set +f
             ;;
	  %%*)
             pp_debug "removing leading %"
	     line="${line#%}"
             set -f
             set -- $line
             set +f
	     ;;
	  %*)
	     pp_error "unknown section $1"
	     newsection='%ignore'
             newsection_enabled=:
	     continue;;
	esac;;
     esac

     test 0 != $pp_if_false && continue	# ignore lines %if'd out

     pp_debug "section=$section (enabled=$section_enabled) newsection=$newsection (enabled=$newsection_enabled)"

     #-- finish processing a previous section
     if test x"$newsection" != x""; then
      $section_enabled && case "$section" in
     	%ignore|%_initial)
                pp_debug "leaving ignored section $section"
		: ignore  # guaranteed to be the last section
		;;
	%set)
                pp_debug "leaving $section: sourcing $pp_wrkdir/tmp"
                $pp_opt_debug && cat $pp_wrkdir/tmp >&2
		. $pp_wrkdir/tmp
		: > $pp_wrkdir/tmp
		;;
	%pre.*|%preun.*|%post.*|%postup.*|%preup.*|%postun.*|%depend.*|%check.*|%conflict.*|%service.*|%fixup)
                pp_debug "leaving $section: substituting $pp_wrkdir/tmp"
                # cat $pp_wrkdir/tmp >&2    # debugging
                $pp_opt_debug && pp_substitute < $pp_wrkdir/tmp >&2
		pp_substitute < $pp_wrkdir/tmp > $pp_wrkdir/tmp.sh
                . $pp_wrkdir/tmp.sh >> $pp_wrkdir/$section ||
                    pp_error "shell error in $section"
		rm -f $pp_wrkdir/tmp.sh
		: > $pp_wrkdir/tmp
		;;
      esac
      section="$newsection"
      section_enabled="$newsection_enabled"
      newsection=
     fi

     #-- ignore section content that is disabled
     $section_enabled || continue

     #-- process some lines in-place
     case "$section" in
	%_initial)
		case "$line" in "") continue;; esac # ignore non-section blanks
		pp_die "Ignoring text before % section introducer";;
	%set|%pre.*|%preun.*|%post.*|%postup.*|%preup.*|%postun.*|%check.*|%service.*|%fixup)
                pp_debug "appending line to \$pp_wrkdir/tmp"
		echo "$line" >> $pp_wrkdir/tmp
		;;
	%files.*)
		test $# -eq 0 && continue;
		pp_files_expand "$@" >> $pp_wrkdir/$section
		;;
	%depend.*)
		pp_debug "Adding explicit dependency $@ to $cpt"
		echo "$@" >> $pp_wrkdir/%depend.$cpt
		;;
	%conflict.*)
		pp_debug "Adding explicit conflict $@ to $cpt"
		echo "$@" >> $pp_wrkdir/%conflict.$cpt
		;;
     esac
  done
  exec <&-

  if test $pp_if_true != 0 -o $pp_if_false != 0; then
	pp_die "missing %endif at end of file"
  fi

  pp_lineno=

  pp_debug " name        = $name"
  pp_debug " version     = $version"
  pp_debug " summary     = $summary"
  pp_debug " description = $description"
  pp_debug " copyright   = $copyright"
  pp_debug ""
  pp_debug "\$pp_components: $pp_components"
  pp_debug "\$pp_services:   $pp_services"
}

pp_set_api_version() {
    case "$1" in
        1.0)    : ;;
        *)      pp_error "This version of polypackage is too old";;
    esac
}

pp_platform=

pp_set_platform () {
    if test -n "$pp_opt_platform"; then
	pp_contains "$pp_platforms" "$pp_opt_platform" ||
		pp_die "$pp_opt_platform: unknown platform"
	pp_platform="$pp_opt_platform"
    else
	uname_s=`uname -s 2>/dev/null`
	pp_platform=
	for p in $pp_platforms; do
	    pp_debug "probing for platform $p"
	    if eval pp_backend_${p}_detect "$uname_s"; then
		pp_platform="$p"
		break;
	    fi
	done
	test -z "$pp_platform" &&
		pp_die "cannot detect platform (supported: $pp_platforms)"
    fi
    pp_debug "pp_platform = $pp_platform"
}

pp_expand_path=

pp_expand_test_usr_bin () {
	awk '$1 == "/usr" || $2 == "/usr" {usr++}
	     $1 == "/bin" || $2 == "/bin" {bin++}
	     END { if (usr == 1 && bin == 1) exit(0); else exit(1); }'
}

pp_set_expand_converter_or_reexec () {
    test -d /usr -a -d /bin ||
	pp_die "missing /usr or /bin"
    echo /usr /bin | pp_expand_test_usr_bin || pp_die "pp_expand_test_usr_bin?"
    if (eval "echo /{usr,bin}" | pp_expand_test_usr_bin) 2>/dev/null; then
	pp_expand_path=pp_expand_path_brace
    elif (eval "echo /@(usr|bin)" | pp_expand_test_usr_bin) 2>/dev/null; then
	pp_expand_path=pp_expand_path_at
    else
	test x"$pp_expand_rexec" != x"true" ||
	    pp_die "problem finding shell that can do brace expansion"
	for shell in bash ksh ksh93; do
	    if ($shell -c 'echo /{usr,bin}' |
			pp_expand_test_usr_bin) 2>/dev/null ||
	       ($shell -c 'echo /@(usr|bin)' |
			pp_expand_test_usr_bin) 2>/dev/null
	    then
                pp_debug "switching to shell $shell"
		pp_expand_rexec=true exec $shell "$0" "$@"
	    fi
	done
	pp_die "cannot find a shell that does brace expansion"
    fi
}

pp_expand_path_brace () {
	typeset f
	eval "for f in $1; do echo \"\$f\"; done|sort -u"
}

pp_expand_path_at () {
	typeset f
	eval "for f in `
	    echo "$1" | sed -e 's/{/@(/g' -e 's/}/)/g' -e 's/,/|/g'
		`; do echo \"\$f\"; done|sort -u"
}

pp_shlib_suffix='.so*'

pp_model_init () {
    #@ $pp_components: whitespace-delimited list of components seen in %files
    pp_components=
    #@ $pp_services: whitespace-delimited list of %service seen
    pp_services=

    rm -f $pp_wrkdir/%files.* \
          $pp_wrkdir/%post.* \
          $pp_wrkdir/%pre.* \
          $pp_wrkdir/%preun.* \
          $pp_wrkdir/%postup.* \
          $pp_wrkdir/%postun.* \
          $pp_wrkdir/%service.* \
          $pp_wrkdir/%set \
          $pp_wrkdir/%fixup
}


pp_have_component () {
	pp_contains "$pp_components" "$1"
}

pp_have_all_components () {
	pp_contains_all "$pp_components" "$@"
}

pp_add_component () {
	pp_add_to_list 'pp_components' "$1"
}

pp_add_service () {
	pp_add_to_list 'pp_services' "$1"
}

pp_service_init_vars () {
	cmd=
	pidfile=
	stop_signal=15		# SIGTERM
	user=root
	group=
	enable=yes		# make it so the service starts on boot
	optional=no		# Whether installing this service is optional
	pp_backend_init_svc_vars
}

pp_service_check_vars () {
	test -n "$cmd" ||
		pp_error "%service $1: cmd not defined"
	case "$enable" in
	    yes|no) : ;;
	    *) pp_error "%service $1: \$enable must be set to yes or no";;
	esac
}

pp_load_service_vars () {
	pp_service_init_vars
	. "$pp_wrkdir/%service.$1"
	pp_service_check_vars "$1"
}

pp_files_expand () {
    typeset _p _mode _group _owner _flags _path _optional _has_target _tree
    typeset _target _file _tgt _m _o _g _f _type _lm _ll _lo _lg _ls _lx
    typeset _ignore _a

    test $# -eq 0 && return

    pp_debug "pp_files_expand: path is: $1"

    case "$1" in "#"*) return;; esac
    _p="$1"; shift

    pp_debug "pp_files_expand: other arguments: $*"

    #-- the mode must be an octal number of at least three digits
    _mode="="
    _a=`eval echo \"$1\"`
    case "$_a" in
	*:*) :;;
	-|=|[01234567][01234567][01234567]*) _mode="$_a"; shift;;
    esac

    #-- the owner:group field may have optional parts
    _a=`eval echo \"$1\"`
    case "$_a" in
	*:*) _group=${_a#*:}; _owner=${_a%:*}; shift;;
	=|-) _group=$_a;      _owner=$_a; shift;;
	*)   _group=;         _owner=;;
    esac

    #-- process the flags argument
    _flags=
    _target=
    _optional=false
    _has_target=false
    _ignore=false
    if test $# -gt 0; then
        _a=`eval echo \"$1\"`
	case ",$_a," in *,volatile,*) _flags="${_flags}v";; esac
	case ",$_a," in *,optional,*) _optional=true;; esac
	case ",$_a," in *,symlink,*) _has_target=true;; esac
	case ",$_a," in *,ignore-others,*) _flags="${_flags}i";; esac
	case ",$_a," in *,ignore,*) _ignore=true;; esac
	shift
    fi

    #-- process the target argument
    if $_has_target; then
	test $# -ne 0 || pp_error "$_p: missing target"
	_a=`eval echo \"$1\"`
	_target="$_a"
	shift
    fi

    pp_debug "pp_files_expand: $_mode|$_owner:$_group|$_flags|$_target|$*"

    test $# -eq 0 || pp_error "$_p: too many arguments"

    #-- process speciall suffixes
    tree=
    case "$_p" in
        *"/**")  _p="${_p%"/**"}"; tree="**";;
        *".%so") _p="${_p%".%so"}$pp_shlib_suffix";;
    esac

    #-- expand the path using the shell glob
    pp_debug "expanding .$_p ... with $pp_expand_path"
    (cd ${pp_destdir} && $pp_expand_path ".$_p") > $pp_wrkdir/tmp.files.exp

    #-- expand path/** by rewriting the glob output file
    case "$tree" in
        "") : ;;
        "**")
            pp_debug "expanding /** tree ..."
            while read _path; do
                _path="${_path#.}"
                pp_find_recurse "$pp_destdir${_path%/}"
            done < $pp_wrkdir/tmp.files.exp |
                 sort -u > $pp_wrkdir/tmp.files.exp2
            mv $pp_wrkdir/tmp.files.exp2 $pp_wrkdir/tmp.files.exp
            ;;
    esac

    while read _path; do
	_path="${_path#.}"
	_file="${pp_destdir}${_path}"
	_tgt=
	_m="$_mode"
	_o="${_owner:--}"
	_g="${_group:--}"
	_f="$_flags"

        case "$_path" in
            /*) :;;
            *)  pp_warn "$_path: inserting leading /"
                _path="/$_path";;  # ensure leading /
        esac

        #-- sanity checks
        case "$_path" in
            */../*|*/..) pp_error "$_path: invalid .. in path";;
            */./*|*/.)   pp_warn  "$_path: invalid component . in path";;
            *//*)        pp_warn  "$_path: redundant / in path";;
        esac

	#-- set the type based on the real file's type
        if $_ignore; then
           _type=f _m=_ _o=_ _g=_
	elif test -h "$_file"; then
	   case "$_path" in
		*/) pp_warn "$_path (symlink $_file): removing trailing /"
		    _path="${_path%/}"
		    ;;
	   esac
	   _type=s
	   if test x"$_target" != x"=" -a -n "$_target"; then
	       _tgt="$_target"
pp_debug "symlink target is $_tgt"
	   else
	       _tgt=`pp_readlink "$_file"`;
               test -z "$_tgt" && pp_error "can't readlink $_file"
               case "$_tgt" in
                    ${pp_destdir}/*)
                       pp_warn "stripped \$destdir from symlink ($_path)"
                       _tgt="${_tgt#$pp_destdir}";;
               esac
	   fi
	   _m=777
	elif test -d "$_file"; then
	   #-- display a warning if the user forgot the trailing /
	   case "$_path" in
		*/) :;;
		*) pp_warn "$_path (matching $_file): adding trailing /"
		   _path="$_path/";;
	   esac
	   _type=d
	   $_has_target && pp_error "$_file: not a symlink"
	elif test -f "$_file"; then
	   case "$_path" in
		*/) pp_warn "$_path (matching $_file): removing trailing /"
		    _path="${_path%/}"
		    ;;
	   esac
	   _type=f
	   $_has_target && pp_error "$_file: not a symlink"
	else
	   $_optional && continue
	   pp_error "$_file: missing"
	   _type=f
	fi

	#-- convert '=' shortcuts into mode/owner/group from ls
	case ":$_m:$_o:$_g:" in *:=:*)
	    if LS_OPTIONS=--color=never /bin/ls -ld "$_file" \
		    > $pp_wrkdir/ls.tmp
	    then
                read _lm _ll _lo _lg _ls _lx < $pp_wrkdir/ls.tmp
                test x"$_m" = x"=" && _m=`pp_mode_from_ls "$_lm"`
                test x"$_o" = x"=" && _o="$_lo"
                test x"$_g" = x"=" && _g="$_lg"
            else
                pp_error "cannot read $_file"
                test x"$_m" = x"=" && _m=-
                test x"$_o" = x"=" && _o=-
                test x"$_g" = x"=" && _g=-
            fi
	    ;;
	esac

	test -n "$_f" || _f=-

	#-- sanity checks
	test -n "$_type" || pp_die "_type empty"
	test -n "$_path" || pp_die "_path empty"
	test -n "$_m" || pp_die "_m empty"
	test -n "$_o" || pp_die "_o empty"
	test -n "$_g" || pp_die "_g empty"

	#-- setuid/gid files must be given an explicit owner/group (or =)
	case "$_o:$_g:$_m" in
	    -:*:[4657][1357]??|-:*:[4657]?[1357]?|-:*:[4657]??[1357])
		pp_error "$_path: setuid file ($_m) missing explicit owner";;
	    *:-:[2367][1357]??|*:-:[2367]?[1357]?|*:-:[2367]??[1357])
		pp_error "$_path: setgid file ($_m) missing explicit group";;
	esac

	# convert numeric uids into usernames; only works for /etc/passwd
	case "$_o" in [0-9]*) _o=`pp_getpwuid $_o`;; esac
	case "$_g" in [0-9]*) _g=`pp_getgrgid $_g`;; esac

	pp_debug "$_type $_m $_o $_g $_f $_path" $_tgt
	$_ignore || echo "$_type $_m $_o $_g $_f $_path" $_tgt
        pp_note_file_used "$_path"
        case "$_f" in *i*) echo "$_path" >> $pp_wrkdir/ign.files;; esac
    done < $pp_wrkdir/tmp.files.exp
}

pp_files_check_duplicates () {
    typeset _path
    if test -s $pp_wrkdir/all.files; then
        sort < $pp_wrkdir/all.files | uniq -d > $pp_wrkdir/duplicate.files
	if test -f $pp_wrkdir/ign.awk; then
	    # Remove ignored files
	    mv $pp_wrkdir/duplicate.files $pp_wrkdir/duplicate.files.ign
	    sed -e 's/^/_ _ _ _ _ /' < $pp_wrkdir/duplicate.files.ign |
		awk -f $pp_wrkdir/ign.awk |
		sed -e 's/^_ _ _ _ _ //' > $pp_wrkdir/duplicate.files
	fi
        while read _path; do
            pp_warn "$_path: file declared more than once"
        done <$pp_wrkdir/duplicate.files
    fi
}

pp_files_check_coverage () {
    pp_find_recurse "$pp_destdir" | sort > $pp_wrkdir/coverage.avail
    if test -s $pp_wrkdir/all.files; then
        sort -u < $pp_wrkdir/all.files
    else
        :
    fi > $pp_wrkdir/coverage.used
    join -v1 $pp_wrkdir/coverage.avail $pp_wrkdir/coverage.used \
        > $pp_wrkdir/coverage.not-packaged
    if test -s $pp_wrkdir/coverage.not-packaged; then
        pp_warn "The following files/directories were found but not packaged:"
        sed -e 's,^,    ,' <  $pp_wrkdir/coverage.not-packaged >&2
    fi
    join -v2 $pp_wrkdir/coverage.avail $pp_wrkdir/coverage.used \
        > $pp_wrkdir/coverage.not-avail
    if test -s $pp_wrkdir/coverage.not-avail; then
        pp_warn "The following files/directories were named but not found:"
        sed -e 's,^,    ,' <  $pp_wrkdir/coverage.not-avail >&2
    fi
}

pp_files_ignore_others () {
    typeset p f

    test -s $pp_wrkdir/ign.files || return

    #-- for each file in ign.files, we remove it from all the
    #   other %files.* lists, except where it has an i flag.
    #   rather than scan each list multiple times, we build
    #   an awk script

    pp_debug "stripping ignore files"

    while read p; do
        echo '$6 == "'"$p"'" && $5 !~ /i/ { next }'
    done < $pp_wrkdir/ign.files > $pp_wrkdir/ign.awk
    echo '{ print }' >> $pp_wrkdir/ign.awk

    $pp_opt_debug && cat $pp_wrkdir/ign.awk

    for f in $pp_wrkdir/%files.*; do
	mv $f $f.ign
        awk -f $pp_wrkdir/ign.awk < $f.ign > $f || pp_error "awk"
    done
}

pp_service_scan_groups () {
    typeset svc

    #-- scan for "group" commands, and build a list of groups
    pp_service_groups=
    if test -n "$pp_services"; then
        for svc in $pp_services; do
	    group=
	    . $pp_wrkdir/%service.$svc
	    if test -n "$group"; then
		pp_contains "$pp_services" "$group" && pp_error \
		    "%service $svc: group name $group in use by a service"
		pp_add_to_list 'pp_service_groups' "$group"
		echo "$svc" >> $pp_wrkdir/%svcgrp.$group
	    fi
        done
    fi
}

pp_service_get_svc_group () {
    (tr '\012' ' ' < $pp_wrkdir/%svcgrp.$1 ; echo) | sed -e 's/ $//'
}

for _sufx in _init '' _names _cleanup _install_script \
    _init_svc_vars _function _probe _vas_platforms
do
 eval "pp_backend$_sufx () { pp_debug pp_backend$_sufx; pp_backend_\${pp_platform}$_sufx \"\$@\"; }"
done


pp_platforms="$pp_platforms aix"

pp_backend_aix_detect () {
	test x"$1" = x"AIX"
}

pp_backend_aix_init () {
        pp_aix_detect_arch
        pp_aix_detect_os

	pp_aix_bosboot=		# components that need bosboot
	pp_aix_lang=en_US
	pp_aix_copyright=
        pp_aix_start_services_after_install=false
        pp_aix_init_services_after_install=true

        pp_aix_sudo=sudo	# AIX package tools must run as root

        case "$pp_aix_os" in
            *) pp_readlink_fn=pp_ls_readlink;;  # XXX
        esac

	pp_aix_abis_seen=
}

pp_aix_detect_arch () {
	pp_aix_arch_p=`uname -p 2>/dev/null`
	case "$pp_aix_arch_p"  in
	   "")      pp_debug "can't get processor type from uname -p"
                    pp_aix_arch_p=powerpc
                    pp_aix_arch=R;;  # guess (lsattr -l proc0 ??)
	   powerpc) pp_aix_arch=R;;
	   *)       pp_aix_arch_p=intel
                    pp_aix_arch=I;;  # XXX? verify
	esac

	case "`/usr/sbin/lsattr -El proc0 -a type -F value`" in
	    PowerPC_POWER*) pp_aix_arch_std=ppc64;;
	    PowerPC*) pp_aix_arch_std=ppc;;
	    *) pp_aix_arch_std=unknown;;
	esac
}

pp_aix_detect_os () {
        typeset r v

        r=`uname -r`
        v=`uname -v`
        pp_aix_os=aix$v$r
}

pp_aix_version_fix () {
    typeset v
    v=`echo $1 | sed 's/[-+]/./' | tr -c -d '[0-9].\012' | awk -F"." '{ printf "%d.%d.%d.%.4s\n", $1, $2, $3, $4 }' | sed 's/[.]*$//g'`
    if test x"$v" != x"$1"; then
        pp_warn "stripped version '$1' to '$v'"
    fi
    case $v in
        ""|*..*|.*|*.) pp_error "malformed '$1'"
                 echo "0.0.0.0";;
        *.*.*.*.*)
                 # 5 components are only valid for fileset updates, not base
                 # filesets (full packages). We trim 5+ components down to 4.
                 pp_warn "version '$1' has too many dots for AIX, truncating"
                 echo "$v" | cut -d. -f1-4;;
        *.*.*.*) echo "$v";;
        *.*.*) echo "$v.0";;
        *.*) echo "$v.0.0";;
        *) echo "$v.0.0.0";;
    esac
}

pp_aix_select () {
	case "$1" in
	    -user) op="";;
	    -root) op="!";;
	    *) pp_die "pp_aix_select: bad argument";;
	esac
	#pp_debug awk '$5 '$op' /^\/(usr|opt)(\/|$)/ { print; }'
	#awk '$5 '$op' /^\/(usr|opt)(\/|$)/ { print; }'
	awk $op'($6 ~ /^\/usr\// || $6 ~ /^\/opt\//) { print; }'
}

pp_aix_copy_root () {
    typeset t m o g f p st target
    while read t m o g f p st; do
        case "$t" in
           d) pp_create_dir_if_missing "$1${p%/}";;
           f) pp_add_transient_file "$1$p"
	      pp_verbose ln "$pp_destdir$p" "$pp_destdir$1$p" ||
		pp_error "can't link $p into $1";;
           *) pp_warn "pp_aix_copy_root: filetype $t not handled";;
        esac
    done
}

pp_aix_size () {
    typeset prefix t m o g f p st

    prefix="$1"
    while read t m o g f p st; do
      case "$t" in f) du -a "$pp_destdir$p";; esac
    done | sed -e 's!/[^/]*$!!' | sort +1 |
    awk '{ if ($2 != d)
           { if (sz) print d,sz;
             d=$2; sz=0 }
           sz += $1; }
         END { if (sz) print d,sz }' |
    sed -n -e "s!^$pp_destdir!$prefix!p"
}

pp_aix_list () {
    awk '{ print "." pfx $6; }' pfx="$1"
}

pp_aix_make_liblpp () {
    typeset out dn fl f

    out="$1"; shift
    dn=`dirname "$2"`
    fl=
    for f
    do
	case "$f" in "$dn/"*) fl="$fl `basename $f`" ;;
		     *) pp_die "liblpp name $f not in $dn/";; esac
    done
    (cd "$dn" && pp_verbose  ar -c -g -r "$out" $fl) || pp_error "ar error"
}

pp_aix_make_script () {
    rm -f "$1"
    echo "#!/bin/sh" > "$1"
    cat >> "$1"
    echo "exit 0" >> "$1"
    chmod +x "$1"
}

pp_aix_inventory () {
    typeset fileset t m o g f p st type

    fileset="$1"
    while read t m o g f p st; do
      case "$p" in *:*) pp_error "path $p contains colon";; esac
      echo "$p:"
      case "$t" in
	f)   type=FILE;      defm=644 ;;
	s)   type=SYMLINK;   defm=777 ;;
	d)   type=DIRECTORY; defm=755 ;;
      esac
      echo " type = $type"
      echo " class = inventory,apply,$fileset"
      if test x"$m" = x"-"; then m="$defm"; fi
      if test x"$o" = x"-"; then o="root"; fi
      if test x"$g" = x"-"; then g="system"; fi
      echo " owner = $o"
      echo " group = $g"

      case "$m" in ????)
	m=`echo $m|sed -e 's/^1/TCB,/' \
		       -e 's/^[23]/TCB,SGID,/' \
		       -e 's/^[45]/TCB,SUID,/' \
		       -e 's/^[67]/TCB,SUID,SGID,/'`;;  # vtx bit ignored
      esac
      echo " mode = $m"
      case "$t" in
	f) if test ! -f "$pp_destdir$p"; then
		pp_error "$p: missing file"
	   fi
	   case "$flags" in
	    *v*)
	      echo " size = VOLATILE"
	      echo " checksum = VOLATILE"
	      ;;
	    *)
	      if test -r "$pp_destdir$p"; then
	        echo " size = $size"
                pp_verbose  sum -r < "$pp_destdir$p" |
	      	  sed -e 's/.*/ checksum = "&"/'
	      fi
	      ;;
	   esac;;
	s)
	   echo " target = $st"
	   ;;
      esac

      #-- Record ABI types seen
      case "$t" in
        f) if test -r "$pp_destdir$p"; then
	    case "`file "$pp_destdir$p"`" in
		*"executable (RISC System/6000)"*) abi=ppc;;
		*"64-bit XCOFF executable"*)       abi=ppc64;;
		*) abi=;;
	    esac
	    if test -n "$abi"; then
		pp_add_to_list pp_aix_abis_seen $abi
	    fi
	   fi;;
      esac

    done
}

pp_aix_depend ()
{
    if test -s "$1"; then
       pp_warn "aix dependencies not implemented"
    fi
}

pp_aix_add_service () {
	typeset svc cmd_cmd cmd_arg f
	svc="$1"

	pp_load_service_vars $svc

	set -- $cmd
	cmd_cmd="$1"; shift
	cmd_arg="${pp_aix_mkssys_cmd_args:-$*}";

	case "$stop_signal" in
		HUP) stop_signal=1;;
		INT) stop_signal=2;;
		QUIT) stop_signal=3;;
		KILL) stop_signal=9;;
		TERM) stop_signal=15;;
		USR1) stop_signal=30;;
		USR2) stop_signal=31;;
		"")
		  pp_error "%service $svc: stop_signal not set";;
		[a-zA-Z]*)
		  pp_error "%service $svc: bad stop_signal ($stop_signal)";;
	esac

	test -z "$pidfile" || pp_error "aix requires empty pidfile (non daemon)"

	pp_add_component run
	if test "$user" = "root"; then
	    uid=0
	else
            uid="\"\`/usr/bin/id -u $user\`\""
	fi


        #-- add command text to create/remove the service
	cat <<-. >> $pp_wrkdir/%post.$svc
svc=$svc
uid=0
cmd_cmd="$cmd_cmd"
cmd_arg="$cmd_arg"
stop_signal=$stop_signal
force_signal=9
srcgroup="$pp_aix_mkssys_group"
instances_allowed=${pp_aix_mkssys_instances_allowed:--Q}

lssrc -s \$svc > /dev/null 2>&1
if [ \$? -eq 0 ]; then
  lssrc -s \$svc | grep "active" > /dev/null 2>&1
  if [ \$? -eq 0 ]; then
    stopsrc -s \$svc > /dev/null 2>&1
  fi
  rmsys -s \$svc > /dev/null 2>&1
fi

mkssys -s \$svc -u \$uid -p "\$cmd_cmd" \${cmd_arg:+-a "\$cmd_arg"} -S -n \$stop_signal -f 9 ${pp_aix_mkssys_args} \${srcgroup:+-G \$srcgroup} \$instances_allowed
.

        #-- add code to start the service on reboot
        ${pp_aix_init_services_after_install} &&
          cat <<-. >> $pp_wrkdir/%post.$svc
id=\`echo "\$svc" | cut -c1-14\`
mkitab "\$id:2:once:/usr/bin/startsrc -s \$svc" > /dev/null 2>&1
.

	${pp_aix_start_services_after_install} &&
          cat <<-. >> $pp_wrkdir/%post.$svc
startsrc -s \$svc
.

if [ -f "$pp_wrkdir/%post.run" ];then
    cat $pp_wrkdir/%post.run >> $pp_wrkdir/%post.$svc
fi
mv $pp_wrkdir/%post.$svc $pp_wrkdir/%post.run


        ${pp_aix_init_services_after_install} &&
           pp_prepend $pp_wrkdir/%preun.$svc <<-.
rmitab `echo "$svc" | cut -c1-14` > /dev/null 2>&1
.
	pp_prepend $pp_wrkdir/%preun.$svc <<-.
stopsrc -s $svc >/dev/null 2>&1
rmssys -s $svc
.

if [ -f "$pp_wrkdir/%preun.run" ];then
    cat $pp_wrkdir/%preun.run >> $pp_wrkdir/%preun.$svc
fi
mv $pp_wrkdir/%preun.$svc $pp_wrkdir/%preun.run
}

pp_backend_aix () {
        typeset briefex instuser instroot svc cmp outbff
        typeset user_wrkdir root_wrkdir
        typeset user_files root_files

	test -n "$pp_destdir" ||
	   pp_error "AIX backend requires the '--destdir' option"

	instuser="/usr/lpp/$name"
	instroot="$instuser/inst_root"
	pp_aix_bff_name=${pp_aix_bff_name:-$name}

	# Here is the component mapping:
	#  run -> $pp_aix_bff_name.rte ('Run time environment')
	#  doc -> $pp_aix_bff_name.doc (non-standard)
	#  dev -> $pp_aix_bff_name.adt ('Application developer toolkit')
	#  dbg -> $pp_aix_bff_name.diag ('Diagnostics')

	test `echo "$summary" | wc -c ` -gt 40 && pp_error "\$summary too long"

	user_wrkdir=$pp_wrkdir/u
	root_wrkdir=$pp_wrkdir/r
	pp_verbose  rm -rf $user_wrkdir $root_wrkdir
	pp_verbose  mkdir -p $user_wrkdir $root_wrkdir

	for svc in $pp_services .; do
	    test . = "$svc" && continue
            pp_aix_add_service $svc
	done

        {
	  echo "4 $pp_aix_arch I $name {"

	  for cmp in $pp_components; do
	    case "$cmp" in
		run) ex=rte  briefex="runtime";;
		doc) ex=doc  briefex="documentation";;
		dev) ex=adt  briefex="developer toolkit";;
		dbg) ex=diag briefex="diagnostics";;
	    esac

	    user_files=$pp_wrkdir/%files.$cmp.u
	    root_files=$pp_wrkdir/%files.$cmp.r

	    pp_aix_select -user < $pp_wrkdir/%files.$cmp > $user_files
	    pp_aix_select -root < $pp_wrkdir/%files.$cmp > $root_files

            # Default to USR only unless there are root files,
            # or a post/pre/check script associated
	    content=U
            if test -s $root_files \
                    -o -s $pp_wrkdir/%pre.$cmp \
                    -o -s $pp_wrkdir/%post.$cmp \
                    -o -s $pp_wrkdir/%preun.$cmp \
                    -o -s $pp_wrkdir/%postun.$cmp \
                    -o -s $pp_wrkdir/%check.$cmp
            then
                content=B
            fi

            if $pp_opt_debug; then
                echo "$cmp USER %files:"
                cat $user_files
                echo "$cmp ROOT %files:"
                cat $root_files
            fi >&2

	    bosboot=N; pp_contains_any "$pp_aix_bosboot" $cmp && bosboot=b

            echo $pp_aix_bff_name.$ex \
             `[ $pp_aix_version ] && pp_aix_version_fix $pp_aix_version || pp_aix_version_fix "$version"` \
	         1 $bosboot $content \
	         $pp_aix_lang "$summary $briefex"
	    echo "["

	    pp_aix_depend $pp_wrkdir/%depend.$cmp

	    echo "%"

	    # generate per-directory size information
	    pp_aix_size < $user_files
	    pp_aix_size $instroot < $root_files

	    pp_aix_list            < $user_files  > $user_wrkdir/$pp_aix_bff_name.$ex.al
	    pp_aix_list $instroot  < $root_files >> $user_wrkdir/$pp_aix_bff_name.$ex.al
	    pp_aix_list            < $root_files  > $root_wrkdir/$pp_aix_bff_name.$ex.al

            if $pp_opt_debug; then
                echo "$cmp USER $pp_aix_bff_name.$ex.al:"
                cat $user_wrkdir/$pp_aix_bff_name.$ex.al
                echo "$cmp ROOT $pp_aix_bff_name.$ex.al:"
                cat $root_wrkdir/$pp_aix_bff_name.$ex.al
            fi >&2

	    pp_aix_inventory $pp_aix_bff_name.$ex < $user_files \
                                       > $user_wrkdir/$pp_aix_bff_name.$ex.inventory
	    pp_aix_inventory $pp_aix_bff_name.$ex < $root_files \
                                       > $root_wrkdir/$pp_aix_bff_name.$ex.inventory

            if $pp_opt_debug; then
                pp_debug "$cmp USER $pp_aix_bff_name.$ex.inventory:"
                cat $user_wrkdir/$pp_aix_bff_name.$ex.inventory
                pp_debug "$cmp ROOT $pp_aix_bff_name.$ex.inventory:"
                cat $root_wrkdir/$pp_aix_bff_name.$ex.inventory
            fi >&2

	    if test x"" != x"${pp_aix_copyright:-$copyright}"; then
	        echo "${pp_aix_copyright:-$copyright}" > $user_wrkdir/$pp_aix_bff_name.$ex.copyright
	        echo "${pp_aix_copyright:-$copyright}" > $root_wrkdir/$pp_aix_bff_name.$ex.copyright
	    fi

	    #-- assume that post/pre uninstall scripts only make
	    #   sense when installed in a root context

	    if test -r $pp_wrkdir/%pre.$cmp; then
			pp_aix_make_script $user_wrkdir/$pp_aix_bff_name.$ex.pre_i \
                < $pp_wrkdir/%pre.$cmp
	    fi

	    if test -r $pp_wrkdir/%post.$cmp; then
		pp_aix_make_script $root_wrkdir/$pp_aix_bff_name.$ex.post_i \
			< $pp_wrkdir/%post.$cmp
	    fi

	    if test -r $pp_wrkdir/%preun.$cmp; then
		pp_aix_make_script $root_wrkdir/$pp_aix_bff_name.$ex.unpost_i \
			< $pp_wrkdir/%preun.$cmp
	    fi

	    if test -r $pp_wrkdir/%postun.$cmp; then
		pp_aix_make_script $root_wrkdir/$pp_aix_bff_name.$ex.unpre_i \
			< $pp_wrkdir/%postun.$cmp
	    fi

	    # remove empty files
	    for f in $user_wrkdir/$pp_aix_bff_name.$ex.* $root_wrkdir/$pp_aix_bff_name.$ex.*; do
	      if test ! -s "$f"; then
                pp_debug "removing empty $f"
                rm -f "$f"
              fi
	    done

	    # copy/link the root files so we can do an easy backup later
	    pp_aix_copy_root $instroot < $root_files

	    echo "%"
	    echo "]"
	  done
	  echo "}"
	} > $pp_wrkdir/lpp_name

        if $pp_opt_debug; then
            echo "/lpp_name :"
            cat $pp_wrkdir/lpp_name
        fi >&2

        #-- copy the /lpp_name file to the destdir
        pp_add_transient_file /lpp_name
        cp $pp_wrkdir/lpp_name $pp_destdir/lpp_name

        #-- copy the liblpp.a files under destdir for packaging
	(cd $user_wrkdir && pp_verbose  ar -c -g -r liblpp.a $name.*) ||
		pp_error "ar error"
	if test -s $user_wrkdir/liblpp.a; then
           pp_add_transient_file $instuser/liblpp.a
	   pp_verbose cp $user_wrkdir/liblpp.a $pp_destdir$instuser/liblpp.a ||
		pp_error "cannot create user liblpp.a"
	fi
	(cd $root_wrkdir && pp_verbose  ar -c -g -r liblpp.a $name.*) ||
		pp_error "ar error"
	if test -s $root_wrkdir/liblpp.a; then
           pp_add_transient_file $instroot/liblpp.a
	   pp_verbose cp $root_wrkdir/liblpp.a $pp_destdir$instroot/liblpp.a ||
		pp_error "cannot create root liblpp.a"
	fi

        { echo ./lpp_name
	  test -s $user_wrkdir/liblpp.a && echo .$instuser/liblpp.a
	  test -s $root_wrkdir/liblpp.a && echo .$instroot/liblpp.a
	  cat $user_wrkdir/$name.*.al   # includes the relocated root files!
	} > $pp_wrkdir/bff.list

	if test -n "$pp_aix_abis_seen" -a x"$pp_aix_arch_std" = x"auto"; then
	    case "$pp_aix_abis_seen" in
		"ppc ppc64"|"ppc64 ppc")
		    pp_aix_arch_std=ppc64
		    ;;
		ppc|ppc64)
		    pp_aix_arch_std=$pp_aix_abis_seen
		    ;;
		*" "*)
		    pp_warn "multiple architectures detected: $pp_aix_abis_seen"
		    pp_aix_arch_std=unknown
		    ;;
		"")
		    pp_warn "no binary executables detected; using noarch"
		    pp_aix_arch_std=noarch
		    ;;
		*)
		    pp_warn "unknown architecture detected $pp_aix_abis_seen"
		    pp_aix_arch_std=$pp_aix_abis_seen
		    ;;
	    esac
	fi

	. $pp_wrkdir/%fixup

        outbff=`pp_backend_aix_names`
        pp_debug "creating: $pp_wrkdir/$outbff"
	(cd $pp_destdir && pp_verbose  /usr/sbin/backup -i -q -p -f -) \
          < $pp_wrkdir/bff.list \
	  > $pp_wrkdir/$outbff || pp_error "backup failed"
	if test -n "$pp_aix_sudo" -o -x /usr/sbin/installp; then
	    $pp_aix_sudo /usr/sbin/installp -l -d $pp_wrkdir/$outbff
	fi
}

pp_backend_aix_cleanup () {
    :
}

pp_backend_aix_names () {
    echo "$name.`[ $pp_aix_version ] && pp_aix_version_fix $pp_aix_version || pp_aix_version_fix "$version"`.bff"
}

pp_backend_aix_install_script () {
	typeset pkgname platform
        #
        # The script should take a first argument being the
        # operation; further arguments refer to components or services
        #
        # list-components           -- lists components in the pkg
        # install component...      -- installs the components
        # uninstall component...    -- uninstalles the components
        # list-services             -- lists the services in the pkg
        # start service...          -- starts the name service
        # stop service...           -- stops the named services
        # print-platform            -- prints the platform group
        #
        pkgname="`pp_backend_aix_names`"
	platform="`pp_backend_aix_probe`"   # XXX should be derived from files

        fsets=
        for cmp in $pp_components; do
	    case "$cmp" in
		run) ex=rte;;
		doc) ex=doc;;
		dev) ex=adt;;
		dbg) ex=diag;;
	    esac
            fsets="$fsets $name.$ex"
        done

        echo '#!/bin/sh'
        pp_install_script_common

        cat <<-.

            cpt_to_fileset () {
                test x"\$*" = x"all" &&
                    set -- $pp_components
                for cpt
                do
                    case "\$cpt" in
                        run) echo "$name.rte";;
                        doc) echo "$name.doc";;
                        dev) echo "$name.adt";;
                        dbg) echo "$name.diag";;
                        *) usage;;
                    esac
                done
            }

	    test \$# -eq 0 && usage
            op="\$1"; shift

            case "\$op" in
                list-components)
                    test \$# -eq 0 || usage \$op
                    echo "$pp_components"
                    ;;
                list-services)
                    test \$# -eq 0 || usage \$op
                    echo "$pp_services"
                    ;;
                list-files)
                    test \$# -ge 1 || usage \$op
                    echo \${PP_PKGDESTDIR:-.}/$pkgname
                    ;;
                install)
                    test \$# -ge 1 || usage \$op
                    verbose /usr/sbin/installp -acX -V0 -F \
                        -d \${PP_PKGDESTDIR:-.}/$pkgname \
                        \`cpt_to_fileset "\$@"\`
                    ;;
                uninstall)
                    test \$# -ge 1 || usage \$op
                    verbose /usr/sbin/installp -u -e/dev/null \
			-V0 \`cpt_to_fileset "\$@"\`
                    ;;
                start|stop)
                    test \$# -ge 1 || usage \$op
                    ec=0
                    for svc
                    do
                        verbose \${op}src -s \$svc || ec=1
                    done
                    exit \$ec
                    ;;
                print-platform)
                    echo "$platform"
		    ;;
                *)
                    usage;;
            esac
.
}

pp_backend_aix_init_svc_vars () {
    :
}

pp_backend_aix_probe () {
	echo "${pp_aix_os}-${pp_aix_arch_std}"
}

pp_backend_aix_vas_platforms () {
    case "${pp_aix_arch_std}" in
	ppc*)	:;;
	*)	pp_die "unknown architecture ${pp_aix_arch_std}";;
    esac
    case "${pp_aix_os}" in
	aix43)	echo "aix-43";;
	aix51)	echo "aix-51 aix-43";;
	aix52)	echo "aix-51 aix-43";;
	aix53)	echo "aix-53 aix-51 aix-43";;
	aix61)	echo "aix-53 aix-51 aix-43";;
	*)	pp_die "unknown system ${pp_aix_os}";;
    esac
}
pp_backend_aix_function () {
    case "$1" in
    pp_mkgroup) cat <<'.';;
            /usr/sbin/lsgroup "$1" >/dev/null &&
		return 0
	    echo "Creating group $1"
            /usr/bin/mkgroup -A "$1"
.
    pp_mkuser:depends) echo pp_mkgroup;;
    pp_mkuser) cat <<'.';;
            /usr/sbin/lsuser "$1" >/dev/null &&
	        return 0
	    pp_mkgroup "${2:-$1}" || return 1
	    echo "Creating user $1"
	    /usr/bin/mkuser \
	        login=false \
	        rlogin=false \
		account_locked=true \
		home="${3:-/nohome.$1}" \
		pgrp="${2:-$1}" \
		"$1"
.
    pp_havelib) cat <<'.';;
            case "$2" in
                "")    pp_tmp_name="lib$1.so";;
                *.*.*) pp_tmp_name="lib$1.so.$2";;
                *.*)   pp_tmp_name="lib$1.so.$2.0";;
                *)     pp_tmp_name="lib$1.so.$2";;
            esac
            for pp_tmp_dir in `echo "/usr/lib:/lib${3:+:$3}" | tr : ' '`; do
                test -r "$pp_tmp_dir/$pp_tmp_name" -a \
		    -r "$pp_tmp_dir/lib$1.so" && return 0
            done
            return 1
.
    *) false;;
    esac
}

pp_platforms="$pp_platforms sd"

pp_backend_sd_detect () {
    test x"$1" = x"HP-UX"
}

pp_backend_sd_init () {
    pp_sd_sudo=sudo
    pp_sd_startlevels=2
    pp_sd_stoplevels=auto
    pp_sd_config_file=
    pp_sd_vendor=
    pp_sd_vendor_tag=OneIdentity
    pp_sd_default_start=1           # config_file default start value

    pp_readlink_fn=pp_ls_readlink   # HPUX has no readlink
    pp_shlib_suffix='.sl'           # .so on most other platforms

    pp_sd_detect_os
}

pp_sd_detect_os () {
    typeset revision

    revision=`uname -r`
    pp_sd_os="${revision#?.}"
    test -z "$pp_sd_os" &&
        pp_warn "cannot detect OS version"
    pp_sd_os_std="hpux`echo $pp_sd_os | tr -d .`"

    case "`uname -m`" in
	9000/[678]??) pp_sd_arch_std=hppa;;
	ia64) pp_sd_arch_std=ia64;;
	*) pp_sd_arch_std=unknown;;
    esac
}

pp_sd_write_files () {
    typeset t m o g f p st line dm
    while read t m o g f p st; do
        line="                file"
        case "$f" in *v*) line="$line -v";; esac    # FIXME for uninstall
	case ${pp_sd_os} in
	    10.*)
		case $t in
		    f) dm=644;;
		    d) p=${p%/}; dm=755;;
		esac
		;;
	    *)
		case $t in
		    f) dm=644;;
		    d) line="$line -t d"; p=${p%/}; dm=755;;
		    s) line="$line -t s";;
		esac
		;;
	esac

        test x"$o" = x"-" && o=root
        test x"$g" = x"-" && g=sys
        test x"$m" = x"-" && m=$dm

        case $t in
            s)
		# swpackage will make unqualified links relative to the
		# current working (source) directory, not the destination;
		# we need to qualify them to prevent this.
		case "$st" in
		    [!/]*) st="`dirname \"$p\"`/$st";;
		esac
		echo "$line -o $o -g $g -m $m $st $p"
		;;
            *)
		echo "$line -o $o -g $g -m $m $pp_destdir$p $p"
		;;
        esac

    done
}

pp_sd_service_group_script () {
    typeset grp svcs scriptpath out
    grp="$1"
    svcs="$2"
    scriptpath="/sbin/init.d/$grp"
    out="$pp_destdir$scriptpath"

    pp_add_file_if_missing $scriptpath run 755 || return 0

    cat <<-. > $out
	#!/sbin/sh
	# generated by pp $pp_version
	svcs="$svcs"
.

    cat <<-'.' >> $out
	#-- starts services in order.. stops them all if any break
	pp_start () {
	    undo=
	    for svc in \$svcs; do
	        /sbin/init.d/\$svc start
	        case \$? in
	          0|4)
	            undo="\$svc \$undo"
	            ;;
	          *)
	            if test -n "\$undo"; then
	                for svc in \$undo; do
	                    /sbin/init.d/\$svc stop
	                done
	                return 1
	            fi
	            ;;
	        esac
	    done
	    return 0
	}

	#-- stops services in reverse
	pp_stop () {
	    reverse=
	    for svc in \$svcs; do
	        reverse="\$svc \$reverse"
	    done
	    rc=0
	    for svc in \$reverse; do
	        /sbin/init.d/\$svc stop || rc=\$?
	    done
	    return \$rc
        }

	case \$1 in
	    start_msg) echo "Starting \$svcs";;
	    stop_msg)  echo "Stopping \$svcs";;
	    start)     pp_start;;
	    stop)      pp_stop;;
	    *)	       echo "usage: \$0 {start|stop|start_msg|stop_msg}"
	               exit 1;;
	esac
.
}

pp_sd_service_script () {
    typeset svc config_file config_value scriptpath out

    svc="$1"
    scriptpath="/sbin/init.d/$svc"

    config_file=${pp_sd_config_file:-/etc/rc.config.d/$svc}
    sd_config_var=`echo run-$svc | tr '[a-z]-' '[A-Z]_'`
    sd_config_value=${pp_sd_default_start:-0}
    pp_load_service_vars "$svc"

    test -n "$user" -a x"$user" != x"root" &&
        cmd="SHELL=/usr/bin/sh /usr/bin/su $user -c \"exec `echo $cmd | sed -e 's,[$\\\`],\\&,g'`\""
    if test -z "$pidfile"; then
        pidfile="/var/run/$svc.pid"
        cmd="$cmd & echo \$! > \$pidfile"
    fi

    pp_debug "config file is $config_file"

    pp_add_file_if_missing $scriptpath run 755
    pp_add_file_if_missing $config_file run 644 v

    cat <<-. >> $pp_destdir$config_file

	# Controls whether the $svc service is started
	$sd_config_var=$sd_config_value
.

    if test ! -f $pp_destdir$scriptpath; then
    cat <<-. > $pp_destdir$scriptpath
	#!/sbin/sh
	# generated by pp $pp_version

	svc="$svc"
	pidfile="$pidfile"
	config_file="$config_file"

	pp_start () {
	    $cmd
	}

	pp_disabled () {
	    test \${$sd_config_var:-0} -eq 0
	}

	pp_stop () {
	    if test ! -s "\$pidfile"; then
	        echo "Unable to stop \$svc (no pid file)"
	        return 1
	    else
	        read pid < "\$pidfile"
	        if kill -0 "\$pid" 2>/dev/null; then
	            if kill -${stop_signal:-TERM} "\$pid"; then
	                rm -f "\$pidfile"
	                return 0
	            else
	                echo "Unable to stop \$svc"
	                return 1
	            fi
	        else
	            rm -f "\$pidfile"
	            return 0
	        fi
	    fi
	}

        pp_running () {
            if test -s "\$pidfile"; then
                read pid < "\$pidfile" 2>/dev/null
                if test \${pid:-0} -gt 1 && kill -0 "\$pid" 2>/dev/null; then
                    # make sure command name matches
                    c="\`echo $cmd | sed -e 's: .*::' -e 's:^.*/::'\`"
                    pid="\`ps -p \$pid 2>/dev/null | sed -n \"s/^ *\(\$pid\) .*\$c *\$/\1/p\"\`"
                    if test -n "\$pid"; then
                        return 0
                    fi
                fi
            fi
            return 1
        }

	case \$1 in
	    start_msg) echo "Starting the \$svc service";;
	    stop_msg)  echo "Stopping the \$svc service";;
	    start)
	            if test -f "\$config_file"; then
	                . \$config_file
	            fi
	            if pp_disabled; then
	                exit 2
	            elif pp_running; then
	                echo "\$svc already running";
	                exit 0
	            elif pp_start; then
	                echo "\$svc started";
	                # rc(1M) says we should exit 4, but nobody expects it!
	                exit 0
	            else
	                exit 1
	            fi;;
	    stop)   if pp_stop; then
	                echo "\$svc stopped";
	                exit 0
	            else
	                exit 1
	            fi;;
	    *) echo "usage: \$0 {start|stop|start_msg|stop_msg}"
	       exit 1;;
	esac
.
    fi
}

pp_sd_make_service () {
        typeset level startpriority stoppriority startlevels stoplevels
        typeset svc svcvar symtype

        svc="$1"
	svcvar=`pp_makevar $svc`

	case ${pp_sd_os} in
	    10.*) symtype="file";;
	    *) symtype="file -t s";;
	esac

        # TODO: Figure out why this check is here
        #-- don't do anything if the script exists
        #if test -s "$pp_destdir/sbin/init.d/$svc"; then
        #    pp_error "$pp_destdir/sbin/init.d/$svc exists"
        #    return
        #fi

        # symlink the script, depending on the priorities chosen
        eval startpriority='${pp_sd_startpriority_'$svcvar'}'
        eval stoppriority='${pp_sd_stoppriority_'$svcvar'}'
        test -z "$startpriority" && startpriority="${pp_sd_startpriority:-50}"
        test -z "$stoppriority" && stoppriority="${pp_sd_stoppriority:-50}"

        eval startlevels='${pp_sd_startlevels_'$svcvar'}'
        test -z "$startlevels" && startlevels="$pp_sd_startlevels"

        eval stoplevels='${pp_sd_stoplevels_'$svcvar'}'
        test -z "$stoplevels" && stoplevels="$pp_sd_stoplevels"

        # create the script and config file
        pp_sd_service_script $svc

        # fix the priority up
        case "$startpriority" in
            ???) :;;
            ??) startpriority=0$startpriority;;
            ?) startpriority=00$startpriority;;
        esac
        case "$stoppriority" in
            ???) :;;
            ??) stoppriority=0$stoppriority;;
            ?) stoppriority=00$stoppriority;;
        esac

        if test x"$stoplevels" = x"auto"; then
            stoplevels=
            test -z "$startlevels" || for level in $startlevels; do
                stoplevels="$stoplevels `expr $level - 1`"
            done
        fi

        # create the symlinks
        test -z "$startlevels" || for level in $startlevels; do
            echo "                ${symtype}" \
                    "/sbin/init.d/$svc" \
                    "/sbin/rc$level.d/S$startpriority$svc"
        done
        test -z "$stoplevels" || for level in $stoplevels; do
            echo "                ${symtype}" \
                    "/sbin/init.d/$svc" \
                    "/sbin/rc$level.d/K$stoppriority$svc"
        done
}

pp_sd_control () {
    typeset ctrl script
    typeset cpt

    ctrl="$1"; shift
    cpt="$1"; shift
    script="$pp_wrkdir/control.$ctrl.$cpt"
    cat <<. >$script
.
    cat "$@" >> $script
    echo "exit 0" >> $script
    /usr/bin/chmod +x $script
    echo "                $ctrl $script"
}

pp_sd_depend () {
    typeset _name _vers
    while read _name _vers; do
	case "$_name" in ""| "#"*) continue ;; esac
	echo "                prerequisites $_name ${_vers:+r>= $_vers}"
    done
}

pp_sd_conflict () {
    typeset _name _vers
    while read _name _vers; do
	case "$_name" in ""| "#"*) continue ;; esac
	echo "                exrequisites $_name ${_vers:+r>= $_vers}"
    done
}

pp_backend_sd () {
    typeset psf cpt svc outfile release swp_flags

    psf=$pp_wrkdir/psf
    release="?.${pp_sd_os%.[0-9][0-9]}.*"

    echo "depot" > $psf
    echo "layout_version 1.0" >>$psf

    #-- vendor
    cat <<. >>$psf
        vendor
            tag             $pp_sd_vendor_tag
            title           "${pp_sd_vendor:-$vendor}"
        end

        product
            tag             $name
            revision        $version
            vendor_tag      $pp_sd_vendor_tag
            is_patch        false
            title           "$summary"
            copyright       "$copyright"
            machine_type    *
            os_name         HP-UX
            os_release      $release
            os_version      ?
            directory       /
            is_locatable    false
.
    test -n "$description" \
        && echo $description > $pp_wrkdir/description \
        && cat <<. >> $psf
            description     < $pp_wrkdir/description
.

    # make convenience service groups
    if test -n "$pp_service_groups"; then
	for grp in $pp_service_groups; do
	    pp_sd_service_group_script \
		$grp "`pp_service_get_svc_group $grp`"
	done
    fi

    for cpt in $pp_components; do
        cat <<. >>$psf
            fileset
                tag             ${pp_sd_fileset_tag:-$cpt}
                title           "${summary:-cpt}"
                revision        $version
.
        test -s $pp_wrkdir/%depend.$cpt &&
              pp_sd_depend < $pp_wrkdir/%depend.$cpt >> $psf
        test -s $pp_wrkdir/%conflict.$cpt &&
              pp_sd_conflict < $pp_wrkdir/%conflict.$cpt >> $psf

	#-- make sure services are shut down during uninstall
        if test $cpt = run -a -n "$pp_services"; then
            for svc in $pp_services; do
                pp_prepend $pp_wrkdir/%preun.$cpt <<-.
			/sbin/init.d/$svc stop
.
            done
        fi

        #-- we put the post/preun code into configure/unconfigure
        # and not postinstall/preremove, because configure/unconfigure
        # scripts are run on the hosts where the package is installed,
        # not loaded (a subtle difference).
        test -s $pp_wrkdir/%pre.$cpt &&
            pp_sd_control checkinstall $cpt $pp_wrkdir/%pre.$cpt >> $psf
        test -s $pp_wrkdir/%post.$cpt &&
            pp_sd_control configure $cpt $pp_wrkdir/%post.$cpt >> $psf
        test -s $pp_wrkdir/%preun.$cpt &&
            pp_sd_control unconfigure $cpt $pp_wrkdir/%preun.$cpt >> $psf
        test -s $pp_wrkdir/%postun.$cpt &&
            pp_sd_control postremove $cpt $pp_wrkdir/%postun.$cpt >> $psf
        test -s $pp_wrkdir/%check.$cpt &&
            pp_sd_control checkinstall $cpt $pp_wrkdir/%check.$cpt >> $psf

        if test $cpt = run -a -n "$pp_services"; then
            for svc in $pp_services; do
                #-- service names are 10 chars max on hpux
                case "$svc" in ???????????*)
                    pp_warn "service name '$svc' is too long for hpux";;
                esac
                pp_sd_make_service $svc >> $psf
            done
            #pp_sd_make_service_config
        fi

        pp_sd_write_files < $pp_wrkdir/%files.$cpt >> $psf

        #-- end fileset clause
        cat <<. >>$psf
            end
.

    done

    #-- end product clause
    cat <<. >>$psf
        end
.

    $pp_opt_debug && cat $psf >&2

    test -s $pp_wrkdir/%fixup && . $pp_wrkdir/%fixup

    outfile=`pp_backend_sd_names`
    case ${pp_sd_os} in
	10.*)
	    swp_flags="-x target_type=tape"
	    ;;
	*)
	    swp_flags="-x media_type=tape"
	    ;;
    esac
    if pp_verbose ${pp_sd_sudo} /usr/sbin/swpackage -s $psf $swp_flags \
        @ $pp_wrkdir/$outfile
    then
        pp_verbose ${pp_sd_sudo} /usr/sbin/swlist -l file -s $pp_wrkdir/$outfile
    else
        pp_error "swpackage failed"
    fi
}

pp_backend_sd_cleanup () {
    :
}

pp_backend_sd_names () {
    echo "$name-$version.$pp_sd_arch_std.depot"
}

pp_backend_sd_install_script () {
    typeset pkgname platform

    pkgname=`pp_backend_sd_names`
    platform="`pp_backend_sd_probe`"

    echo "#!/bin/sh"
    pp_install_script_common
    cat <<.

        cpt_to_tags () {
            test x"\$*" = x"all" && set -- $pp_components
            for cpt
            do
                echo "$name.\$cpt"
            done
        }

        test \$# -eq 0 && usage
        op="\$1"; shift

        case "\$op" in
            list-components)
                test \$# -eq 0 || usage \$op
                echo "$pp_components"
                ;;
            list-services)
                test \$# -eq 0 || usage \$op
                echo "$pp_services"
                ;;
            list-files)
                test \$# -ge 1 || usage \$op
                echo \${PP_PKGDESTDIR:-.}/$pkgname
                ;;
            install)
                test \$# -ge 1 || usage \$op
                verbose /usr/sbin/swinstall -x verbose=0 \
                    -s \${PP_PKGDESTDIR:-\`pwd\`}/$pkgname \
                    \`cpt_to_tags "\$@"\`
                ;;
            uninstall)
                test \$# -ge 1 || usage \$op
                verbose /usr/sbin/swremove -x verbose=0 \
                    \`cpt_to_tags "\$@"\`
                ;;
            start|stop)
                test \$# -ge 1 || usage \$op
                ec=0
                for svc
                do
                    verbose /sbin/init.d/\$svc \$op
                    [ \$? -eq 4 -o \$? -eq 0 ] || ec=1
                done
                exit \$ec
                ;;
            print-platform)
		echo "$platform"
		;;
            *)
                usage
                ;;
        esac
.
}

pp_backend_sd_probe () {
    echo "${pp_sd_os_std}-${pp_sd_arch_std}"
}

pp_backend_sd_vas_platforms () {
    case "`pp_backend_sd_probe`" in
	hpux*-hppa) echo hpux-pa;;
	hpux*-ia64) echo hpux-ia64 hpux-pa;;
	*)	    pp_die "unknown system `pp_backend_sd_probe`";;
    esac
}

pp_backend_sd_init_svc_vars () {
    :
}
pp_backend_sd_function () {
    case "$1" in
        pp_mkgroup) cat <<'.';;
	    /usr/sbin/groupmod "$1" 2>/dev/null ||
		/usr/sbin/groupadd "$1"
.
        pp_mkuser:depends) echo pp_mkgroup;;
        pp_mkuser) cat <<'.';;
	    pp_mkgroup "${2:-$1}" || return 1
	    /usr/sbin/useradd \
		-g "${2:-$1}" \
		-d "${3:-/nonexistent}" \
		-s "${4:-/bin/false}" \
		"$1"
.
        pp_havelib) cat <<'.';;
            for pp_tmp_dir in `echo /usr/lib${3:+:$3} | tr : ' '`; do
                test -r "$pp_tmp_dir/lib$1${2:+.$2}.sl" && return 0
            done
            return 1
.
        *) false;;
    esac
}

pp_platforms="$pp_platforms solaris"

pp_backend_solaris_detect () {
	test x"$1" = x"SunOS"
}

pp_backend_solaris_init () {
	pp_solaris_category=
	pp_solaris_istates="s S 1 2 3"	# run-states when install is ok
	pp_solaris_rstates="s S 1 2 3"	# run-states when remove is ok
	pp_solaris_maxinst=
	pp_solaris_vendor=
	pp_solaris_pstamp=
	pp_solaris_copyright=
	pp_solaris_name=
	pp_solaris_desc=
	pp_solaris_package_arch=auto

        pp_solaris_detect_os
        pp_solaris_detect_arch

        pp_solaris_init_svc

        #-- readlink not reliably available on Solaris
	pp_readlink_fn=pp_ls_readlink
}

pp_solaris_detect_os () {
        typeset osrel

        osrel=`/usr/bin/uname -r`
        case "$osrel" in
	    5.[0-6])	pp_solaris_os="sol2${osrel#5.}";;
	    5.*)        pp_solaris_os="sol${osrel#5.}";;
        esac
        test -z "$pp_solaris_os" &&
             pp_warn "can't determine OS suffix from uname -r"

}

pp_solaris_detect_arch () {
	pp_solaris_arch=`/usr/bin/optisa amd64 sparcv9 i386 sparc`
	[ -z "$pp_solaris_arch" ] &&
	    pp_error "can't determine processor architecture"
	case "$pp_solaris_arch" in
	    amd64)   pp_solaris_arch_std=x86_64;;
	    i386)    pp_solaris_arch_std=i386;;
	    sparcv9) pp_solaris_arch_std=sparc64;;
	    sparc)   pp_solaris_arch_std=sparc;;
	    *)       pp_solaris_arch_std=unknown;;
	esac
}

pp_solaris_is_request_script_necessary () {
    typeset has_optional_services

    has_optional_services=no
    for _svc in $pp_services; do
    	pp_load_service_vars $_svc
	if test "$optional" = "yes"; then
	    has_optional_services=yes
	fi
    done

    # If the package has no optional services and only one component, don't
    # create a request script at all.
    if test "$has_optional_services" = "no" &&
       test `echo $pp_components | wc -w` -eq 1; then
	return 1 # no
    fi

    return 0 # yes
}

pp_solaris_request () {
    typeset _cmp _svc

    #-- The common part of the request script contains the ask() function
    #   and resets the CLASSES list to empty
    cat <<'.'
	trap 'exit 3' 15
	ask () {
	   ans=`ckyorn -d "$1" \
                -p "Do you want to $2"` \
            || exit $?
	   case "$ans" in y*|Y*) return 0;; *) return 1;; esac
	}
	CLASSES=
.
    #-- each of our components adds itself to the CLASSES list
    for _cmp in $pp_components; do
      case "$_cmp" in
            run) :;;
            doc) echo 'ask y "install the documentation files" &&';;
            dev) echo 'ask y "install the development files" &&';;
            dbg) echo 'ask n "install the diagnostic files" &&';;
      esac
      echo '    CLASSES="$CLASSES '$_cmp'"'
    done

    #-- the request script writes the CLASSES var to its output
    cat <<'.'
	echo "CLASSES=$CLASSES" > $1
.

    if test -n "$pp_services"; then
        echo 'SERVICES='
        for _svc in $pp_services; do
	    pp_load_service_vars $_svc
	    if test "$enable" = "yes"; then
		_default_prompt=y
	    else
		_default_prompt=n
	    fi
	    if test "$optional" = "yes"; then
		echo 'ask '$_default_prompt' "install '$_svc' service" &&'
	    fi
            echo '    SERVICES="$SERVICES '$_svc'"'
        done
        echo 'echo "SERVICES=$SERVICES" >> $1'
    fi

}

pp_solaris_procedure () {
    cat <<.

        #-- $2 for $1 component of $name
        case " \$CLASSES " in *" $1 "*)
.
    cat
    cat <<.
        ;; esac
.
}

pp_solaris_depend () {
    typeset _name _vers
    while read _name _vers; do
	if test -n "$_name"; then
	    echo "P $_name $_name"
	    test -n "$_vers" && echo " $_vers"
	fi
    done
}

pp_solaris_conflict () {
    typeset _name _vers
    while read _name _vers; do
	if test -n "$_name"; then
	    echo "I $_name $_name"
	    test -n "$_vers" && echo " $_vers"
	fi
    done
}

pp_solaris_space() {
    echo "$2:$3:$1" >> $pp_wrkdir/space.cumulative
}

pp_solaris_sum_space () {
    if test -s $pp_wrkdir/space.cumulative; then
        sort -t: +2 < $pp_wrkdir/space.cumulative |
        awk -F: 'NR==1{n=$3}{if($3==n){b+=$1;i+=$2}else{print n" "b" "i;b=$1;i=$2;n=$3}}END{print n" "b" "i}' > $pp_wrkdir/space
    fi
}

pp_solaris_proto () {
	typeset t m o g f p st
	typeset abi

	while read t m o g f p st; do
	  # Use Solaris default mode, owner and group if all unspecified
	  if test x"$m$o$g" = x"---"; then
	    m="?"; o="?"; g="?"
	  fi
	  test x"$o" = x"-" && o="root"
	  case "$t" in
	    f) test x"$g" = x"-" && g="bin"
	       test x"$m" = x"-" && m=444
	       case "$f" in
		*v*) echo "v $1 $p=$pp_destdir$p $m $o $g";;
		*)   echo "f $1 $p=$pp_destdir$p $m $o $g";;
	       esac
	       if test -r "$pp_destdir$p"; then
		  #-- Use file to record ABI types seen
		  case "`file "$pp_destdir$p"`" in
		    *"ELF 32"*80386*) abi=i386;;
		    *"ELF 64"*AMD*) abi=x86_64;;
		    *"ELF 32"*SPARC*) abi=sparc;;
		    *"ELF 64"*SPARC*) abi=sparc64;;
		    *) abi=;;
		  esac
		  if test -n "$abi"; then
		    pp_add_to_list pp_solaris_abis_seen $abi
		  fi
	       fi
               ;;
	    d) test x"$g" = x"-" && g="sys"
	       test x"$m" = x"-" && m=555
	       echo "d $1 $p $m $o $g"
               ;;
	    s) test x"$g" = x"-" && g="bin"
	       test x"$m" = x"-" && m=777
               if test x"$m" != x"777" -a x"$m" != x"?"; then
                  pp_warn "$p: invalid mode $m for symlink, should be 777 or -"
	       fi
	       echo "s $1 $p=$st $m $o $g"
               ;;
	  esac
	done
}

pp_backend_solaris () {
        typeset _cmp _svc _grp

	prototype=$pp_wrkdir/prototype
	: > $prototype

	pkginfo=$pp_wrkdir/pkginfo
	: > $pkginfo
	echo "i pkginfo=$pkginfo" >> $prototype

        case "${pp_solaris_name:-$name}" in
            [0-9]*)
                pp_error "Package name '${pp_solaris_name:-$name}'" \
                        "cannot start with a number"
                ;;
            ???????????????*)
                pp_warn "Package name '${pp_solaris_name:-$name}'" \
                        "too long for Solaris 2.6 or 2.7 (max 9 characters)"
                ;;
            ??????????*)
                pp_warn "Package name '${pp_solaris_name:-$name}'" \
                        "too long for 2.7 Solaris (max 9 characters)"
                ;;
        esac

        #-- generate the package info file
	echo "VERSION=$version" >> $pkginfo
	echo "PKG=${pp_solaris_name:-$name}" >> $pkginfo
	echo "CLASSES=$pp_components" >> $pkginfo
	echo "BASEDIR=/" >> $pkginfo
	echo "NAME=$name $version" >> $pkginfo
	echo "CATEGORY=${pp_solaris_category:-application}" >> $pkginfo

	desc="${pp_solaris_desc:-$description}"
	test -n "$desc" &&
	  echo "DESC=$desc" >> $pkginfo

	test -n "$pp_solaris_rstates" &&
	  echo "RSTATES=$pp_solaris_rstates" >> $pkginfo
	test -n "$pp_solaris_istates" &&
	  echo "ISTATES=$pp_solaris_istates" >> $pkginfo
	test -n "$pp_solaris_maxinst" &&
	  echo "MAXINST=$pp_solaris_maxinst" >> $pkginfo
	test -n "${pp_solaris_vendor:-$vendor}" &&
	  echo "VENDOR=${pp_solaris_vendor:-$vendor}" >> $pkginfo
	test -n "$pp_solaris_pstamp" &&
	  echo "PSTAMP=$pp_solaris_pstamp" >> $pkginfo

	if test -n "${pp_solaris_copyright:-$copyright}"; then
	    echo "${pp_solaris_copyright:-$copyright}" > $pp_wrkdir/copyright
	    echo "i copyright=$pp_wrkdir/copyright" >> $prototype
	fi

        #-- scripts to run before and after install
        : > $pp_wrkdir/postinstall
        : > $pp_wrkdir/preremove
        : > $pp_wrkdir/postremove
	for _cmp in $pp_components; do
        #-- add the preinstall scripts in definition order
        if test -s $pp_wrkdir/%pre.$_cmp; then
            pp_solaris_procedure $_cmp preinst < $pp_wrkdir/%pre.$_cmp \
                >> $pp_wrkdir/preinstall
        fi
        #-- add the postinstall scripts in definition order
        if test -s $pp_wrkdir/%post.$_cmp; then
            pp_solaris_procedure $_cmp postinst < $pp_wrkdir/%post.$_cmp \
                >> $pp_wrkdir/postinstall
        fi
        #-- add the preremove rules in reverse definition order
        if test -s $pp_wrkdir/%preun.$_cmp; then
            pp_solaris_procedure $_cmp preremove < $pp_wrkdir/%preun.$_cmp |
                    pp_prepend $pp_wrkdir/preremove
        fi
        #-- add the postremove scripts in definition order
        if test -s $pp_wrkdir/%postun.$_cmp; then
            pp_solaris_procedure $_cmp postremove < $pp_wrkdir/%postun.$_cmp \
                >> $pp_wrkdir/postremove
        fi
        #-- Add the check script in definition order
        if test -s $pp_wrkdir/%check.$_cmp; then
            pp_solaris_procedure $_cmp checkinstall \
                        < $pp_wrkdir/%check.$_cmp \
			>> $pp_wrkdir/checkinstall
        fi
        #-- All dependencies and conflicts are merged together for Solaris pkgs
        test -s $pp_wrkdir/%depend.$_cmp &&
              pp_solaris_depend < $pp_wrkdir/%depend.$_cmp >> $pp_wrkdir/depend
        test -s $pp_wrkdir/%conflict.$_cmp &&
              pp_solaris_conflict < $pp_wrkdir/%conflict.$_cmp >> $pp_wrkdir/depend
	done


	if pp_solaris_is_request_script_necessary; then
	    pp_solaris_request > $pp_wrkdir/request
	fi

        test -n "$pp_services" &&
            for _svc in $pp_services; do
                pp_load_service_vars $_svc
                pp_solaris_smf $_svc
                pp_solaris_make_service $_svc
                pp_solaris_install_service $_svc | pp_prepend $pp_wrkdir/postinstall
                pp_solaris_remove_service $_svc | pp_prepend $pp_wrkdir/preremove
                pp_solaris_remove_service $_svc | pp_prepend $pp_wrkdir/postremove
                unset pp_svc_xml_file
            done

        test -n "$pp_service_groups" &&
	    for _grp in $pp_service_groups; do
		pp_solaris_make_service_group \
		    $_grp "`pp_service_get_svc_group $_grp`"
	    done

        #-- if installf was used; we need to indicate a termination
        grep installf $pp_wrkdir/postinstall >/dev/null &&
            echo 'installf -f $PKGINST' >> $pp_wrkdir/postinstall

        pp_solaris_sum_space

        # NB: pkginfo and copyright are added earlier
        for f in compver depend space checkinstall \
                 preinstall request postinstall \
                 preremove postremove; do
            if test -s $pp_wrkdir/$f; then
		case $f in
		    *install|*remove|request)
			# turn scripts into a proper shell scripts
			mv $pp_wrkdir/$f $pp_wrkdir/$f.tmp
			{ echo "#!/bin/sh";
			  echo "# $f script for ${pp_solaris_name:-$name}-$version"
			  cat $pp_wrkdir/$f.tmp
			  echo "exit 0"; } > $pp_wrkdir/$f
			chmod +x $pp_wrkdir/$f
			rm -f $pp_wrkdir/$f.tmp
			;;
		esac
                if $pp_opt_debug; then
                    pp_debug "contents of $f:"
                    cat $pp_wrkdir/$f >&2
                fi
                echo "i $f=$pp_wrkdir/$f" >> $prototype
            fi
        done

        #-- create the prototype file which lists the files to install
        # do this as late as possible because files could be added
	pp_solaris_abis_seen=
	for _cmp in $pp_components; do
	  pp_solaris_proto $_cmp < $pp_wrkdir/%files.$_cmp
	done >> $prototype

	if test x"$pp_solaris_package_arch" = x"auto"; then
	    if pp_contains "$pp_solaris_abis_seen" sparc64; then
		pp_solaris_package_arch_std="sparc64"
		echo "ARCH=sparcv9" >> $pkginfo
	    elif pp_contains "$pp_solaris_abis_seen" sparc; then
		pp_solaris_package_arch_std="sparc"
		echo "ARCH=sparc" >> $pkginfo
	    elif pp_contains "$pp_solaris_abis_seen" x86_64; then
		pp_solaris_package_arch_std="x86_64"
		echo "ARCH=amd64" >> $pkginfo
	    elif pp_contains "$pp_solaris_abis_seen" i386; then
		pp_solaris_package_arch_std="i386"
		echo "ARCH=i386" >> $pkginfo
	    else
		pp_warn "No ELF files found: not supplying an ARCH type"
		pp_solaris_package_arch_std="noarch"
	    fi
	else
	    pp_solaris_package_arch_std="$pp_solaris_package_arch"
	    echo "ARCH=$pp_solaris_package_arch" >> $pkginfo
	fi

	mkdir $pp_wrkdir/pkg

	. $pp_wrkdir/%fixup

if $pp_opt_debug; then
  echo "$pkginfo::"; cat $pkginfo
  echo "$prototype::"; cat $prototype
fi >&2

	pkgmk -d $pp_wrkdir/pkg -f $prototype \
		|| { error "pkgmk failed"; return; }
        pkgtrans -s $pp_wrkdir/pkg \
		$pp_wrkdir/`pp_backend_solaris_names` \
                ${pp_solaris_name:-$name} \
		|| { error "pkgtrans failed"; return; }
}

pp_backend_solaris_cleanup () {
	:
}

pp_backend_solaris_names () {
	echo ${pp_solaris_name:-$name}-$version-${pp_solaris_package_arch_std:-$pp_solaris_arch}.pkg
}

pp_backend_solaris_install_script () {
        typeset pkgname platform

	platform="${pp_solaris_os:-solaris}-${pp_solaris_package_arch_std:-$pp_solaris_arch}"

        echo "#! /sbin/sh"
        pp_install_script_common
        pkgname=`pp_backend_solaris_names`

        cat <<.
            tmpnocheck=/tmp/nocheck\$\$
            tmpresponse=/tmp/response\$\$
            trap 'rm -f \$tmpnocheck \$tmpresponse' 0

            make_tmpfiles () {
                cat <<-.. > \$tmpresponse
                        CLASSES=\$*
                        SERVICES=$pp_services
..
                cat <<-.. > \$tmpnocheck
			mail=
			instance=overwrite
			partial=nocheck
			runlevel=nocheck
			idepend=nocheck
			rdepend=nocheck
			space=nocheck
			setuid=nocheck
			conflict=nocheck
			action=nocheck
			basedir=default
..
            }

            test \$# -eq 0 && usage
            op="\$1"; shift

            case "\$op" in
                list-components)
                    test \$# -eq 0 || usage \$op
                    echo "$pp_components"
                    ;;
                list-services)
                    test \$# -eq 0 || usage \$op
                    echo "$pp_services"
                    ;;
                list-files)
                    test \$# -ge 1 || usage \$op
                    echo \${PP_PKGDESTDIR:-.}/$pkgname
                    ;;
                install)
                    test \$# -ge 1 || usage \$op
                    make_tmpfiles "\$@"
                    verbose /usr/sbin/pkgadd -n -d \${PP_PKGDESTDIR:-.}/$pkgname \
                        -r \$tmpresponse \
                        -a \$tmpnocheck \
                        ${pp_solaris_name:-$name}
                    ;;
                uninstall)
                    test \$# -ge 1 || usage \$op
                    make_tmpfiles "\$@"
                    verbose /usr/sbin/pkgrm -n \
                        -a \$tmpnocheck \
                        ${pp_solaris_name:-$name}
                    ;;
                start|stop)
                    test \$# -ge 1 || usage \$op
                    ec=0
                    for svc
                    do
                        verbose /etc/init.d/\$svc \$op || ec=1
                    done
                    exit \$ec
                    ;;
                print-platform)
		    echo "$platform"
		    ;;
                *)
                    usage
                    ;;
            esac
.
}

pp_solaris_dynlib_depend () {
	xargs ldd 2>/dev/null |
	sed -e '/^[^ 	]*:$/d' -e 's,.*=>[	 ]*,,' -e 's,^[ 	]*,,' |
	sort -u |
	grep -v '^/usr/platform/' | (
	  set -- ""; shift
	  while read p; do
	    set -- "$@" -p "$p"
	    if [ $# -gt 32 ]; then
		echo "$# is $#" >&2
		pkgchk -l "$@"
		set -- ""; shift
	    fi
	  done
	  [ $# -gt 0 ] && pkgchk -l "$@"
	)|
	awk '/^Current status:/{p=0} p==1 {print $1} /^Referenced by/ {p=1}' |
	sort -u |
	xargs -l32 pkginfo -x |
	awk 'NR % 2 == 1 { name=$1; } NR%2 == 0 { print name, $2 }'
}

pp_solaris_add_dynlib_depends () {
    typeset tmp
    tmp=$pp_wrkdir/tmp.dynlib

    for _cmp in $pp_components; do
	awk '{print destdir $6}' destdir="$pp_destdir" \
		< $pp_wrkdir/%files.$_cmp |
	pp_solaris_dynlib_depend > $tmp
	if test -s $tmp; then
	    cat $tmp >> $pp_wrkdir/%depend.$_cmp
	fi
	rm -f $tmp
    done
}

pp_backend_solaris_probe () {
    echo "${pp_solaris_os}-${pp_solaris_arch_std}"
}

pp_backend_solaris_vas_platforms () {
    case `pp_backend_solaris_probe` in
	sol10-sparc* | sol9-sparc* | sol8-sparc*)
			echo solaris8-sparc solaris7-sparc solaris26-sparc;;
	sol7-sparc*)	echo                solaris7-sparc solaris26-sparc;;
	sol26-sparc*)	echo                               solaris26-sparc;;
	sol8-*86)	echo solaris8-x86;;
	sol10-*86 | sol10-x86_64)
			echo solaris10-x64 solaris8-x86;;
	*)		pp_die "unknown system `pp_backend_solaris_probe`";;
    esac
}
pp_backend_solaris_function() {
    case "$1" in
        pp_mkgroup) cat<<'.';;
	    /usr/sbin/groupmod "$1" 2>/dev/null && return 0
            /usr/sbin/groupadd "$1"
.
        pp_mkuser:depends) echo pp_mkgroup;;
        pp_mkuser) cat<<'.';;
	    id "$1" >/dev/null 2>/dev/null && return 0
	    pp_mkgroup "${2:-$1}" || return 1
	    /usr/sbin/useradd \
		-g "${2:-$1}" \
		-d "${3:-/nonexistent}" \
		-s "${4:-/bin/false}" \
		"$1"
.
    *) false;;
    esac
}

pp_backend_solaris_init_svc_vars () {
    _smf_category=${pp_solaris_smf_category:-application}
    _smf_method_envvar_name=${smf_method_envvar_name:-"PP_SMF_SERVICE"}
    pp_solaris_service_shell=/sbin/sh
}

pp_solaris_init_svc () {
    smf_version=1
    smf_type=service
    solaris_user=
    solaris_stop_signal=
    solaris_sysv_init_start=S70     # invocation order for start scripts
    solaris_sysv_init_kill=K30      # invocation order for kill scripts
    solaris_sysv_init_start_states="2" # states to install start link
    solaris_sysv_init_kill_states="S 0 1"  # states to install kill link

    #
    # To have the service be installed to start automatically,
    #   %service foo
    #   solaris_sysv_init_start_states="S 0 1 2"
    #
}

pp_solaris_smf () {
    typeset f _pp_solaris_service_script svc _pp_solaris_manpage

    pp_solaris_name=${pp_solaris_name:-$name}
    pp_solaris_manpath=${pp_solaris_manpath:-"/usr/share/man"}
    pp_solaris_mansect=${pp_solaris_mansect:-1}
    smf_start_timeout=${smf_start_timeout:-60}
    smf_stop_timeout=${smf_stop_timeout:-60}
    smf_restart_timeout=${smf_restart_timeout:-60}

    svc=${pp_solaris_smf_service_name:-$1}
    _pp_solaris_service_script=${pp_solaris_service_script:-"/etc/init.d/${pp_solaris_service_script_name:-$svc}"}
    _pp_solaris_manpage=${pp_solaris_manpage:-$svc}

    if [ -z $pp_svc_xml_file ]; then
        pp_svc_xml_file="/var/svc/manifest/$_smf_category/$svc.xml"
        echo "## Generating the smf service manifest file for $pp_svc_xml_file"
    else
        echo "## SMF service manifest file already defined at $pp_svc_xml_file"
        if [ -z $pp_solaris_smf_service_name ] || [ -z $pp_solaris_smf_category ] || [ -z $pp_solaris_service_script ] || [ -z $smf_method_envvar_name ]; then
          pp_error "All required variables are not set.\n"\
                   "When using a custom manifest file all of the following variables must be set:\n"\
                   "pp_solaris_smf_service_name, pp_solaris_smf_category, pp_solaris_service_script and smf_method_envvar_name.\n\n"\
                   "Example:\n"\
                   " \$pp_solaris_smf_category=application\n"\
                   " \$pp_solaris_smf_service_name=pp\n\n"\
                   "  <service name='application/pp' type='service' version='1'>\n\n"\
                   "Example:\n"\
                   " \$pp_solaris_service_script=/etc/init.d/pp\n\n"\
                   "  <exec_method type='method' name='start' exec='/etc/init.d/pp' />\n\n"\
                   "Example:\n"\
                   " \$smf_method_envvar_name=PP_SMF_SERVICE\n\n"\
                   "  <method_environment>\n"\
                   "    <envvar name='PP_SMF_SERVICE' value='1'/>\n"\
                   "  </method_environment>\n"

          return 1
        fi
        return 0
    fi

    f=$pp_svc_xml_file
    pp_add_file_if_missing $f ||
        return 0
    pp_solaris_add_parent_dirs "$f"

    _pp_solaris_smf_dependencies="
          <dependency name='pp_local_filesystems'
                grouping='require_all'
                restart_on='none'
                type='service'>
                <service_fmri value='svc:/system/filesystem/local'/>
          </dependency>

          <dependency name='pp_single-user'
                grouping='require_all'
                restart_on='none'
                type='service'>
                <service_fmri value='svc:/milestone/single-user' />
          </dependency>
"
    _pp_solaris_smf_dependencies=${pp_solaris_smf_dependencies:-$_pp_solaris_smf_dependencies}

    cat <<-. >$pp_destdir$f
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM '/usr/share/lib/xml/dtd/service_bundle.dtd.1'>
<!--
	$copyright
        Generated by PolyPackage $pp_version
-->

    <service_bundle type='manifest' name='${pp_solaris_name}:${svc}' >
          <service name='$_smf_category/$svc'
                type='$smf_type'
                version='$smf_version'>

          <create_default_instance enabled='false'/>

          <single_instance />

          $_pp_solaris_smf_dependencies

          $pp_solaris_smf_additional_dependencies

          <method_context>
                <method_credential user='${solaris_user:-$user}' />
                <method_environment>
                    <envvar name='$_smf_method_envvar_name' value='1'/>
                </method_environment>
          </method_context>

          <exec_method type='method' name='start'
                exec='$_pp_solaris_service_script start'
                timeout_seconds='$smf_start_timeout' />

          <exec_method type='method' name='stop'
                exec='$_pp_solaris_service_script stop'
                timeout_seconds='$smf_stop_timeout' />

          <exec_method type='method' name='restart'
                exec='$_pp_solaris_service_script restart'
                timeout_seconds='$smf_restart_timeout' />

          $pp_solaris_smf_property_groups

          <template>
              <common_name>
                  <loctext xml:lang='C'>$description</loctext>
              </common_name>
              <documentation>
                  <manpage title='$pp_solaris_manpage' section='$pp_solaris_mansect' manpath='$pp_solaris_manpath'/>
              </documentation>
          </template>
        </service>
    </service_bundle>
.
}

pp_solaris_make_service_group () {
    typeset group out file svcs svc

    group="$1"
    svcs="$2"
    file="/etc/init.d/$group"
    out="$pp_destdir$file"

    #-- return if the script is supplied already
    pp_add_file_if_missing "$file" run 755 || return 0
    pp_solaris_add_parent_dirs "$file"

    echo "#! /sbin/sh" > $out
    echo "# polypkg service group script for these services:" >> $out
    echo "svcs=\"$svcs\"" >> $out

    cat <<'.' >>$out

	#-- starts services in order.. stops them all if any break
	pp_start () {
	    undo=
	    for svc in $svcs; do
		if /etc/init.d/$svc start; then
		    undo="$svc $undo"
		else
		    if test -n "$undo"; then
		        for svc in $undo; do
			   /etc/init.d/$svc stop
			done
			return 1
		    fi
		fi
	    done
	    return 0
	}

	#-- stops services in reverse
	pp_stop () {
	    reverse=
	    for svc in $svcs; do
		reverse="$svc $reverse"
	    done
	    rc=0
	    for svc in $reverse; do
		/etc/init.d/$svc stop || rc=$?
	    done
	    return $rc
	}

	#-- returns true only if all services return true status
	pp_status () {
	    rc=0
	    for svc in $svcs; do
		/etc/init.d/$svc status || rc=$?
	    done
	    return $rc
	}

        case "$1" in
            start)   pp_start;;
            stop)    pp_stop;;
            status)  pp_status;;
            restart) pp_stop && pp_start;;
            *)       echo "usage: $0 {start|stop|restart|status}" >&2; exit 1;;
        esac
.
}

pp_solaris_make_service () {
    typeset file out svc

    svc="${pp_solaris_smf_service_name:-$1}"
    file=${pp_solaris_service_script:-"/etc/init.d/${pp_solaris_service_script_name:-$svc}"}
    out="$pp_destdir$file"

    #-- return if we don't need to create the init script
    pp_add_file_if_missing "$file" run 755 ||
        return 0
    pp_solaris_add_parent_dirs "$file"

    echo "#! /sbin/sh" >$out
    echo "#-- This service init file generated by polypkg" >>$out

    #-- Start SMF integration.
    if [ -n "$pp_svc_xml_file" ] ; then
        cat <<_EOF >>$out
if [ -x /usr/sbin/svcadm ] && [ "x\$1" != "xstatus" ] && [ "t\$$_smf_method_envvar_name" = "t" ] ; then
    case "\$1" in
        start)
            echo "starting $svc"
            /usr/sbin/svcadm clear svc:/$_smf_category/$svc:default >/dev/null 2>&1
            /usr/sbin/svcadm enable -s $_smf_category/$svc
            RESULT=\$?
            if [ "\$RESULT" -ne 0 ] ; then
                echo "Error \$RESULT starting $svc" >&2
            fi
            ;;
        stop)
            echo "stopping $svc"
            /usr/sbin/svcadm disable -ts $_smf_category/$svc
	    RESULT=0
            ;;
        restart)
            echo "restarting $svc"
            /usr/sbin/svcadm disable -ts $_smf_category/$svc
            /usr/sbin/svcadm clear svc:/$_smf_category/$svc:default >/dev/null 2>&1
            /usr/sbin/svcadm enable -s $_smf_category/$svc
            RESULT=\$?
            if [ "\$RESULT" -ne 0 ] ; then
                echo "Error \$RESULT starting $svc" >&2
            fi
            ;;
        *)
            echo "Usage: $file {start|stop|restart|status}" >&2
            RESULT=1
    esac
    exit $RESULT
fi
_EOF
    fi

    #-- Construct a start command that builds a pid file as needed
    #   and forks the daemon.  Services started by smf may not fork.
    if test -z "$pidfile"; then
	# The service does not define a pidfile, so we have to make
	# our own up. On Solaris systems where there is no /var/run
	# we must use /tmp to guarantee the pid files are removed after
	# a system crash.
	if test -z "$pp_piddir"; then
	    pp_piddir="/var/run"
	fi
	cat <<. >>$out
	    pp_isdaemon=0
	    pp_piddirs="${pp_piddir}${pp_piddir+ }/var/run /tmp"
	    for pp_piddir in \$pp_piddirs; do
		test -d "\$pp_piddir/." && break
	    done
	    pidfile="\$pp_piddir/$svc.pid"
.
    else
	# The service is able to write its own PID file
	cat <<. >>$out
	    pp_isdaemon=1
	    pidfile="$pidfile"
.
    fi

    pp_su=
    if test "${user:-root}" != "root"; then
	pp_su="su $user -c exec "
    fi

    cat <<. >>$out
	stop_signal="${stop_signal:-TERM}"
	svc="${svc}"

        # generated command to run $svc as a service
	pp_exec () {
	    if [ \$pp_isdaemon -ne 1 ]; then
		if [ "t\$PP_SMF_SERVICE" = "t" ]; then
		    ${pp_su}$cmd &
		    echo \$! > \$pidfile
		else
		    echo "via exec."
		    echo \$$ > \$pidfile
		    exec ${pp_su}$cmd
		    return 1
		fi
	    else
		${pp_su}$cmd
	    fi
	}
.

    #-- write the invariant section of the init script
    cat <<'.' >>$out

        # returns true if $svc is running
        pp_running () {
            if test -s "$pidfile"; then
                read pid < "$pidfile" 2>/dev/null
                if test ${pid:-0} -gt 1 && kill -0 "$pid" 2>/dev/null; then
                    # make sure command name matches up to the first 8 chars
                    c="`echo $cmd | sed -e 's: .*::' -e 's:^.*/::' -e 's/^\(........\).*$/\1/'`"
                    pid="`ps -p $pid 2>/dev/null | sed -n \"s/^ *\($pid\) .*$c *$/\1/p\"`"
                    if test -n "$pid"; then
                        return 0
                    fi
                fi
            fi
            return 1
        }

        # prints a message describing $svc's running state
        pp_status () {
            if pp_running; then
                echo "service $svc is running (pid $pid)"
                return 0
            elif test -f "$pidfile"; then
                echo "service $svc is not running, but pid file exists"
                return 2
            else
                echo "service $svc is not running"
                return 1
            fi
        }

        # starts $svc
        pp_start () {
            if pp_running; then
                echo "service $svc already running" >&2
                return 0
            fi
            echo "starting $svc... \c"
            if pp_exec; then
                echo "done."
            else
                echo "ERROR."
                exit 1
            fi
        }

        # stops $svc
        pp_stop () {
            if pp_running; then
                echo "stopping $svc... \c"
                if kill -$stop_signal $pid; then
                    rm -f "$pidfile"
                    echo "done."
                else
                    echo "ERROR."
                    return 1
                fi
            else
                echo "service $svc already stopped" >&2
                return 0
            fi
        }

        umask 022
        case "$1" in
            start)   pp_start;;
            stop)    pp_stop;;
            status)  pp_status;;
            restart) pp_stop && pp_start;;
            *)       echo "usage: $0 {start|stop|restart|status}" >&2; exit 1;;
        esac
.
}

pp_solaris_remove_service () {
    typeset file svc

    svc="${pp_solaris_smf_service_name:-$1}"
    file=${pp_solaris_service_script:-"/etc/init.d/${pp_solaris_service_script_name:-$svc}"}

    echo '
if [ "x${PKG_INSTALL_ROOT}" = 'x' ]; then
    if [ -x /usr/sbin/svcadm ] ; then
        /usr/sbin/svcadm disable -s '$svc' 2>/dev/null
	case "`uname -r`-$pp_svc_xml_file" in
	  5.1[1-9]*-/var/svc/manifest/*|5.[2-9]*-/var/svc/manifest/*)
	    # Use manifest-import if > 5.10 and manifest in default location
	    /usr/sbin/svcadm restart manifest-import 2>/dev/null
	    ;;
	  *)
	    /usr/sbin/svccfg delete '$svc' 2>/dev/null
	    ;;
	esac
    else
        '$file' stop >/dev/null 2>/dev/null
    fi
fi
    '
}

pp_solaris_install_service () {
    typeset s k l file svc

    svc="${pp_solaris_smf_service_name:-$1}"
    file=${pp_solaris_service_script:-"/etc/init.d/${pp_solaris_service_script_name:-$svc}"}

    s="${solaris_sysv_init_start}$svc"
    k="${solaris_sysv_init_kill}$svc"

    echo '
if [ "x${PKG_INSTALL_ROOT}" != "x" ]; then
  if [ -x ${PKG_INSTALL_ROOT}/usr/sbin/svcadm ]; then
    case "`uname -r`-$pp_svc_xml_file" in
      5.1[1-9]*-/var/svc/manifest/*|5.[2-9]*-/var/svc/manifest/*)
	# Use manifest-import if > 5.10 and manifest in default location
	echo "/usr/sbin/svcadm restart manifest-import 2>/dev/null" >> ${PKG_INSTALL_ROOT}/var/svc/profile/upgrade
	;;
      *)
	echo "/usr/sbin/svccfg import '$pp_svc_xml_file' 2>/dev/null" >> ${PKG_INSTALL_ROOT}/var/svc/profile/upgrade
	;;
    esac
  else'
    test -n "${solaris_sysv_init_start_states}" &&
        for state in ${solaris_sysv_init_start_states}; do
            l="/etc/rc$state.d/$s"
            echo "echo '$l'"
            echo "installf -c run \$PKGINST \$PKG_INSTALL_ROOT$l=$file s"
            pp_solaris_space /etc/rc$state.d 0 1
        done
    test -n "${solaris_sysv_init_kill_states}" &&
        for state in ${solaris_sysv_init_kill_states}; do
            l="/etc/rc$state.d/$k"
            echo "echo '$l'"
            echo "installf -c run \$PKGINST \$PKG_INSTALL_ROOT$l=$file s"
            pp_solaris_space /etc/rc$state.d 0 1
        done
    echo '
  fi
else
    if [ -x /usr/sbin/svcadm ]; then
        echo "Registering '$svc' with SMF"
        /usr/sbin/svcadm disable -s '$svc' 2>/dev/null
	case "`uname -r`-$pp_svc_xml_file" in
	  5.1[1-9]*-/var/svc/manifest/*|5.[2-9]*-/var/svc/manifest/*)
	    # Use manifest-import if > 5.10 and manifest in default location
	    /usr/sbin/svcadm restart manifest-import
	    # Wait for import to complete, otherwise it will not know
	    # about our service until after we try to start it
	    echo Waiting for manifest-import...
	    typeset waited
	    waited=0
	    while [ $waited -lt 15 ] && ! /usr/bin/svcs -l '$svc' >/dev/null 2>&1; do
		sleep 1
		waited=`expr $waited + 1`
	    done
	    if /usr/bin/svcs -l '$svc' >/dev/null 2>&1; then
		echo OK
	    else
		echo manifest-import took to long, you might have to control '$svc' manually.
	    fi
	    ;;
	  *)
	    /usr/sbin/svccfg delete '$svc' 2>/dev/null
	    /usr/sbin/svccfg import '$pp_svc_xml_file'
	    ;;
	esac
    else'
    test -n "${solaris_sysv_init_start_states}" &&
        for state in ${solaris_sysv_init_start_states}; do
            l="/etc/rc$state.d/$s"
            echo "echo '$l'"
            echo "installf -c run \$PKGINST \$PKG_INSTALL_ROOT$l=$file s"
            pp_solaris_space /etc/rc$state.d 0 1
        done
    test -n "${solaris_sysv_init_kill_states}" &&
        for state in ${solaris_sysv_init_kill_states}; do
            l="/etc/rc$state.d/$k"
            echo "echo '$l'"
            echo "installf -c run \$PKGINST \$PKG_INSTALL_ROOT$l=$file s"
            pp_solaris_space /etc/rc$state.d 0 1
        done
    echo '
    fi
fi'
}

pp_solaris_add_parent_dirs () {
    typeset dir

    dir=${1%/*}
    while test -n "$dir"; do
	if awk "\$6 == \"$dir/\" {exit 1}" < $pp_wrkdir/%files.run; then
	    echo "d - - - - $dir/" >> $pp_wrkdir/%files.run
	fi
	dir=${dir%/*}
    done
}

pp_platforms="$pp_platforms deb"

pp_backend_deb_detect () {
    test -f /etc/debian_version
}

pp_deb_cmp_full_name () {
    local prefix
    prefix="${pp_deb_name:-$name}"
    case "$1" in
        run) echo "${prefix}" ;;
        dbg) echo "${prefix}-${pp_deb_dbg_pkgname}";;
        dev) echo "${prefix}-${pp_deb_dev_pkgname}";;
        doc) echo "${prefix}-${pp_deb_doc_pkgname}";;
        *)   pp_error "unknown component '$1'";
    esac
}

pp_backend_deb_init () {
    pp_deb_dpkg_version="2.0"
    pp_deb_name=
    pp_deb_version=
    pp_deb_release=
    pp_deb_arch=
    pp_deb_arch_std=
    pp_deb_maintainer="One Identity LLC <support@oneidentity.com>"
    pp_deb_copyright=
    pp_deb_distro=
    pp_deb_control_description=
    pp_deb_summary=
    pp_deb_description=
    pp_deb_dbg_pkgname="dbg"
    pp_deb_dev_pkgname="dev"
    pp_deb_doc_pkgname="doc"
    pp_deb_section=contrib # Free software that depends on non-free software

    # Detect the host architecture
    pp_deb_detect_arch

    # Make sure any programs we require are installed
    pp_deb_check_required_programs
}

pp_deb_check_required_programs () {
    local p needed notfound ok
    needed= notfound=
    for prog in dpkg dpkg-deb install md5sum fakeroot
    do
        if which $prog 2>/dev/null >/dev/null; then
	    pp_debug "$prog: found"
	else
	    pp_debug "$prog: not found"
	    case "$prog" in
		dpkg|dpkg-deb)	p=dpkg;;
		install|md5sum) p=coreutils;;
		fakeroot)	p=fakeroot;;
		*)		pp_die "unexpected dpkg tool $prog";;
	    esac
	    notfound="$notfound $prog"
	    pp_contains "$needed" "$p" || needed="$needed $p"
	fi
    done
    if [ -n "$notfound" ]; then
	pp_error "cannot find these programs: $notfound"
	pp_error "please install these packages: $needed"
    fi
}

pp_deb_munge_description () {
    # Insert a leading space on each line, replace blank lines with a
    #space followed by a full-stop.
    pp_deb_control_description="`echo ${pp_deb_description:-$description} | \
        sed 's,^\(.*\)$, \1, ' | sed 's,^[ \t]*$, .,g' | fmt -w 80`"
}

pp_deb_detect_arch () {
   pp_deb_arch=`dpkg-architecture -qDEB_HOST_ARCH`
   pp_deb_arch_std=`uname -m`
}

pp_deb_sanitize_version() {
    echo "$@" | tr -d -c '[:alnum:].+-:~'
}

pp_deb_version_final() {
    if test -n "$pp_deb_version"; then
        # Don't sanitize; assume the user is sane (hah!)
        echo "$pp_deb_version"
    else
        pp_deb_sanitize_version "$version"
    fi
}

pp_deb_conflict () {
    local _name _vers _conflicts

    _conflicts="Conflicts:"
    while read _name _vers; do
	case "$_name" in ""| "#"*) continue ;; esac
	_conflicts="$_conflicts $_name"
	test -n "$_vers" && _conflicts="$_conflicts $_name (>= $vers)"
	_conflicts="${_conflicts},"
    done
    echo "${_conflicts%,}"
}

pp_deb_make_control() {
    local cmp="$1"
    local installed_size

    # compute the installed size
    installed_size=`pp_deb_files_size < $pp_wrkdir/%files.$cmp`

    package_name=`pp_deb_cmp_full_name "$cmp"`
    cat <<-.
	Package: ${package_name}
	Version: `pp_deb_version_final`-${pp_deb_release:-1}
	Section: ${pp_deb_section:-contrib}
	Priority: optional
	Architecture: ${pp_deb_arch}
	Maintainer: ${pp_deb_maintainer:-$maintainer}
	Description: ${pp_deb_summary:-$summary}
	${pp_deb_control_description}
	Installed-Size: ${installed_size}
.
    if test -s $pp_wrkdir/%depend."$cmp"; then
	sed -ne '/^[ 	]*$/!s/^[ 	]*/Depends: /p' \
	    < $pp_wrkdir/%depend."$cmp"
    fi
    if test -s $pp_wrkdir/%conflict."$cmp"; then
	pp_deb_conflict < $pp_wrkdir/%conflict."$cmp"
    fi
}

pp_deb_make_md5sums() {
    local cmp="$1"; shift
    local pkg_dir

    pkg_dir=$pp_wrkdir/`pp_deb_cmp_full_name $cmp`
    (cd $pkg_dir && md5sum "$@") > $pkg_dir/DEBIAN/md5sums ||
	pp_error "cannot make md5sums"
}

pp_deb_make_package_maintainer_script() {
    local output="$1"
    local source="$2"
    local desc="$3"

    # See if we need to create this script at all
    if [ -s "$source" ]
    then

        # Create header
        cat <<-. >$output || pp_error "Cannot create $output"
	#!/bin/sh
	# $desc
	# Generated by PolyPackage $pp_version

.

        cat $source >> "$output" || pp_error "Cannot append to $output"

        # Set perms
        chmod 755 "$output" || pp_error "Cannot chmod $output"
    fi
}

pp_deb_handle_services() {
    local svc

    #-- add service start/stop code
    if test -n "$pp_services"; then
        #-- record the uninstall commands in reverse order
        for svc in $pp_services; do
            pp_load_service_vars $svc

            # Create init script (unless one exists)
            pp_deb_service_make_init_script $svc

            #-- append %post code to install the svc
	    test x"yes" = x"$enable" &&
            cat<<-. >> $pp_wrkdir/%post.run
		case "\$1" in
		    configure)
		        # Install the service links
		        update-rc.d $svc defaults
		        ;;
		esac
.

            #-- prepend %preun code to stop svc
            cat<<-. | pp_prepend $pp_wrkdir/%preun.run
		case "\$1" in
		    remove|deconfigure|upgrade)
		        # Stop the $svc service
		        invoke-rc.d $svc stop
		        ;;
		esac
.

            #-- prepend %postun code to remove service
            cat<<-. | pp_prepend $pp_wrkdir/%postun.run
		case "\$1" in
		    purge)
		        # Remove the service links
		        update-rc.d $svc remove
		        ;;
		esac
.
        done
        #pp_deb_service_remove_common | pp_prepend $pp_wrkdir/%preun.run
    fi

}
pp_deb_fakeroot () {
    if test -s $pp_wrkdir/fakeroot.save; then
	fakeroot -i $pp_wrkdir/fakeroot.save -s $pp_wrkdir/fakeroot.save "$@"
    else
	fakeroot -s $pp_wrkdir/fakeroot.save "$@"
    fi
}

pp_deb_files_size () {
    local t m o g f p st
    while read t m o g f p st; do
        case $t in
            f|s) du -k "${pp_destdir}$p";;
            d)   echo 4;;
        esac
    done | awk '{n+=$1} END {print n}'
}

pp_deb_make_DEBIAN() {
    local cmp="${1:-run}"
    local data cmp_full_name
    local old_umask

    old_umask=`umask`
    umask 0022
    cmp_full_name=`pp_deb_cmp_full_name $cmp`
    data=$pp_wrkdir/$cmp_full_name

    # Create DEBIAN dir $data/DEBIAN
    mkdir -p $data/DEBIAN

    # Create control file
    pp_deb_make_control $cmp > $data/DEBIAN/control

    # Copy in conffiles
    if test -f $pp_wrkdir/%conffiles.$cmp; then
	cp $pp_wrkdir/%conffiles.$cmp $data/DEBIAN/conffiles
    fi

    # Create preinst
    pp_deb_make_package_maintainer_script "$data/DEBIAN/preinst" \
        "$pp_wrkdir/%pre.$cmp" "Pre-install script for $cmp_full_name"\
        || exit $?

    # Create postinst
    pp_deb_make_package_maintainer_script "$data/DEBIAN/postinst" \
        "$pp_wrkdir/%post.$cmp" "Post-install script for $cmp_full_name"\
        || exit $?

    # Create prerm
    pp_deb_make_package_maintainer_script "$data/DEBIAN/prerm" \
        "$pp_wrkdir/%preun.$cmp" "Pre-uninstall script for $cmp_full_name"\
        || exit $?

    # Create postrm
    pp_deb_make_package_maintainer_script "$data/DEBIAN/postrm" \
        "$pp_wrkdir/%postun.$cmp" "Post-uninstall script for $cmp_full_name"\
        || exit $?

    umask $old_umask
}

pp_deb_make_data() {
    local _l t m o g f p st data
    local data share_doc owner group
    cmp=$1
    data=$pp_wrkdir/`pp_deb_cmp_full_name $cmp`
    cat $pp_wrkdir/%files.${cmp} | while read t m o g f p st; do
	if test x"$m" = x"-"; then
	    case "$t" in
		d) m=755;;
		f) m=644;;
	    esac
	fi
	test x"$o" = x"-" && o=root
	test x"$g" = x"-" && g=root
        case "$t" in
        f) # Files
           pp_deb_fakeroot install -D -o $o -g $g -m ${m} $pp_destdir/$p $data/$p;
           if [ x"$f" = x"v" ]
           then
               # File marked as "volatile". Assume this means it's a conffile
	       # TODO: check this as admins like modified conffiles to be left
	       #       behind
               echo "$p" >> $pp_wrkdir/%conffiles.$cmp
           fi;;

        d) # Directories
           pp_deb_fakeroot install -m ${m} -o $o -g $g -d $data/$p;;

        s) # Symlinks
           # Remove leading / from vars
           rel_p=`echo $p | sed s,^/,,`
           rel_st=`echo $st | sed s,^/,,`
           # TODO: we are always doing absolute links here. We should follow
	   # the debian policy of relative links when in the same top-level
	   # directory
           (cd $data; ln -sf $st $rel_p);;
	    *) pp_error "Unsupported data file type: $t";;
	esac
    done

    # If no copyright file is present add one. This is a debian requirement.
    share_doc="/usr/share/doc/`pp_deb_cmp_full_name $cmp`"
    if [ ! -f "$data/$share_doc/copyright" ]
    then
        echo "${pp_deb_copyright:-$copyright}" > "$pp_wrkdir/copyright"
        install -D -m 644 "$pp_wrkdir/copyright" "$data/$share_doc/copyright"
    fi

}

pp_deb_makedeb () {
    local cmp
    local package_build_dir

    cmp="$1"

    package_build_dir=$pp_wrkdir/`pp_deb_cmp_full_name $cmp`

    # Create package dir
    mkdir -p $package_build_dir

    # Copy in data
    pp_deb_make_data $cmp ||
	pp_die "Could not make DEBIAN data files for $cmp"

    # Make control files
    # must be done after copying data so conffiles are found
    pp_deb_make_DEBIAN $cmp ||
	pp_die "Could not make DEBIAN control files for $cmp"

    # Create md5sums
    pp_deb_make_md5sums $cmp `(cd $package_build_dir;
	find . -name DEBIAN -prune -o -type f -print | sed "s,^\./,,")` ||
	    pp_die "Could not make DEBIAN md5sums for $cmp"
}

pp_backend_deb () {
    local debname

    # Munge description for control file inclusion
    pp_deb_munge_description

    # Handle services
    pp_deb_handle_services $cmp

    for cmp in $pp_components
    do
        debname=`pp_deb_name $cmp`
        pp_deb_makedeb $cmp
    done

    . $pp_wrkdir/%fixup

    for cmp in $pp_components
    do
        debname=`pp_deb_name $cmp`
	# Create debian package
	pp_debug "Building `pp_deb_cmp_full_name $cmp` -> $output"
	pp_deb_fakeroot dpkg-deb \
	    --build $pp_wrkdir/`pp_deb_cmp_full_name $cmp` \
	    $pp_wrkdir/$debname ||
		pp_error "failed to create $cmp package"
    done
}

pp_backend_deb_cleanup () {
    # rm -rf $pp_wrkdir
    :
}

pp_deb_name () {
    local cmp="${1:-run}"
    echo `pp_deb_cmp_full_name $cmp`"_"`pp_deb_version_final`"-${pp_deb_release:-1}_${pp_deb_arch}.deb"
}
pp_backend_deb_names () {
    for cmp in $pp_components
    do
        pp_deb_name $cmp
    done
}

pp_backend_deb_install_script () {
    local cmp _cmp_full_name

    echo "#!/bin/sh"
    pp_install_script_common

    cat <<.

        cmp_to_pkgname () {
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
         echo "$cmp) echo '`pp_deb_cmp_full_name $cmp`';;"
    done
    cat <<.
                *) usage;;
                esac
            done
        }


        cmp_to_pathname () {
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
         echo "$cmp) echo \${PP_PKGDESTDIR:-.}/'`pp_deb_name $cmp`';;"
    done
    cat <<.
                *) usage;;
		esac
            done
        }

        test \$# -eq 0 && usage
        op="\$1"; shift
        case "\$op" in
            list-components)
                test \$# -eq 0 || usage \$op
                echo $pp_components
                ;;
            list-services)
                test \$# -eq 0 || usage \$op
                echo $pp_services
                ;;
            list-files)
                test \$# -ge 1 || usage \$op
                cmp_to_pathname "\$@"
                ;;
            install)
                test \$# -ge 1 || usage \$op
                dpkg --install \`cmp_to_pathname "\$@"\`
                ;;
            uninstall)
                test \$# -ge 1 || usage \$op
                dpkg --remove \`cmp_to_pkgname "\$@"\`; :
                ;;
            start|stop)
                test \$# -ge 1 || usage \$op
                ec=0
                for svc
                do
                    /etc/init.d/\$svc \$op || ec=1
                done
                exit \$ec
                ;;
            print-platform)
                test \$# -eq 0 || usage \$op
		echo "linux-${pp_deb_arch}"
		;;
            *)
                usage
                ;;
        esac
.
}

pp_backend_deb_probe() {
    local arch distro release

    pp_deb_detect_arch

    # /etc/debian_version exists on Debian & Ubuntu, so it's no use
    # to us. Use lsb_release instead.

    case `(lsb_release -is || echo no-lsb) 2>/dev/null` in
        Debian)
            distro=deb
	    ;;
        Ubuntu)
            distro=ubu
	    ;;
	no-lsb)
	    echo unknown-$pp_deb_arch_std
	    return 0
	    ;;
        *)
            distro=unknown
	    ;;
    esac

    release=`lsb_release -rs`

    # If release is not numeric, use the codename
    case $release in
        *[!.0-9r]*)
	    release=`lsb_release -cs`
	    case $release in
		buzz)
		    release="11"
		    ;;
		rex)
		    release="12"
		    ;;
		bo)
		    release="13"
		    ;;
		hamm)
		    release="20"
		    ;;
		slink)
		    release="21"
		    ;;
		potato)
		    release="22"
		    ;;
		woody)
		    release="30"
		    ;;
		sarge)
		    release="31"
		    ;;
		etch)
		    release="40"
		    ;;
		lenny)
		    release="50"
		    ;;
		squeeze)
		    release="60"
		    ;;
        wheezy)
            release="70"
            ;;
        jessie)
            release="80"
            ;;
        stretch)
            release="90"
            ;;
	    esac
	    ;;
	*)
	    # Remove trailing revision number and any dots
            release=`echo $release | cut -dr -f1 | tr -d .`
	    ;;
    esac

    echo $distro$release-$pp_deb_arch_std
}

pp_backend_deb_vas_platforms () {
    case "$pp_deb_arch_std" in
	x86_64)	echo "linux-x86_64.deb";; # DO NOT add linux-x86.deb here!!
	*86)	echo "linux-x86.deb";;
	*)	pp_die "unknown architecture ${pp_deb_arch_std}";;
    esac
}
pp_backend_deb_init_svc_vars () {

    reload_signal=
    start_runlevels=${pp_deb_default_start_runlevels-"2 3 4 5"} # == lsb default-start
    stop_runlevels=${pp_deb_default_stop_runlevels-"0 1 6"}     # == lsb default-stop
    svc_description="${pp_deb_default_svc_description}" # == lsb short descr
    svc_process=

    lsb_required_start='$local_fs $network'
    lsb_should_start=
    lsb_required_stop='$local_fs'
    lsb_description=

    start_priority=50
    stop_priority=50            #-- stop_priority = 100 - start_priority
}

pp_deb_service_make_init_script () {
    local svc=$1
    local script=/etc/init.d/$svc
    local out=$pp_destdir$script
    local _process _cmd

    pp_add_file_if_missing $script run 755 v || return 0

    #-- start out as an empty shell script
    cat <<-'.' >$out
	#!/bin/sh
.

    #-- determine the process name from $cmd unless $svc_process is given
    set -- $cmd
    #_process=${svc_process:-"$1"} --? WTF

    #-- construct a start command that builds a pid file if needed
    #-- the command name in /proc/[pid]/stat is limited to 15 characters 
    _cmd="$cmd";
    _cmd_path=`echo $cmd | cut -d" " -f1`
    _cmd_name=`basename $_cmd_path | cut -c1-15`
    _cmd_args=`echo $cmd | cut -d" " -f2-`
    test x"$_cmd_path" != x"$_cmd_args" || _cmd_args=

    #-- generate the LSB init info
    cat <<-. >>$out
	### BEGIN INIT INFO
	# Provides: ${svc}
	# Required-Start: ${lsb_required_start}
	# Should-Start: ${lsb_should_start}
	# Required-Stop: ${lsb_required_stop}
	# Default-Start: ${start_runlevels}
	# Default-Stop: ${stop_runlevels}
	# Short-Description: ${svc_description:-no description}
	### END INIT INFO
	# Generated by PolyPackage ${pp_version}
	# ${copyright}

.

    if test x"${svc_description}" = x"${pp_deb_default_svc_description}"; then
        svc_description=
    fi

    #-- write service-specific definitions
    cat <<. >>$out
NAME="${_cmd_name}"
DESC="${svc_description:-$svc service}"
USER="${user}"
GROUP="${group}"
PIDFILE="${pidfile}"
STOP_SIGNAL="${stop_signal}"
RELOAD_SIGNAL="${reload_signal}"
CMD="${_cmd}"
DAEMON="${_cmd_path}"
DAEMON_ARGS="${_cmd_args}"
SCRIPTNAME=${script}
.

    #-- write the generic part of the init script
    cat <<'.' >>$out

[ -x "$DAEMON" ] || exit 0

[ -r /etc/default/$NAME ] && . /etc/default/$NAME

[ -f /etc/default/rcS ] && . /etc/default/rcS

. /lib/lsb/init-functions

do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
    if [ -n "$PIDFILE" ]
    then
        pidfile_opt="--pidfile $PIDFILE"
    else
        pidfile_opt="--make-pidfile --background --pidfile /var/run/$NAME.pid"
    fi
    if [ -n "$USER" ]
    then
        user_opt="--user $USER"
    fi
    if [ -n "$GROUP" ]
    then
        group_opt="--group $GROUP"
    fi

	start-stop-daemon --start --quiet $pidfile_opt $user_opt --exec $DAEMON --test > /dev/null \
	    || return 1

    # Note: there seems to be no way to tell whether the daemon will fork itself or not, so pass
    # --background for now
    start-stop-daemon --start --quiet $pidfile_opt $user_opt --exec $DAEMON -- \
    	$DAEMON_ARGS \
    	|| return 2
}

do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
    if [ -n "$PIDFILE" ]
    then
        pidfile_opt="--pidfile $PIDFILE"
    else
        pidfile_opt="--pidfile /var/run/$NAME.pid"
    fi
    if [ -n "$USER" ]
    then
        user_opt="--user $USER"
    fi
    if [ -n $STOP_SIGNAL ]
    then
        signal_opt="--signal $STOP_SIGNAL"
    fi
	start-stop-daemon --stop --quiet $signal_opt --retry=TERM/30/KILL/5 $pidfile_opt --name $NAME
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec $DAEMON
	[ "$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	test -z $PIDFILE || rm -f $PIDFILE
	return "$RETVAL"
}

do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
    if [ -n "$PIDFILE" ]
    then
        pidfile_opt="--pidfile $PIDFILE"
    else
        pidfile_opt="--pidfile /var/run/$NAME.pid"
    fi
    if [ -n "$RELOAD_SIGNAL" ]
    then
	    start-stop-daemon --stop --signal $RELOAD_SIGNAL --quiet $pidfile_opt --name $NAME
    fi
	return 0
}

case "$1" in
  start)
	[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  reload|force-reload)
    if [ -n "$RELOAD_SIGNAL" ]
    then
	    log_daemon_msg "Reloading $DESC" "$NAME"
	    do_reload
	    log_end_msg $?
    else
        # Do a restart instead
        "$0" restart
    fi
	;;
  restart)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
	  	# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	#echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload}" >&2
	exit 3
	;;
esac

:
.
    chmod 755 $out
}
pp_backend_deb_function() {
    case "$1" in
        pp_mkgroup) cat<<'.';;
	    /usr/sbin/groupmod "$1" 2>/dev/null && return 0
            /usr/sbin/groupadd "$1"
.
        pp_mkuser:depends) echo pp_mkgroup;;
        pp_mkuser) cat<<'.';;
	    pp_tmp_system=
	    id -u "$1" >/dev/null 2>/dev/null && return 0
	    # deb 3.1's useradd changed API in 4.0. Gah!
	    /usr/sbin/useradd --help 2>&1 | /bin/grep -q .--system &&
		pp_tmp_system=--system
	    pp_mkgroup "${2:-$1}" || return 1
	    /usr/sbin/useradd \
		-g "${2:-$1}" \
		-d "${3:-/nonexistent}" \
		-s "${4:-/bin/false}" \
		$pp_tmp_system \
		"$1"
.
        pp_havelib) cat<<'.';;
            for pp_tmp_dir in `echo "/usr/lib:/lib${3:+:$3}" | tr : ' '`; do
                test -r "$pp_tmp_dir/lib$1.so{$2:+.$2}" && return 0
            done
            return 1
.
    *) false;;
    esac
}

pp_platforms="$pp_platforms kit"

pp_backend_kit_detect () {
    test x"$1" = x"OSF1"
}

pp_backend_kit_init () {
        pp_kit_name=
        pp_kit_package=
        pp_kit_desc=
        pp_kit_version=
        pp_kit_subset=
        pp_readlink_fn=pp_ls_readlink
        pp_kit_startlevels="2 3"
        pp_kit_stoplevels="0 2 3"
}

pp_backend_kit () {
    typeset mi_file k_file svc outfile
    typeset desc

    pp_backend_kit_names > /dev/null

    if test -z "$pp_kit_desc"; then
        pp_kit_desc="$description"
    fi

    mi_file="$pp_wrkdir/$pp_kit_subset.mi"
    k_file="$pp_wrkdir/$pp_kit_subset.k"
    scp_file="$pp_wrkdir/$pp_kit_subset.scp"

    desc="${pp_kit_desc:-$description}"

    cat <<-. >> $k_file
	NAME='$name'
	CODE=$pp_kit_name
	VERS=$pp_kit_version
	MI=$mi_file
	COMPRESS=0
	%%
	$pp_kit_subset	.	0	'$desc'
.

    if test -n "$pp_services"; then
        for svc in $pp_services; do
            pp_kit_make_service $svc
            pp_prepend $pp_wrkdir/%preun.run <<-.
		/sbin/init.d/$svc stop
.
         done
    fi

    pp_backend_kit_make_mi "$mi_file"
    pp_backend_kit_make_scp
    #rm -rf  $pp_wrkdir/kit_dest
    mkdir -p $pp_wrkdir/kit_dest
    pp_backend_kit_kits $k_file $pp_opt_destdir $pp_wrkdir/kit_dest
    tar cvf $pp_wrkdir/$pp_kit_subset.tar -C $pp_wrkdir/kit_dest .
    gzip -c $pp_wrkdir/$pp_kit_subset.tar > $pp_wrkdir/$pp_kit_subset.tar.gz
    #rm -rf $pp_wrkdir/$pp_kit_subset.tar $pp_wrkdir/scps
}

pp_backend_kit_make_mi () {
    # XXX this information should go into the .inv files
    typeset t m o g f p st line dm
    while read t m o g f p st; do
        case $t in
            f|d)
                echo "0	.$p	$pp_kit_subset"
                echo "        chmod $m $p" >> $pp_wrkdir/%post.run
                if [ x"$o" = x"-" ] ; then
                    echo "        chown root $p" >> $pp_wrkdir/%post.run
                else
                    echo "        chown $o $p" >> $pp_wrkdir/%post.run
                fi
                if [ x"$g" = x"-" ] ; then
                    echo "        chgrp 0 $p" >> $pp_wrkdir/%post.run
                else
                    echo "        chgrp $g $p" >> $pp_wrkdir/%post.run
                fi
                ;;
            s)
                echo "        ln -s $st $p" >> $pp_wrkdir/%post.run
                echo "        rm -f $p" >> $pp_wrkdir/%preun.run
                ;;
         esac
    done < $pp_wrkdir/%files.run | sort -k3  |uniq > $1
}


pp_backend_kit_make_scp () {
    scpdir="$pp_wrkdir/scps"
    mkdir "$scpdir" && touch "$scpdir"/$pp_kit_subset.scp
    cat <<EOF >"$scpdir"/$pp_kit_subset.scp

    . /usr/share/lib/shell/libscp

    case "\$ACT" in
    PRE_L)
    STL_ScpInit



    ;;
    POST_L)
        STL_ScpInit
        STL_LinkCreate
EOF

    cat $pp_wrkdir/%post.run >>"$scpdir"/$pp_kit_subset.scp
    cat >>"$scpdir"/$pp_kit_subset.scp <<EOF
    ;;
    PRE_D)
        STL_ScpInit
        STL_LinkRemove
EOF
    cat $pp_wrkdir/%preun.run >>"$scpdir"/$pp_kit_subset.scp
    cat >>"$scpdir"/$pp_kit_subset.scp <<EOF
        ;;
    POST_D)

        ;;
    C)
        STL_ScpInit

        case "\$1" in
        INSTALL)
        echo "Installation of the \$_DESC (\$_SUB) subset is complete."
        ;;
    DELETE)
        ;;
    esac

        ;;
    V)

        ;;
    esac

    exit 0
EOF
    chmod 744 "$scpdir"/$pp_kit_subset.scp
}


pp_backend_kit_cleanup () {
    :
}

pp_backend_kit_names () {
    if test -z "$pp_kit_name"; then
        pp_warn "pp_kit_name not specified, using XXX"
        pp_kit_name=XXX
    fi
    case "$pp_kit_name" in
        ???) : ok;;
        *) pp_error "\$pp_kit_name $pp_kit_name must be three characters";;
    esac
    if test -z "$pp_kit_package"; then
        pp_warn "pp_kit_package not specified, using YYYY"
        pp_kit_package=YYYY
    fi
    if test -z "$pp_kit_version"; then
        pp_kit_version=`echo $version|tr -d '.a-zA-Z'`
    fi
    case "$pp_kit_version" in
        [0-9]) pp_kit_version="${pp_kit_version}00";;
        [0-9][0-9]) pp_kit_version="${pp_kit_version}0";;
        [0-9][0-9][0-9]) : ok;;
        *) pp_error "\$pp_kit_version $pp_kit_version must be three digits, ";;
    esac
    if test -z "$pp_kit_subset"; then
        pp_kit_subset="$pp_kit_name$pp_kit_package$pp_kit_version"
    fi
    echo "$pp_kit_subset.tar.gz"
}

pp_backend_kit_install_script () {
    typeset pkgname platform

    pkgname=`pp_backend_kit_names`
    platform="`pp_backend_kit_probe`"

    echo "#!/bin/sh"
    pp_install_script_common
    cat <<.

        cpt_to_tags () {
            test x"\$*" = x"all" && set -- $pp_components
            for cpt
            do
                echo "$name.\$cpt"
            done
        }

        test \$# -eq 0 && usage
        op="\$1"; shift

        case "\$op" in
            list-components)
                test \$# -eq 0 || usage \$op
                echo "$pp_components"
                ;;
            list-services)
                test \$# -eq 0 || usage \$op
                echo "$pp_services"
                ;;
            list-files)
                test \$# -ge 1 || usage \$op
                echo \${PP_PKGDESTDIR:-.}/$pkgname
                ;;
            install)
                test \$# -ge 1 || usage \$op
                verbose echo \${PP_PKGDESTDIR:-\`pwd\`}/$pkgname \`cpt_to_tags "\$@"\`
                #verbose swinstall -x verbose=0 -s \${PP_PKGDESTDIR:-\`pwd\`}/$pkgname \`cpt_to_tags "\$@"\`
                ;;
            uninstall)
                test \$# -ge 1 || usage \$op
                verbose echo \`cpt_to_tags "\$@"\`
                #verbose swremove -x verbose=0 \`cpt_to_tags "\$@"\`
                ;;
            start|stop)
                test \$# -ge 1 || usage \$op
                ec=0
                for svc
                do
                    verbose /sbin/init.d/\$svc \$op
                    [ \$? -eq 4 -o \$? -eq 0 ] || ec=1
                done
                exit \$ec
                ;;
            print-platform)
		echo "$platform"
		;;
            *)
                usage
                ;;
        esac
.
}

pp_backend_kit_function () {
    case "$1" in
        pp_mkgroup) cat <<'.';;
            grep "^$1:" /etc/group >/dev/null ||
                /usr/sbin/groupadd $1
.
        pp_mkuser) cat <<'.';;
            eval user=\$$#
            grep "^$user:" /etc/passwd >/dev/null ||
                /usr/sbin/useradd -s /usr/bin/false "$@"
.
        pp_havelib) cat <<'.';;
            for dir in `echo /usr/lib${3+:$3} | tr : ' '`; do
                test -r "$dir/lib$1.${2-sl}" && return 0
            done
            return 1
.
        *) pp_error "unknown function request: $1";;
    esac
}

pp_backend_kit_init_svc_vars () {
    :
}

pp_backend_kit_probe () {
    echo tru64-`uname -r | sed 's/V\([0-9]*\)\.\([0-9]*\)/\1\2/'`
}

pp_kit_service_group_script () {
    typeset grp svcs scriptpath out
    grp="$1"
    svcs="$2"
    scriptpath="/sbin/init.d/$grp"
    out="$pp_destdir$scriptpath"

    pp_add_file_if_missing $scriptpath run 755 || return 0

    cat <<-. > $out
	#!/sbin/sh
	# generated by pp $pp_version
	svcs="$svcs"
.

cat <<-'.' >> $out
	#-- starts services in order.. stops them all if any break
	pp_start () {
	    undo=
	    for svc in $svcs; do
	        /sbin/init.d/$svc start
	        case $? in
	            0|4)
	                undo="$svc $undo"
	                ;;
	            *)
	                if test -n "$undo"; then
	                for svc in $undo; do
	                    /sbin/init.d/$svc stop
	                done
	                return 1
	                fi
	                ;;
	        esac
	    done
	    return 0
	}

	#-- stops services in reverse
	pp_stop () {
	    reverse=
	        for svc in $svcs; do
	            reverse="$svc $reverse"
	        done
	        rc=0
	        for svc in $reverse; do
	            /sbin/init.d/$svc stop || rc=$?
	        done
	        return $rc
	}

	case "$1" in
	    start_msg) echo "Starting $svcs";;
	stop_msg)  echo "Stopping $svcs";;
	start)     pp_start;;
	stop)      pp_stop;;
	*)         echo "usage: $0 {start|stop|start_msg|stop_msg}"
	    exit 1;;
	esac
.
}

pp_kit_service_script () {
    typeset svc scriptpath out

    svc="$1"
    scriptpath="/sbin/init.d/$svc"

    pp_load_service_vars "$svc"

    test -n "$user" -a x"$user" != x"root" &&
    cmd="SHELL=/usr/bin/sh /usr/bin/su $user -c \"exec `echo $cmd | sed -e 's,[$\\\`],\\&,g'`\""
    if test -z "$pidfile"; then
        pidfile="/var/run/$svc.pid"
        cmd="$cmd & echo \$! > \$pidfile"
    fi

    pp_add_file_if_missing $scriptpath run 755

    cat <<-. > $pp_destdir$scriptpath
	svc="$svc"
	pidfile="$pidfile"

	pp_start () {
	    $cmd
	}
.
    cat <<-'.' >>$pp_destdir$scriptpath
	    pp_stop () {
	        if test ! -s "$pidfile"; then
	            echo "Unable to stop $svc (no pid file)"
	                return 1
	        else
	            read pid < "$pidfile"
	            if kill -0 "$pid" 2>/dev/null; then
	                if kill -${stop_signal:-TERM} "$pid"; then
	                    rm -f "$pidfile"
	                    return 0
	                else
	                    echo "Unable to stop $svc"
	                    return 1
	                fi
	            else
	                rm -f "$pidfile"
	                return 0
	            fi
	        fi
	    }

	    pp_running () {
	        if test ! -s "$pidfile"; then
	            return 1
	        else
	            read pid < "$pidfile"
	            kill -0 "$pid" 2>/dev/null
	        fi
	    }
	    case "$1" in
	        start_msg) echo "Starting the $svc service";;
	        stop_msg)  echo "Stopping the $svc service";;
	        start)
	            if pp_running; then
	                echo "$svc already running";
	                exit 0
	            elif pp_start; then
	                echo "$svc started";
	# rc(1M) says we should exit 4, but nobody expects it!
	                exit 0
	            else
	                exit 1
	            fi
	            ;;
	        stop)
	            if pp_stop; then
	                echo "$svc stopped";
	                exit 0
	            else
	                exit 1
	            fi
	            ;;
	        *) echo "usage: $0 {start|stop|start_msg|stop_msg}"
	           exit 1
	           ;;
	    esac
.
}

pp_kit_make_service () {
    typeset level priority startlevels stoplevels
    typeset svc svcvar

    svc="$1"
    svcvar=`pp_makevar $svc`

    #-- don't do anything if the script exists
    if test -s "$pp_destdir/sbin/init.d/$svc"; then
        pp_error "$pp_destdir/sbin/init.d/$svc exists"
        return
    fi

    # symlink the script, depending on the priorities chosen
    eval priority='${pp_kit_priority_'$svcvar'}'
    test -z "$priority" && priority="${pp_kit_priority:-50}"

    eval startlevels='${pp_kit_startlevels_'$svcvar'}'
    test -z "$startlevels" && startlevels="$pp_kit_startlevels"

    eval stoplevels='${pp_kit_stoplevels_'$svcvar'}'
    test -z "$stoplevels" && stoplevels="$pp_kit_stoplevels"

    # create the script and config file
    pp_kit_service_script $svc

    # fix the priority up
    case "$priority" in
        ???) :;;
        ??) priority=0$priority;;
        ?) priority=00$priority;;
    esac

    if test x"$stoplevels" = x"auto"; then
        stoplevels=
        test -z "$startlevels" || for level in $startlevels; do
            stoplevels="$stoplevels `expr $level - 1`"
        done
    fi

    # create the symlinks
    test -z "$startlevels" || for level in $startlevels; do
        echo "        ln -s /sbin/init.d/$svc /sbin/rc$level.d/S$priority$svc" >>$pp_wrkdir/%post.run
        echo "        rm /sbin/rc$level.d/S$priority$svc" >>$pp_wrkdir/%preun.run
    done
    test -z "$stoplevels" || for level in $stoplevels; do
        echo "        ln -s /sbin/init.d/$svc /sbin/rc$level.d/K$priority$svc" >>$pp_wrkdir/%post.run
        echo "        rm -f /sbin/rc$level.d/K$priority$svc" >>$pp_wrkdir/%preun.run
    done
}




pp_backend_kit_sizes () {
    awk '
    BEGIN { root = usr = var = 0; }
    {
        if (substr($9, 1, 1) != "l")
            if (substr($10, 1, 6) == "./var/")
                var += $2;
            else if (substr($10, 1, 10) == "./usr/var/")
                var += $2
            else if (substr($10, 1, 6) == "./usr/")
                usr += $2
            else
                root += $2
    }
    END { printf "%d\t%d\t%d", root, usr, var }
    ' "$@"
}

pp_kit_kits_global () {
    line=`sed -n '/^%%/q;/^'$2'=/{s/^'$2'=//p;q;}' <"$1"`
    test -z "$line" && return 1
    eval "echo $line"
    :
}

pp_backend_kit_kits () {
    typeset KITFILE FROMDIR TODIR
    typeset SCPDIR

    SCPDIR="$pp_wrkdir/scps"

    PATH="/usr/lbin:/usr/bin:/etc:/usr/ucb:$PATH"; export PATH # XXX
    #umask 2 # XXX

    test $# -ge 3 || pp_die "pp_backend_kit_kits: too few arguments"
    KITFILE="$1"; shift
    FROMDIR="$1"; shift
    TODIR="$1"; shift

    test -f "$KITFILE" || pp_die "$KITFILE not found"
    test -d "$FROMDIR" || pp_die "$FROMDIR not found"
    test -d "$TODIR"   || pp_die "$TODIR not found"

    INSTCTRL="$TODIR/instctrl"
    mkdir -p "$INSTCTRL" || pp_die "cannot create instctrl directory"
    chmod 775 "$INSTCTRL"

    grep "%%" $KITFILE > /dev/null || pp_die "no %% in $KITFILE"

    typeset NAME CODE VERS MI ROOT COMPRESS
    typeset S_LIST ALLSUBS

    NAME=`pp_kit_kits_global "$KITFILE" NAME` || pp_die "no NAME in $KITFILE"
    CODE=`pp_kit_kits_global "$KITFILE" CODE` || pp_die "no CODE in $KITFILE"
    VERS=`pp_kit_kits_global "$KITFILE" VERS` || pp_die "no VERS in $KITFILE"
    MI=`pp_kit_kits_global "$KITFILE" MI` || pp_die "no MI in $KITFILE"
    ROOT=`pp_kit_kits_global "$KITFILE" ROOT`
    COMPRESS=`pp_kit_kits_global "$KITFILE" COMPRESS`

    test -f "$MI" || pp_die "Inventory file $MI not found"

    case "$ROOT" in
    *ROOT)
        test -f "$TODIR/$ROOT" ||
            pp_die "Root image $ROOT not found in $TODIR" ;;
    esac

    ALLSUBS=`awk 'insub==1 {print $1} /^%%/ {insub=1}' <"$KITFILE"`
    test $# -eq 0 && set -- $ALLSUBS

    pp_debug "Creating $# $NAME subsets."
    pp_debug "ALLSUBS=<$ALLSUBS>"

    if test x"$COMPRESS" = x"1"; then
        COMPRESS=:
    else
        COMPRESS=false
    fi

    #rm -f *.ctrl Volume*

    for SUB
    do
        test -z "$SUB" && pp_die "SUB is empty"

        typeset INV CTRL ROOTSIZE USRSIZE VARSIZE TSSUB
	#rm -f Volume*
	case $SUB in
            .*) :;;
	    *)  pp_verbose rm -f "$TODIR/$SUB"* "$INSTCTRL/$SUB"*;;
        esac

        TSSUB="$pp_wrkdir/ts.$SUB"

	pp_debug "kits: Subset $SUB"

	INV="$SUB.inv"
	CTRL="$SUB.ctrl"
	pp_debug "kits: Generating media creation information..."

        # Invcutter takes as input
        #   SUB dir/path
        # and generates stl_inv(4) files, like this
        #   f 0 00000 0 0 100644 2/11/09 010 f dir/path none SUB
	grep "	$SUB\$" "$MI" |
            pp_verbose /usr/lbin/invcutter \
                -v "$VERS" -f "$FROMDIR" > "$INSTCTRL/$INV" ||
            pp_die "failed to create $INSTCTRL/$INV"
        chmod 664 "$INSTCTRL/$INV"

        pp_backend_kit_sizes "$INSTCTRL/$INV" > "$pp_wrkdir/kit.sizes"
        read ROOTSIZE USRSIZE VARSIZE < "$pp_wrkdir/kit.sizes"

        # Prefix each line with $FROMDIR. This will be stripped
        awk '$1 != "d" {print from $10}' from="$FROMDIR/" \
            > "$TSSUB" < "$INSTCTRL/$INV" ||
            pp_die "failed"

        NVOLS=0

	pp_debug "kits: Creating $SUB control file..."

        sed '1,/^%%/d;/^'"$SUB"'/{p;q;}' < "$KITFILE" > "$pp_wrkdir/kit.line"
        read _SUB _IGNOR DEPS FLAGS DESC < "$pp_wrkdir/kit.line"
        if test -z "$_SUB"; then
            pp_warn "No such subset $SUB in $KITFILE"
            continue
	fi
        DEPS=`echo $DEPS | tr '|' ' '`
        case $FLAGS in
            FLGEXP*) pp_verbose FLAGS='"${'"$FLAGS"'}"' ;;
        esac
        case $DESC in
            *%*) DESC=`echo $DESC|awk -F% '{printf "%-36s%%%s\n", $1, $2}'`;;
        esac

	cat > "$INSTCTRL/$CTRL" <<-.
		NAME='$NAME $SUB'
		DESC=$DESC
		ROOTSIZE=$ROOTSIZE
		USRSIZE=$USRSIZE
		VARSIZE=$VARSIZE
		NVOLS=1:$NVOLS
		MTLOC=1:$TLOC
		DEPS="$DEPS"
		FLAGS=$FLAGS
.
        chmod 664 "$INSTCTRL/$CTRL"

	pp_debug "kits: Making tar image"

	pp_verbose tar cfPR "$TODIR/$SUB" "$FROMDIR/" "$TSSUB" ||
             pp_error "problem creating kit file"

        if $COMPRESS; then
            pp_debug "kits: Compressing"
            (cd "$TODIR" && compress -f -v "$SUB") ||
                pp_die "problem compressing $TODIR/$SUB"
            SPC=`expr $SUB : '\(...\).*'`    # first three characters
            SVC=`expr $SUB : '.*\(...\)'`    # last three characters
            : > "$INSTCTRL/$SPC$SVC.comp"
            chmod 664 "$INSTCTRL/$SPC$SVC.comp"
            pp_debug "kits: Padding compressed file to 10kB" # wtf?
            rm -f "$TODIR/$SUB"
            pp_verbose \
            dd if="$TODIR/$SUB.Z" of="$TODIR/$SUB" bs=10k conv=sync ||
                pp_die "problem moving compressed file"
            rm -f "$TODIR/$SUB.Z"
        fi
        chmod 664 "$TODIR/$SUB"

	if test -f "$SCPDIR/$SUB.scp"; then
		cp "$SCPDIR/$SUB.scp" "$INSTCTRL/$SUB.scp"
                chmod 755 "$INSTCTRL/$SUB.scp"
	else
		pp_debug "kits: null subset control program for $SUB"
		: > "$INSTCTRL/$SUB.scp"
		chmod 744 "$INSTCTRL/$SUB.scp"
	fi

        pp_debug "kits: Finished creating media image for $SUB"
    done

    pp_debug "kits: Creating $CODE.image"

    case "$ROOT" in
    *ROOT)	ALLSUBS="$ROOT $ALLSUBS"
                ;;
    esac

    (cd "$TODIR" && sum $ALLSUBS) > "$INSTCTRL/$CODE.image"
    chmod 664 "$INSTTRL/$CODE.image"
    pp_debug "kits: Creating INSTCTRL"
    (cd "$INSTCTRL" && tar cpvf - *) > "$TODIR/INSTCTRL"
    chmod 664 "$TODIR/INSTCTRL"
    cp "$INSTCTRL/$CODE.image" "$TODIR/$CODE.image"
    chmod 664 "$TODIR/$CODE.image"

    pp_debug "kits: Media image production complete"
}

pp_platforms="$pp_platforms rpm"

pp_backend_rpm_detect () {
    test x"$1" = x"Linux" -a ! -f /etc/debian_version
}

pp_backend_rpm_init () {

    pp_rpm_version=
    pp_rpm_summary=
    pp_rpm_description=
    pp_rpm_group="Applications/Internet"
    pp_rpm_license="Unspecified"
    pp_rpm_vendor=
    pp_rpm_url=
    pp_rpm_packager=
    pp_rpm_provides=
    pp_rpm_requires=
    pp_rpm_requires_pre=
    pp_rpm_requires_post=
    pp_rpm_requires_preun=
    pp_rpm_requires_postun=
    pp_rpm_release=
    pp_rpm_epoch=
    pp_rpm_dev_group="Development/Libraries"
    pp_rpm_dbg_group="Development/Tools"
    pp_rpm_doc_group="Documentation"
    pp_rpm_dev_description=
    pp_rpm_dbg_description=
    pp_rpm_doc_description=
    pp_rpm_dev_requires=
    pp_rpm_dev_requires_pre=
    pp_rpm_dev_requires_post=
    pp_rpm_dev_requires_preun=
    pp_rpm_dev_requires_postun=
    pp_rpm_dbg_requires=
    pp_rpm_dbg_requires_pre=
    pp_rpm_dbg_requires_post=
    pp_rpm_dbg_requires_preun=
    pp_rpm_dbg_requires_postun=
    pp_rpm_doc_requires=
    pp_rpm_doc_requires_pre=
    pp_rpm_doc_requires_post=
    pp_rpm_doc_requires_preun=
    pp_rpm_doc_requires_postun=
    pp_rpm_dev_provides=
    pp_rpm_dbg_provides=
    pp_rpm_doc_provides=

    pp_rpm_autoprov=
    pp_rpm_autoreq=
    pp_rpm_autoreqprov=

    pp_rpm_dbg_pkgname=debug
    pp_rpm_dev_pkgname=devel
    pp_rpm_doc_pkgname=doc

    pp_rpm_defattr_uid=root
    pp_rpm_defattr_gid=root

    pp_rpm_detect_arch
    pp_rpm_detect_distro
    pp_rpm_rpmbuild=`pp_rpm_detect_rpmbuild`

    # SLES8 doesn't always come with readlink
    test -x /usr/bin/readlink -o -x /bin/readlink ||
        pp_readlink_fn=pp_ls_readlink
}

pp_rpm_detect_arch () {
    pp_rpm_arch=auto

    #-- Find the default native architecture that RPM is configured to use
    cat <<-. >$pp_wrkdir/dummy.spec
	Name: dummy
	Version: 1
	Release: 1
	Summary: dummy
	Group: ${pp_rpm_group}
	License: ${pp_rpm_license}
	%description
	dummy
.
    $pp_opt_debug && cat $pp_wrkdir/dummy.spec
    pp_rpm_arch_local=`rpm -q --qf '%{arch}\n' --specfile $pp_wrkdir/dummy.spec`
    rm $pp_wrkdir/dummy.spec

    #-- Ask the kernel what machine architecture is in use
    local arch
    for arch in "`uname -m`" "`uname -p`"; do
	case "$arch" in
	    i?86)
		pp_rpm_arch_std=i386
		break
		;;
	    x86_64|ppc|ppc64|ppc64le|ia64|s390|s390x)
		pp_rpm_arch_std="$arch"
		break
		;;
	    powerpc)
		# Probably AIX
		case "`/usr/sbin/lsattr -El proc0 -a type -F value`" in
		    PowerPC_POWER*)	pp_rpm_arch_std=ppc64;;
		    *)			pp_rpm_arch_std=ppc;;
		esac
		break
		;;
	    *)	pp_rpm_arch_std=unknown
		;;
	esac
    done

    #-- Later on, when files are processed, we use 'file' to determine
    #   what platform ABIs are used. This is used when pp_rpm_arch == auto
    pp_rpm_arch_seen=
}

pp_rpm_detect_distro () {
    pp_rpm_distro=
    if test -f /etc/whitebox-release; then
       pp_rpm_distro=`awk '
          /^White Box Enterprise Linux release/ { print "wbel" $6; exit; }
       ' /etc/whitebox-release`
    elif test -f /etc/mandrakelinux-release; then
       pp_rpm_distro=`awk '
          /^Mandrakelinux release/ { print "mand" $3; exit; }
       ' /etc/mandrake-release`
    elif test -f /etc/mandrake-release; then
       pp_rpm_distro=`awk '
          /^Linux Mandrake release/ { print "mand" $4; exit; }
          /^Mandrake Linux release/ { print "mand" $4; exit; }
       ' /etc/mandrake-release`
    elif test -f /etc/fedora-release; then
       pp_rpm_distro=`awk '
          /^Fedora Core release/ { print "fc" $4; exit; }
          /^Fedora release/ { print "f" $3; exit; }
       ' /etc/fedora-release`
    elif test -f /etc/redhat-release; then
       pp_rpm_distro=`awk '
          /^Red Hat Enterprise Linux/ { print "rhel" $7; exit; }
          /^CentOS release/           { print "centos" $3; exit; }
          /^CentOS Linux release/     { print "centos" $4; exit; }
          /^Red Hat Linux release/    { print "rh" $5; exit; }
       ' /etc/redhat-release`
    elif test -f /etc/SuSE-release; then
       pp_rpm_distro=`awk '
          /^SuSE Linux [0-9]/ { print "suse" $3; exit; }
          /^SUSE LINUX [0-9]/ { print "suse" $3; exit; }
          /^openSUSE [0-9]/   { print "suse" $2; exit; }
          /^S[uU]SE Linux Enterprise Server [0-9]/ { print "sles" $5; exit; }
          /^S[uU]SE LINUX Enterprise Server [0-9]/ { print "sles" $5; exit; }
          /^SuSE SLES-[0-9]/  { print "sles" substr($2,6); exit; }
       ' /etc/SuSE-release`
    elif test -f /etc/os-release; then
      pp_rpm_distro="`. /etc/os-release && echo \$ID\$VERSION`"
    elif test -f /etc/pld-release; then
       pp_rpm_distro=`awk '
          /^[^ ]* PLD Linux/ { print "pld" $1; exit; }
       ' /etc/pld-release`
    elif test X"`uname -s 2>/dev/null`" = X"AIX"; then
	local r v
	r=`uname -r`
	v=`uname -v`
	pp_rpm_distro="aix$v$r"
    fi
    pp_rpm_distro=`echo $pp_rpm_distro | tr -d .`
    test -z "$pp_rpm_distro" &&
       pp_warn "unknown distro"
}

pp_rpm_detect_rpmbuild () {
    local cmd
    for cmd in rpmbuild rpm; do
        if `which $cmd > /dev/null 2>&1`; then
            echo $cmd
            return 0
        fi
    done

    pp_error "Could not find rpmbuild"
    # Default to `rpmbuild` in case it magically appears
    echo rpmbuild
    return 1
}

pp_rpm_label () {
    local label arg
    label="$1"; shift
    for arg
    do
        test -z "$arg" || echo "$label: $arg"
    done
}

pp_rpm_writefiles () {
    local _l t m o g f p st fo farch
    while read t m o g f p st; do
        _l="$p"
	test $t = d && _l="%dir ${_l%/}/"
	if test $t = s; then
	    # rpm warns if %attr contains a mode for symlinks
	    m=-
        elif test x"$m" = x"-"; then
            case "$t" in
                d) m=755;;
                f) m=644;;
            esac
        fi
        test x"$o" = x"-" && o="${pp_rpm_defattr_uid:-root}"
        test x"$g" = x"-" && g="${pp_rpm_defattr_gid:-root}"
	_l="%attr($m,$o,$g) $_l"

	if test "$t" = "f" -a x"$pp_rpm_arch" = x"auto"; then
	    fo=`file "${pp_destdir}$p" 2>/dev/null`
	    #NB: The following should match executables and shared objects,
	    #relocatable objects. It will not match .a files however.
	    case "$fo" in
		*": ELF 32-bit LSB "*", Intel 80386"*)
		    farch=i386;;
		*": ELF 64-bit LSB "*", AMD x86-64"*|\
		*": ELF 64-bit LSB "*", x86-64"*)
		    farch=x86_64;;
		*": ELF 32-bit MSB "*", PowerPC"*)
		    farch=ppc;;
        *": ELF 64-bit LSB "*", 64-bit PowerPC"*)
            farch=ppc64le;;
		*": ELF 64-bit MSB "*", 64-bit PowerPC"*)
		    farch=ppc64;;
		*": ELF 64-bit LSB "*", IA-64"*)
		    farch=ia64;;
		*": ELF 32-bit MSB "*", IBM S/390"*)
		    farch=s390;;
		*": ELF 64-bit MSB "*", IBM S/390"*)
		    farch=s390x;;
		*"executable (RISC System/6000)"*)
		    farch=ppc;;
		*"64-bit XCOFF executable"*)
		    farch=ppc64;;
        *": ELF 64-bit LSB "*", ARM aarch64"*)
            farch=aarch64;;
		*" ELF "*)
		    farch=ELF;;
		*)
		    farch=noarch;;
	    esac
	    # If file(1) doesn't provide enough info, try readelf(1)
	    if test "$farch" = "ELF"; then
		fo=`readelf -h "${pp_destdir}$p" | awk '{if ($1 == "Class:") {class=$2} else if ($1 == "Machine:") {machine=$0; sub(/^ *Machine: */, "", machine)}} END {print class " " machine}' 2>/dev/null`
		case "$fo" in
		    "ELF32 Intel 80386")
			farch=i386;;
		    "ELF64 "*[xX]"86-64")
			farch=x86_64;;
		    "ELF32 PowerPC")
			farch=ppc;;
		    "ELF64 PowerPC"*)
			farch=ppc64;;
		    "ELF64 IA-64")
			farch=ia64;;
		    "ELF32 IBM S/390")
			farch=s390;;
		    "ELF64 IBM S/390")
			farch=s390x;;
            "ELF64 AArch64")
            farch=aarch64;;
		    *)
			farch=noarch;;
		esac
	    fi
	    pp_debug "file: $fo -> $farch"
	    test x"$farch" = x"noarch" || pp_add_to_list pp_rpm_arch_seen $farch
	fi

	case $f in *v*) _l="%config(noreplace) $_l";; esac
	echo "$_l"
    done
    echo
}

pp_rpm_subname () {
    case "$1" in
        run) : ;;
        dbg) echo "${2}${pp_rpm_dbg_pkgname}";;
        dev) echo "${2}${pp_rpm_dev_pkgname}";;
        doc) echo "${2}${pp_rpm_doc_pkgname}";;
        *)   pp_error "unknown component '$1'";
    esac
}

pp_rpm_depend () {
    local _name _vers
    while read _name _vers; do
        case "$_name" in ""| "#"*) continue ;; esac
        echo "Requires: $_name ${_vers:+>= $_vers}"
    done
}

pp_rpm_conflict () {
    local _name _vers
    while read _name _vers; do
        case "$_name" in ""| "#"*) continue ;; esac
        echo "Conflicts: $_name ${_vers:+>= $_vers}"
    done
}

pp_rpm_override_requires () {
    local orig_find_requires

    if test -z "$pp_rpm_depend_filter_cmd"; then
	return 0
    fi

    orig_find_requires=`rpm --eval '%{__find_requires}'`
    cat << EOF > "$pp_wrkdir/filtered-find-requires"
$orig_find_requires \$@ | $pp_rpm_depend_filter_cmd
EOF
    chmod +x "$pp_wrkdir/filtered-find-requires"
    echo "%define __find_requires $pp_wrkdir/filtered-find-requires"
    # Might be necessary for old versions of RPM? Not for 4.4.2.
    #echo "%define _use_internal_dependency_generator 0"
}

pp_backend_rpm () {
    local cmp specfile _summary _group _desc _pkg _subname svc _script

	specfile=$pp_wrkdir/$name.spec
        : > $specfile

        #-- force existence of a 'run' component
        pp_add_component run
        : >> $pp_wrkdir/%files.run

	if test -z "$pp_rpm_arch"; then
            pp_error "Unknown RPM architecture"
            return 1
        fi

	#-- Write the header components of the RPM spec file
	cat <<-. >>$specfile
		Name: ${pp_rpm_name:-$name}
		Version: ${pp_rpm_version:-$version}
		Release: ${pp_rpm_release:-1}
		Summary: ${pp_rpm_summary:-$summary}
		Group:   ${pp_rpm_group}
		License: ${pp_rpm_license}
.
	pp_rpm_label "URL"              "$pp_rpm_url"             >>$specfile
	pp_rpm_label "Vendor"           "${pp_rpm_vendor:-$vendor}" >>$specfile
	pp_rpm_label "Packager"         "$pp_rpm_packager"        >>$specfile
	pp_rpm_label "Provides"         "$pp_rpm_provides"        >>$specfile
	pp_rpm_label "Requires(pre)"    "$pp_rpm_requires_pre"    >>$specfile
	pp_rpm_label "Requires(post)"   "$pp_rpm_requires_post"   >>$specfile
	pp_rpm_label "Requires(preun)"  "$pp_rpm_requires_preun"  >>$specfile
	pp_rpm_label "Requires(postun)" "$pp_rpm_requires_postun" >>$specfile
	pp_rpm_label "AutoProv"         "$pp_rpm_autoprov"        >>$specfile
	pp_rpm_label "AutoReq"          "$pp_rpm_autoreq"         >>$specfile
	pp_rpm_label "AutoReqProv"      "$pp_rpm_autoreqprov"     >>$specfile

	test -n "$pp_rpm_serial" && pp_warn "pp_rpm_serial deprecated"
	if test -n "$pp_rpm_epoch"; then
	    #-- Epoch was introduced in RPM 2.5.6
	    case `$pp_rpm_rpmbuild --version 2>/dev/null` in
		1.*|2.[0-5].*|2.5.[0-5])
		    pp_rpm_label "Serial" $pp_rpm_epoch >>$specfile;;
		*)
		    pp_rpm_label "Epoch" $pp_rpm_epoch >>$specfile;;
	    esac
	fi

        if test -n "$pp_rpm_requires"; then
            pp_rpm_label "Requires" "$pp_rpm_requires" >>$specfile
        elif test -s $pp_wrkdir/%depend.run; then
            pp_rpm_depend < $pp_wrkdir/%depend.run >> $specfile
        fi
        if test -s $pp_wrkdir/%conflict.run; then
            pp_rpm_conflict < $pp_wrkdir/%conflict.run >> $specfile
        fi

	pp_rpm_override_requires >> $specfile

	cat <<-. >>$specfile

		%description
		${pp_rpm_description:-$description}
.

	for cmp in $pp_components; do
		case $cmp in
		   run) continue;;
		   dev) _summary="development tools for $pp_rpm_summary"
		   	_group="$pp_rpm_dev_group"
			_desc="${pp_rpm_dev_description:-Development libraries for $name. $pp_rpm_description.}"
		   	;;
		   doc) _summary="documentation for $pp_rpm_summary"
		   	_group="$pp_rpm_doc_group"
			_desc="${pp_rpm_doc_description:-Documentation for $name. $pp_rpm_description.}"
		   	;;
		   dbg) _summary="diagnostic tools for $pp_rpm_summary"
		   	_group="$pp_rpm_dbg_group"
			_desc="${pp_rpm_dbg_description:-Diagnostic tools for $name.}"
		   	;;
		esac

                _subname=`pp_rpm_subname $cmp`
		cat <<-.

			%package $_subname
			Summary: $name $_summary
			Group: $_group
.
                for _script in pre post preun postun; do
                    eval '_pkg="$pp_rpm_'$cmp'_requires_'$_script'"'
                    if test -n "$_pkg"; then
                        eval pp_rpm_label "Requires($_script)" $_pkg
                    fi
                done
                eval '_pkg="$pp_rpm_'$cmp'_requires"'
                if test -n "$_pkg"; then
                    eval pp_rpm_label Requires ${pp_rpm_name:-$name} $_pkg
                elif test -s $pp_wrkdir/%depend.$cmp; then
                    pp_rpm_depend < $pp_wrkdir/%depend.$cmp >> $specfile
                fi
                if test -s $pp_wrkdir/%conflict.$cmp; then
                    pp_rpm_conflict < $pp_wrkdir/%conflict.$cmp >> $specfile
                fi

                eval '_pkg="$pp_rpm_'$cmp'_provides"'
		eval pp_rpm_label Provides $_pkg

		cat <<-.

			%description $_subname
			$_desc
.
	done >>$specfile

        #-- NB: we don't put any %prep, %build or %install RPM sections
	#   into the spec file.

        #-- add service start/stop code
        if test -n "$pp_services"; then
            pp_rpm_service_install_common >> $pp_wrkdir/%post.run

            #-- record the uninstall commands in reverse order
            for svc in $pp_services; do
                pp_load_service_vars $svc

                pp_rpm_service_make_init_script $svc

                #-- append %post code to install the svc
                pp_rpm_service_install $svc >> $pp_wrkdir/%post.run

                #-- prepend %preun code to uninstall svc
                # (use files in case vars are modified)
                pp_rpm_service_remove $svc | pp_prepend $pp_wrkdir/%preun.run
            done
            pp_rpm_service_remove_common | pp_prepend $pp_wrkdir/%preun.run
        fi

	# make convenience service groups
        if test -n "$pp_service_groups"; then
	    for grp in $pp_service_groups; do
		pp_rpm_service_group_make_init_script \
		    $grp "`pp_service_get_svc_group $grp`"
	    done
	fi

	#-- Write the RPM %file sections
        #   (do this after services, since services adds to %files.run)
	for cmp in $pp_components; do
            _subname=`pp_rpm_subname $cmp`

            if test -s $pp_wrkdir/%check.$cmp; then
                echo ""
                echo "%pre $_subname"
                cat $pp_wrkdir/%check.$cmp
                echo :   # causes script to exit true by default
            fi

            if test -s $pp_wrkdir/%files.$cmp; then
                echo ""
                echo "%files $_subname"
                pp_rpm_writefiles < $pp_wrkdir/%files.$cmp
            fi

            if test -n "$pp_rpm_ghost"; then
                for ghost in $pp_rpm_ghost; do
                    echo "%ghost $ghost"
                done
            fi

            if test -s $pp_wrkdir/%pre.$cmp; then
                echo ""
                echo "%pre $_subname"
                cat $pp_wrkdir/%pre.$cmp
                echo :   # causes script to exit true
            fi

            if test -s $pp_wrkdir/%post.$cmp; then
                echo ""
                echo "%post $_subname"
                cat $pp_wrkdir/%post.$cmp
                echo :   # causes script to exit true
            fi

            if test -s $pp_wrkdir/%preun.$cmp; then
                echo ""
                echo "%preun $_subname"
                cat $pp_wrkdir/%preun.$cmp
                echo :   # causes script to exit true
            fi

            if test -s $pp_wrkdir/%postun.$cmp; then
                echo ""
                echo "%postun $_subname"
                cat $pp_wrkdir/%postun.$cmp
                echo :   # causes script to exit true
            fi
	done >>$specfile

        #-- create a suitable work area for rpmbuild
	cat <<-. >$pp_wrkdir/.rpmmacros
		%_topdir $pp_wrkdir
		# XXX Note escaped %% for use in headerSprintf
		%_rpmfilename   %%{ARCH}/%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm
	.
	mkdir $pp_wrkdir/RPMS
	mkdir $pp_wrkdir/BUILD

	if test x"$pp_rpm_arch" = x"auto"; then
	    #-- Reduce the arch_seen list to exactly one item
	    case "$pp_rpm_arch_seen" in
		"i386 x86_64"|"x86_64 i386")
		    pp_rpm_arch_seen=x86_64;;
		*"s390 s390x"* | *"s390x s390"* )
		    pp_rpm_arch_seen=s390x;;
        *"aarch64"* )
            pp_rpm_arch_seen=aarch64;;
		*" "*)
		    pp_error "detected multiple targets: $pp_rpm_arch_seen"
		    pp_rpm_arch_seen=unknown;;	    # not detected
		"")
		    pp_warn "detected no binaries: using target noarch"
		    pp_rpm_arch_seen=noarch;;
		*)
		    pp_debug "detected architecture $pp_rpm_arch_seen"
	    esac
	    pp_rpm_arch="$pp_rpm_arch_seen"
	fi

        . $pp_wrkdir/%fixup

$pp_opt_debug && cat $specfile

        pp_debug "creating: `pp_backend_rpm_names`"

pp_debug "pp_rpm_arch_seen = <${pp_rpm_arch_seen}>"
pp_debug "pp_rpm_arch = <${pp_rpm_arch}>"

	HOME=$pp_wrkdir \
	pp_verbose \
        $pp_rpm_rpmbuild -bb \
		--buildroot="$pp_destdir/" \
                --target="${pp_rpm_arch}" \
                --define='_unpackaged_files_terminate_build 0' \
                --define='_use_internal_dependency_generator 0' \
                `$pp_opt_debug && echo --verbose || echo --quiet` \
                $pp_rpm_rpmbuild_extra_flags \
		$specfile ||
            pp_error "Problem creating RPM packages"

	for f in `pp_backend_rpm_names`; do
	    # The package might be in an arch-specific subdir
	    pkgfile=not-found
	    for dir in $pp_wrkdir/RPMS/${pp_rpm_arch} $pp_wrkdir/RPMS; do
		if test -f $dir/$f; then
		    pkgfile=$dir/$f
		fi
	    done
	    if test x"$pkgfile" = x"not-found"; then
                pp_error "Problem predicting RPM filename: $f"
	    else
		ln $pkgfile $pp_wrkdir/$f
	    fi
	done
}

pp_rpm_output_name () {
    echo "${pp_rpm_name:-$name}`pp_rpm_subname "$1" -`-${pp_rpm_version:-$version}-${pp_rpm_release:-1}.${pp_rpm_arch}.rpm"
}

pp_backend_rpm_names () {
    local cmp _subname
    for cmp in $pp_components; do
	pp_rpm_output_name $cmp
    done
}

pp_backend_rpm_cleanup () {
    :
}

pp_rpm_print_requires () {
    local _subname _name

    echo "CPU:$pp_rpm_arch"
    ## XXX should be lines of the form (from file/ldd/objdump)
    #    EXEC:/bin/sh
    #    RTLD:libc.so.4:open
    rpm -q --requires -p $pp_wrkdir/`pp_rpm_output_name $1` |sed -e '/^rpmlib(/d;s/ //g;s/^/RPM:/' | sort -u
}

pp_backend_rpm_install_script () {
    local cmp _subname

    echo "#!/bin/sh"
    pp_install_script_common

    cat <<.

        cmp_to_pkgname () {
	    local oi name
	    if test x"\$1" = x"--only-installed"; then
		#-- only print if installation detected
		oi=false
		shift
	    else
		oi=true
	    fi
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
        _subname=`pp_rpm_subname $cmp -`
         echo "$cmp) name=${pp_rpm_name:-$name}${_subname};;"
    done
    cat <<.
                *) usage;;
                esac
		if \$oi || rpm -q "\$name" >/dev/null 2>/dev/null; then
		    echo "\$name"
		fi
            done
        }


        cmp_to_pathname () {
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
        echo "$cmp) echo \${PP_PKGDESTDIR:-.}/`pp_rpm_output_name $cmp` ;;"
    done
    cat <<.
                *) usage;;
                esac
            done
        }

	print_requires () {
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
        echo "$cmp) cat <<'._end'"
	pp_rpm_print_requires $cmp
        echo "._end"; echo ';;'
    done
    cat <<.
                *) usage;;
                esac
            done
        }

        test \$# -eq 0 && usage
        op="\$1"; shift
        case "\$op" in
            list-components)
                test \$# -eq 0 || usage \$op
                echo $pp_components
                ;;
            list-services)
                test \$# -eq 0 || usage \$op
                echo $pp_services
                ;;
            list-files)
                test \$# -ge 1 || usage \$op
                cmp_to_pathname "\$@"
                ;;
            install)
                test \$# -ge 1 || usage \$op
                verbose rpm -U --replacepkgs --oldpackage \
                    \`cmp_to_pathname "\$@"\`
                ;;
            uninstall)
                test \$# -ge 1 || usage \$op
                pkgs=\`cmp_to_pkgname --only-installed "\$@"\`
                if test -z "\$pkgs"; then
                    verbosemsg "nothing to uninstall"
                else
                    verbose rpm -e \$pkgs
                fi
                ;;
            start|stop)
                test \$# -ge 1 || usage \$op
                ec=0
                for svc
                do
                    verbose /etc/init.d/\$svc \$op || ec=1
                done
                exit \$ec
                ;;
            print-platform)
                test \$# -eq 0 || usage \$op
		echo "linux-${pp_rpm_arch}"
		;;
            print-requires)
                test \$# -ge 1 || usage \$op
                print_requires "\$@"
		;;
            *)
                usage
                ;;
        esac
.

}

pp_backend_rpm_probe () {
        echo "${pp_rpm_distro}-${pp_rpm_arch_std}"
}

pp_backend_rpm_vas_platforms () {
    case "$pp_rpm_arch_std" in
	x86_64)	echo "linux-x86_64.rpm linux-x86.rpm";;
	*86)	echo "linux-x86.rpm";;
	s390)	echo "linux-s390";;
	s390x)	echo "linux-s390x";;
	ppc*)	echo "linux-glibc23-ppc64 linux-glibc22-ppc64";;
	ia64)	echo "linux-ia64";;
	*)	pp_die "unknown architecture $pp_rpm_arch_std";;
    esac
}

pp_rpm_service_install_common () {
    cat <<-'.'

        _pp_install_service () {
            local svc level
            svc="$1"
            if [ -x /usr/lib/lsb/install_initd -a ! -r /etc/redhat-release ]
            then
                # LSB-style install
                /usr/lib/lsb/install_initd /etc/init.d/$svc &> /dev/null
            elif [ -x /sbin/chkconfig ]; then
                # Red Hat/chkconfig-style install
                /sbin/chkconfig --add $svc &> /dev/null
                /sbin/chkconfig $svc off &> /dev/null
            else
		: # manual links under /etc/init.d
            fi
        }

        _pp_enable_service () {
            local svc level
            svc="$1"
            if [ -x /usr/lib/lsb/install_initd -a ! -r /etc/redhat-release ]
            then
                # LSB-style install
		: # not sure how to enable
            elif [ -x /sbin/chkconfig ]; then
                # Red Hat/chkconfig-style install
                /sbin/chkconfig $svc on &> /dev/null
            else
                # manual install
                set -- `sed -n -e 's/^# Default-Start://p' /etc/init.d/$svc`
                start_priority=`sed -n -e 's/^# X-Quest-Start-Priority:[[:space:]]*//p' /etc/init.d/$svc`
                stop_priority=`sed -n -e 's/^# X-Quest-Stop-Priority:[[:space:]]*//p' /etc/init.d/$svc`

                # Provide default start & stop priorities of 20 & 80 in
                # accordance with Debian update-rc.d defaults
                if [ -z "$start_priority" ]; then
                    start_priority=20
                fi
                if [ -z "$stop_priority" ]; then
                    stop_priority=80
                fi
                    
                if [ -d "/etc/rc.d" ];then
                    rcdir=/etc/rc.d
                else
                    rcdir=/etc
                fi

                for level
                do ln -sf /etc/init.d/$svc $rcdir/rc$level.d/S$start_priority$svc; done
                set -- `sed -n -e 's/^# Default-Stop://p' /etc/init.d/$svc`
                for level
                do ln -sf /etc/init.d/$svc $rcdir/rc$level.d/K$stop_priority$svc; done
            fi
        }
.
}

pp_rpm_service_remove_common () {
    cat <<-'.'

        _pp_remove_service () {
            local svc
            svc="$1"
            /etc/init.d/$svc stop >/dev/null 2>&1
            if [ -x /usr/lib/lsb/remove_initd -a ! -r /etc/redhat-release ]
            then
                /usr/lib/lsb/remove_initd /etc/init.d/$svc &> /dev/null
            elif [ -x /sbin/chkconfig ]; then
                /sbin/chkconfig --del $svc &> /dev/null
            else
                if [ -d "/etc/rc.d" ];then
                    rcdir=/etc/rc.d
                else
                    rcdir=/etc
                fi

                rm -f $rcdir/rc?.d/[SK]??$svc
            fi
        }
.
}


pp_rpm_service_install () {
    pp_rpm_service_make_init_script $1 >/dev/null ||
        pp_error "could not create init script for service $1"
    echo "_pp_install_service $1"
    test $enable = yes && echo "_pp_enable_service $1"
}

pp_rpm_service_remove () {
    cat <<-.
        if [ "\$1" = "remove" -o "\$1" = "0" ]; then
            # only remove the service if not upgrade
            _pp_remove_service $1
        fi
.
}


pp_backend_rpm_init_svc_vars () {

    reload_signal=
    start_runlevels=${pp_rpm_default_start_runlevels-"2 3 4 5"} # == lsb default-start
    stop_runlevels=${pp_rpm_default_stop_runlevels-"0 1 6"} # == lsb default-stop
    svc_description="${pp_rpm_default_svc_description}" # == lsb short descr
    svc_process=

    lsb_required_start='$local_fs $network'
    lsb_should_start=
    lsb_required_stop=
    lsb_description=

    start_priority=50
    stop_priority=50            #-- stop_priority = 100 - start_priority
}

pp_rpm_service_group_make_init_script () {
    local grp=$1
    local svcs="$2"
    local script=/etc/init.d/$grp
    local out=$pp_destdir$script

    pp_add_file_if_missing $script run 755 || return 0

    cat <<-. >>$out
	#!/bin/sh
	svcs="$svcs"
.

    cat <<-'.' >>$out

        #-- prints usage message
        pp_usage () {
            echo "usage: $0 {start|stop|status|restart|reload|condrestart|try-restart|force-reload}" >&2
            return 2
        }

        #-- starts services in order.. stops them all if any break
        pp_start () {
            undo=
            for svc in $svcs; do
                if /etc/init.d/$svc start; then
                    undo="$svc $undo"
                else
                    if test -n "$undo"; then
                        for svc in $undo; do
                           /etc/init.d/$svc stop
                        done
                        return 1
                    fi
                fi
            done
            return 0
        }

        #-- stops services in reverse
        pp_stop () {
            reverse=
            for svc in $svcs; do
                reverse="$svc $reverse"
            done
            rc=0
            for svc in $reverse; do
                /etc/init.d/$svc stop || rc=$?
            done
            return $rc
        }

        #-- returns true only if all services return true status
        pp_status () {
            rc=0
            for svc in $svcs; do
                /etc/init.d/$svc status || rc=$?
            done
            return $rc
        }

        pp_reload () {
            rc=0
            for svc in $svcs; do
                /etc/init.d/$svc reload || rc=$?
            done
            return $rc
        }

        case "$1" in
            start)          pp_start;;
            stop)           pp_stop;;
            restart)        pp_stop; pp_start;;
            status)         pp_status;;
            try-restart|condrestart)
                            if pp_status >/dev/null; then
                                    pp_restart
                            fi;;
            reload)         pp_reload;;
            force-reload)   if pp_status >/dev/null; then
                                    pp_reload
                            else
                                    pp_restart
                            fi;;
            *)              pp_usage;;
        esac
.
    chmod 755 $out
}

pp_rpm_service_make_init_script () {
    local svc=$1
    local script=/etc/init.d/$svc
    local out=$pp_destdir$script
    local _process _cmd _rpmlevels

    pp_add_file_if_missing $script run 755 || return 0

    #-- start out as an empty shell script
    cat <<-'.' >$out
	#!/bin/sh
.

    #-- determine the process name from $cmd unless $svc_process is given
    set -- $cmd
    _process=${svc_process:-"$1"}

    #-- construct a start command that builds a pid file if needed
    _cmd="$cmd";
    if test -z "$pidfile"; then
        pidfile=/var/run/$svc.pid
        _cmd="$cmd & echo \$! > \$pidfile"
    fi
    if test "$user" != "root"; then
        _cmd="su $user -c exec $_cmd";
    fi

    #-- generate the Red Hat chkconfig headers
    _rpmlevels=`echo $start_runlevels | tr -d ' '`
    cat <<-. >>$out
	# chkconfig: ${_rpmlevels:--} ${start_priority:-50} ${stop_priority:-50}
	# description: ${svc_description:-no description}
	# processname: ${_process}
	# pidfile: ${pidfile}
.

    #-- generate the LSB init info
    cat <<-. >>$out
	### BEGIN INIT INFO
	# Provides: ${svc}
	# Required-Start: ${lsb_required_start}
	# Should-Start: ${lsb_should_start}
	# Required-Stop: ${lsb_required_stop}
	# Default-Start: ${start_runlevels}
	# Default-Stop: ${stop_runlevels}
	# Short-Description: ${svc_description}
	### END INIT INFO
	# Generated by PolyPackage ${pp_version}
	# ${copyright}

	prog="`echo $cmd | sed -e 's: .*::' -e 's:^.*/::'`"

.

    if test x"${svc_description}" = x"${pp_rpm_default_svc_description}"; then
        svc_description=
    fi

    #-- write service-specific definitions
    cat <<. >>$out
	#-- definitions specific to service ${svc}
	svc_name="${svc_description:-$svc service}"
	user="${user}"
	pidfile="${pidfile}"
	stop_signal="${stop_signal}"
	reload_signal="${reload_signal}"
	pp_exec_cmd () { $_cmd; }
.

    #-- write the generic part of the init script
    cat <<'.' >>$out

        #-- use system message logging, if available
        if [ -f /lib/lsb/init-functions -a ! -r /etc/redhat-release ]; then
            . /lib/lsb/init-functions
            pp_success_msg () { log_success_msg "$@"; }
            pp_failure_msg () { log_failure_msg "$@"; }
            pp_warning_msg () { log_warning_msg "$@"; }
        elif [ -f /etc/init.d/functions ]; then
            . /etc/init.d/functions
            pp_success_msg () { echo -n "$*"; success "$@"; echo; }
            pp_failure_msg () { echo -n "$*"; failure "$@"; echo; }
            pp_warning_msg () { echo -n "$*"; warning "$@"; echo; }
        else
            pp_success_msg () { echo ${1:+"$*:"} OK; }
            pp_failure_msg () { echo ${1:+"$*:"} FAIL; }
            pp_warning_msg () { echo ${1:+"$*:"} WARNING; }
        fi

        #-- prints a status message
        pp_msg () { echo -n "$*: "; }

        #-- prints usage message
        pp_usage () {
            echo "usage: $0 {start|stop|status|restart|reload|condrestart|try-restart|force-reload}" >&2
            return 2
        }

        #-- reloads the service, if possible
        #   returns 0=success 1=failure 3=unimplemented
        pp_reload () {
            test -n "$reload_signal" || return 3 # unimplemented
            pp_msg "Reloading ${svc_name}"
            if pp_signal -${reload_signal}; then
                pp_success_msg
                return 0
            else
                pp_failure_msg "not running"
                return 1
            fi
        }

        #-- delivers signal $1 to the pidfile
        #   returns 0=success 1=failure
        pp_signal () {
            if test -s "$pidfile"; then
                read pid < "$pidfile" 2>/dev/null
                kill "$@" "$pid" 2>/dev/null
            else
                return 1
            fi
        }

        #-- verifies that ${svc_name} is running
        #   returns 0=success 1=failure
        pp_running () {
            if test -s "$pidfile"; then
                read pid < "$pidfile" 2>/dev/null
                if test ${pid:-0} -gt 1 && kill -0 "$pid" 2>/dev/null; then
                    # make sure name matches
                    pid="`ps -p $pid 2>/dev/null | sed -n \"s/^ *\($pid\) .*$prog *$/\1/p\"`"
                    if test -n "$pid"; then
                        return 0
                    fi
                fi
            fi
            return 1
        }

        #-- prints information about the service status
        #   returns 0=running 1=crashed 3=stopped
        pp_status () {
            pp_msg "Checking for ${svc_name}"
	    if pp_running; then
                pp_success_msg "running"
                return 0
            elif test -s "$pidfile"; then
                pp_failure_msg "not running (crashed)"
                return 1
            else
                pp_failure_msg "not running"
                return 3
            fi
        }

        #-- starts the service
        #   returns 0=success 1=failure
        pp_start () {
            pp_msg "Starting ${svc_name}"
            if pp_status >/dev/null; then
                pp_warning_msg "already started"
                return 0
            elif pp_exec_cmd; then
                pp_success_msg
                return 0
            else
                pp_failure_msg "cannot start"
                return 1
            fi
        }

        #-- stops the service
        #   returns 0=success (always)
        pp_stop () {
            pp_msg "Stopping ${svc_name}"
            if pp_signal -${stop_signal}; then
                pp_success_msg
            else
                pp_success_msg "already stopped"
            fi
            rm -f "$pidfile"
            return 0
        }

        #-- stops and starts the service
        pp_restart () {
            pp_stop
            pp_start
        }

        case "$1" in
            start)          pp_start;;
            stop)           pp_stop;;
            restart)        pp_restart;;
            status)         pp_status;;
            try-restart|condrestart)
                            if pp_status >/dev/null; then
                                    pp_restart
                            fi;;
            reload)         pp_reload;;
            force-reload)   if pp_status >/dev/null; then
                                    pp_reload
                            else
                                    pp_restart
                            fi;;
            *)              pp_usage;;
        esac

.
    chmod 755 $out
}
pp_backend_rpm_function () {
    case "$1" in
        pp_mkgroup) cat<<'.';;
            /usr/sbin/groupadd -f -r "$1"
.
        pp_mkuser:depends) echo pp_mkgroup;;
        pp_mkuser) cat<<'.';;
            pp_mkgroup "${2:-$1}" || return 1
            /usr/sbin/useradd \
		-g "${2:-$1}" \
		-M -d "${3:-/nonexistent}" \
		-s "${4:-/bin/false}" \
		-r "$1"
.
        pp_havelib) cat<<'.';;
            for pp_tmp_dir in `echo "/usr/lib:/lib${3:+:$3}" | tr : ' '`; do
                test -r "$pp_tmp_dir/lib$1.so{$2:+.$2}" && return 0
            done
            return 1
.
	*) false;;
    esac
}

: NOTES <<.

 # creating a dmg file for publishing on the web
    hdiutil create -srcfolder /path/foo foo.dmg
    hdiutil internet-enable -yes /path/foo.dmg
 # Layout for packages
    <name>-<cpy>/component/<file>
    <name>-<cpt>/extras/postinstall
    <name>-<cpt>/extras/postupgrade
 # /Developer/usr/bin/packagemaker (man packagemaker)

    Make a bunch of packages, and then build a 'distribution'
    which is only understood by macos>10.4

 # Message files in the resource path used are
    Welcome.{rtf,html,rtfd,txt} - limited text shown in Intro
    ReadMe.{rtf,html,rtfd,txt} - scrollable/printable, after Intro
    License.{rtf,html,rtfd,txt} - ditto, user must click 'Accept'
    background.{jpg,tif,gif,pict,eps,pdf} 620x418 background image

 # These scripts looked for in the resource path
    InstallationCheck $pkgpath $defaultloc $targetvol
	0:ok 32:warn 32+x:warn[1] 64:stop 96+x:stop[2]
    VolumeCheck $volpath
	0:ok 32:failure 32+x:failure[3]
    preflight   $pkgpath $targetloc $targetvol    [priv]
    preinstall  $pkgpath $targetloc $targetvol    [priv]
    preupgrade  $pkgpath $targetloc $targetvol    [priv]
    postinstall $pkgpath $targetloc $targetvol    [priv]
    postupgrade $pkgpath $targetloc $targetvol    [priv]
    postflight  $pkgpath $targetloc $targetvol    [priv]
	0:ok else fail (for all scripts)

    A detailed reason is deduced by finding an index x (16..31)
    in the file InstallationCheck.strings or VolumeCheck.strings.

    Scripts marked [priv] are executed with root privileges.
    None of the [priv] scripts are used by metapackages.

 # Default permissions
    Permissions of existing directories should match those
    of a clean install of the OS; typically root:admin 0775
    New directories or files should be 0775 or 0664 with the
    appropriate user:group.
    Exceptions:
	/etc	root:admin 0755
	/var    root:admin 0755

    <http://developer.apple.com/documentation/DeveloperTools/Conceptual/SoftwareDistribution4/Concepts/sd_pkg_flags.html>
    Info.plist = {
     CFBundleGetInfoString: "1.2.3, One Identity LLC.",
     CFBundleIdentifier: "com.quest.rc.openssh",
     CFBundleShortVersionString: "1.2.3",
     IFMajorVersion: 1,
     IFMinorVersion: 2,
     IFPkgFlagAllowBackRev: false,
     IFPkgFlagAuthorizationAction: "AdminAuthorization",
     IFPkgFlagDefaultLocation: "/",
     IFPkgFlagFollowLinks: true,
     IFPkgFlagInstallFat: false,
     IFPkgFlagInstalledSize: <integer>,	    # this is added by packagemaker
     IFPkgFlagIsRequired: false,
     IFPkgFlagOverwritePermissions: false,
     IFPkgFlagRelocatable: false,
     IFPkgFlagRestartAction: "NoRestart",
     IFPkgFlagRootVolumeOnly: false,
     IFPkgFlagUpdateInstalledLanguages: false,
     IFPkgFormatVersion= 0.10000000149011612,
     IFRequirementDicts: [ {
       Level = "requires",
       SpecArgument = "/opt/quest/lib/libvas.4.2.0.dylib",
       SpecType = "file",
       TestObject = true,
       TestOperator = "eq", } ]
    }

    Description.plist = {
     IFPkgDescriptionDescription = "this is the description text",
     IFPkgDescriptionTitle = "quest-openssh"
    }

 # Startup scripts
    'launchd' is a kind of combined inetd and rc/init.d system.
    <http://developer.apple.com/documentation/MacOSX/Conceptual/BPSystemStartup/Articles/DesigningDaemons.html>
    Create a /Library/LaunchDaemons/$daemonname.plist file
    Examples found in /System/Library/LaunchDaemons/
    See manual page launchd.plist(5) for details:

    { Label: "com.quest.rc.foo",                        # required
      Program: "/sbin/program",
      ProgramArguments: [ "/sbin/program", "arg1", "arg2" ], # required
      RunAtLoad: true,
      WatchPaths: [ "/etc/crontab" ],
      QueueDirectories: [ "/var/cron/tabs" ],
      inetdCompatibility: { Wait: false },                   # inetd-only
      OnDemand: false,                                       # recommended
      SessionCreate: true,
      UserName: "nobody",
      InitGroups: true,
      Sockets: {                                             # inetd only
	Listeners: {
	   SockServiceName: "ssh",
	   Bonjour: ["ssh", "sftp-ssh"], } },
      Disabled: false,
      StandardErrorPath: "/dev/null",
    }


    How to add a new user
	dscl . -create /Users/$user
	dscl . -create /Users/$user UserShell /bin/bash
	dscl . -create /Users/$user RealName "$user"
	dscl . -create /Users/$user UniqueID $uid
	dscl . -create /Users/$user PrimaryGroupID $gid
	dscl . -create /Users/$user NFSHomeDirectory /Users/$user
	dscl . -passwd /Users/$user "$passwd"
	mkdir /Users/$user
	chown $uid.$gid /Users/$user

.


pp_platforms="$pp_platforms macos"

pp_backend_macos_detect () {
    [ x"$1" = x"Darwin" ]
}

pp_backend_macos_init () {
    pp_macos_default_bundle_id_prefix="com.quest.rc."
    pp_macos_bundle_id=
    pp_macos_bundle_vendor=
    pp_macos_bundle_version=
    pp_macos_bundle_info_string=
    pp_macos_pkg_type=bundle
    pp_macos_pkg_license=
    pp_macos_pkg_readme=
    pp_macos_pkg_welcome=
    pp_macos_sudo=sudo
    pp_macos_installer_plugin=
    # OS X puts the library version *before* the .dylib extension
    pp_shlib_suffix='*.dylib'
}

pp_macos_plist () {
    typeset in
    in=""
    while test $# -gt 0; do
     case "$1" in

      start-plist) cat <<-.; in="  "; shift ;;
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
.
      end-plist) echo "</plist>"; in=; shift;;

      '[')   echo "$in<array>"; in="$in  "; shift;;
      ']')   echo "$in</array>"; in="${in#  }"; shift;;
      '{')   echo "<dict>"; in="$in      "; shift;;
      '}')   echo "</dict>"; in="${in#      }"; shift;;
      key)         shift; echo "$in<key>$1</key>"; shift;;
      string)      shift;
		   echo "$1" | sed -e 's/&/&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;' \
				   -e 's/^/'"$in"'<string>/;s/$/<\/string>/';
		   shift;;
      true)        echo "$in<true/>"; shift;;
      false)       echo "$in<false/>"; shift;;
      real)        shift; echo "$in<real>$1</real>"; shift;;
      integer)     shift; echo "$in<integer>$1</integer>"; shift;;
      date)        shift; echo "$in<date>$1</date>"; shift;; # ISO 8601 format
      data)        shift; echo "$in<data>$1</data>"; shift;; # base64 encoded
      *)	   pp_error "pp_macos_plist: bad argument '$1'"; shift;;
     esac
    done
}

pp_macos_rewrite_cpio () {
    typeset script
    script=$pp_wrkdir/cpio-rewrite.pl
    cat <<-'.' >$script
	#!/usr/bin/perl
	#
	# Filter a cpio file, applying the user/group/mode specified in %files
	#
	# A CPIO header block has octal fields at the following offset/lengths:
	#   0  6 magic
	#   6  6 dev
	#  12  6 ino
	#  18  6 mode
	#  24  6 uid
	#  30  6 gid
	#  36  6 nlink
	#  42  6 rdev
	#  48 11 mtime
	#  59  6 namesize (including NUL terminator)
	#  65 11 filesize
	#  76    --
	#
	use strict;
	use warnings;
	no strict 'subs';

	# set %uid, %gid, %mode based on %files
	my (%uid, %gid, %mode, %users, %groups);
	my %type_map = ( d => 0040000, f => 0100000, s => 0120000 );
	while (<DATA>) {
	    my ($type,$mode,$uid,$gid,$flags,$name) =
	        m/^(.) (\S+) (\S+) (\S+) (\S+) (\S+)/;
	    $mode = $type eq "f" ? "0644" : "0755" if $mode eq "-";
	    $uid = 0 if $uid eq "-";
	    $gid = 0 if $gid eq "-";
	    if ($uid ne "=" and $uid =~ m/\D/) {
	        unless (exists $users{$uid}) {
	            my @pw = getpwnam($uid) or die "bad username '$uid'";
	            $users{$uid} = $pw[2];
	        }
	        $uid = $users{$uid};
	    }
	    if ($gid ne "=" and $gid =~ m/\D/) {
	        unless (exists $groups{$gid}) {
	            my @gr = getgrnam($gid) or die "bad group'$gid'";
	            $groups{$gid} = $gr[2];
	        }
	        $gid = $groups{$gid};
	    }
	    $name =~ s:/$:: if $type eq "d";
	    $name = ".".$name."\0";
	    $uid{$name} = sprintf("%06o",int($uid)) unless $uid eq "=";
	    $gid{$name} = sprintf("%06o",int($gid)) unless $gid eq "=";
	    $mode{$name} = sprintf("%06o",oct($mode)|$type_map{$type}) unless $mode eq "=";
	}
	undef %users;
	undef %groups;
	# parse the cpio file
	my $hdrlen = 76;
	while (read(STDIN, my $header, $hdrlen)) {
	    my ($name, $namesize, $filesize);
	    my $filepad = 0;
	    if ($header =~ m/^07070[12]/) {
	        # SVR4 ASCII format, convert to ODC
	        if ($hdrlen == 76) {
	            # Read in rest of header and update header len for SVR4
	            read(STDIN, $header, 110 - 76, 76);
	            $hdrlen = 110;
	        }
	        my $ino = hex(substr($header, 6, 8)) & 0x3ffff;
	        my $mode = hex(substr($header, 14, 8)) & 0x3ffff;
	        my $uid = hex(substr($header, 22, 8)) & 0x3ffff;
	        my $gid = hex(substr($header, 30, 8)) & 0x3ffff;
	        my $nlink = hex(substr($header, 38, 8)) & 0x3ffff;
	        my $mtime = hex(substr($header, 46, 8)) & 0xffffffff;
	        $filesize = hex(substr($header, 54, 8)) & 0xffffffff;
	        my $dev_maj = hex(substr($header, 62, 8));
	        my $dev_min = hex(substr($header, 70, 8));
	        my $dev = &makedev($dev_maj, $dev_min) & 0x3ffff;
	        my $rdev_maj = hex(substr($header, 78, 8));
	        my $rdev_min = hex(substr($header, 86, 8));
	        my $rdev = &makedev($rdev_maj, $rdev_min) & 0x3ffff;
	        $namesize = hex(substr($header, 94, 8)) & 0x3ffff;
	        read(STDIN, $name, $namesize);
	        # Header + name is padded to a multiple of 4 bytes
	        my $namepad = (($hdrlen + $namesize + 3) & 0xfffffffc) - ($hdrlen + $namesize);
	        read(STDIN, my $padding, $namepad) if ($namepad);
	        # File data is padded to be a multiple of 4 bytes
	        $filepad = (($filesize + 3) & 0xfffffffc) - $filesize;

	        my $new_header = sprintf("070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", $dev, $ino, $mode, $uid, $gid, $nlink, $rdev, $mtime, $namesize, $filesize);
	        $header = $new_header;
	    } elsif ($header =~ m/^070707/) {
	        # POSIX Portable ASCII Format
	        $namesize = oct(substr($header, 59, 6));
	        $filesize = oct(substr($header, 65, 11));
	        read(STDIN, $name, $namesize);
	    } else {
	        die "bad magic";
	    }
	    # update uid, gid and mode (already in octal)
	    substr($header, 24, 6) = $uid{$name} if exists $uid{$name};
	    substr($header, 30, 6) = $gid{$name} if exists $gid{$name};
	    substr($header, 18, 6) = $mode{$name} if exists $mode{$name};
	    print($header, $name);
	    # check for trailer at EOF
	    last if $filesize == 0 && $name =~ /^TRAILER!!!\0/;
	    # copy-through the file data
	    while ($filesize > 0) {
	        my $seg = 8192;
	        $seg = $filesize if $filesize < $seg;
	        read(STDIN, my $data, $seg);
	        print $data;
	        $filesize -= $seg;
	    }
	    # If file data is padded, skip it
	    read(STDIN, my $padding, $filepad) if ($filepad);
	}
	# pass through any padding at the end (blocksize-dependent)
	for (;;) {
	    my $numread = read(STDIN, my $data, 8192);
	    last unless $numread;
	    print $data;
	}
	exit(0);

	sub makedev {
	    (((($_[0] & 0xff)) << 24) | ($_[1] & 0xffffff));
	}
	__DATA__
.
    # Append to the script the %files data
    cat "$@" </dev/null >> $script
    /usr/bin/perl $script || pp_error "pp_macos_rewrite_cpio error";
}

pp_macos_files_bom () {
    typeset _l t m o g f p st owner
    while read t m o g f p st; do
	# make sure that $m is padded up to 4 digits long
	case "$m" in
	    ?) m="000$m";;
	    ??) m="00$m";;
	    ???) m="0$m";;
	    ?????*) pp_error "pp_macos_writebom: mode '$m' too long";;
	esac

	# convert owner,group into owner/group in octal
	case $o in -)	o=0;; esac
	case $g in -)	g=0;; esac
	owner=`pp_d2o $o`/`pp_d2o $g`

	case $t in
	    f)
		test x"$m" = x"000-" && m=0644
		echo ".$p	10$m	$owner	`
		    /usr/bin/cksum < "${pp_destdir}$p" |
		    awk '{print $2 "	" $1}'`"
		;;
	    d)
		test x"$m" = x"000-" && m=0755
		echo ".${p%/}	4$m	$owner"
		;;
	    s)
		test x"$m" = x"000-" && m=0755
		rl=`/usr/bin/readlink "${pp_destdir}$p"`
		#test x"$rl" = x"$st" ||
		#    pp_error "symlink mismatch $rl != $st"
		echo ".$p	12$m	$owner	`
		    /usr/bin/readlink -n "${pp_destdir}$p" |
		    /usr/bin/cksum |
		    awk '{print $2 "	" $1}'`	$st"
		;;
	esac
    done
}

pp_macos_bom_fix_parents () {
    perl -pe '
	sub dirname { my $d=shift; $d=~s,/[^/]*$,,; $d; }
	sub chk { my $d=shift;
		  &chk(&dirname($d)) if $d =~ m,/,;
		  unless ($seen{$d}++) {
		    # Make sure we do not override system directories
		    if ($d =~ m:^\./(etc|var)$:) {
		      my $tgt = "private/$1";
		      my ($sum, $len) = split(/\s+/, `/usr/bin/printf "$tgt" | /usr/bin/cksum /dev/stdin`);
		      print "$d\t120755\t0/0\t$len\t$sum\t$tgt\n";
		    } elsif ($d eq "." || $d eq "./Library") {
		      print "$d\t41775\t0/80\n";
		    } elsif ($d eq "./Applications" || $d eq "./Developer") {
		      print "$d\t40775\t0/80\n";
		    } else {
		      print "$d\t40755\t0/0\n";
		    }
		  }
		}
	m/^(\S+)\s+(\d+)/;
	if (oct($2) & 040000) {
	    $seen{$1}++; # directory
	}
	&chk(&dirname($1));'
}

pp_macos_files_size () {
    typeset _l t m o g f p st owner
    while read t m o g f p st; do
	case $t in
	    f)	wc -c < "${pp_destdir}$p";;
	    s)	echo 4095;;
	    d)	;; # always seems to be zero
	esac
    done | awk '{n+=1+int($1/4096)} END {print n*4}'
}

pp_o2d () {
    awk 'BEGIN { x=0; '`echo "$1" |
	sed -e 's/./x=x*8+&;/g'`'print x;}' </dev/null
}
pp_d2o () {
    case "$1" in
	[0-7]) echo $1;;
	*) awk 'BEGIN { printf("%o\n", 0+('"$1"'));}' < /dev/null;;
    esac
}

pp_macos_mkbom () {
    #/usr/bin/mkbom -i $1 $2
    typeset path mode ugid size cksum linkpath
    typeset bomstage

    # Use mkbom if it understands -i (avoids a copy)
    if /usr/bin/mkbom -i /dev/null "$2" 2>/dev/null; then
	rm -f "$2"
	/usr/bin/mkbom -i "$1" "$2"
	return
    fi

    # On 10.4 we have this nonsense.
    pp_warn "mkbom workaround: copying source files to staging area"

    bomstage=$pp_wrkdir/bom_stage
    $pp_macos_sudo /bin/mkdir "$bomstage"
    while IFS='	' read path mode ugid size cksumi linkpath; do
	if test -h "$pp_destdir/$path"; then
	    $pp_macos_sudo /bin/ln -s "$linkpath" "$bomstage/$path"
	else
	    if test -d "$pp_destdir/$path"; then
		$pp_macos_sudo /bin/mkdir -p "$bomstage/$path"
	    else
		$pp_macos_sudo /bin/cp "$pp_destdir/$path" "$bomstage/$path"
	    fi
	    $pp_macos_sudo /bin/chmod $mode "$bomstage/$path"
	    $pp_macos_sudo /usr/sbin/chown `echo $ugid| tr / :` "$bomstage/$path"
	fi
    done <"$1"
    (cd $bomstage && $pp_macos_sudo mkbom . $pp_wrkdir/bom_stage.bom) ||
	pp_error "mkbom failed"
    $pp_macos_sudo mv $pp_wrkdir/bom_stage.bom "$2"
}

pp_backend_macos () {
    : ${pp_macos_bundle_id:=$pp_macos_default_bundle_id_prefix$name}
    case "$pp_macos_pkg_type" in
	bundle) pp_backend_macos_bundle;;
	flat) pp_backend_macos_flat;;
	*) pp_error "unsupported package type $pp_macos_pkg_type";;
    esac
}

pp_backend_macos_bundle () {
    typeset pkgdir Contents Resources lprojdir svc
    typeset Info_plist Description_plist
    typeset bundle_vendor bundle_version size cmp filelists

    mac_version=`sw_vers -productVersion`
    bundle_vendor=${pp_macos_bundle_vendor:-$vendor}

    if test -z "$pp_macos_bundle_version"; then
        bundle_version=`echo "$version.0.0.0" | sed -n -e 's/[^0-9.]//g' \
            -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'`
    else
        bundle_version="$pp_macos_bundle_version"
    fi
    source_version=`echo $version | sed 's/.*\.//'`

    # build the package layout
    pkgdir=$pp_wrkdir/$name.pkg
    Contents=$pkgdir/Contents
    Resources=$Contents/Resources
    lprojdir=$Resources/en.lproj
    mkdir $pkgdir $Contents $Resources $lprojdir ||
	pp_error "Can't make package temporary directories"

    echo "major: 1" > $Resources/package_version
    echo "minor: 0" >> $Resources/package_version
    echo "pmkrpkg1" > $Contents/PkgInfo
    case $mac_version in
        "10.6"*)
            xattr -w "com.apple.TextEncoding" "macintosh;0" "$Resources/package_version"
            xattr -w "com.apple.TextEncoding" "macintosh;0" "$Contents/PkgInfo"
            ;;
    esac

    # Copy welcome file/dir for display at package install time.
    if test -n "$pp_macos_pkg_welcome"; then
	typeset sfx
	sfx=`echo "$pp_macos_pkg_welcome"|sed 's/^.*\.\([^\.]*\)$/\1/'`
	case "$sfx" in
	    rtf|html|rtfd|txt) ;;
	    *) sfx=txt;;
	esac
	cp -R ${pp_macos_pkg_welcome} $Resources/Welcome.$sfx
    fi

    # Copy readme file/dir for display at package install time.
    if test -n "$pp_macos_pkg_readme"; then
	typeset sfx
	sfx=`echo "$pp_macos_pkg_readme"|sed 's/^.*\.\([^\.]*\)$/\1/'`
	case "$sfx" in
	    rtf|html|rtfd|txt) ;;
	    *) sfx=txt;;
	esac
	cp -R ${pp_macos_pkg_readme} $Resources/ReadMe.$sfx
    fi

    # Copy license file/dir for display at package install time.
    if test -n "$pp_macos_pkg_license"; then
	typeset sfx
	sfx=`echo "$pp_macos_pkg_license"|sed 's/^.*\.\([^\.]*\)$/\1/'`
	case "$sfx" in
	    rtf|html|rtfd|txt) ;;
	    *) sfx=txt;;
	esac
	cp -R ${pp_macos_pkg_license} $Resources/License.$sfx
    fi

    # Add services (may modify %files)
    for svc in $pp_services .; do
	test . = "$svc" && continue
	pp_macos_add_service $svc
    done

    # Find file lists (%files.* includes ignore files)
    for cmp in $pp_components; do
	test -f $pp_wrkdir/%files.$cmp && filelists="$filelists${filelists:+ }$pp_wrkdir/%files.$cmp"
    done

    # compute the installed size
    size=`cat $filelists | pp_macos_files_size`

    #-- Create Info.plist
    Info_plist=$Contents/Info.plist
    pp_macos_plist \
	start-plist \{ \
	key CFBundleGetInfoString string \
	    "${pp_macos_bundle_info_string:-$version $bundle_vendor}" \
	key CFBundleIdentifier string \
	    "${pp_macos_bundle_id}" \
    key CFBundleName string "$name" \
    key CFBundleShortVersionString string "$bundle_version.$source_version" \
	key IFMajorVersion integer 1 \
	key IFMinorVersion integer 0 \
	key IFPkgFlagAllowBackRev false \
	key IFPkgFlagAuthorizationAction string "RootAuthorization" \
	key IFPkgFlagDefaultLocation string "/" \
	key IFPkgFlagFollowLinks true \
	key IFPkgFlagInstallFat true \
	key IFPkgFlagInstalledSize integer $size \
	key IFPkgFlagIsRequired false \
	key IFPkgFlagOverwritePermissions true \
	key IFPkgFlagRelocatable false \
	key IFPkgFlagRestartAction string "NoRestart" \
	key IFPkgFlagRootVolumeOnly true \
	key IFPkgFlagUpdateInstalledLanguages false \
	key IFPkgFlagUseUserMask false \
	key IFPkgFormatVersion real 0.10000000149011612 \
	key SourceVersion string $source_version \
	\} end-plist> $Info_plist

    # write en.lproj/Description.plist
    Description_plist=$lprojdir/Description.plist
    pp_macos_plist \
 	start-plist \{ \
        key IFPkgDescriptionDeleteWarning string "" \
	    key IFPkgDescriptionDescription string "$pp_macos_bundle_info_string" \
	    key IFPkgDescriptionTitle       string "$name" \
	    key IFPkgDescriptionVersion string "$bundle_version.$source_version" \
 	\} end-plist > $Description_plist

    # write Resources/files
    awk '{print $6}' $filelists > $Resources/files

    # write package size file
    printf \
"NumFiles 0
InstalledSize $size
CompressedSize 0
" > $Resources/$name.sizes

    # write Resources/preinstall
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%pre.$cmp; then
	    if test ! -s $Resources/preinstall; then
		echo "#!/bin/sh" > $Resources/preinstall
		chmod +x $Resources/preinstall
	    fi
	    cat $pp_wrkdir/%pre.$cmp >> $Resources/preinstall
	    echo : >> $Resources/preinstall
	fi
    done

    # write Resources/postinstall
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%post.$cmp; then
	    if test ! -s $Resources/postinstall; then
		echo "#!/bin/sh" > $Resources/postinstall
		chmod +x $Resources/postinstall
	    fi
	    cat $pp_wrkdir/%post.$cmp >> $Resources/postinstall
	    echo : >> $Resources/postinstall
	fi
    done

    # write Resources/postupgrade
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%postup.$cmp; then
	    if test ! -s $Resources/postupgrade; then
		echo "#!/bin/sh" > $Resources/postupgrade
		chmod +x $Resources/postupgrade
	    fi
	    cat $pp_wrkdir/%postup.$cmp >> $Resources/postupgrade
	    echo : >> $Resources/postupgrade
	fi
    done

    # write Resources/preremove
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%preun.$cmp; then
	    if test ! -s $Resources/preremove; then
		echo "#!/bin/sh" > $Resources/preremove
		chmod +x $Resources/preremove
	    fi
	    cat $pp_wrkdir/%preun.$cmp >> $Resources/preremove
	    echo : >> $Resources/preremove
	fi
    done

    # write Resources/postremove
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%postun.$cmp; then
	    if test ! -s $Resources/postremove; then
		echo "#!/bin/sh" > $Resources/postremove
		chmod +x $Resources/postremove
	    fi
	    cat $pp_wrkdir/%postun.$cmp >> $Resources/postremove
	    echo : >> $Resources/postremove
	fi
    done

    # write uninstall info
    echo "version=$version" > $Resources/uninstall
    if [ -n "$pp_macos_requires" ];then
        echo "requires=$pp_macos_requires" >> $Resources/uninstall
    fi

    . $pp_wrkdir/%fixup

    # Create the bill-of-materials (Archive.bom)
    cat $filelists | pp_macos_files_bom | sort |
	pp_macos_bom_fix_parents > $pp_wrkdir/tmp.bomls

    pp_macos_mkbom $pp_wrkdir/tmp.bomls $Contents/Archive.bom

    # Create the cpio archive (Archive.pax.gz)
    (
    cd $pp_destdir &&
    awk '{ print "." $6 }' $filelists | sed 's:/$::' | sort | /usr/bin/cpio -o | pp_macos_rewrite_cpio $filelists | gzip -9f -c > $Contents/Archive.pax.gz
    )

    # Copy installer plugins if any
    if test -n "$pp_macos_installer_plugin"; then
	if test ! -f "$pp_macos_installer_plugin/InstallerSections.plist"; then
	    pp_error "Missing InstallerSections.plist file in $pp_macos_installer_plugin"
	fi
	mkdir -p $pkgdir/Plugins
	cp -R "$pp_macos_installer_plugin"/* $pkgdir/Plugins
    fi

    test -d $pp_wrkdir/bom_stage && $pp_macos_sudo rm -rf $pp_wrkdir/bom_stage

    rm -f ${name}-${version}.dmg
    hdiutil create -fs HFS+ -srcfolder $pkgdir -volname $name ${name}-${version}.dmg
}

pp_backend_macos_flat () {
    typeset pkgdir bundledir Resources lprojdir svc
    typeset Info_plist Description_plist
    typeset bundle_vendor bundle_version size numfiles cmp filelists

    mac_version=`sw_vers -productVersion`
    bundle_vendor=${pp_macos_bundle_vendor:-$vendor}

    if test -z "$pp_macos_bundle_version"; then
        bundle_version=`echo "$version.0.0.0" | sed -n -e 's/[^0-9.]//g' \
            -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'`
    else
        bundle_version="$pp_macos_bundle_version"
    fi
    source_version=`echo $version | sed 's/.*\.//'`

    # build the flat package layout
    pkgdir=$pp_wrkdir/pkg
    bundledir=$pp_wrkdir/pkg/$name.pkg
    Resources=$pkgdir/Resources
    lprojdir=$Resources/en.lproj
    mkdir $pkgdir $bundledir $Resources $lprojdir ||
	pp_error "Can't make package temporary directories"

    # Add services (may modify %files)
    for svc in $pp_services .; do
	test . = "$svc" && continue
	pp_macos_add_service $svc
    done

    # Find file lists (%files.* includes ignore files)
    for cmp in $pp_components; do
	test -f $pp_wrkdir/%files.$cmp && filelists="$filelists${filelists:+ }$pp_wrkdir/%files.$cmp"
    done

    # compute the installed size and number of files/dirs
    size=`cat $filelists | pp_macos_files_size`
    numfiles=`cat $filelists | wc -l`
    numfiles="${numfiles##* }"

    # Write Distribution file
    cat <<-. >$pkgdir/Distribution
	<?xml version="1.0" encoding="UTF-8"?>
	<installer-script minSpecVersion="1.000000" authoringTool="com.quest.rc.PolyPkg" authoringToolVersion="$pp_version" authoringToolBuild="$pp_revision">
	    <title>$name $version</title>
	    <options customize="never" allow-external-scripts="no"/>
	    <domains enable_localSystem="true"/>
.
    if test -n "$pp_macos_pkg_welcome"; then
	cp -R "${pp_macos_pkg_welcome}" $Resources
	echo "    <welcome file=\"${pp_macos_pkg_welcome##*/}\"/>" >>$pkgdir/Distribution
    fi
    if test -n "$pp_macos_pkg_readme"; then
	cp -R "${pp_macos_pkg_readme}" $Resources
	echo "    <readme file=\"${pp_macos_pkg_readme##*/}\"/>" >>$pkgdir/Distribution
    fi
    if test -n "$pp_macos_pkg_license"; then
	cp -R "${pp_macos_pkg_license}" $Resources
	echo "    <license file=\"${pp_macos_pkg_license##*/}\"/>" >>$pkgdir/Distribution
    fi
    cat <<-. >>$pkgdir/Distribution
	    <choices-outline>
	        <line choice="choice0"/>
	    </choices-outline>
	    <choice id="choice0" title="$name $version">
	        <pkg-ref id="${pp_macos_bundle_id}"/>
	    </choice>
	    <pkg-ref id="${pp_macos_bundle_id}" installKBytes="$size" version="$version" auth="Root">#$name.pkg</pkg-ref>
	</installer-script>
.

    # write scripts archive
    # XXX - missing preupgrade, preflight, postflight
    mkdir $pp_wrkdir/scripts
    for cmp in $pp_components; do
	if test -s $pp_wrkdir/%pre.$cmp; then
	    if test ! -s $pp_wrkdir/scripts/preinstall; then
		echo "#!/bin/sh" > $pp_wrkdir/scripts/preinstall
		chmod +x $pp_wrkdir/scripts/preinstall
	    fi
	    cat $pp_wrkdir/%pre.$cmp >> $pp_wrkdir/scripts/preinstall
	    echo : >> $pp_wrkdir/scripts/preinstall
	fi
	if test -s $pp_wrkdir/%post.$cmp; then
	    if test ! -s $pp_wrkdir/scripts/postinstall; then
		echo "#!/bin/sh" > $pp_wrkdir/scripts/postinstall
		chmod +x $pp_wrkdir/scripts/postinstall
	    fi
	    cat $pp_wrkdir/%post.$cmp >> $pp_wrkdir/scripts/postinstall
	    echo : >> $pp_wrkdir/scripts/postinstall
	fi
	if test -s $pp_wrkdir/%postup.$cmp; then
	    if test ! -s $pp_wrkdir/scripts/postupgrade; then
		echo "#!/bin/sh" > $pp_wrkdir/scripts/postupgrade
		chmod +x $pp_wrkdir/scripts/postupgrade
	    fi
	    cat $pp_wrkdir/%postup.$cmp >> $pp_wrkdir/scripts/postupgrade
	    echo : >> $pp_wrkdir/scripts/postupgrade
	fi
	# XXX - not supported
	if test -s $pp_wrkdir/%preun.$cmp; then
	    if test ! -s $pp_wrkdir/scripts/preremove; then
		echo "#!/bin/sh" > $pp_wrkdir/scripts/preremove
		chmod +x $pp_wrkdir/scripts/preremove
	    fi
	    cat $pp_wrkdir/%preun.$cmp >> $pp_wrkdir/scripts/preremove
	    echo : >> $pp_wrkdir/scripts/preremove
	fi
	# XXX - not supported
	if test -s $pp_wrkdir/%postun.$cmp; then
	    if test ! -s $pp_wrkdir/scripts/postremove; then
		echo "#!/bin/sh" > $pp_wrkdir/scripts/postremove
		chmod +x $pp_wrkdir/scripts/postremove
	    fi
	    cat $pp_wrkdir/%postun.$cmp >> $pp_wrkdir/scripts/postremove
	    echo : >> $pp_wrkdir/scripts/postremove
	fi
    done
    if test "`echo $pp_wrkdir/scripts/*`" != "$pp_wrkdir/scripts/*"; then
	# write scripts archive, scripts are mode 0755 uid/gid 0/0
	# resetting the owner and mode is not strictly required
	(
	cd $pp_wrkdir/scripts || pp_error "Can't cd to $pp_wrkdir/scripts"
	rm -f $pp_wrkdir/tmp.files.scripts
	for s in *; do
	    echo "f 0755 0 0 - ./$s" >>$pp_wrkdir/tmp.files.scripts
	done
	find . -type f | /usr/bin/cpio -o | pp_macos_rewrite_cpio $pp_wrkdir/tmp.files.scripts | gzip -9f -c > $bundledir/Scripts
	)
    fi

    # Write PackageInfo file
    cat <<-. >$bundledir/PackageInfo
	<?xml version="1.0" encoding="UTF-8"?>
	<pkg-info format-version="2" identifier="${pp_macos_bundle_id}" version="$version" install-location="/" relocatable="false" overwrite-permissions="true" followSymLinks="true" auth="root">
	    <payload installKBytes="$size" numberOfFiles="$numfiles"/>
.
    if test -s $bundledir/Scripts; then
	echo "    <scripts>" >>$bundledir/PackageInfo
	for s in preflight postflight preinstall postinstall preupgrade postupgrade; do
	    if test -s "$pp_wrkdir/scripts/$s"; then
		echo "	<$s file=\"$s\"/>" >>$bundledir/PackageInfo
	    fi
	done
	echo "    </scripts>" >>$bundledir/PackageInfo
    fi
    cat <<-. >>$bundledir/PackageInfo
	</pkg-info>
.

    . $pp_wrkdir/%fixup

    # Create the bill-of-materials (Bom)
    cat $filelists | pp_macos_files_bom | sort |
	pp_macos_bom_fix_parents > $pp_wrkdir/tmp.bomls
    pp_macos_mkbom $pp_wrkdir/tmp.bomls $bundledir/Bom

    # Create the cpio payload
    (
    cd $pp_destdir || pp_error "Can't cd to $pp_destdir"
    awk '{ print "." $6 }' $filelists | sed 's:/$::' | sort | /usr/bin/cpio -o | pp_macos_rewrite_cpio $filelists | gzip -9f -c > $bundledir/Payload
    )

    # Copy installer plugins if any
    if test -n "$pp_macos_installer_plugin"; then
	if test ! -f "$pp_macos_installer_plugin/InstallerSections.plist"; then
	    pp_error "Missing InstallerSections.plist file in $pp_macos_installer_plugin"
	fi
	mkdir -p $pkgdir/Plugins
	cp -R "$pp_macos_installer_plugin"/* $pkgdir/Plugins
    fi

    test -d $pp_wrkdir/bom_stage && $pp_macos_sudo rm -rf $pp_wrkdir/bom_stage

    # Create the flat package with xar (like pkgutil --flatten does)
    # Note that --distribution is only supported by Mac OS X 10.6 and above
    xar_flags="--compression=bzip2 --no-compress Scripts --no-compress Payload"
    case $mac_version in
        "10.5"*) ;;
	*)	 xar_flags="$xar_flags --distribution";;
    esac
    (cd $pkgdir && /usr/bin/xar $xar_flags -cf "../$name-$version.pkg" *)
}

pp_backend_macos_cleanup () {
    :
}

pp_backend_macos_names () {
    case "$pp_macos_pkg_type" in
	bundle) echo ${name}.pkg;;
	flat) echo ${name}-${version}.pkg;;
	*) pp_error "unsupported package type $pp_macos_pkg_type";;
    esac
}

pp_backend_macos_install_script () {
    echo '#!/bin/sh'
    typeset pkgname platform

    pkgname="`pp_backend_macos_names`"
    platform="`pp_backend_macos_probe`"
    pp_install_script_common

    cat <<.
	test \$# -eq 0 && usage
	op="\$1"; shift

	case "\$op" in
	list-components)
	    test \$# -eq 0 || usage \$op
	    echo "$pp_components"
	    ;;
	list-services)
	    test \$# -eq 0 || usage \$op
	    echo "$pp_services"
	    ;;
	list-files)
	    test \$# -ge 1 || usage \$op
	    echo \${PP_PKGDESTDIR:-.}/"$pkgname"
	    ;;
	install)
	    test \$# -ge 1 || usage \$op
	    vol=/Volumes/pp\$\$
	    pkg=\$vol/${name}-${version}.pkg
	    hdiutil attach -readonly -mountpoint \$vol \
		\${PP_PKGDESTDIR:-.}/"$pkgname"
	    trap "hdiutil detach \$vol" 0
	    installer -pkginfo -pkg \$pkg
	    installer -verbose -pkg \$pkg -target /
	    ;;
	uninstall)
	    test \$# -ge 1 || usage \$op
	    # XXX
	    echo "Uninstall not implemented" >&2
	    exit 1;;
	start|stop)
	    test \$# -ge 1 || usage \$op
	    ec=0
	    for svc
	    do
		# XXX
		echo "\${op} not implemented" >&2
		ec=1
	    done
	    exit \$ec
	    ;;
	print-platform)
	    echo "$platform"
	    ;;
	*)
	    usage;;
	esac
.
}

pp_backend_macos_init_svc_vars () {
    pp_macos_start_services_after_install=true
    pp_macos_service_name=
    pp_macos_default_service_id_prefix="com.quest.rc."
    pp_macos_service_id=
    pp_macos_service_user=
    pp_macos_service_group=
    pp_macos_service_initgroups=
    pp_macos_service_umask=
    pp_macos_service_cwd=
    pp_macos_service_nice=
    pp_macos_svc_plist_file=
}

pp_macos_launchd_plist () {
    typeset svc svc_id

    svc="$1"
    svc_id="$2"

    set -- $cmd

    if [ -n "$pp_macos_svc_plist_file" ]; then
        echo "## Launchd plist file already defined at $pp_macos_svc_plist_file"
        return
    fi

    echo "## Generating the launchd plist file for $svc"
    pp_macos_svc_plist_file="$pp_wrkdir/$svc.plist"
    cat <<-. > $pp_macos_svc_plist_file
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN
	http://www.apple.com/DTDs/PropertyList-1.0.dtd >
	<plist version="1.0">
	<dict>
	    <key>Label</key>
	    <string>$svc_id</string>
	    <key>ProgramArguments</key>
	    <array>
.
    while test $# != 0; do
	printf "        <string>$1</string>\n" >> $pp_macos_svc_plist_file
	shift
    done
    cat <<-. >> $pp_macos_svc_plist_file
	    </array>
	    <key>KeepAlive</key>
	    <true/>
.
    if test -n "$pp_macos_service_user"; then
	printf "    <key>UserName</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_user</string>\n" >> $pp_macos_svc_plist_file
    fi
    if test -n "$pp_macos_service_group"; then
	printf "    <key>GroupName</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_group</string>\n" >> $pp_macos_svc_plist_file
    fi
    if test -n "$pp_macos_service_initgroups"; then
	printf "    <key>InitGroups</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_initgroups</string>\n" >> $pp_macos_svc_plist_file
    fi
    if test -n "$pp_macos_service_umask"; then
	printf "    <key>Umask</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_umask</string>\n" >> $pp_macos_svc_plist_file
    fi
    if test -n "$pp_macos_service_cwd"; then
	printf "    <key>WorkingDirectory</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_cwd</string>\n" >> $pp_macos_svc_plist_file
    fi
    if test -n "$pp_macos_service_nice"; then
	printf "    <key>Nice</key>\n" >> $pp_macos_svc_plist_file
	printf "    <string>$pp_macos_service_nice</string>\n" >> $pp_macos_svc_plist_file
    fi
    cat <<-. >> $pp_macos_svc_plist_file
	</dict>
	</plist>
.
}

pp_macos_add_service () {
    typeset svc svc_id plist_file plist_dir

    pp_load_service_vars "$1"
    svc=${pp_macos_service_name:-$1}
    svc_id=${pp_macos_service_id:-$pp_macos_default_service_id_prefix$svc}

    #-- create a plist file for svc
    pp_macos_launchd_plist "$svc" "$svc_id"

    #-- copy the plist file into place and add to %files
    plist_dir="/Library/LaunchDaemons"
    plist_file="$plist_dir/$svc_id.plist"
    mkdir -p "$pp_destdir/$plist_dir"
    cp "$pp_macos_svc_plist_file" "$pp_destdir/$plist_file"
    pp_add_file_if_missing "$plist_file"

    #-- add code to start the service on install & upgrade
    ${pp_macos_start_services_after_install} && <<-. >> $pp_wrkdir/%post.$svc
	# start service '$svc' automatically after install
	launchctl load "$plist_file"
.
    ${pp_macos_start_services_after_install} && <<-. >> $pp_wrkdir/%postup.$svc
        # start service '$svc' automatically after upgrade
        # This is necessary if the service is new since the previous version.
        # XXX: Does launchd automatically reload an service if its binary
        # is replaced?
        launchctl load "$plist_file"
.
}

pp_backend_macos_probe () {
    typeset name vers arch
    case `sw_vers -productName` in
         "Mac OS X") name="macos";;
	 *)          name="unknown";;
    esac
    vers=`sw_vers -productVersion | sed -e 's/^\([^.]*\)\.\([^.]*\).*/\1\2/'`
    arch=`arch`
    echo "$name$vers-$arch"
}

pp_backend_macos_vas_platforms () {
    echo "osx"    # XXX non-really sure what they do.. it should be "macos"
}
pp_backend_macos_function () {
    case "$1" in
	_pp_macos_search_unused) cat<<'.';;
	    # Find an unused value in the given path
	    # args: path attribute minid [maxid]
		pp_tmp_val=$3
		while :; do
		    test $pp_tmp_val -ge ${4:-999999} && return 1
		    /usr/bin/dscl . -search "$1" "$2" $pp_tmp_val |
			grep . > /dev/null || break
		    pp_tmp_val=`expr $pp_tmp_val + 1`
		done
		echo $pp_tmp_val
.
        pp_mkgroup:depends) echo _pp_macos_search_unused;;
        pp_mkgroup) cat<<'.';;
	    set -e
	    /usr/bin/dscl . -read /Groups/"$1" >/dev/null 2>&1 && return
	    pp_tmp_gid=`_pp_macos_search_unused /Groups PrimaryGroupID 100`
	    /usr/bin/dscl . -create /Groups/"$1"
	    /usr/bin/dscl . -create /Groups/"$1" PrimaryGroupID $pp_tmp_gid
	    /usr/bin/dscl . -create /Groups/"$1" RealName "Group $1"
	    /usr/bin/dscl . -create /Groups/"$1" GroupMembership ""
	    /usr/bin/dscl . -create /Groups/"$1" Password '*'
.
        pp_mkuser:depends) echo pp_mkgroup _pp_macos_search_unused;;
        pp_mkuser) cat<<'.';;
	    set -e
	    /usr/bin/dscl . -read /Users/"$1" >/dev/null 2>&1 && return
	    pp_tmp_uid=`_pp_macos_search_unused /Users UniqueID 100`
	    pp_mkgroup "${2:-$1}"
	    pp_tmp_gid=`/usr/bin/dscl . -read /Groups/"${2:-$1}" \
		PrimaryGroupID | awk '{print $2}'`
	    /usr/bin/dscl . -create /Users/"$1"
	    /usr/bin/dscl . -create /Users/"$1" PrimaryGroupID $pp_tmp_gid
	    /usr/bin/dscl . -create /Users/"$1" NFSHomeDirectory \
				    "${3:-/var/empty}"
	    /usr/bin/dscl . -create /Users/"$1" UserShell \
				    "${4:-/usr/bin/false}"
	    /usr/bin/dscl . -create /Users/"$1" RealName "$1"
	    /usr/bin/dscl . -create /Users/"$1" UniqueID $pp_tmp_uid
	    /usr/bin/dscl . -create /Users/"$1" Password '*'
.
        pp_havelib) cat<<'.';;
	    # (use otool -L to find dependent libraries)
            for pp_tmp_dir in `echo "${3:+$3:}/usr/local/lib:/lib:/usr/lib" |
		    tr : ' '`; do
                test -r "$pp_tmp_dir/lib$1{$2:+.$2}.dylib" && return 0
            done
            return 1
.
	*) false;;
    esac
}

pp_platforms="$pp_platforms inst"

pp_backend_inst_detect () {
    case "$1" in
	IRIX*)	return 0;;
	*)	return 1;;
    esac
}

pp_backend_inst_init () {
    pp_readlink_fn=pp_ls_readlink
}

pp_backend_inst_create_idb()
{
    typeset t m o g f p st

    while read t m o g f p st; do
        if test x"$o" = x"-"; then
            o="root"
        fi
        if test x"$g" = x"-"; then
            g="sys"
        fi
        case "$t" in
            f)  test x"$m" = x"-" && m=444
                echo "f 0$m $o $g $p $p $name.sw.base"
                ;;
            d)  test x"$m" = x"-" && m=555
                echo "d 0$m $o $g $p $p $name.sw.base"
                ;;
            s)  test x"$m" = x"-" && m=777
                test x"$m" = x"777" ||
                    pp_warn "$p: invalid mode $m for symlink, should be 777 or -"
                echo "l 0$m $o $g $p $p $name.sw.base symval($st)"
                ;;
        esac
    done
}

pp_backend_inst_create_spec()
{
    echo "product $name"
    echo "    id \"${summary}. Version: ${version}\""
    echo "    image sw"
    echo "        id \"Software\""
    echo "        version $version"
    echo "        order 9999"
    echo "        subsys base"
    echo "            id \"Base Software\""
    echo "            replaces self"
    echo "            exp $name.sw.base"
    echo "        endsubsys"
    echo "    endimage"
    echo "endproduct"
}

pp_backend_inst () {
    curdir=`pwd`

    cd "$pp_opt_wrkdir"

    # initialize
    pp_inst_tardist=tardist
    pp_inst_spec=${name}.spec
    pp_inst_idb=${name}.idb
 
    rm -rf $pp_inst_tardist $pp_inst_spec $pp_inst_idb
    mkdir -p $pp_inst_tardist

    # Create idb file
    (for _cmp in $pp_components; do
        cat  %files.$_cmp | sort +4u -6 | pp_backend_inst_create_idb
    done) >> $pp_inst_idb

    pp_backend_inst_create_spec >> $pp_inst_spec

    # Generate tardist
    gendist -verbose -all -root / -source $pp_opt_destdir -idb $pp_inst_idb -spec $pp_inst_spec -dist $pp_inst_tardist $name
    tar -cvf `pp_backend_inst_names` $pp_inst_tardist

    cd "$curdir"
}

pp_backend_inst_cleanup () {
    :
}

pp_backend_inst_names () {
    echo ${name}-${version}.tardist
}

pp_backend_inst_install_script () {
    :
}

pp_backend_inst_function () {
    echo false
}

pp_backend_inst_init_svc_vars () {
    :
}

pp_backend_inst_probe () {
    cpu=`hinv|sed -n '/^CPU/{s/000 /k /;s/^CPU: //;s/ Process.*//;s/^MIPS //;p;q;}'|tr A-Z a-z`
    echo irix`uname -r`-$cpu
}

pp_backend_inst_vas_platforms () {
    echo "irix-65"
}

pp_platforms="$pp_platforms null"

pp_backend_null_detect () {
    ! :
}

pp_backend_null_init () {
    :
}


pp_backend_null () {
    :
}

pp_backend_null_cleanup () {
    :
}

pp_backend_null_names () {
    :
}

pp_backend_null_install_script () {
    :
}

pp_backend_null_function () {
    echo false
}

pp_backend_null_init_svc_vars () {
    :
}

pp_backend_null_probe () {
    echo unknown-unknown
}

pp_backend_null_vas_platforms () {
:
}

pp_platforms="$pp_platforms bsd"

pp_bsd_munge_text () {
    # Insert a leading space on each line, replace blank lines with a
    #space followed by a full-stop.
    test -z "$1" && pp_die "pp_bsd_munge_text requires a parameter"
    echo ${1} | sed "s,^\(.*\)$, \1, " | sed "s,^[ \t]*$, .,g"
}

pp_backend_bsd_detect () {
	test x"$1" = x"FreeBSD"
}

pp_backend_bsd_init () {

    # Get the OS revision
    pp_bsd_detect_os

    # Get the arch (i386/amd64)
    pp_bsd_detect_arch

    pp_bsd_name=
    pp_bsd_version=
    pp_bsd_origin=
    pp_bsd_comment=
    pp_bsd_arch=
    pp_bsd_abi=
    pp_bsd_www=
    pp_bsd_maintainer=
    pp_bsd_prefix="/usr/local/"
    pp_bsd_desc=
    pp_bsd_message=

    # pp_bsd_category must be in array format comma separated
    # pp_bsd_category=[security,network]
    pp_bsd_category=

    # pp_bsd_licenselogic can be one of the following: single, and, or unset
    pp_bsd_licenselogic=

    # pp_bsd_licenses must be in array format comma separated
    # pp_bsd_licenses=[GPLv2,MIT]
    pp_bsd_licenses=

    # pp_bsd_annotations. These can be any key: value pair
    # key must be separated by a :
    # keyvalue pairs must be comma separated
    # pp_bsd_annotations="repo_type: binary, somekey: somevalue"
    # since all packages created by PolyPackage will be of type binary
    # let's just set it now.
    pp_bsd_annotations="repo_type: binary"

    pp_bsd_dbg_pkgname="debug"
    pp_bsd_dev_pkgname="devel"
    pp_bsd_doc_pkgname="doc"

    # Make sure any programs we require are installed
    pp_bsd_check_required_programs

}

pp_bsd_cmp_full_name () {
    typeset prefix
    prefix="${pp_bsd_name:-$name}"
    case "$1" in
        run) echo "${prefix}" ;;
        dbg) echo "${prefix}-${pp_bsd_dbg_pkgname}";;
        dev) echo "${prefix}-${pp_bsd_dev_pkgname}";;
        doc) echo "${prefix}-${pp_bsd_doc_pkgname}";;
        *)   pp_error "unknown component '$1'";
    esac
}

pp_bsd_check_required_programs () {
    local p needed notfound ok
    needed= notfound=

    # list of programs FreeBSD needs in order to create a binary package
    for prog in ${pp_bsd_required_programs:-"pkg"}
    do
        if which $prog 2>&1 > /dev/null; then
            pp_debug "$prog: found"
        else
            pp_debug "$prog: not found"
            case "$prog" in
                pkg) p=pkg;;
                *)   pp_die "Unexpected pkg tool $prog";;
            esac
            notfound="$notfound $prod"
            pp_contains "$needed" "$p" || needed="$needed $p"
        fi
    done
    if [ -n "$notfound" ]; then
        pp_error "cannot find these programs: $notfound"
        pp_error "please install these packages: $needed"
    fi
}

pp_bsd_detect_os () {
    typeset revision

    pp_bsd_os=`uname -s`
    revision=`uname -r`
    pp_bsd_os_rev=`echo $revision | awk -F '-' '{print $1}'`
}

pp_bsd_detect_arch() {
    pp_bsd_platform="`uname -m`" 
    case $pp_bsd_platform in
        amd64) pp_bsd_platform_std=x86_64;;
        i386)  pp_bsd_platform_std=i386;;
        *)     pp_bsd_platform_std=unknown;;
    esac
}

pp_bsd_label () {
    local label arg
    label="$1"; shift
    for arg
    do
        test -z "$arg" || echo "$label: $arg"
    done
}

pp_bsd_make_annotations () {

    test -z $1 && pp_die "pp_bsd_make_annotations requires a parameter"
    manifest=$1

    # Add annotations. These can be any key: value pair
    # key must be separated by a :
    # key:value pairs must be comma separated.
    if test -n "$pp_bsd_annotations"; then
        pp_debug "Processing annotations:"
        pp_bsd_label "annotations" "{" >> $manifest

        SAVEIFS=$IFS
        IFS=,
        for annotate in $pp_bsd_annotations; do
            # Remove any spaces at the start of the line
            annotate=`echo $annotate | sed 's/^ *//'`
            pp_debug "  $annotate"
            echo "  $annotate" >> $manifest
        done
        IFS=$SAVEIFS
        echo "}" >> $manifest
    fi
}

pp_bsd_make_depends() {
    typeset package origin version
    cmp=$1
    manifest=$2

    if test -s $pp_wrkdir/%depend.${cmp}; then
        echo "deps: {" >> $manifest
        cat $pp_wrkdir/%depend.${cmp} | while read package origin version; do
            if test x != x$package; then
                pp_debug "Processing dependency: $package"
                if test x != x$origin -a x != x$version; then
                    pp_debug "  $package: {origin: \"$origin\", version: \"$version\"}"
                    echo "  $package: {origin: \"$origin\", version: \"$version\"}" >> $manifest
                else
                    pp_warn "Dependency $package is missing origin or version or both"
                fi
            fi
        done
        echo "}" >> $manifest
    fi
}

pp_bsd_make_messages () {
    test -z $1 && pp_die "pp_bsd_make_messages requires a parameter"
    manifest=$1
   
    pp_debug "Processing messages"

    # Empty messages: [ ] is OK in the manifest
    pp_bsd_label "messages" "[" >> $manifest
    # Look for a single message in the variable pp_bsd_message
    if test -n "$pp_bsd_message"; then
        echo "  { message: \"`pp_bsd_munge_text "$pp_bsd_message"`\" }," >> $manifest
    fi
    local a=1
    # Look for messages in the variables pp_bsd_message_[1..n]
    var="pp_bsd_messages_1"
    while [ -n "${!var}" ]; do
        echo "  { message: \"`pp_bsd_munge_text "${!var}"`\" }," >> $manifest
        a=`expr $a + 1`
        var="pp_bsd_messages_$a"
    done
    echo "]" >> $manifest
}

pp_bsd_make_manifest() { 
    local cmp manifest

    cmp="$1"
    manifest="$2"

    package_name=`pp_bsd_cmp_full_name $cmp`

    # Required for pkg +MANIFEST
    cat <<-. >> $manifest
  name: "${package_name}"
  version: "${pp_bsd_version:-$version}"
  origin: "${pp_bsd_origin}"
  www: "${pp_bsd_www}"
  desc: "`pp_bsd_munge_text "${pp_bsd_desc:-$description}"`"
  comment: "${pp_bsd_comment:-$summary}"
  maintainer: "${pp_bsd_maintainer}"
  prefix: "${pp_bsd_prefix}"
.

    # Optional, so if they are not included in the pkg-product.pp file then do not create the label
    pp_bsd_label "categories" "${pp_bsd_categories}" >> $manifest
    pp_bsd_label "arch" "${pp_bsd_arch}" >> $manifest
    pp_bsd_label "abi" "${pp_bsd_abi}" >> $manifest
    pp_bsd_label "licenselogic" "${pp_bsd_licenselogic}" >> $manifest
    pp_bsd_label "licenses" "${pp_bsd_licenses}" >> $manifest

    pp_bsd_make_annotations $manifest
    pp_bsd_make_depends $cmp $manifest

    pp_bsd_make_messages $manifest
}

pp_bsd_fakeroot () {
    if test -s $pp_wrkdir/fakeroot.save; then
    fakeroot -i $pp_wrkdir/fakeroot.save -s $pp_wrkdir/fakeroot.save "$@"
    else
    fakeroot -s $pp_wrkdir/fakeroot.save "$@"
    fi
}

pp_bsd_make_data() {
    # t = file type
    # m = file mode
    # o = file owner
    # g = file group
    # f = ?
    # p = file path
    # st = file link
    #
    # EXAMPLE: f 755 root httpd v /usr/bin/hello goodbye
    # -> /usr/bin/hello: {uname: root, gname: httpd, perm: 755 } goodbye
    typeset _l t m o g f p st datadir
    cmp=$1
    datadir=$pp_wrkdir/`pp_bsd_cmp_full_name $cmp`
    local path

    outfilelist="$pp_wrkdir/files.list.$cmp"
    outdirslist="$pp_wrkdir/dirs.list.$cmp"

    pp_debug "Processing $pp_wrkdir/%file.${cmp}"

    echo "files: {" > $outfilelist
    echo "directories: {" > $outdirslist

    cat $pp_wrkdir/%files.${cmp} | while read t m o g f p st; do
        test x"$o" = x"-" && o="${pp_bsd_defattr_uid:-root}"
        test x"$g" = x"-" && g="${pp_bsd_defattr_gid:-wheel}"
        path=$p
        case "$t" in
            f) # Files
                # For now just skip the file if it is volatile, we will need to remove it in the pre uninstall script
                if [ x"$f" != x"v" ]; then
                    # If the directory doesn't exist where we are going to copy this file, then create it first
                    if [ ! -d `dirname "$datadir$path"` ]; then
                        pp_debug "creating directory `dirname "$datadir$path"`"
                        mkdir -p `dirname "$datadir$path"`
                    fi

                    pp_debug "install -D $datadir -o $o -g $g -h sha256 -m ${m} -v $pp_destdir$p $datadir$path";
                    pp_bsd_fakeroot install -D $datadir -o $o -g $g -h sha256 -m ${m} -v $pp_destdir$p $datadir$path;
                    echo "  \"$path\": \"-\", \"$path\": {uname: $o, gname: $g, perm: ${m}}" >> $outfilelist;
                else
                    pp_warn "file $f was marked as volatile, skipping"
                fi;
                ;; 
            d) # Directories
                pp_debug "install -D $datadir -o $o -g $g -m ${m} -d -v $datadir$path";
                pp_bsd_fakeroot install -D $datadir -o $o -g $g -m ${m} -d -v $datadir$path;
                echo "  \"$path\": \"-\", \"$path\": {uname: $o, gname: $g, perm: ${m}}" >> $outdirslist;
                 ;;
            s) # Symlinks
                pp_debug "Found symlink: $datadir$path";
                # Remove leading /
                rel_p=`echo $p | sed s,^/,,`
                (cd $datadir; ln -sf $st $rel_p);
                # Do we care if the file doesn't exist? Just symnlink it regardless and throw a warning? This will be important in the case 
                # where we depend on other packages to be installed and will be using the libs from that package.
                if [ ! -e "$datadir$path" ]; then
                    pp_warn "$datadir$path does not exist"
                fi
                echo "  \"$path\": \"$st\"" >> $outfilelist;
                ;;
            *)  pp_error "Unsupported data file type: %t";;
        esac    
    done     

    echo "}" >> $outfilelist
    echo "}" >> $outdirslist
    cat $outfilelist >> $manifest
    cat $outdirslist >> $manifest

    pp_debug "Finished processing $pp_wrkdir/%file.${cmp}"
}

pp_bsd_makebsd() {
    typeset cmp
    typeset package_build_dir
    local manifest postinstall preinstall preuninstall postuninstall preupgrade postupgrade

    cmp="$1"

    if test -z "$pp_bsd_platform"; then
        pp_error "Unknown BSD architecture"
        return 1
    fi

    _subname=`pp_bsd_cmp_full_name $cmp`
    package_build_dir=$pp_wrkdir/$_subname

    manifest="$package_build_dir/+MANIFEST"
    postinstall="$package_build_dir/+POST_INSTALL"
    preinstall="$package_build_dir/+PRE_INSTALL"
    preuninstall="$package_build_dir/+PRE_DEINSTALL"
    postuninstall="$package_build_dir/+POST_DEINSTALL"
    preupgrade="$package_build_dir/+PRE_UPGRADE"
    postupgrade="$package_build_dir/+POST_UPGRADE"

    # Create package dir
    mkdir -p $package_build_dir

    pp_bsd_make_manifest $cmp $manifest
    pp_bsd_make_data $cmp

    pp_debug "Processing pre/post install scripts"

    if test -s $pp_wrkdir/%pre.$cmp; then
         pp_debug "Found %pre.$cmp"
         {
             cat "$pp_wrkdir/%pre.$cmp"
         } > $preinstall
         pp_debug "Created $preinstall"
    fi

    if test -s $pp_wrkdir/%post.$cmp; then
         pp_debug "Found %post.$cmp"
         {
             echo "# Post install script for "
             cat "$pp_wrkdir/%post.$cmp"
         } > $postinstall
         pp_debug "Created $postinstall"
    fi

    pp_debug "Processing pre/post uninstall scripts"

    if test -s $pp_wrkdir/%preun.$cmp; then
        pp_debug "Found %preun.$cmp"
        {   
            echo "# Pre uninstall script for ${pp_bsd_name:-$name}"
            cat "$pp_wrkdir/%preun.$cmp"
        } > $preuninstall
        pp_debug "Created pkg $preuninstall"
    fi

    if test -s $pp_wrkdir/%postun.$cmp; then
        pp_debug "Found %postun.$cmp"
        {   
            echo "# Post uninstall script for ${pp_bsd_name:-$name}"
            cat "$pp_wrkdir/%postun.$cmp"
        } > $postuninstall
        pp_debug "Created $postuninstall"
    fi

    if test -s $pp_wrkdir/%preup.$cmp; then
        pp_debug "Found %preup.$cmp"
        {
            echo "# Pre upgrade script for ${pp_bsd_name:-$name}"
            cat "$pp_wrkdir/%preup.$cmp"
        } > $preupgrade
        pp_debug "Created pkg $preupgrade"
    fi

    if test -s $pp_wrkdir/%postup.$cmp; then
        pp_debug "Found %postup.$cmp"
        {
            echo "# Post upgrade script for ${pp_bsd_name:-$name}"
            cat "$pp_wrkdir/%postup.$cmp"
        } > $postupgrade
        pp_debug "Created $postupgrade"
    fi
}

pp_backend_bsd() {
    #get-files-dir-entries
    #create-manifest
    #create-preuninstall
    #create-postinstall
    #create-package
    #
    pp_bsd_handle_services

    for cmp in $pp_components
    do
        _subname=`pp_bsd_cmp_full_name $cmp`
        pp_debug "Generating packaging specific files for $_subname"
        pp_bsd_makebsd $cmp
    done    

    # call this to fixup any files before creating the actual packages
    . $pp_wrkdir/%fixup

    for cmp in $pp_components
    do
        _subname=`pp_bsd_cmp_full_name $cmp`
        package_build_dir=$pp_wrkdir/$_subname
    	# Build the actual packages now
        pp_debug "Building FreeBSD $_subname"
        pp_debug "Running package create command: pkg create -m $package_build_dir -r $pp_wrkdir/`pp_bsd_cmp_full_name $cmp` -o $pp_wrkdir"
        pp_bsd_fakeroot pkg create -m $package_build_dir -r $pp_wrkdir/`pp_bsd_cmp_full_name $cmp` -o $pp_wrkdir -v
    done

}

pp_bsd_name () {
    typeset cmp="${1:-run}"
    echo `pp_bsd_cmp_full_name $cmp`"-${pp_bsd_version:-$version}.txz"
}

pp_backend_bsd_names () {
    for cmp in $pp_components; do
    	echo `pp_bsd_cmp_full_name $cmp`"-${pp_bsd_version:-$version}.txz"
    done
}

pp_backend_bsd_cleanup () {
    :
}

pp_backend_bsd_probe () {
        echo "${pp_bsd_os}-${pp_bsd_platform_std}"
        echo "${pp_bsd_os}${pp_bsd_os_rev}-${pp_bsd_platform_std}"
}


pp_backend_bsd_vas_platforms() {
    case "${pp_bsd_platform_std}" in
        x86_64) echo "FreeBSD-x86_64.txz FreeBSD-i386.txz";;
        i386)   echo "FreeBSD-i386.txz";;
        *) pp_die "unknown architecture $pp_bsd_platform_std";;
    esac
}


pp_backend_bsd_install_script () {
    typeset cmp _cmp_full_name

	echo "#!/bin/sh"
    pp_install_script_common

    cat <<.

        cmp_to_pkgname () {
            test x"\$*" = x"all" && set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
         echo "                    $cmp) echo '`pp_bsd_cmp_full_name $cmp`';;"
    done

    cat <<.
                    *) usage;;
                esac
            done
        }

        cmp_to_pathname () {
            test x"\$*" = x"all" &&
                set -- $pp_components
            for cmp
            do
                case \$cmp in
.
    for cmp in $pp_components; do
        echo "                    $cmp) echo \${PP_PKGDESTDIR:-.}/'`pp_bsd_name $cmp`';;"
    done

    cat <<.
                    *) usage;;
                esac
            done
        }

        test \$# -eq 0 && usage
        op="\$1"; shift
        case "\$op" in
            list-components)
                test \$# -eq 0 || usage \$op
                echo $pp_components
                ;;
            list-services)
                test \$# -eq 0 || usage \$op
                echo $pp_services
                ;;
            list-files)
                test \$# -ge 1 || usage \$op
                cmp_to_pathname "\$@"
                ;;
            install)
                test \$# -ge 1 || usage \$op
                pkg add \`cmp_to_pathname "\$@"\`
                ;;
            uninstall)
                test \$# -ge 1 || usage \$op
                pkg remove \`cmp_to_pkgname "\$@"\`; :
                ;;
            start|stop)
                test \$# -ge 1 || usage \$op
                ec=0
                for svc
                do
                    /etc/rc.d/\$svc \$op || ec=1
                done
                exit \$ec
                ;;
            print-platform)
                test \$# -eq 0 || usage \$op
                echo "${pp_bsd_os}-${pp_bsd_platform}"
                echo '`pp_backend_bsd_probe`'
                ;;
            *)
                usage
                ;;
        esac
.
}
pp_backend_bsd_init_svc_vars () {
	svc_process_regex="${pp_bsd_svc_process_regex}"
    svc_description=$summary
    svc_init_prefix="${pp_bsd_prefix}"
    svc_init_filename="${pp_bsd_svc_init_filename}"     # == $svc
    svc_init_filepath="${pp_bsd_svc_init_filepath}"     # == $pp_bsd_prefix/etc/rc.d/ by default

    bsd_svc_before="${pp_bsd_svc_before}"
    bsd_svc_require="${pp_bsd_svc_require}"
    bsd_svc_keyword="${pp_bsd_svc_keyword}"
    
}

pp_bsd_service_make_init_info() {
	local svc=$1
	local out=$2
	cat <<-. >$out
	#!/bin/sh
	#
	# FreeBSD Script Header Detail
	#
	# PROVIDE: $svc
.

	if [ ! -z "$bsd_svc_before" ]; then
	cat <<-. >>$out
		# BEFORE: $bsd_svc_before
.
	fi

	if [ ! -z "$bsd_svc_require" ]; then
    cat <<-. >>$out
		# REQUIRE: $bsd_svc_require
.
	fi

	if [ ! -z "$bsd_svc_keyword" ]; then
    cat <<-. >>$out
		# KEYWORD: $bsd_svc_keyword
.
	fi

	cat <<-'.' >>$out
		### END INIT INFO

.

}

pp_bsd_service_make_init_set_vars() {
	local svc=$1
    local out=$2

	svc_command="$cmd"
	svc_pre_command="${pp_bsd_svc_pre_command}"
	svc_pre_command_args="${pp_bsd_svc_pre_command_args}"

	local run_command="${svc_pre_command:-$svc_command}"
	local run_pre_command_args="${svc_pre_command:+"${svc_pre_command_args}"}"
	local run_post_command_args="${svc_command:+"${svc_command_args}"}"
    local run_post_command_without_pre_command="${svc_pre_command:+"$svc_command"}"
	local run_post_command_with_args="${run_post_command_without_pre_command}${run_post_command_args:+" $run_post_command_args"}"
	local run_command_args="${run_pre_command_args:+"$run_pre_command_args"}${run_post_command_with_args:+" $run_post_command_with_args"}"

    # https://www.freebsd.org/cgi/man.cgi?query=rc.subr
	cat <<-. >>$out
	# FreeBSD rc subroutines
	. /etc/rc.subr

	# 0: Not running.
	# 1: Running normally
	# 2: Running, but no PID file.
	# 3: Running, but PID file doesn't match running processes.
	# If the PID file is found but no process, the file is removed and 0 is returned.
	DAEMON_RUNNING=0

	name="$svc"
	desc="${svc_description:-\$name}"

	start_cmd="\${name}_start"
	status_cmd="\${name}_status"
	stop_cmd="\${name}_stop"

	# Loads any variables set in /etc/rc.conf.d/\$name
	load_rc_config \$name

	: \${${svc}_enable:="Yes"}
	: \${${svc}_pidfile:="${pidfile:-/var/run/\${name\}.pid}"}
	: \${${svc}_args:="$run_command_args"}
	: \${${svc}_cmd:="$run_command"}

	# Regex used in the pp_check_daemon_running ps check to find our running processe(s)
	# If it's set in /etc/rc.conf.d/\$name this will be used first
	# then check if pp_bsd_svc_process_regex is set, finally set to the \${name}_cmd
	# When set to \${name}_cmd pp_check_daemon_running will only find the parent process pid
	: \${${svc}_process_regex:="${pp_bsd_svc_process_regex:-${cmd}}"}

	# For additional information about the rc.subr see:
	# https://www.freebsd.org/cgi/man.cgi?query=rc.subr
	rcvar="\${name}_enable"

	pidfile=\${${svc}_pidfile}

	command="\$${svc}_cmd"
	command_args="\$${svc}_args"

.

}

pp_bsd_service_make_init_body() {
	local svc=$1
	local out=$2

	cat<<-'.' >>$out
	pp_exec_cmd() { (eval $command $command_args) }

	pp_success_msg () { echo ${1:+"$*:"} OK; }
	pp_failure_msg () { echo ${1:+"$*:"} FAIL; }
	pp_warning_msg () { echo ${1:+"$*:"} WARNING; }

	#-- prints a status message
	pp_msg () { echo -n "$*: "; }

	# Kills process $1.
	# First a sigterm, then wait up to 10 seconds
	# before issuing a sig kill.
	pp_signal () {
	    # Kill the processes the nice way first
	    if [ -z "$1" ]; then
	        # No pid file. Use the list from pp_check_daemon_running
	        kill $PROCESSES 2>/dev/null
	    else
	        kill $1 2>/dev/null
	    fi
	    count=1

	    #Check to make sure the processes died, if not kill them the hard way
	    while [ $count -le 10 ]; do
	        sleep 1
	        pp_check_daemon_running
	        if [ $DAEMON_RUNNING -eq 0 ]; then
	            break;
	        fi
	        if [ $count -eq 1 ]; then
	            # We tried killing the pid associated to the pidfile, now try the ones we found from pp_check_daemon_running
	            kill $PROCESSES 2>/dev/null
	        fi
	        count=`expr $count + 1`
	    done
	    # Check one more time to make sure we got them all
	    if [ $DAEMON_RUNNING -ne 0 ]; then
	       # These guys don't want to go down the nice way, now just kill them
	       kill -9 $PROCESSES 2>/dev/null
	    fi
	    # make sure to remove the pidfile
	    rm -f $pidfile
	}

	# Check to see if the daemon process is running
	# Sets the PROCESSES global variable with all pids that match
	# ${name}_process_regex 
	# Sets global variable DAEMON_RUNNING to one of the following:
	# 0: Not Running
	# 1: Running normally
	# 2: Running, but no PID file
	# 3: Running, but PID file doesn't match running processes.
	# 
	pp_check_daemon_running()
	{
		DAEMON_RUNNING=0
.
	cat<<-. >>$out

		PROCESSES="\`eval ps -axo pid,args | grep "\${${svc}_process_regex}" | grep -v grep | awk '{print \$1}'\`"

.
	cat<<-'.' >>$out
    if [ -f $pidfile ]; then
        if [ ! -z "$PROCESSES" ]; then
            PARENT_PID=`cat $pidfile 2>/dev/null`
            PPROCESS=`echo $PROCESSES | grep "${PARENT_PID:-"NOPID"}"`
            if [ $? -eq 0 ]; then
                DAEMON_RUNNING=1
            else
                DAEMON_RUNNING=3
            fi
        else
            rm -r $pidfile
        fi
    else
        if [ ! -z "$PROCESSES" ]; then
            DAEMON_RUNNING=2
        fi
    fi
	}
.
	cat <<-. >>$out

	# starts the service
	${svc}_start()
.
	cat <<-'.' >>$out
	{
	    pp_msg "Starting ${desc}"
	    pp_check_daemon_running

	    if [ $DAEMON_RUNNING -eq 0 ]; then
	        pp_exec_cmd
	        RETVAL=$?
	        if [ $RETVAL -eq 0 ]; then
	            pp_success_msg
	        else
	            pp_failure_msg "cannot start"
	        fi
	    else
	        if [ $DAEMON_RUNNING -eq 1 ]; then
	            pp_success_msg "${name} appears to be running already"
	        else
	            pp_warning_msg "${name} is already running but without a pid file"
	        fi
	    fi
	}

.

	cat <<-. >>$out
	# stops the service
	${svc}_stop()
.

	cat <<-'.' >>$out
	{
	    pp_msg "Stopping ${desc}"
	    pp_check_daemon_running

	    if [ $DAEMON_RUNNING -ne 0 ]; then
	        pp_signal `cat $pidfile 2>/dev/null`
	        if [ -n "$pidfile" ]; then
	            loop_cnt=1
	            while [ -e ${pidfile} ]; do
	                sleep 1
	                loop_cnt=`expr $loop_cnt + 1`
	                if [ $loop_cnt -eq 10 ]; then
	                    break
	                fi
	            done
	        fi
	        rm -f $pidfile

	        pp_success_msg
	    else
	        pp_failure_msg
	        echo -n "$desc does not appear to be running."
	        echo
	    fi
	}
.

	cat <<-. >>$out
	# prints information about the service status
	# returns:
	# 0=running
	# 1=Not running
	# 2=Running without pidfile
	# 3=Running with pid that doesn't match pidfile
	${svc}_status()
.
	
	cat <<-'.' >>$out
	{
	    pp_msg "Checking ${desc}"
	    pp_check_daemon_running
	    if [ $DAEMON_RUNNING -eq 1 ]; then
	        pp_success_msg "PID $PARENT_PID: running"
	        return 0
	    else
	        if [ $DAEMON_RUNNING -eq 0 ]; then
	            pp_failure_msg "not running"
	            return 1
	        elif [ $DAEMON_RUNNING -eq 2 ]; then
	            pp_warning_msg "running without a pid file"
	            return 2
	        else
	            pp_warning_msg "running but pid file doesn't match running processe()"
	            return 3
	        fi
	    fi
	}

	run_rc_command "$1"
.
}

pp_bsd_service_make_init_script () {
    local svc=${svc_init_filename:-$1}
    local script="${svc_init_filepath:-"${svc_init_prefix}/etc/rc.d"}/$svc"
    script=`echo $script | sed 's://*:/:g'`
    local out=$pp_destdir$script

	pp_add_file_if_missing $script run 755 || return 0

	pp_bsd_service_make_init_info "$svc" "$out"
	pp_bsd_service_make_init_set_vars "$svc" "$out"
	pp_bsd_service_make_init_body "$svc" "$out"

	chmod 755 $out

}

pp_bsd_handle_services () {
	if test -n "$pp_services"; then
		for svc in $pp_services; do
			pp_load_service_vars $svc
 			# Append some code to %post to install the svc TODO: Figure out why/what
			pp_bsd_service_make_init_script $svc
			# prepend some code to %preun to uninstall svc TODO: Figure out why/what
		done
	fi
}
pp_backend_bsd_function() {
    case "$1" in
        pp_mkgroup) cat<<'.';;
            /usr/sbin/pw group show "$1" 2>/dev/null && return 0
            /usr/sbin/pw group add "$1"
.
        pp_mkuser:depends) echo pp_mkgroup;;
        pp_mkuser) cat<<'.';;
            #Check if user exists
            /usr/sbin/pw user show "$1" 2>/dev/null && return 0
            pp_mkgroup "${2:-$1}" || return 1
            echo "Creating user $1"
            /usr/sbin/pw user add \
                -n "$1" \
                -d "${3:-/nonexistent}" \
                -g "${2:-$1}" \
                -s "${4:-/bin/false}"
.
        pp_havelib) cat<<'.';;
            for pp_tmp_dir in `echo "/usr/local/lib:/usr/lib:/lib${3:+:$3}" | tr : ' '`; do
                test -r "$pp_tmp_dir/lib$1.so{$2:+.$2}" && return 0
            done
            return 1
.
        *) false;;
    esac
}


quest_require_vas () {
    typeset v d

    if test $# -ne 1; then
        return
    fi
    set -- `echo "$1" | tr . ' '` 0 0 0

    for d
    do
        echo $d | grep '^[0-9][0-9]*$' > /dev/null ||
            pp_error "quest_require_vas: Bad version component $d"
    done

    test $# -lt 4 &&
            pp_error "quest_require_vas: missing version number"

    case "$1.$2.$3.$4" in
        *.0.0.0) v=$1;;
        *.*.0.0) v=$1.$2;;
        *.*.*.0) v=$1.$2.$3;;
        *)       v=$1.$2.$3.$4;;
    esac

    cat <<.
        if test -x /opt/quest/bin/vastool &&
           /opt/quest/bin/vastool -v |
            awk 'NR == 1 {print \$4}' |
            awk -F. '{ if (\$1<$1 || \$1==$1 && ( \
                           \$2<$2 || \$2==$2 && ( \
                           \$3<$3 || \$2==$3 && ( \
                           \$4<$4 )))) exit(1); }'
        then
            exit 0
        else
            echo "Requires VAS $v or later"
            exit 1
        fi
.
}
pp_main ${1+"$@"}
