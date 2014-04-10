#! /bin/sh
#

# PROVIDE: hockeypuck
# REQUIRE: DAEMON
# KEYWORD: shutdown

#
# Add the following lines to /etc/rc.conf to enable hockeypuck:
#
#hockeypuck_enable="YES"

# This expects:
# - the hockeypuck bin in in the $PATH
# - the hockeypuck config in /usr/local/etc/hockeypuck.conf
# - a user named hockeypuck in a group named hockeypuck
# - a hockeypuck-writable directory /var/run/hockeypuck

. /etc/rc.subr

name="hockeypuck"
rcvar="hockeypuck_enable"

load_rc_config $name

: ${hockeypuck_user:=hockeypuck}
: ${hockeypuck_group:=hockeypuck}
: ${hockeypuck_enable:=NO}
: ${hockeypuck_flags:=run --config /usr/local/etc/hockeypuck.conf}
: ${hockeypuck_chdir:=/var/run/hockeypuck}

command="hockeypuck"
command_args="&"

run_rc_command "$1"
