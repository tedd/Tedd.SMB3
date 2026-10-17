#!/bin/sh
set -eu
workspace=$1
base="$workspace/samba"
mkdir -p "$base/private" "$base/state" "$base/cache" "$base/lock" "$base/run" "$base/log" "$base/export"
cat > "$base/smb.conf" <<EOF
[global]
server role = standalone server
workgroup = WORKGROUP
netbios name = TEDDTEST
security = user
map to guest = Never
server min protocol = SMB3_11
server max protocol = SMB3_11
server signing = mandatory
smb encrypt = if_required
smb ports = 1447
interfaces = lo eth0
bind interfaces only = yes
private dir = $base/private
state directory = $base/state
cache directory = $base/cache
lock directory = $base/lock
pid directory = $base/run
ncalrpc dir = $base/run/ncalrpc
log file = $base/log/log.%m
passdb backend = tdbsam:$base/private/passdb.tdb
load printers = no
disable spoolss = yes
[files]
path = $base/export
read only = no
valid users = root
EOF
printf 'testpass\ntestpass\n' | smbpasswd -s -c "$base/smb.conf" -a root
exec smbd --foreground --no-process-group --configfile="$base/smb.conf"
