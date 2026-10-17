#!/bin/sh
set -eu
host=$1
port=$2
workspace=$3
repo=$4
mode=${5:-sign}
test -d "$workspace"
mkdir -p "$workspace/mount-linux"
mount -t cifs "//$host/files" "$workspace/mount-linux" -o "port=$port,vers=3.1.1,username=smbtest,password=testpass,sec=ntlmssp,$mode,cache=none"
trap 'umount "$workspace/mount-linux"' EXIT
python3 "$repo/tests/interop/mount_roundtrip.py" "$workspace/mount-linux"
grep " $workspace/mount-linux " /proc/mounts
