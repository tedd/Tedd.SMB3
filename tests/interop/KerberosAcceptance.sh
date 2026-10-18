#!/bin/sh
set -eu
workspace=$(realpath -e "${1:?Supply the running Samba AD task workspace}")
case "$workspace" in /mnt/d/Workspaces/AI/?*) ;; *) exit 2 ;; esac
base="$workspace/samba-ad"
test -f "$base/krb5.conf" && test -f "$base/service.keytab"
export PYTHONDONTWRITEBYTECODE=1
export KRB5_CONFIG="$base/krb5.conf" KRB5CCNAME="FILE:$base/client.ccache"
export KRB5RCACHEDIR="$base/tmp" TMPDIR="$base/tmp"
export DOTNET_CLI_HOME="$workspace/linux/dotnet-home" DOTNET_CLI_TELEMETRY_OPTOUT=1
export SMB3_TEST_SAMBA_CONFIG="$base/domain/etc/smb.conf"
export TEDD_SMB_PASSWORD='Smb3-Test-Only-42!'
mkdir -p "$base/export"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dotnet "$workspace/artifacts/bin/Tedd.SMB3.Host/release/Tedd.SMB3.Host.dll" serve \
    --root "$base/export" --user smbtest@SMB3.TEST --port 15445 --writable --allow-unencrypted \
    --kerberos-principal cifs/smb3server.smb3.test@SMB3.TEST --keytab "$base/service.keytab" \
    > "$base/host.log" 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true' EXIT HUP INT TERM
count=0
until grep -q '^Listening' "$base/host.log"; do
    count=$((count + 1))
    if [ "$count" -gt 50 ] || ! kill -0 "$server" 2>/dev/null; then cat "$base/host.log"; exit 1; fi
    sleep 0.1
done
python3 "$script_dir/kerberos_auth.py" 127.0.0.1 15445 false
python3 "$script_dir/kerberos_auth.py" 127.0.0.1 15445 true
python3 "$script_dir/kerberos_auth.py" 127.0.0.1 15445 true smbservice
test -z "$(find "$base/export" -mindepth 1 -print -quit)"
