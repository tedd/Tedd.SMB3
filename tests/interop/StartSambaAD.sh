#!/bin/sh
# Disposable, loopback-only AD realm. Run as root inside WSL; no system config changes.
set -eu
workspace=${1:?Supply a dedicated task workspace under /mnt/d/Workspaces/AI}
case "$workspace" in
    /mnt/d/Workspaces/AI/?*) ;;
    *) echo 'Workspace must be under /mnt/d/Workspaces/AI.' >&2; exit 2 ;;
esac
workspace=$(realpath -e "$workspace")
case "$workspace" in /mnt/d/Workspaces/AI/?*) ;; *) exit 2 ;; esac
base="$workspace/samba-ad"
if [ -e "$base" ]; then
    echo 'samba-ad already exists; use a fresh task workspace.' >&2
    exit 2
fi
mkdir "$base"
# DrvFS lacks the POSIX ACL/ownership behavior required by Samba AD provisioning.
mount -t tmpfs -o size=512m,mode=0700 tmpfs "$base"
mkdir -p "$base/tmp" "$base/log" "$base/run" "$base/lock" "$base/cache"
export TMPDIR="$base/tmp" PYTHONDONTWRITEBYTECODE=1
samba-tool domain provision --targetdir="$base/domain" --realm=SMB3.TEST \
    --domain=SMB3TEST --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --host-name=smb3dc --host-ip=127.0.0.1 --use-rfc2307 \
    --adminpass='Smb3-Test-Only-42!' \
    --option='interfaces=127.0.0.1/32' --option='bind interfaces only=yes' \
    --option='server services=kdc' \
    --option='tls enabled=no' --option="log file=$base/log/samba.log" \
    --option="pid directory=$base/run" --option="lock directory=$base/lock" \
    --option="cache directory=$base/cache" --option="ncalrpc dir=$base/run/ncalrpc"
config="$base/domain/etc/smb.conf"
samba-tool user create smbtest 'Smb3-Test-Only-42!' --configfile="$config"
samba-tool user create smbservice 'Smb3-Test-Only-42!' --configfile="$config"
samba-tool spn add cifs/smb3server.smb3.test smbservice --configfile="$config"
samba-tool domain exportkeytab "$base/service.keytab" \
    --principal=cifs/smb3server.smb3.test --configfile="$config"
cat > "$base/krb5.conf" <<EOF
[libdefaults]
 default_realm = SMB3.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = false
 rdns = false
[realms]
 SMB3.TEST = {
  kdc = 127.0.0.1
 }
[domain_realm]
 .smb3.test = SMB3.TEST
 smb3.test = SMB3.TEST
EOF
echo "Test realm SMB3.TEST at 127.0.0.1; config $base/krb5.conf"
echo "After stopping Samba, unmount $base before removing the task workspace."
samba --foreground --no-process-group --configfile="$config" || {
    tail -60 "$base/log/samba.log" >&2
    exit 1
}
