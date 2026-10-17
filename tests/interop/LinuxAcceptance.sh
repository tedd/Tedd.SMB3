#!/bin/sh
# Requires the C# and private Samba fixtures described in README.md to be running.
set -eu
workspace=$1
repo=$2
windows_host=$3
python="$workspace/venv/bin/python"
tests="$workspace/release/artifacts/bin/Tedd.Smb.Tests/release/Tedd.Smb.Tests.dll"
sh "$repo/tests/interop/LinuxMount.sh" 127.0.0.1 1445 "$workspace" "$repo" sign
sh "$repo/tests/interop/LinuxMount.sh" 127.0.0.1 1446 "$workspace" "$repo" seal
sh "$repo/tests/interop/LinuxMount.sh" "$windows_host" 1448 "$workspace" "$repo" sign
sh "$repo/tests/interop/LinuxMount.sh" "$windows_host" 1448 "$workspace" "$repo" seal
"$python" "$repo/tests/interop/independent_clients.py" 127.0.0.1 1445 false
"$python" "$repo/tests/interop/independent_clients.py" 127.0.0.1 1446 true
"$python" "$repo/tests/interop/rpc_shares.py" 127.0.0.1 1445
"$python" "$repo/tests/interop/rpc_shares.py" 127.0.0.1 1446
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet "$tests" client 127.0.0.1 1447 files false
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet "$tests" client 127.0.0.1 1447 files true
