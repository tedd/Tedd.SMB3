# Tedd.Smb

Managed C# SMB 3.1.1 client and file server for .NET 10 on Windows and Linux.
The filesystem and command model is adapted from the local
`D:\source\pdpsrc\bsd\smbd` SMB 2.0.2 implementation. Networking, authentication,
cryptography, and filesystem access execute in the C# process. Samba is only an
independent interoperability test dependency.

The server provides one configured account and disk share, plus `IPC$`/`srvsvc`
share enumeration. It supports NTLMv2, SHA-512 preauthentication integrity,
AES-128-CMAC signing, AES-128-GCM/CCM encryption, compounds, Unicode filenames,
64-bit file offsets, directory enumeration, create/read/write/flush, truncation,
rename, deletion, and share-access enforcement across its connections.

Encryption is required by default; signing is required for unencrypted sessions.
Shares are read-only unless writable service is enabled. SMB1 file operations,
guest access, Kerberos/domain integration, leases/oplocks, byte-range locks,
durable handles, multichannel, change notifications, alternate streams, Windows
ACL management, compression, and Apple AAPL extensions are outside this file
transfer implementation. Applications requiring these facilities need a server
that implements them. Sessions and handles cannot be recovered after reconnect.

The export must be a trusted directory managed by the service account. Paths
reject traversal, symbolic links/reparse points, streams, and DOS device names.
Do not permit other untrusted local processes to replace directory components
while the server is running: path validation is not an operating-system sandbox.
Run with filesystem permissions limited to the intended export.

Windows timestamps and attributes use native filesystem APIs. Linux preserves
logical creation/change timestamps and hidden/archive attributes in `user.tedd.smb3.*`
xattrs; the backing filesystem and backups must preserve them. Explicit logical
timestamp updates return an error when the filesystem cannot persist them.
Other local programs do not maintain these logical timestamps. SMB share modes
coordinate this server's handles; independent server instances need separate
exports. Transfers use at most 64 KiB per read/write, with 32 credits, 32 commands
per compound, 64 trees and 1,024 handles per connection, and 32 connections by
default. Requests on each connection execute in order.

## Build and managed tests

Install the .NET 10 SDK, then run from PowerShell:

```powershell
.\build.ps1 -Workspace D:\Workspaces\AI\tedd-smb3-build
```

The script places generated files, caches and test fixtures in the designated
workspace. Library and host outputs are under `artifacts\bin` there. It does not
install a service or change system SMB policies.

## Run the server

Create the export first and supply the account password through the process
environment. For local development on Windows:

```powershell
$env:TEDD_SMB_PASSWORD = '<password>'
dotnet D:\Workspaces\AI\tedd-smb3-build\artifacts\bin\Tedd.Smb.Host\release\Tedd.Smb.Host.dll serve `
  --root D:\Exports\files --share files --user smbuser --bind 127.0.0.1 --port 1445 --writable
```

Linux uses the same host DLL and options with Linux paths. Port 445 permits
ordinary UNC mounts; binding a privileged port on Linux requires the appropriate
capability or account. Windows' system SMB service commonly occupies port 445.
Recent Windows versions support alternate TCP ports through `New-SmbMapping
-TcpPort`; Linux supports `mount.cifs -o port=...`. Listen on a specific network
address to expose a share remotely. `--allow-unencrypted` allows signed sessions
while retaining encryption support. Ctrl-C stops the foreground host.

## Client library

Reference `src/Tedd.Smb/Tedd.Smb.csproj`:

```csharp
using Tedd.Smb;

await using var client = await SmbClient.ConnectAsync("server", "files", new()
{
    UserName = "smbuser",
    Password = password,
    Port = 445,
    Encrypt = true
});
await client.WriteAllBytesAsync("example.bin", new byte[] { 1, 2, 3 });
byte[] data = await client.ReadAllBytesAsync("example.bin");
IReadOnlyList<SmbEntry> entries = await client.ListDirectoryAsync();
await client.MoveAsync("example.bin", "renamed.bin");
await client.DeleteAsync("renamed.bin");
```

`OpenAsync` returns an asynchronous disposable handle with offset reads/writes,
flush, truncation, and timestamp/attribute updates. `GetInfoAsync` queries file
metadata. `CreateDirectoryAsync` and `DeleteAsync(path, directory: true)` manage
directories. Use handle reads for files too large for a byte array. Connections
serialize requests, support cancellation/timeouts, and must be replaced after a
transport or integrity failure. Authentication uses NTLMv2; credentials must be
accepted by the target server. `Encrypt=false` still requires signing and honors
server-required encryption. The client targets SMB 3.1.1 exclusively.

## Native interoperability tests

Use disposable exports and the test-only `smbtest` / `testpass` account.
`tests/interop/WindowsMount.ps1` creates a native Windows SMB mapping, verifies
the dialect and security flags through `GetFileInformationByHandleEx`, exercises
file operations, and removes the mapping:

```powershell
$env:TEDD_SMB_PASSWORD = 'testpass'
.\tests\interop\WindowsMount.ps1 -Server SERVER -Port 1445
.\tests\interop\WindowsMount.ps1 -Server OTHER_ENDPOINT -Port 1446 -RequireEncryption
```

Use separate endpoints for security modes to avoid Windows connection reuse.
The Linux helper requires root/CIFS mount permission and `cifs-utils`, and
unmounts its test mount on exit:

```sh
sh tests/interop/LinuxMount.sh SERVER 1445 /mnt/d/Workspaces/AI/smb-tests /mnt/d/SourceCode/Tedd.SMB3 sign
sh tests/interop/LinuxMount.sh SERVER 1446 /mnt/d/Workspaces/AI/smb-tests /mnt/d/SourceCode/Tedd.SMB3 seal
```

Create the workspace first. `mount_roundtrip.py` tests Unicode names, listing,
hash-verified transfers, rename, truncation, offset writes, fsync, timestamps and
deletion through the mounted filesystem. These tests do not weaken signing or
encryption policies and do not stop the Windows SMB service.

For independent Python clients, install `tests/interop/requirements.txt` in a
virtual environment within the task workspace, setting `TMPDIR` and pip's cache
there. Run `independent_clients.py HOST PORT true|false` and
`rpc_shares.py HOST PORT` against the C# server.

`StartSamba.sh WORKSPACE` creates private Samba state and an independent server
on port 1447, using the existing Linux `root` account with a task-local password
database. It requires a POSIX filesystem at `WORKSPACE/samba` and a foreground
terminal. In WSL, a temporary filesystem mounted at that task-local path avoids
DrvFS ownership limitations. Stop the test server and unmount it before deleting
the workspace. The C# client acceptance executable runs on either OS:

```sh
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet Tedd.Smb.Tests.dll client HOST 1447 files false
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet Tedd.Smb.Tests.dll client HOST 1447 files true
```

Protocol references:
[MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/),
[MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/),
[MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/),
[MS-SRVS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/).
