# Tedd.SMB3

[![NuGet](https://img.shields.io/nuget/v/Tedd.SMB3.svg)](https://www.nuget.org/packages/Tedd.SMB3)
[![Build](https://github.com/tedd/Tedd.SMB3/actions/workflows/nuget-publish.yml/badge.svg?branch=main)](https://github.com/tedd/Tedd.SMB3/actions/workflows/nuget-publish.yml)

[Documentation and examples](https://tedd.no/Tedd.SMB3/) ·
[Source](https://github.com/tedd/Tedd.SMB3)

Managed C# SMB 3.1.1 client and file server for .NET 10 on Windows and Linux.
The filesystem and command model is adapted from the local
`D:\source\pdpsrc\bsd\smbd` SMB 2.0.2 implementation. Networking, authentication,
cryptography, and filesystem access execute in the C# process. Samba is only an
independent interoperability test dependency.

The server registers a storage provider for each named share, plus `IPC$`/`srvsvc`
share enumeration. Providers can expose application data without a backing directory.
Windows and Linux directory providers are included. The server supports NTLMv2,
native Kerberos authentication, SHA-512 preauthentication integrity,
AES-128-CMAC signing, AES-128-GCM/CCM encryption, compounds, Unicode filenames,
64-bit file offsets, directory enumeration, create/read/write/flush, truncation,
rename, deletion, share-access enforcement across its connections, and negotiated
unchained LZNT1 compression.

Encryption is required by default; signing is required for unencrypted sessions.
Shares are read-only unless writable service is enabled. SMB1 file operations,
guest access, leases/oplocks, byte-range locks,
durable handles, multichannel, change notifications, alternate streams, Windows
ACL management and Apple AAPL extensions are outside this file
transfer implementation. Applications requiring these facilities need a server
that implements them. Sessions and handles cannot be recovered after reconnect.

Directory-provider exports must be trusted directories managed by the service account. Paths
reject traversal, symbolic links/reparse points, streams, and DOS device names.
Do not permit other untrusted local processes to replace directory components
while the server is running: path validation is not an operating-system sandbox.
Run with filesystem permissions limited to the intended export.

The Windows directory provider uses native timestamps and attributes. The Linux
directory provider preserves
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
dotnet D:\Workspaces\AI\tedd-smb3-build\artifacts\bin\Tedd.SMB3.Host\release\Tedd.SMB3.Host.dll serve `
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

Install the package in a .NET 10 project:

```sh
dotnet add package Tedd.SMB3
```

Alternatively, reference `src/Tedd.SMB3/Tedd.SMB3.csproj`.

```csharp
using Tedd.SMB3;

string password = Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD")
    ?? throw new InvalidOperationException("Set TEDD_SMB_PASSWORD.");

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

## Host a share from C#

Create the export directory before starting the server. This example explicitly
enables writes and listens on all IPv4 interfaces; choose the listen address
and filesystem permissions appropriate for the intended clients.

```csharp
using System.Net;
using Tedd.SMB3;

string password = Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD")
    ?? throw new InvalidOperationException("Set TEDD_SMB_PASSWORD.");
ISmbShareProvider provider = SmbDirectoryProvider.Create(args[0]);
await using var server = new SmbServer(new()
{
    Shares = [new("files", provider) { Writable = true }],
    UserName = "smbuser",
    Password = password,
    ListenAddress = IPAddress.Any,
    Port = 1445,
    RequireEncryption = true
});
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
await server.RunAsync(stop.Token);
```

A server accepts up to 256 shares in `SmbServerOptions.Shares`, with a separate
`Writable` policy and optional `Authorize` predicate for each. For example,
`Shares = [new("documents", applicationProvider) { Writable = true },
new("files", SmbDirectoryProvider.Create(exportPath))]` combines application data
with a read-only directory. `SmbDirectoryProvider.Create` selects
`WindowsDirectoryProvider` or `LinuxDirectoryProvider` for the current OS.
`RootPath`, `ShareName`, and `Writable` remain a shorthand for one directory share;
configure either `RootPath` or `Shares`.

Implement `ISmbShareProvider` for custom storage. All paths are share-relative,
use `/` separators, and represent the root as an empty string. `ResolvePath`
provides canonical names; object IDs and volume IDs must remain stable through
renames. `ISmbFile` supplies offset-based asynchronous I/O, length changes and
flush. Providers supply metadata, capacity, enumeration and namespace changes
without exposing native handles. The application owns provider resources and
must keep them alive until server shutdown. The server coordinates its own
opens; providers must enforce their backing store's containment and concurrency
requirements. Reuse the same provider instance when exposing aliases of one store.

The .NET client negotiates LZNT1 compression by default. `EnableCompression = false`
disables it in either client or server options. Compression runs before encryption
and after signing; uncompressible data remains uncompressed. Chained compression
and other compression algorithms are not supported.

For Kerberos server authentication, set `AuthenticationProvider` to
`new SmbKerberosAuthentication("cifs/hostname@REALM", keytabPath)` on Linux, or omit
the keytab argument on Windows to use the service account's credentials. Linux
requires MIT Kerberos GSSAPI, a realm configuration, a service keytab and a private
writable replay-cache directory (`KRB5RCACHEDIR`). Windows requires the service
account and SPN to be configured in its domain. Kerberos authenticates the caller;
it does not impersonate the caller for provider operations. Every share must
supply an explicit `Authorize` predicate when an external authentication provider
is configured. A Linux example is:

```csharp
AuthenticationProvider = new SmbKerberosAuthentication(
    "cifs/files.example.test@EXAMPLE.TEST", "/etc/service/files.keytab"),
Shares = [new("documents", applicationProvider)
{
    Authorize = principal => principal == "reader@EXAMPLE.TEST"
}]
```

The console host accepts `--kerberos-principal cifs/hostname@REALM`, an explicit
`--user allowed-principal`, and `--keytab PATH` on Linux. It permits only that
principal to connect to its share. `ISmbAuthenticationProvider` supports other
application authentication integrations that produce SMB session keys. The .NET
client currently authenticates with NTLMv2.

## Mount from Windows

Start the server with `--bind` set to a reachable address, `--share files`,
`--user smbuser`, and `--port 1445`. Windows 11 24H2 / Windows Server 2025 or
later supports an alternate TCP port through `New-SmbMapping -TcpPort`.
Run in PowerShell and supply the server's configured password:

```powershell
$credential = Get-Credential -UserName smbuser
New-SmbMapping -LocalPath 'S:' -RemotePath '\\server\files' -TcpPort 1445 `
  -UserName $credential.UserName -Password $credential.GetNetworkCredential().Password `
  -RequireIntegrity $true -RequirePrivacy $true -Persistent $false
Get-ChildItem S:\
Get-SmbConnection | Where-Object ShareName -eq 'files'
Remove-SmbMapping -LocalPath 'S:' -Force
```

Replace `server` with the server hostname or IP address. On clients without
`-TcpPort`, run the server on port 445 and omit that parameter. File Explorer
can then open `\\server\files`. The Windows system SMB service commonly owns
port 445. Windows policies must permit NTLMv2 authentication.

See [New-SmbMapping](https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbmapping?view=windowsserver2025-ps).

## Mount from Linux

Install your distribution's `cifs-utils` package. Use the same account, share,
and port as the server. The command prompts for the SMB password:

```sh
sudo mkdir -p /mnt/tedd-smb
sudo mount -t cifs //server/files /mnt/tedd-smb \
  -o "username=smbuser,vers=3.1.1,sec=ntlmssp,seal,port=1445,uid=$(id -u),gid=$(id -g)"
ls -la /mnt/tedd-smb
findmnt /mnt/tedd-smb
sudo umount /mnt/tedd-smb
```

`seal` requests encryption. For a server on port 445, omit `port=1445`.
Mounting requires root or appropriate mount permissions and kernel SMB 3.1.1
support. See [mount.cifs](https://www.man7.org/linux/man-pages/man8/mount.cifs.8.html).

## Publishing

The `main` and `deploy` branches build and run the managed protocol, security,
and file transfer checks on Windows and Linux. The library is packaged with
its README and a separate symbol package.

NuGet publication runs from `deploy` when the project version changes, when
that branch is first created, or through an explicit workflow dispatch on
`deploy`. Authentication uses [NuGet Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)
through GitHub Actions OIDC. Configure the NuGet.org policy for repository
owner `tedd`, repository `Tedd.SMB3`, workflow file `nuget-publish.yml`, and
environment `nuget`, with permission to publish `Tedd.SMB3` (including its
initial release). The NuGet account defaults to `tedd`; set the `NUGET_USER`
repository or environment variable to use another account. The publishing job
requests a temporary credential through `NuGet/login`; no API-key secret is
required.

The Pages workflow publishes `site/` from `deploy`. In repository Settings →
Pages, select GitHub Actions as the source. The public site is
[tedd.no/Tedd.SMB3](https://tedd.no/Tedd.SMB3/).

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
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet Tedd.SMB3.Tests.dll client HOST 1447 files false
TEDD_SMB_USER=root TEDD_SMB_PASSWORD=testpass dotnet Tedd.SMB3.Tests.dll client HOST 1447 files true
```

For a disposable Samba AD Kerberos realm inside WSL, build into a dedicated
workspace and start the following in a WSL root terminal:

```sh
sh tests/interop/StartSambaAD.sh /mnt/d/Workspaces/AI/tedd-smb3-build
```

The realm uses `SMB3.TEST`, a loopback-only KDC, test accounts, and task-local
configuration/keytab/database files on tmpfs. It requires the Samba AD tools,
MIT GSSAPI, Python Samba bindings, and Python cryptography package. It does not
join Windows to a domain or change system DNS/Kerberos configuration. In a second
WSL root terminal, run:

```sh
sh tests/interop/KerberosAcceptance.sh /mnt/d/Workspaces/AI/tedd-smb3-build
```

The client uses Samba GENSEC with a mandatory Kerberos mechanism. Checks include
SMB signing, encryption, compression, file transfer, share authorization and
Kerberos replay rejection. Windows SSPI domain interoperability requires a
separately configured Windows domain environment. Stop the test KDC before
unmounting its `samba-ad` directory and removing the task workspace.

Protocol references:
[MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/),
[MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/),
[MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/),
[MS-SRVS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/).
