param(
    [Parameter(Mandatory)][string]$Server,
    [string]$Share = 'files',
    [string]$UserName = 'smbtest',
    [int]$Port = 445,
    [switch]$RequireEncryption
)
$ErrorActionPreference = 'Stop'
if (-not $env:TEDD_SMB_PASSWORD) { throw 'TEDD_SMB_PASSWORD is required.' }
$remote = "\\$Server\$Share"
$parameters = @{ RemotePath=$remote; UserName=$UserName; Password=$env:TEDD_SMB_PASSWORD; Persistent=$false; RequireIntegrity=$true }
if ($Port -ne 445) { $parameters.TcpPort = $Port }
if ($RequireEncryption) { $parameters.RequirePrivacy = $true }
New-SmbMapping @parameters -ErrorAction Stop | Out-Null
try {
    $folder = Join-Path $remote ('native-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($folder) | Out-Null
    $first = Join-Path $folder 'unicode-æøå-文件.bin'
    $second = Join-Path $folder 'renamed.bin'
    $operationError = $null
    try {
        $payload = [byte[]]::new(262267)
        [Security.Cryptography.RandomNumberGenerator]::Fill($payload)
        [IO.File]::WriteAllBytes($first, $payload)
        if (-not ('NativeSmbInfo' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class NativeSmbInfo {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, byte[] info, uint size);
}
'@
        }
        $handle = [IO.File]::Open($first, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $info = [byte[]]::new(256)
            if (-not [NativeSmbInfo]::GetFileInformationByHandleEx($handle.SafeFileHandle, 13, $info, $info.Length)) { throw "Remote protocol query failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
            $major = [BitConverter]::ToUInt16($info, 8)
            $minor = [BitConverter]::ToUInt16($info, 10)
            $revision = [BitConverter]::ToUInt16($info, 12)
            $flags = [BitConverter]::ToUInt32($info, 16)
            Write-Output "Windows native protocol $major.$minor.$revision flags=0x$($flags.ToString('X'))"
            if ($major -ne 3 -or $minor -ne 1 -or $revision -ne 1) { throw 'SMB 3.1.1 was not established.' }
            if (($flags -band 0x10) -eq 0 -and ($flags -band 8) -eq 0) { throw 'SMB integrity was not established.' }
            if ($RequireEncryption -and ($flags -band 8) -eq 0) { throw 'SMB encryption was not established.' }
        } finally { $handle.Dispose() }
        $actual = [IO.File]::ReadAllBytes($first)
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($payload)) -ne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($actual))) { throw 'File hash mismatch.' }
        if ([IO.Directory]::GetFiles($folder).Count -ne 1) { throw 'Directory listing mismatch.' }
        [IO.File]::Move($first, $second)
        $stream = [IO.File]::Open($second, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
        try { $stream.SetLength(32771); $stream.Position=65536; $stream.Write([byte[]](1,2,3)); $stream.Flush($true) } finally { $stream.Dispose() }
        if ([IO.FileInfo]::new($second).Length -ne 65539) { throw 'Truncate/offset mismatch.' }
        [IO.File]::SetLastWriteTimeUtc($second, [DateTime]::Parse('2023-11-14T22:13:20Z').ToUniversalTime())
    } catch { $operationError = $_ } finally {
        try {
            foreach ($path in @($first, $second)) { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
            [IO.Directory]::Delete($folder)
        } catch { if ($null -eq $operationError) { $operationError = $_ } else { Write-Warning "Fixture cleanup failed: $_" } }
    }
    if ($null -ne $operationError) { throw $operationError }
    Write-Output 'PASS Windows native SMB mount: Unicode, listing, create/read/write, SHA256, rename, truncate, offset write, flush, timestamps, delete'
} finally { Remove-SmbMapping -RemotePath $remote -Force -UpdateProfile:$false }
