param([string]$Workspace = 'D:\Workspaces\AI\tedd-smb3-build', [switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$Workspace = [IO.Path]::GetFullPath($Workspace)
if (-not $Workspace.StartsWith('D:\Workspaces\AI\', [StringComparison]::OrdinalIgnoreCase) -or $Workspace.TrimEnd('\') -eq 'D:\Workspaces\AI') { throw 'Workspace must be a dedicated child of D:\Workspaces\AI.' }
New-Item -ItemType Directory -Path $Workspace,(Join-Path $Workspace 'temp') -Force | Out-Null
$env:DOTNET_CLI_HOME = Join-Path $Workspace 'dotnet-home'
$env:NUGET_PACKAGES = Join-Path $Workspace 'packages'
$env:TEMP = Join-Path $Workspace 'temp'
$env:TMP = $env:TEMP
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$artifacts = Join-Path $Workspace 'artifacts'
dotnet build (Join-Path $PSScriptRoot 'Tedd.SMB3.slnx') --configuration Release --artifacts-path $artifacts --nologo
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
if (-not $SkipTests) {
    dotnet (Join-Path $artifacts 'bin\Tedd.SMB3.Tests\release\Tedd.SMB3.Tests.dll') (Join-Path $Workspace 'fixtures')
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}
