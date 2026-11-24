param([string]$Workspace = 'D:\Workspaces\AI\tedd-smb3-build', [switch]$SkipTests, [switch]$NetworkDirect)
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
if ($NetworkDirect) {
    if (![OperatingSystem]::IsWindows() -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
        throw 'The Network Direct build requires Windows x64.'
    }
    $cmake = (Get-Command cmake.exe -ErrorAction SilentlyContinue).Source
    if (!$cmake) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $cmake = & $vswhere -latest -prerelease -products '*' -requires Microsoft.VisualStudio.Component.VC.CMake.Project -find 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' | Select-Object -First 1
    }
    if (!$cmake) { throw 'Install CMake 3.24 or later and Visual Studio with the Desktop development with C++ workload.' }
    $native = Join-Path $Workspace 'networkdirect'
    & $cmake -S (Join-Path $PSScriptRoot 'src/native/networkdirect') -B $native -A x64
    if ($LASTEXITCODE -ne 0) { throw 'Network Direct configuration failed.' }
    & $cmake --build $native --config Release
    if ($LASTEXITCODE -ne 0) { throw 'Network Direct compilation failed.' }
    foreach ($project in 'Tedd.SMB3','Tedd.SMB3.Host','Tedd.SMB3.Tests') {
        Copy-Item -LiteralPath (Join-Path $native 'Release/Tedd.SMB3.NetworkDirect.dll') -Destination (Join-Path $artifacts "bin/$project/release")
    }
}
if (-not $SkipTests) {
    dotnet (Join-Path $artifacts 'bin\Tedd.SMB3.Tests\release\Tedd.SMB3.Tests.dll') (Join-Path $Workspace 'fixtures')
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}
