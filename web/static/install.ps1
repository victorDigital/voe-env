param([Parameter(Mandatory = $true)][uri] $BaseUrl)
$ErrorActionPreference = 'Stop'
$origin = $BaseUrl.GetLeftPart([System.UriPartial]::Authority)
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    default { throw 'Supported architectures are x86_64 and ARM64.' }
}
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\VOE\bin'
$configDirectory = Join-Path $env:USERPROFILE '.voe'
$download = [System.IO.Path]::GetTempFileName()
try {
    Invoke-WebRequest "$origin/downloads/ve-windows-$arch.exe" -OutFile $download -UseBasicParsing
    New-Item -ItemType Directory -Force -Path $installDirectory, $configDirectory | Out-Null
    Move-Item $download (Join-Path $installDirectory 've.exe') -Force
    [System.IO.File]::WriteAllText((Join-Path $configDirectory 'server-url'), "$origin`n")
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $installDirectory) {
        [Environment]::SetEnvironmentVariable('Path', "$installDirectory;$userPath".TrimEnd(';'), 'User')
    }
    $env:Path = "$installDirectory;$env:Path"
    Write-Host 'Installed ve. Run: ve auth'
} finally {
    Remove-Item $download -ErrorAction SilentlyContinue
}
