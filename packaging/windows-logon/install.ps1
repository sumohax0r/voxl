# Run elevated, after verifying the build. Keeps every existing system provider.
$ErrorActionPreference = 'Stop'
$destination = Join-Path $env:ProgramW6432 'VoxlLogon'
$clsid = '{A9876D86-53B1-4C76-A451-9682022BF25A}'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
# Only administrators and SYSTEM may replace code loaded into LogonUI.
& icacls.exe $destination /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
if ($LASTEXITCODE) { throw 'Failed to protect the installation directory' }
Copy-Item (Join-Path $PSScriptRoot 'voxl-logon.dll') $destination -Force
$key = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
New-Item $key -Force | Out-Null
Set-Item $key (Join-Path $destination 'voxl-logon.dll')
New-ItemProperty $key -Name ThreadingModel -Value Both -PropertyType String -Force | Out-Null
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
New-Item $key -Force | Out-Null
Set-Item $key 'Voxl Windows sign-in'
Write-Output 'Provider registered. Keep the normal Windows password provider and RDP enabled.'
Write-Output 'Restart Voxl with --auth-mode=os --auth-users=ai --windows-sign-in=true in the console session as SYSTEM.'
