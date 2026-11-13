$ErrorActionPreference = 'Stop'
$clsid = '{A9876D86-53B1-4C76-A451-9682022BF25A}'
# Remove only Voxl registration. The DLL may remain loaded until sign-out/reboot.
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Recurse -ErrorAction SilentlyContinue
Write-Output 'Voxl provider unregistered. Remove --windows-sign-in from the launcher to restore browser-only authentication.'
