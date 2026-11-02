# Runs once, at the first sign-in during the image build, from the provisioning disc; then shuts the machine down.
$ErrorActionPreference = 'Stop'
Start-Transcript C:\machines-setup.log
$here = Split-Path $PSCommandPath

# The host's channel: the virtio-serial driver (Red Hat's), trusted first so it installs without a prompt.
$cert = (Get-AuthenticodeSignature "$here\vioserial\vioser.cat").SignerCertificate
$store = New-Object Security.Cryptography.X509Certificates.X509Store 'TrustedPublisher', 'LocalMachine'
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()
pnputil /add-driver "$here\vioserial\vioser.inf" /install

$installer = Get-ChildItem "$here\python-*-amd64.exe"
Start-Process -Wait $installer.FullName -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0', 'Include_launcher=0', 'Shortcuts=0'
$python = (Get-ChildItem 'C:\Program Files\Python3*\python.exe').FullName
& $python -m pip install --no-index --find-links "$here\wheels" -r "$here\requirements.txt"
if ($LASTEXITCODE) { throw "pip failed: $LASTEXITCODE" }

New-Item -ItemType Directory -Force C:\machines, C:\work | Out-Null
Copy-Item "$here\helper.py" C:\machines\
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run machines "`"$(Split-Path $python)\pythonw.exe`" C:\machines\helper.py"

# A quiet desktop that never sleeps or locks. None of this is worth failing the build over.
$ErrorActionPreference = 'Continue'
powercfg /hibernate off
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
powercfg /change disk-timeout-ac 0
reg add 'HKCU\Control Panel\Desktop' /v ScreenSaveActive /t REG_SZ /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreen /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run OneDriveSetup -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath C:\
& $python -c "import win32api as a; d = a.EnumDisplaySettings(None, -1); d.PelsWidth, d.PelsHeight = 1920, 1080; print(a.ChangeDisplaySettings(d, 1))"

Stop-Transcript
shutdown /s /t 5
