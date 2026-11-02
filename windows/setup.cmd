@echo off
rem Runs once during the image build, as SYSTEM, from SetupComplete.cmd: after setup, before the first sign-in.
rem The helper comes first, so the build can talk to the machine as early as possible.
set py=C:\Program Files\Python314
pnputil /add-driver "%~dp0vioserial\vioser.inf" /install
for %%f in ("%~dp0python-*-amd64.exe") do start /wait "" "%%~f" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=0 Shortcuts=0
"%py%\python.exe" -m pip install --no-index --find-links "%~dp0wheels" -r "%~dp0requirements.txt" || exit /b 1
mkdir C:\work
copy /y "%~dp0helper.py" C:\machines\
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v machines /t REG_SZ /d "\"%py%\pythonw.exe\" C:\machines\helper.py" /f

rem A quiet desktop that never sleeps or locks.
powercfg /hibernate off
powercfg /change monitor-timeout-ac 0
powercfg /change standby-timeout-ac 0
powercfg /change disk-timeout-ac 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreen /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
