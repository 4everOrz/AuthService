title ÖØÆô·þÎñ


@echo off
set /a num=10
:Cir
for /l %%i in (1,1,2000) do echo Waiting... >nul
set /a num=%num%-1
if not %num%==0 goto Cir

start AuthService.exe
exit

