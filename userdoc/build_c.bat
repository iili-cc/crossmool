@echo off
call "H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d G:\workspaces\git\corssmool\crossmool\c\crossmool
call build_msvc.bat
exit /b %ERRORLEVEL%
