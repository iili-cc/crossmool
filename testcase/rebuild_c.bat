@echo off
setlocal
set MSBUILD=H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe
set PROJ=G:\workspaces\git\corssmool\crossmool\c\crossmool\build\crossmool.vcxproj

echo Building crossmool.dll (Release x64)...
"%MSBUILD%" "%PROJ%" /p:Configuration=Release /p:Platform=x64 /t:Build /m /nologo
if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED with error %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
echo BUILD SUCCESS
dir "G:\workspaces\git\corssmool\crossmool\c\crossmool\build\Release\crossmool.dll"
