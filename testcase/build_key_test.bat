@echo off
call "H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
cd /d "%~dp0"
cl /I "../c/crossmool/include" /I "../c/crossmool/gmssl_install/include" test_key_parse.c "../c/crossmool/gmssl_install/lib/gmssl.lib" /Fe:test_key_parse.exe
if %ERRORLEVEL% NEQ 0 (
    echo 编译失败
    exit /b 1
)
echo 编译成功，运行测试...
test_key_parse.exe