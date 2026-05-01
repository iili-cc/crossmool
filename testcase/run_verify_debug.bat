@echo off
chcp 65001 >nul
echo ============ Java-Python SM2 互通测试 ============
echo.
echo 执行 Python 验证脚本...
echo.
H:\Programs\Python3\python.exe testcase\java_to_python_verify.py
echo.
echo 退出码：%ERRORLEVEL%
echo.
echo ============ 查看日志文件 ============
type testcase\java_interop_test_20260430.log
echo.
pause