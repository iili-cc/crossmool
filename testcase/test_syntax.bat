@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool
H:\Programs\Python3\python.exe -c "import ast; ast.parse(open('testcase/java_to_c_verify_test.py', encoding='utf-8').read()); print('Syntax OK')"
pause