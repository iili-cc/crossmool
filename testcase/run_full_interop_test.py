#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java-Go 双向互通性测试编排脚本
运行完整的 SM2/SM3/SM4 互通性测试并生成报告
"""

import os
import sys
import json
import subprocess
from datetime import datetime

# 配置
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTCASE_DIR = os.path.join(WORKSPACE, "testcase")
JAVA_CROSSMOOL_DIR = os.path.join(WORKSPACE, "java", "crossmool")
GO_INTEROP_DIR = os.path.join(TESTCASE_DIR, ".go_interop_temp")
GO_GEN_DATA_DIR = os.path.join(GO_INTEROP_DIR, "go_gen_data")

JAVA_HOME = os.environ.get("JAVA_HOME", r"H:\Programs\Java\jdk-21.0.1+12")
MVN_HOME = os.environ.get("MVN_HOME", r"G:\workspaces\maven\apache-maven-3.9.9")

# 结果统计
results = {
    "java_to_go": {"pass": 0, "fail": 0, "tests": []},
    "go_to_java": {"pass": 0, "fail": 0, "tests": []},
}

def log_section(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def log_step(step):
    print(f"\n[STEP] {step}")

def log_result(test_name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {test_name}" + (f" - {detail}" if detail else ""))
    return passed

def print_unicode_safe(text):
    """安全打印 Unicode 文本到 Windows 控制台"""
    print(text.encode('utf-8').decode('gbk', errors='replace'))

def run_command(cmd, cwd=None, capture=True):
    """运行命令并返回结果"""
    print(f"  执行：{' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture,
            text=True,
            shell=isinstance(cmd, str),
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)

def test_java_to_go():
    """Java 生成数据，Go 验证"""
    log_section("Java → Go 互通性测试")

    # 1. 编译 Java 项目
    log_step("编译 Java 项目")
    success, output = run_command(
        f'"{MVN_HOME}\\bin\\mvn" compile -q', cwd=JAVA_CROSSMOOL_DIR
    )
    if not success:
        print(f"  Java 编译失败：{output}")
        return False
    print("  Java 编译成功")

    # 2. 编译 Java 测试数据生成器
    log_step("编译 Java 测试数据生成器")
    classpath = f"{TESTCASE_DIR};{JAVA_CROSSMOOL_DIR}\\target\\classes;{JAVA_CROSSMOOL_DIR}\\target\\dependency\\*"
    src_file = os.path.join(TESTCASE_DIR, "GenerateGoInteropData.java")
    success, output = run_command(
        f'"{JAVA_HOME}\\bin\\javac" -cp "{classpath}" "{src_file}"'
    )
    if not success:
        print(f"  Java 测试生成器编译失败：{output}")
        return False
    print("  Java 测试生成器编译成功")

    # 3. 运行 Java 生成测试数据
    log_step("运行 Java 生成测试数据")
    json_output = os.path.join(TESTCASE_DIR, "java_go_test_data.json")
    success, output = run_command(
        f'"{JAVA_HOME}\\bin\\java" -cp "{classpath}" GenerateGoInteropData "{json_output}"',
        cwd=TESTCASE_DIR,
    )
    if not success:
        print(f"  Java 生成测试数据失败：{output}")
        return False
    print(f"  测试数据已保存到：{json_output}")

    # 4. 运行 Go 验证
    log_step("运行 Go 验证程序")
    success, output = run_command(
        "go run main.go ../java_go_test_data.json",
        cwd=GO_INTEROP_DIR,
        capture=False,
    )
    if not success:
        print("  Go 验证失败")
        return False
    print("  Go 验证成功")

    # 解析 Go 输出
    for line in output.split("\n"):
        if "[PASS]" in line:
            test_name = line.split("]")[1].split("-")[0].strip()
            results["java_to_go"]["pass"] += 1
            results["java_to_go"]["tests"].append({"name": test_name, "passed": True})
        elif "[FAIL]" in line:
            test_name = line.split("]")[1].split("-")[0].strip()
            results["java_to_go"]["fail"] += 1
            results["java_to_go"]["tests"].append({"name": test_name, "passed": False})

    return True

def test_go_to_java():
    """Go 生成数据，Java 验证"""
    log_section("Go → Java 互通性测试")

    # 1. 运行 Go 生成测试数据
    log_step("运行 Go 生成测试数据")
    json_output = os.path.join(TESTCASE_DIR, "go_java_test_data.json")
    success, output = run_command(
        f"go run main.go \"{json_output}\"",
        cwd=GO_GEN_DATA_DIR,
        capture=False,
    )
    if not success:
        print("  Go 生成测试数据失败")
        return False
    print(f"  测试数据已保存到：{json_output}")

    # 2. 编译 Java 验证器
    log_step("编译 Java 验证器")
    classpath = f"{TESTCASE_DIR};{JAVA_CROSSMOOL_DIR}\\target\\classes;{JAVA_CROSSMOOL_DIR}\\target\\dependency\\*"
    src_file = os.path.join(TESTCASE_DIR, "VerifyGoInteropData.java")
    success, output = run_command(
        f'"{JAVA_HOME}\\bin\\javac" -cp "{classpath}" "{src_file}"'
    )
    if not success:
        print(f"  Java 验证器编译失败：{output}")
        return False
    print("  Java 验证器编译成功")

    # 3. 运行 Java 验证
    log_step("运行 Java 验证程序")
    success, output = run_command(
        f'"{JAVA_HOME}\\bin\\java" -cp "{classpath}" VerifyGoInteropData "{json_output}"',
        cwd=TESTCASE_DIR,
        capture=False,
    )
    if not success:
        print("  Java 验证失败")
        return False
    print("  Java 验证成功")

    # 解析 Java 输出
    for line in output.split("\n"):
        if "[PASS]" in line:
            test_name = line.split("]")[1].split("-")[0].strip()
            results["go_to_java"]["pass"] += 1
            results["go_to_java"]["tests"].append({"name": test_name, "passed": True})
        elif "[FAIL]" in line:
            test_name = line.split("]")[1].split("-")[0].strip()
            results["go_to_java"]["fail"] += 1
            results["go_to_java"]["tests"].append({"name": test_name, "passed": False})

    return True

def generate_report():
    """生成测试报告"""
    log_section("测试报告")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [
        "# Java-Go SM2/SM3/SM4 互通性测试报告",
        f"\n**生成时间**: {timestamp}\n",
        "## 测试摘要\n",
        "| 测试方向 | 通过 | 失败 | 总计 |",
        "|---------|------|------|------|",
        f"| Java → Go | {results['java_to_go']['pass']} | {results['java_to_go']['fail']} | {results['java_to_go']['pass'] + results['java_to_go']['fail']} |",
        f"| Go → Java | {results['go_to_java']['pass']} | {results['go_to_java']['fail']} | {results['go_to_java']['pass'] + results['go_to_java']['fail']} |",
        f"| **总计** | {results['java_to_go']['pass'] + results['go_to_java']['pass']} | {results['java_to_go']['fail'] + results['go_to_java']['fail']} | {results['java_to_go']['pass'] + results['java_to_go']['fail'] + results['go_to_java']['pass'] + results['go_to_java']['fail']} |",
        "\n## 详细结果\n",
        "### Java → Go 测试结果\n",
    ]

    for test in results["java_to_go"]["tests"]:
        status = "✅" if test["passed"] else "❌"
        report_lines.append(f"- {status} {test['name']}")

    report_lines.extend(["\n### Go → Java 测试结果\n"])
    for test in results["go_to_java"]["tests"]:
        status = "✅" if test["passed"] else "❌"
        report_lines.append(f"- {status} {test['name']}")

    total_pass = results["java_to_go"]["pass"] + results["go_to_java"]["pass"]
    total_fail = results["java_to_go"]["fail"] + results["go_to_java"]["fail"]

    if total_fail == 0:
        report_lines.extend(["\n## 结论\n", "**[PASS] 所有测试通过！Java 和 Go 实现完全互通。**"])
    else:
        report_lines.extend([
            f"\n## 结论\n",
            f"**[WARN] 有 {total_fail} 个测试失败，请检查失败项。**",
        ])

    # 保存报告
    report_path = os.path.join(TESTCASE_DIR, "java_go_interop_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"\n测试报告已保存到：{report_path}")

    # 打印摘要
    print("\n" + "=" * 60)
    print("  测试摘要")
    print("=" * 60)
    print(f"  Java → Go: {results['java_to_go']['pass']} 通过，{results['java_to_go']['fail']} 失败")
    print(f"  Go → Java: {results['go_to_java']['pass']} 通过，{results['go_to_java']['fail']} 失败")
    print(f"  总计：{total_pass} 通过，{total_fail} 失败")

    return total_fail == 0

def main():
    print("=" * 60)
    print("  Java-Go SM2/SM3/SM4 双向互通性测试")
    print("=" * 60)

    os.chdir(WORKSPACE)

    # 运行测试
    java_to_go_ok = test_java_to_go()
    go_to_java_ok = test_go_to_java()

    # 生成报告
    all_ok = generate_report()

    print("\n" + "=" * 60)
    if all_ok:
        print("  [PASS] 所有测试通过！")
        return 0
    else:
        print("  [FAIL] 部分测试失败！")
        return 1

if __name__ == "__main__":
    sys.exit(main())