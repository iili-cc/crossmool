#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""简单测试脚本"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'python' / 'crossmool' / 'src'))

print("开始测试导入...")
try:
    from sm2_util import SM2Util
    print("✓ SM2Util 导入成功")
except Exception as e:
    print(f"✗ 导入失败：{type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n测试完成")