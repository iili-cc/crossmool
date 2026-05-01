import sys
sys.path.insert(0, 'python/crossmool/src')

try:
    from sm2_util import SM2Util
    print('SM2Util 导入成功')
except Exception as e:
    print(f'导入失败：{type(e).__name__}: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)