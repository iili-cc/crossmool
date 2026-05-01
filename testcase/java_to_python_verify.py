#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 到 Python 互通测试脚本

读取 Java 生成的密钥和加密结果，使用 Python SM2Util 进行解密和验签
验证 Java 和 Python 实现之间的互通性
"""

import json
import os
import sys
import logging
from datetime import datetime
from pathlib import Path

# 添加 Python 实现路径
sys.path.insert(0, str(Path(__file__).parent.parent / 'python' / 'crossmool' / 'src'))

from sm2_util import SM2Util

# 配置日志
LOG_FILE = 'testcase/java_interop_test_20260430.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 路径配置
KEYS_FILE = 'testcase/keys/java/keys.json'
JAVA_ENCRYPT_DIR = 'testcase/results/java_encrypt'
OUTPUT_DIR = 'testcase/results/python_verify_from_java'

def load_java_keys():
    """加载 Java 生成的密钥"""
    logger.info(f"加载 Java 密钥文件：{KEYS_FILE}")
    with open(KEYS_FILE, 'r', encoding='utf-8') as f:
        keys = json.load(f)
    
    # 提取密钥
    encryption_public_key = keys['encryption_public_key']['hex']
    encryption_private_key = keys['encryption_private_key']['hex']
    signature_public_key = keys['signature_public_key']['hex']
    signature_private_key = keys['signature_private_key']['hex']
    
    logger.info("密钥加载成功")
    logger.info(f"  加密公钥：{encryption_public_key[:40]}...")
    logger.info(f"  加密私钥：{encryption_private_key[:40]}...")
    logger.info(f"  签名公钥：{signature_public_key[:40]}...")
    logger.info(f"  签名私钥：{signature_private_key[:40]}...")
    
    return {
        'encryption_public_key': encryption_public_key,
        'encryption_private_key': encryption_private_key,
        'signature_public_key': signature_public_key,
        'signature_private_key': signature_private_key
    }

def load_java_test_cases():
    """加载 Java 加密测试用例"""
    logger.info(f"加载 Java 加密结果目录：{JAVA_ENCRYPT_DIR}")
    
    test_cases = []
    java_encrypt_path = Path(JAVA_ENCRYPT_DIR)
    
    # 查找所有 test_*.json 文件
    for json_file in sorted(java_encrypt_path.glob('test_*.json')):
        if json_file.name.startswith('summary'):
            continue
            
        logger.info(f"  读取测试用例：{json_file.name}")
        with open(json_file, 'r', encoding='utf-8') as f:
            test_case = json.load(f)
            test_case['source_file'] = json_file.name
            test_cases.append(test_case)
    
    logger.info(f"共加载 {len(test_cases)} 个测试用例")
    return test_cases

def verify_decrypt(test_case, keys):
    """
    对单个测试用例进行解密和验签
    返回验证结果
    """
    result = {
        'test_case_id': test_case['test_case_id'],
        'test_case_name': test_case['test_case_name'],
        'original_plaintext': test_case['plaintext'],
        'ciphertext_hex': test_case['ciphertext_hex'],
        'signature_hex': test_case['signature_hex'],
        'decrypt_success': False,
        'decrypt_result': None,
        'decrypt_error': None,
        'verify_success': False,
        'verify_error': None,
        'match_plaintext': False
    }
    
    # 1. 解密
    logger.info(f"测试用例 {test_case['test_case_id']} ({test_case['test_case_name']}): 开始解密")
    try:
        decrypted_bytes = SM2Util.decrypt_from_hex(
            test_case['ciphertext_hex'],
            keys['encryption_private_key'],
            keys['encryption_public_key']  # 提供公钥，gmssl 解密时需要
        )
        decrypted_text = decrypted_bytes.decode('utf-8')
        result['decrypt_success'] = True
        result['decrypt_result'] = decrypted_text
        logger.info(f"  解密成功：{decrypted_text}")
    except Exception as e:
        result['decrypt_error'] = str(e)
        logger.error(f"  解密失败：{e}")
    
    # 2. 验签
    logger.info(f"测试用例 {test_case['test_case_id']}: 开始验签")
    try:
        # 验签使用原文
        original_bytes = test_case['plaintext'].encode('utf-8')
        verify_result = SM2Util.verify(
            original_bytes,
            keys['signature_public_key'],
            test_case['signature_hex']
        )
        result['verify_success'] = verify_result
        if verify_result:
            logger.info(f"  验签成功")
        else:
            logger.error(f"  验签失败：签名不匹配")
            result['verify_error'] = "签名验证失败"
    except Exception as e:
        result['verify_error'] = str(e)
        logger.error(f"  验签失败：{e}")
    
    # 3. 检查解密结果是否与原文匹配
    if result['decrypt_success'] and result['decrypt_result']:
        result['match_plaintext'] = (result['decrypt_result'] == test_case['plaintext'])
        if result['match_plaintext']:
            logger.info(f"  ✓ 解密结果与原文匹配")
        else:
            logger.error(f"  ✗ 解密结果与原文不匹配")
            logger.error(f"    原文：{test_case['plaintext']}")
            logger.error(f"    解密：{result['decrypt_result']}")
    
    return result

def save_results(all_results):
    """保存验证结果"""
    # 创建输出目录
    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"创建输出目录：{OUTPUT_DIR}")
    
    # 保存每个测试用例的结果
    for result in all_results:
        output_file = output_path / f"test_{result['test_case_id']}_{result['test_case_name']}_verify.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"保存测试结果：{output_file.name}")
    
    # 保存汇总结果
    summary = {
        'test_date': datetime.now().isoformat(),
        'total_tests': len(all_results),
        'decrypt_success_count': sum(1 for r in all_results if r['decrypt_success']),
        'verify_success_count': sum(1 for r in all_results if r['verify_success']),
        'match_count': sum(1 for r in all_results if r['match_plaintext']),
        'all_passed': all(r['decrypt_success'] and r['verify_success'] and r['match_plaintext'] for r in all_results),
        'results': all_results
    }
    
    summary_file = output_path / 'summary.json'
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    logger.info(f"保存汇总结果：{summary_file.name}")
    
    return summary

def main():
    """主函数"""
    logger.info("=" * 60)
    logger.info("Java 到 Python 互通测试开始")
    logger.info(f"日志文件：{LOG_FILE}")
    logger.info("=" * 60)
    
    try:
        # 1. 加载 Java 密钥
        keys = load_java_keys()
        
        # 2. 加载 Java 加密测试用例
        test_cases = load_java_test_cases()
        
        # 3. 对每个测试用例进行解密和验签
        all_results = []
        for test_case in test_cases:
            result = verify_decrypt(test_case, keys)
            all_results.append(result)
            logger.info("-" * 60)
        
        # 4. 保存结果
        summary = save_results(all_results)
        
        # 5. 输出汇总
        logger.info("=" * 60)
        logger.info("测试结果汇总")
        logger.info("=" * 60)
        logger.info(f"总测试数：{summary['total_tests']}")
        logger.info(f"解密成功：{summary['decrypt_success_count']}")
        logger.info(f"验签成功：{summary['verify_success_count']}")
        logger.info(f"结果匹配：{summary['match_count']}")
        logger.info(f"全部通过：{summary['all_passed']}")
        logger.info("=" * 60)
        
        if summary['all_passed']:
            logger.info("✓ 所有测试通过！Java 和 Python SM2 实现完全互通")
            return 0
        else:
            logger.error("✗ 部分测试失败，请查看日志文件了解详情")
            return 1
            
    except Exception as e:
        logger.error(f"测试过程中发生错误：{e}", exc_info=True)
        return 2

if __name__ == '__main__':
    exit(main())