"""将静态分析结果转换为固定长度的特征向量,供AI模型使用"""
import numpy as np
from collections import Counter
from typing import Dict, Any

# 特征向量总维度
FEATURE_DIM = 200

# 高频操作码白名单（基于正常模型统计得出，50个）
TOP_OPCODES = [
    'BININT', 'BININT1', 'BININT2', 'SHORT_BINUNICODE', 'EMPTY_DICT',
    'MEMOIZE', 'APPENDS', 'SETITEMS', 'TUPLE', 'TUPLE1', 'TUPLE2', 'TUPLE3',
    'DICT', 'EMPTY_LIST', 'MARK', 'STOP', 'POP', 'POP_MARK', 'DUP',
    'FLOAT', 'BINFLOAT', 'INT', 'LONG', 'STRING', 'UNICODE',
    'SHORT_BINSTRING', 'APPEND', 'LIST', 'GLOBAL', 'STACK_GLOBAL',
    'REDUCE', 'BUILD', 'NEWOBJ', 'NONE', 'SETITEM', 'PROTO', 'FRAME',
    'BINGET', 'LONG_BINGET', 'BINUNICODE', 'BINPUT', 'LONG_BINPUT',
    'BINPERSID', 'EMPTY_TUPLE', 'TRUE', 'FALSE', 'BYTEARRAY8',
    'SHORT_BINBYTES', 'BINBYTES', 'NEXT_BUFFER',
]

def extract_features(static_result: Dict[str, Any]) -> np.ndarray:
    """
    从静态分析结果中提取固定维度特征向量
    返回: numpy array, shape (FEATURE_DIM,)
    """
    features = []
    
    # 1. 操作码频率特征（前100维）
    opcode_dist = static_result.get('opcode_distribution', {})
    total_ops = max(1, static_result.get('total_opcodes', 1))
    for op in TOP_OPCODES[:100]:
        features.append(opcode_dist.get(op, 0) / total_ops)
    
    # 如果TOP_OPCODES不足100个，补0
    while len(features) < 100:
        features.append(0.0)
    
    # 2. 元数据特征（10维）
    features.append(min(static_result.get('file_size', 0) / 1e9, 1.0))        # 文件大小归一化
    features.append(min(static_result.get('total_opcodes', 0) / 10000, 1.0))   # 操作码总数
    features.append(static_result.get('unique_opcodes', 0) / max(1, static_result.get('total_opcodes', 1)))
    features.append(static_result.get('suspicious_ops_count', 0))
    features.append(min(static_result.get('entropy_mean', 0) / 8.0, 1.0))
    features.append(min(static_result.get('entropy_max', 0) / 8.0, 1.0))
    features.append(static_result.get('high_entropy_block_ratio', 0))
    
    risk_flags = static_result.get('risk_flags', {})
    features.append(1.0 if risk_flags.get('has_exec_opcodes') else 0.0)
    features.append(1.0 if risk_flags.get('has_suspicious_keywords') else 0.0)
    features.append(1.0 if risk_flags.get('has_high_entropy_blocks') else 0.0)
    
    # 3. Trigram 频率特征（90维，取top trigrams的前90个）
    trigram_top = static_result.get('trigram_top100', {})
    sorted_trigrams = sorted(trigram_top.items(), key=lambda x: x[1], reverse=True)
    for i, (_, count) in enumerate(sorted_trigrams[:90]):
        features.append(min(count / max(1, total_ops), 1.0))
    while len(features) < 200:
        features.append(0.0)
    
    return np.array(features, dtype=np.float32)