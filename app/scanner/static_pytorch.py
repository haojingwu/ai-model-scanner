"""PyTorch模型文件的静态分析"""
import pickletools
import zipfile
import io
import math
from collections import Counter
from typing import Dict, Any, List, Tuple

PYTORCH_SAFE_GLOBALS = {
    'collections OrderedDict',
    'torch._utils _rebuild_tensor_v2',
    'torch._utils _rebuild_parameter',
    'torch FloatStorage', 'torch LongStorage',
    'torch.nn.parameter Parameter', 'torch Tensor', 'torch Size',
    'builtins print',
}
SUSPICIOUS_KEYWORDS = [
    'os.system', 'subprocess', 'socket', 'exec', 'eval',
    'base64', 'compile', '__import__', 'open', 'write',
    'requests', 'urllib', 'http', '.connect', 'reverse_shell',
]

def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def _extract_pickle_bytes(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        raw_bytes = f.read()
    if raw_bytes[:4] == b'PK\x03\x04':
        with zipfile.ZipFile(io.BytesIO(raw_bytes), 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.pkl') or 'data' in name:
                    return zf.read(name)
            names = zf.namelist()
            if names:
                return zf.read(names[0])
        raise ValueError("无法从ZIP文件中提取pickle数据")
    return raw_bytes

def _build_full_global_name(ops_list: List[Tuple[str, str, int]], idx: int) -> str:
    """
    从STACK_GLOBAL的位置向前查找，重构完整模块名.函数名
    STACK_GLOBAL的arg为None时，真正的模块和函数名在前两条SHORT_BINUNICODE里
    """
    if idx < 2:
        return ''
    prev1 = ops_list[idx - 1]
    prev2 = ops_list[idx - 2]
    if prev1[0] == 'MEMOIZE' and prev2[0] == 'SHORT_BINUNICODE':
        # 需要再往前找：SHORT_BINUNICODE(模块) + MEMOIZE + SHORT_BINUNICODE(函数) + MEMOIZE + STACK_GLOBAL
        if idx >= 4 and ops_list[idx - 3][0] == 'MEMOIZE' and ops_list[idx - 4][0] == 'SHORT_BINUNICODE':
            module = ops_list[idx - 4][1]
            func = prev2[1]
            return f"{module} {func}"
    return ''

def analyze_pytorch_file(file_path: str) -> Dict[str, Any]:
    with open(file_path, 'rb') as f:
        raw_bytes = f.read()
    
    try:
        pickle_data = _extract_pickle_bytes(file_path)
    except Exception:
        pickle_data = raw_bytes
    
    # 先收集所有操作码到列表（含索引），方便向前查找
    ops_list = []
    opcode_sequence = []
    for opcode, arg, pos in pickletools.genops(pickle_data):
        arg_str = str(arg) if arg else ''
        ops_list.append((opcode.name, arg_str, pos))
        opcode_sequence.append(opcode.name)
    
    suspicious_ops = []
    
    for idx, (opcode_name, arg_str, pos) in enumerate(ops_list):
        if opcode_name in ('GLOBAL', 'STACK_GLOBAL'):
            # 如果arg为None/空，尝试从前面重构完整名称
            if not arg_str or arg_str == 'None':
                if opcode_name == 'STACK_GLOBAL':
                    full_name = _build_full_global_name(ops_list, idx)
                    if full_name:
                        arg_str = full_name
                    else:
                        continue                # 重构失败，跳过
                else:
                    continue                    # GLOBAL且空参数
            if arg_str in PYTORCH_SAFE_GLOBALS:
                continue                        # 白名单
            found = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in arg_str.lower()]
            suspicious_ops.append({
                'opcode': opcode_name, 'arg': arg_str[:200],
                'position': pos, 'suspicious_keywords': found
            })
        elif opcode_name in ('INST', 'OBJ', 'NEWOBJ'):
            found = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in arg_str.lower()]
            if found:
                suspicious_ops.append({
                    'opcode': opcode_name, 'arg': arg_str[:200],
                    'position': pos, 'suspicious_keywords': found
                })
    
    opcode_counter = Counter(opcode_sequence)
    total_ops = len(opcode_sequence)
    trigrams = []
    for i in range(len(opcode_sequence) - 2):
        trigrams.append(f"{opcode_sequence[i]}_{opcode_sequence[i+1]}_{opcode_sequence[i+2]}")
    trigram_counter = Counter(trigrams)
    entropy_values = []
    for i in range(0, len(raw_bytes), 256):
        block = raw_bytes[i:i+256]
        entropy_values.append(_calculate_entropy(block))
    high_entropy_blocks = sum(1 for x in entropy_values if x > 7.0)
    
    return {
        'file_size': len(raw_bytes), 'total_opcodes': total_ops,
        'unique_opcodes': len(opcode_counter), 'suspicious_ops_count': len(suspicious_ops),
        'suspicious_ops': suspicious_ops,
        'opcode_distribution': dict(opcode_counter.most_common(30)),
        'trigram_top100': dict(trigram_counter.most_common(100)),
        'entropy_mean': sum(entropy_values) / max(1, len(entropy_values)),
        'entropy_max': max(entropy_values) if entropy_values else 0,
        'high_entropy_block_ratio': high_entropy_blocks / max(1, len(entropy_values)),
        'risk_flags': {
            'has_exec_opcodes': any(
                op['opcode'] in ('GLOBAL','STACK_GLOBAL') for op in suspicious_ops
            ),
            'has_suspicious_keywords': any(
                len(op['suspicious_keywords'])>0 for op in suspicious_ops
            ),
            'has_high_entropy_blocks': high_entropy_blocks > 0,
        }
    }