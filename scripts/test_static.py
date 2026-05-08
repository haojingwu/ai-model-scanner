import sys
sys.path.insert(0, '.')
from app.scanner.identifier import identify_model_type
from app.scanner.static_pytorch import analyze_pytorch_file

print("=" * 50)
print("测试1: 正常PyTorch模型")
import torch
m = torch.nn.Linear(10, 2)
torch.save(m.state_dict(), '/tmp/normal.pth')
print(f"文件类型: {identify_model_type('/tmp/normal.pth')}")
r = analyze_pytorch_file('/tmp/normal.pth')
print(f"操作码总数: {r['total_opcodes']}, 可疑数: {r['suspicious_ops_count']}")
print(f"风险标志: {r['risk_flags']}")

print("\n" + "=" * 50)
print("测试2: 含REDUCE的可疑文件")
import pickle
class Evil:
    def __reduce__(self): return (eval, ("print('x')",))
with open('/tmp/sus.pth', 'wb') as f: pickle.dump(Evil(), f)
print(f"文件类型: {identify_model_type('/tmp/sus.pth')}")
r2 = analyze_pytorch_file('/tmp/sus.pth')
print(f"可疑操作码数: {r2['suspicious_ops_count']}")
for op in r2['suspicious_ops']:
    print(f"  {op['opcode']}: {op['arg'][:80]}")
    if op['suspicious_keywords']: print(f"  -> 关键词: {op['suspicious_keywords']}")
print(f"风险标志: {r2['risk_flags']}")
print("\n静态分析模块测试完成!")