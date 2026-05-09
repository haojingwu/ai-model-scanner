"""训练AI异常检测模型 - 优化版"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from app.scanner.static_pytorch import analyze_pytorch_file
from app.detector.features import extract_features
from app.detector.model import AnomalyDetector
import torch
import torch.nn as nn
import pickle

def generate_diverse_samples(n_samples: int = 500) -> np.ndarray:
    """生成多样化的正常PyTorch模型样本"""
    print(f"[*] 生成 {n_samples} 个多样化正常模型样本...")
    features_list = []
    
    archs = ['linear', 'mlp', 'conv', 'rnn', 'transformer', 'batchnorm', 'dropout']
    
    for i in range(n_samples):
        arch = np.random.choice(archs)
        try:
            if arch == 'linear':
                model = nn.Linear(np.random.randint(5, 200), np.random.randint(2, 50))
            elif arch == 'mlp':
                layers = []
                in_dim = np.random.randint(5, 100)
                for _ in range(np.random.randint(2, 6)):
                    out_dim = np.random.randint(8, 128)
                    layers.append(nn.Linear(in_dim, out_dim))
                    layers.append(nn.ReLU())
                    in_dim = out_dim
                layers.append(nn.Linear(in_dim, np.random.randint(2, 20)))
                model = nn.Sequential(*layers)
            elif arch == 'conv':
                model = nn.Sequential(
                    nn.Conv2d(np.random.randint(1, 8), np.random.randint(4, 32), 3),
                    nn.ReLU(),
                    nn.AdaptiveAvgPool2d(1),
                    nn.Flatten(),
                    nn.Linear(np.random.randint(4, 32), np.random.randint(2, 20))
                )
            elif arch == 'rnn':
                model = nn.LSTM(np.random.randint(5, 30), np.random.randint(8, 64), 
                               num_layers=np.random.randint(1,3), batch_first=True)
            elif arch == 'transformer':
                model = nn.TransformerEncoder(
                    nn.TransformerEncoderLayer(d_model=np.random.randint(16,34)*4, nhead=4, batch_first=True),
                    num_layers=np.random.randint(1,4)
                )
            elif arch == 'batchnorm':
                model = nn.Sequential(
                    nn.Linear(20, 64), nn.BatchNorm1d(64), nn.ReLU(),
                    nn.Linear(64, 10)
                )
            else:
                model = nn.Sequential(
                    nn.Linear(30, 64), nn.Dropout(0.3), nn.ReLU(),
                    nn.Linear(64, 5)
                )
            
            tmp_path = f"/tmp/train_opt_{i}.pth"
            torch.save(model.state_dict(), tmp_path)
            result = analyze_pytorch_file(tmp_path)
            features = extract_features(result)
            features_list.append(features)
        except:
            continue
        
        if (i+1) % 100 == 0:
            print(f"  已生成 {i+1}/{n_samples}")
    
    return np.array(features_list)

def generate_malicious_samples(n_samples: int = 30) -> np.ndarray:
    """生成恶意样本特征（用于验证，不参与训练）"""
    features_list = []
    malicious_payloads = [
        lambda: (eval, ("print('x')",)),
        lambda: (exec, ("import os; os.system('ls')",)),
        lambda: (__import__('os').system, ('id',)),
        lambda: (open, ('/etc/passwd',)),
    ]
    
    for i in range(n_samples):
        payload = malicious_payloads[i % len(malicious_payloads)]
        class Evil:
            def __reduce__(self): return payload()
        tmp_path = f"/tmp/train_evil_{i}.pth"
        with open(tmp_path, 'wb') as f:
            pickle.dump(Evil(), f)
        try:
            result = analyze_pytorch_file(tmp_path)
            features = extract_features(result)
            features_list.append(features)
        except:
            continue
    
    return np.array(features_list)

if __name__ == "__main__":
    print("=" * 50)
    print("训练 AI 异常检测模型 (优化版)")
    print("=" * 50)
    
    X_normal = generate_diverse_samples(500)
    X_malicious = generate_malicious_samples(30)
    print(f"正常样本: {X_normal.shape}, 恶意样本: {X_malicious.shape}")
    
    # 训练模型
    detector = AnomalyDetector()
    detector.model.contamination = 0.01
    detector.train(X_normal)
    
    # 验证正常样本
    print("\n[*] 正常样本验证 (前50个):")
    normal_preds = [detector.predict(x) for x in X_normal[:50]]
    anomaly_count = sum(1 for p in normal_preds if p['is_anomaly'])
    scores = [p['anomaly_score'] for p in normal_preds]
    print(f"  误判率: {anomaly_count}/50 = {anomaly_count/50*100:.1f}%")
    print(f"  分数范围: {min(scores):.3f} - {max(scores):.3f}")
    print(f"  平均分: {np.mean(scores):.3f}")
    
    # 验证恶意样本
    print("\n[*] 恶意样本验证:")
    evil_preds = [detector.predict(x) for x in X_malicious]
    detected = sum(1 for p in evil_preds if p['is_anomaly'])
    evil_scores = [p['anomaly_score'] for p in evil_preds]
    print(f"  检出率: {detected}/{len(X_malicious)} = {detected/len(X_malicious)*100:.1f}%")
    print(f"  分数范围: {min(evil_scores):.3f} - {max(evil_scores):.3f}")
    print(f"  平均分: {np.mean(evil_scores):.3f}")
    
    print("\n训练完成!")