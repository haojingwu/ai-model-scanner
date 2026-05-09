"""训练AI异常检测模型 - 增强版"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from app.scanner.static_pytorch import analyze_pytorch_file
from app.detector.features import extract_features
from app.detector.model import AnomalyDetector
import torch
import torch.nn as nn

def generate_diverse_samples(n_samples: int = 200) -> np.ndarray:
    """生成多样化的正常PyTorch模型样本"""
    print(f"[*] 生成 {n_samples} 个多样化正常模型样本...")
    features_list = []
    
    for i in range(n_samples):
        # 随机选择模型架构
        arch = np.random.choice(['linear', 'mlp', 'conv', 'rnn'])
        
        try:
            if arch == 'linear':
                model = nn.Linear(np.random.randint(5, 100), np.random.randint(2, 20))
            elif arch == 'mlp':
                layers = []
                in_dim = np.random.randint(5, 50)
                for _ in range(np.random.randint(2, 5)):
                    out_dim = np.random.randint(8, 64)
                    layers.append(nn.Linear(in_dim, out_dim))
                    layers.append(nn.ReLU())
                    in_dim = out_dim
                layers.append(nn.Linear(in_dim, np.random.randint(2, 10)))
                model = nn.Sequential(*layers)
            elif arch == 'conv':
                model = nn.Sequential(
                    nn.Conv2d(np.random.randint(1, 4), np.random.randint(4, 16), 3),
                    nn.ReLU(),
                    nn.AdaptiveAvgPool2d(1),
                    nn.Flatten(),
                    nn.Linear(np.random.randint(4, 16), np.random.randint(2, 10))
                )
            else:
                model = nn.LSTM(np.random.randint(5, 20), np.random.randint(8, 32), batch_first=True)
            
            tmp_path = f"/tmp/train_normal_{i}.pth"
            torch.save(model.state_dict(), tmp_path)
            
            result = analyze_pytorch_file(tmp_path)
            features = extract_features(result)
            features_list.append(features)
        except Exception as e:
            continue
        
        if (i + 1) % 50 == 0:
            print(f"  已生成 {i+1}/{n_samples}")
    
    return np.array(features_list)

if __name__ == "__main__":
    print("=" * 50)
    print("训练 AI 异常检测模型 (增强版)")
    print("=" * 50)
    
    # 生成训练样本
    X = generate_diverse_samples(200)
    print(f"特征矩阵: {X.shape}")
    
    # 训练模型，降低污染率
    detector = AnomalyDetector()
    detector.model.contamination = 0.01  # 降低异常预期比例
    detector.train(X)
    
    # 验证正常样本
    print("\n[*] 验证: 正常样本预测")
    normal_preds = [detector.predict(x) for x in X[:20]]
    anomaly_count = sum(1 for p in normal_preds if p['is_anomaly'])
    scores = [p['anomaly_score'] for p in normal_preds]
    print(f"  误判为异常: {anomaly_count}/20")
    print(f"  异常分数范围: {min(scores):.3f} - {max(scores):.3f}")
    print(f"  平均异常分数: {np.mean(scores):.3f}")
    
    # 验证恶意样本
    print("\n[*] 验证: 恶意样本预测")
    import pickle
    class Evil:
        def __reduce__(self): return (eval, ("print('x')",))
    evil_path = "/tmp/evil_test.pth"
    with open(evil_path, 'wb') as f:
        pickle.dump(Evil(), f)
    evil_result = analyze_pytorch_file(evil_path)
    evil_features = extract_features(evil_result)
    evil_pred = detector.predict(evil_features)
    print(f"  恶意样本: is_anomaly={evil_pred['is_anomaly']}, score={evil_pred['anomaly_score']:.3f}")
    
    print("\n训练完成!")