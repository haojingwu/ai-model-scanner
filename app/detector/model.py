"""Isolation Forest 异常检测模型"""
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_PATH = "models/anomaly_detector.pkl"

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.05,     # 预期5%异常率
            random_state=42,
            n_jobs=-1
        )
        self.trained = False
    
    def train(self, normal_features: np.ndarray):
        """用正常样本特征训练模型"""
        if normal_features.shape[0] < 10:
            raise ValueError(f"正常样本不足: {normal_features.shape[0]}，至少需要10个")
        
        normalized = self.scaler.fit_transform(normal_features)
        self.model.fit(normalized)
        self.trained = True
        self._save()
        print(f"[AI] 训练完成，样本数: {normal_features.shape[0]}")
    
    def predict(self, features: np.ndarray) -> dict:
        """预测单个样本"""
        if not self.trained:
            return {"is_anomaly": False, "anomaly_score": 0.0}
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        normalized = self.scaler.transform(features)
        score = self.model.decision_function(normalized)[0]  # 越大越正常
        prediction = self.model.predict(normalized)[0]       # 1正常, -1异常
        
        # 转换为 0-1 的异常分数（越大越异常）
        anomaly_score = max(0.0, min(1.0, (0.5 - score) + 0.5))
        
        return {
            "is_anomaly": prediction == -1,
            "anomaly_score": float(anomaly_score),
        }
    
    def _save(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump({"scaler": self.scaler, "model": self.model}, MODEL_PATH)
        print(f"[AI] 模型已保存至 {MODEL_PATH}")
    
    @classmethod
    def load(cls):
        """加载已训练的模型"""
        detector = cls()
        if os.path.exists(MODEL_PATH):
            data = joblib.load(MODEL_PATH)
            detector.scaler = data["scaler"]
            detector.model = data["model"]
            detector.trained = True
            print(f"[AI] 模型已加载: {MODEL_PATH}")
        else:
            print(f"[AI] 模型文件不存在，需要先训练: {MODEL_PATH}")
        return detector