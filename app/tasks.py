import json, os
import numpy as np
from app.celery_app import celery_app
from app.scanner.sandbox_runner import run_sandbox
from app.scanner.static_pytorch import analyze_pytorch_file
from app.detector.features import extract_features
from app.detector.model import AnomalyDetector

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def _make_serializable(obj):
    if isinstance(obj, (np.integer,)):
        return int(obj)
    elif isinstance(obj, (np.floating,)):
        return float(obj)
    elif isinstance(obj, (np.bool_,)):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_make_serializable(v) for v in obj]
    return obj

@celery_app.task(name='app.tasks.run_sandbox_analysis', bind=True, max_retries=2)
def run_sandbox_analysis(self, scan_id: str, file_path: str, model_type: str):
    try:
        self.update_state(state='PROGRESS', meta={'step': 'sandbox'})
        sandbox_result = _make_serializable(run_sandbox(file_path, model_type))

        self.update_state(state='PROGRESS', meta={'step': 'ai'})
        static_result = analyze_pytorch_file(file_path)
        features = extract_features(static_result)
        detector = AnomalyDetector.load()
        ai_result = _make_serializable(detector.predict(features))

        score = 0.0
        if sandbox_result.get('status') == 'exception':
            score += 0.4
        score += ai_result.get('anomaly_score', 0) * 0.4
        if sandbox_result.get('exit_code', 0) != 0:
            score += 0.2
        score = min(score, 1.0)

        risk_level = 'HIGH' if score > 0.7 else 'MEDIUM' if score > 0.3 else 'LOW'

        result = {
            'scan_id': scan_id, 'risk_level': risk_level, 'risk_score': score,
            'sandbox': sandbox_result, 'ai_detection': ai_result,
        }

        with open(f'{RESULTS_DIR}/{scan_id}.json', 'w') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        return result
    except Exception as e:
        self.retry(exc=e, countdown=10)