from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from app.scanner.identifier import identify_model_type
from app.scanner.static_pytorch import analyze_pytorch_file
from app.detector.features import extract_features
from app.detector.model import AnomalyDetector
from app.tasks import run_sandbox_analysis
import uuid, os, json

app = FastAPI(title="AI Model Supply Chain Scanner")
UPLOAD_DIR = "uploads"
RESULTS_DIR = "results"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

def _make_serializable(obj):
    """递归转换所有 numpy 类型为 Python 原生类型"""
    import numpy as np
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

@app.post("/api/v1/scan")
async def scan_model(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pth', '.pt', '.h5', '.hdf5', '.keras')):
        raise HTTPException(400, "不支持的文件类型")

    scan_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{scan_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    model_type = identify_model_type(file_path)
    if model_type in ('not_found', 'unknown'):
        return JSONResponse({"scan_id": scan_id, "risk_level": "ERROR", "detail": f"无法识别文件类型: {model_type}"})

    static = _make_serializable(analyze_pytorch_file(file_path))
    features = extract_features(static)
    detector = AnomalyDetector.load()
    ai = _make_serializable(detector.predict(features))

    if static['risk_flags']['has_exec_opcodes'] and static['risk_flags']['has_suspicious_keywords']:
        return JSONResponse({"scan_id": scan_id, "risk_level": "HIGH", "scan_stage": "static", "details": {"static_analysis": static, "ai_detection": ai}})

    if not ai['is_anomaly'] and not static['risk_flags']['has_exec_opcodes']:
        return JSONResponse({"scan_id": scan_id, "risk_level": "LOW", "scan_stage": "static+ai", "details": {"static_analysis": static, "ai_detection": ai}})

    task = run_sandbox_analysis.delay(scan_id, file_path, model_type)
    return JSONResponse({"scan_id": scan_id, "risk_level": "PENDING", "scan_stage": "sandbox", "task_id": str(task.id), "details": {"static_analysis": static, "ai_detection": ai}})

@app.get("/api/v1/result/{scan_id}")
async def get_result(scan_id: str):
    path = os.path.join(RESULTS_DIR, f"{scan_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"scan_id": scan_id, "status": "pending"}