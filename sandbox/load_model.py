"""沙箱内部模型加载脚本 - 在 Docker 容器中执行"""
import sys
import json
import os

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "reason": "参数不足，需要: 模型路径 模型类型"}))
        sys.exit(1)
    
    model_path = sys.argv[1]
    model_type = sys.argv[2]  # 'pytorch' 或 'keras'
    
    result = {
        "status": "unknown",
        "model_type": model_type,
        "model_path": model_path,
        "file_exists": os.path.exists(model_path)
    }
    
    try:
        if model_type == 'pytorch':
            import torch
            print(f"[*] 开始加载PyTorch模型: {model_path}", flush=True)
            model = torch.load(model_path, map_location='cpu')
            result["status"] = "loaded"
            result["object_type"] = str(type(model))
            # 如果是 state_dict，报告键的数量
            if isinstance(model, dict):
                result["keys_count"] = len(model.keys())
                result["sample_keys"] = list(model.keys())[:5]
                
        elif model_type == 'keras':
            import tensorflow as tf
            print(f"[*] 开始加载Keras模型: {model_path}", flush=True)
            model = tf.keras.models.load_model(model_path, compile=False)
            result["status"] = "loaded"
            result["object_type"] = str(type(model))
            result["layers_count"] = len(model.layers)
            result["sample_layers"] = [str(layer.__class__.__name__) for layer in model.layers[:5]]
        
        else:
            result["status"] = "error"
            result["reason"] = f"不支持的模型类型: {model_type}"
    
    except Exception as e:
        result["status"] = "exception"
        result["exception_type"] = type(e).__name__
        result["exception_msg"] = str(e)[:500]
    
    # 输出 JSON 结果（宿主机会捕获这个输出）
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
