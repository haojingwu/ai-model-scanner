"""识别上传的模型文件类型"""
import os
import zipfile

def identify_model_type(file_path: str) -> str:
    if not os.path.exists(file_path):
        return 'not_found'
    if os.path.isdir(file_path):
        if os.path.exists(os.path.join(file_path, 'saved_model.pb')):
            return 'tensorflow_savedmodel'
        return 'unknown'
    with open(file_path, 'rb') as f:
        magic = f.read(8)
    # pickle protocol 0-5: \x80\x02 到 \x80\x05, 以及纯ASCII的 protocol 0
    if magic[:1] == b'\x80' and magic[1:2] in (b'\x02', b'\x03', b'\x04', b'\x05'):
        return 'pytorch'
    if magic[:4] == b'PK\x03\x04':
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()
                if any('data' in n or '.pkl' in n for n in names):
                    return 'pytorch'
        except:
            pass
        return 'pytorch'
    if magic[:8] == b'\x89HDF\r\n\x1a\n':
        return 'keras_h5'
    return 'unknown'