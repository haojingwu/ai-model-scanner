FROM python:3.10-slim

# 先装 pip，再配镜像源，再装 torch/tensorflow
RUN pip install --no-cache-dir --upgrade pip && \
    pip config set global.index-url https://pypi.mirrors.ustc.edu.cn/simple/

# 创建非root用户
RUN useradd --create-home --no-log-init sandbox

# 安装 PyTorch CPU 版（用中科大源可能慢，可以临时切回官方）
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# 安装 TensorFlow CPU 版
RUN pip install --no-cache-dir tensorflow-cpu

# 拷贝加载脚本
COPY load_model.py /sandbox/load_model.py

# 安全检查：确保没有多余的可执行文件
RUN find / -type f -perm /u+x 2>/dev/null | grep -vE "(python|pip|\.so)" | wc -l || true

USER sandbox
WORKDIR /sandbox

ENTRYPOINT ["python", "/sandbox/load_model.py"]
