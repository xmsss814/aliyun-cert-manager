FROM python:3.12-slim

LABEL org.opencontainers.image.title="aliyun-cert-manager" \
      org.opencontainers.image.description="阿里云 SSL 证书自动管理工具（守护进程版）"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 可选：构建时通过 --build-arg PIP_INDEX_URL 覆盖（如使用国内镜像加速）
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

# 优先单独 COPY requirements，利用 layer 缓存
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scripts/cert_manager.py /app/scripts/cert_manager.py

# 容器内默认证书输出目录；可通过 volume 覆盖到宿主机
ENV CERT_DIR=/data/certs \
    DAEMON=1

RUN mkdir -p "${CERT_DIR}"

VOLUME ["/data/certs"]

# 默认 daemon 模式，间隔由 INTERVAL_HOURS 控制
CMD ["python3", "/app/scripts/cert_manager.py"]
