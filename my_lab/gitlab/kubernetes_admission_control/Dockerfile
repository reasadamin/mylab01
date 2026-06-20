# Dockerfile - FastAPI + sentence-transformers inference service.
#
# Multi-stage build:
#   * builder  - creates the venv (CPU-only torch) and bakes the model.
#   * runtime  - minimal image, non-root, model preloaded, fully offline.
#
# Security properties the admission + runtime stages rely on:
#   * Runs as a non-root user (UID 10001) on unprivileged port 8080.
#   * Model is baked at build time and HF_*_OFFLINE=1 is set, so the running
#     container needs no network and can run on a READ-ONLY root filesystem.
#     The only writable path it needs is /tmp (HOME=/tmp), which the deployment
#     supplies via an emptyDir volume.
#   * Pinned base image and pinned dependencies for reproducible builds.
#
# Pin the base by digest for full immutability:
#   docker buildx imagetools inspect python:3.12-slim
# then append @sha256:... to both FROM lines.

# --- Stage 1: builder ------------------------------------------------------
FROM python:3.12-slim AS builder

ENV VENV=/opt/venv \
    HF_HOME=/opt/models \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Isolated virtualenv so the runtime stage can copy it wholesale.
RUN python -m venv "$VENV"
ENV PATH="$VENV/bin:$PATH"

WORKDIR /build

# CPU-only torch first, from the PyTorch CPU index, so sentence-transformers
# reuses it instead of dragging in the multi-GB CUDA build.
RUN pip install --no-cache-dir torch==2.12.1 --index-url https://download.pytorch.org/whl/cpu

# Application dependencies (torch already satisfied above).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake the embedding model into /opt/models at build time -> no runtime download.
ARG MODEL_NAME=all-MiniLM-L6-v2
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${MODEL_NAME}')"

# --- Stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim AS runtime

# Dedicated non-root user to run the service.
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --shell /usr/sbin/nologin --home-dir /code app

ENV PATH="/opt/venv/bin:$PATH" \
    HF_HOME=/opt/models \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    MODEL_NAME=all-MiniLM-L6-v2 \
    HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Bring over the venv and the baked model from the builder stage.
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/models /opt/models

WORKDIR /code
COPY app/ ./app/

# Drop privileges.
USER 10001

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]