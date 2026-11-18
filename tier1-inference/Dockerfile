FROM python:3.12.10-slim-bookworm
ARG INSTALL_NEURAL=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TIER1_HOST=0.0.0.0 \
    TIER1_PORT=9000 \
    HF_HOME=/tmp/hf-cache
WORKDIR /app

COPY requirements.txt requirements-neural.txt pyproject.toml ./
RUN if [ "${INSTALL_NEURAL}" = "1" ]; then \
        python -m pip install --no-cache-dir -r requirements-neural.txt; \
    else \
        python -m pip install --no-cache-dir -r requirements.txt; \
    fi \
    && useradd --uid 10001 --create-home tier1 \
    && mkdir -p /models && chown -R tier1:tier1 /models

COPY --chown=tier1:tier1 tier1_inference /app/tier1_inference
USER tier1
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/health', timeout=2)"]

CMD ["python", "-m", "tier1_inference"]
