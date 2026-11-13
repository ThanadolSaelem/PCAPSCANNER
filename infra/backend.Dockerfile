FROM python:3.12.10-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# Offline -r parsing only; no dumpcap setuid/capture capabilities.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/* \
    && (chmod u-s /usr/bin/dumpcap || true)
COPY backend/requirements.txt /app/backend/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/backend/requirements.txt \
    && useradd --uid 10001 --create-home scanner \
    && mkdir -p /data/captures && chown -R scanner:scanner /data
COPY --chown=scanner:scanner backend /app/backend
USER scanner
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
