FROM python:3.12.10-slim-bookworm
ARG ZEEK_PACKAGE_VERSION=9.0.1-0
ARG YARA_PACKAGE_VERSION=4.2.3-4
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PATH="/opt/zeek/bin:${PATH}"
WORKDIR /app
# Offline -r parsing only; no dumpcap setuid/capture capabilities.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg tshark "yara=${YARA_PACKAGE_VERSION}" \
    && install -d -m 0755 /etc/apt/keyrings \
    && curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
        | gpg --dearmor -o /etc/apt/keyrings/zeek.gpg \
    && chmod 0644 /etc/apt/keyrings/zeek.gpg \
    && echo 'deb [signed-by=/etc/apt/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
        > /etc/apt/sources.list.d/zeek.list \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "zeek=${ZEEK_PACKAGE_VERSION}" \
    && test "$(dpkg-query -W -f='${Version}' zeek)" = "${ZEEK_PACKAGE_VERSION}" \
    && test "$(dpkg-query -W -f='${Version}' yara)" = "${YARA_PACKAGE_VERSION}" \
    && apt-get purge -y --auto-remove curl gnupg \
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
