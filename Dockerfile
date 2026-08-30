FROM python:3.13-alpine AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir setuptools \
    && pip wheel --no-cache-dir --no-build-isolation --wheel-dir /wheels .

FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OUTPUT_DIR=/data \
    SYSLOG_HOST=0.0.0.0 \
    SYSLOG_PORT=5514

RUN addgroup -S -g 10001 pbp-monitor \
    && adduser -S -D -H -u 10001 -G pbp-monitor pbp-monitor \
    && install -d -o pbp-monitor -g pbp-monitor -m 0700 /app /data /config

WORKDIR /app
COPY --from=builder /wheels /wheels

RUN pip install --no-cache-dir --no-index --find-links /wheels panos-pbp-monitoring \
    && rm -rf /wheels

LABEL org.opencontainers.image.title="PAN-OS PBP Monitoring" \
      org.opencontainers.image.version="0.19.1" \
      org.opencontainers.image.description="Event-driven PAN-OS packet-buffer diagnostic collector" \
      org.opencontainers.image.source="https://github.com/tbortolossi/panos-pbp-monitoring" \
      org.opencontainers.image.licenses="LicenseRef-Proprietary"

USER 10001:10001

EXPOSE 5514/udp 8080/tcp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import pathlib,sys; sys.exit(0 if b'pbp-orchestrator' in pathlib.Path('/proc/1/cmdline').read_bytes() else 1)"

CMD ["pbp-orchestrator", "--env-file", "/dev/null"]
