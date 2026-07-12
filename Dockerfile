FROM python:3.12-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY config/ config/
COPY core/ core/
COPY scanner/ scanner/
COPY reports/ reports/
COPY cli/ cli/
COPY web/ web/
COPY tests/ tests/

RUN pip install --no-cache-dir -e .[dev]

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

RUN mkdir -p /tmp/apk-analyzer/{uploads,reports,temp}

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV APK_UPLOAD_DIR=/tmp/apk-analyzer/uploads
ENV APK_OUTPUT_DIR=/tmp/apk-analyzer/reports
ENV APK_TEMP_DIR=/tmp/apk-analyzer/temp

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/docs')" || exit 1

ENTRYPOINT ["dexray"]

CMD ["--help"]
