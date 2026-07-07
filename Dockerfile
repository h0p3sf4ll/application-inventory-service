FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY ado_mobile_scanner.py mobile_app_inventory_tracer.py ./
COPY appsec_scan_router ./appsec_scan_router
COPY application_inventory_service ./application_inventory_service
COPY mobile_scanner ./mobile_scanner

RUN python -m pip install . \
    && useradd --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /reports \
    && chown -R scanner:scanner /reports /app

USER scanner

VOLUME ["/reports"]
EXPOSE 48731

ENTRYPOINT ["application-inventory-service-container"]
CMD ["--help"]
