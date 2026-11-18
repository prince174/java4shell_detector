FROM golang:1.26-alpine AS crane
ARG GOPROXY
ARG GOSUMDB
RUN --mount=type=bind,source=certs,target=/run/corporate-ca \
    for cert in /run/corporate-ca/*.crt; do \
        if [ -f "$cert" ]; then cp "$cert" /usr/local/share/ca-certificates/ || exit 1; fi; \
    done && update-ca-certificates
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/google/go-containerregistry/cmd/crane@v0.22.1

FROM python:3.13-slim
RUN --mount=type=bind,source=certs,target=/run/corporate-ca \
    for cert in /run/corporate-ca/*.crt; do \
        if [ -f "$cert" ]; then cp "$cert" /usr/local/share/ca-certificates/ || exit 1; fi; \
    done && update-ca-certificates
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 INVENTORY_REPORT_DIR=/reports
RUN apt-get update && apt-get install -y --no-install-recommends git zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && groupadd --gid 10001 detector \
    && useradd --uid 10001 --gid detector --create-home detector \
    && install -d -o detector -g detector /reports
WORKDIR /app
COPY --from=crane /out/crane /usr/local/bin/crane
COPY inventory_common.py bitbucket_inventory.py nexus_inventory.py web_app.py index.html ./
COPY docs/architecture.html docs/
EXPOSE 8080
USER 10001:10001
CMD ["python", "web_app.py", "--host", "0.0.0.0"]
