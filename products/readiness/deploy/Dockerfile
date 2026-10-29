# Pinned by digest so a rebuild uses the same base; Dependabot proposes updates.
# Build from the repository root: docker build -f products/readiness/deploy/Dockerfile -t acxelin-readiness .
ARG BASE=python:3.13-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
FROM ${BASE}
# Apply distribution security updates even when the pinned base predates their publication.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home /scan scanner
COPY core /src/core
COPY products/readiness /src/readiness
RUN pip install --no-cache-dir /src/core "/src/readiness[crawler,aws]" && rm -rf /src && pip uninstall -y pip
# The console keeps its settings, certificates and token here; mount a volume to keep them.
RUN mkdir -p /data && chown scanner /data
ENV ACXELIN_READINESS_HOME=/data/console
VOLUME /data
USER scanner
WORKDIR /scan
ENTRYPOINT ["acxelin-readiness"]
CMD ["scan", "."]
