FROM python:3.12-slim

# nuclei is pinned to an exact release and verified against a hash pinned here, not against
# a checksum file fetched from the same host as the binary.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG TARGETARCH

# nmap provides service/version detection. curl and unzip exist only to fetch nuclei and are
# removed afterwards. Without these two binaries the adapters are unavailable and a scan
# silently degrades to version inference only.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends nmap ca-certificates curl unzip; \
    ARCH="${TARGETARCH:-amd64}"; \
    case "$ARCH" in \
      amd64) SHA="$NUCLEI_SHA256_AMD64" ;; \
      arm64) SHA="$NUCLEI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip"; \
    echo "${SHA}  /tmp/nuclei.zip" | sha256sum -c -; \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    rm /tmp/nuclei.zip; \
    apt-get purge -y --auto-remove curl unzip; \
    rm -rf /var/lib/apt/lists/*

# Scans run unprivileged. The connect scan (-sT) needs no raw-socket capability.
RUN useradd --create-home --uid 10001 cerberus
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=cerberus:cerberus . .
USER cerberus

# Templates are baked in at build time and auto-update is disabled at scan time, so an image
# corresponds to one fixed template set and a scan can be reproduced from the image alone.
RUN nuclei -update-templates -no-color

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
