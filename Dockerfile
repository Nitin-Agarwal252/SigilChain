FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OQS_INSTALL_PATH=/usr/local \
    LD_LIBRARY_PATH=/usr/local/lib

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# liboqs-python is a Python wrapper and does not include the native liboqs
# shared library. Build the native library into the image so runtime does
# not need to download or compile dependencies.
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
       "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65" \
    && cmake --build /tmp/liboqs/build --parallel 4 \
    && cmake --install /tmp/liboqs/build \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

# Validator and console containers don't need a document-import engine.
FROM base AS app
COPY agent /app/agent
COPY crypto /app/crypto
COPY trace_console /app/trace_console
COPY validator /app/validator
COPY security /app/security
COPY watermark /app/watermark
COPY config.py /app/config.py
COPY scripts /app/scripts
COPY tests /app/tests
EXPOSE 8001 8002 8003 8501

# Only the sender CLI needs office/text conversion filters. Keep the larger
# LibreOffice layer out of the network-facing validators and trace console.
FROM base AS cli
RUN apt-get update \
    && apt-get install -y --no-install-recommends libreoffice-writer libreoffice-calc \
       libreoffice-impress fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
COPY agent /app/agent
COPY crypto /app/crypto
COPY trace_console /app/trace_console
COPY validator /app/validator
COPY security /app/security
COPY watermark /app/watermark
COPY config.py /app/config.py
COPY scripts /app/scripts
COPY tests /app/tests
EXPOSE 8001 8002 8003 8501
