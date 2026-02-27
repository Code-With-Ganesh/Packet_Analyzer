# ============================================
# DPI Engine — Docker Multi-stage Build
# ============================================
# Stage 1: Compile C++ DPI Engine
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY include/ include/
COPY src/ src/

RUN g++ -std=c++17 -O2 -I include \
    -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp

# ============================================
# Stage 2: Production Image
FROM python:3.12-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy C++ binary from builder
COPY --from=builder /app/dpi_engine ./dpi_engine
RUN chmod +x dpi_engine

# Copy application files
COPY server.py .
COPY dashboard.py .
COPY rules.json .
COPY templates/ templates/
COPY include/*.pcap include/

# Create directories
RUN mkdir -p static include

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/')" || exit 1

# Run the server
ENV FLASK_ENV=production
CMD ["python", "server.py"]
