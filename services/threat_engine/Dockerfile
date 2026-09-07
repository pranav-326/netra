FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy common library and service requirements
COPY common /app/common
COPY services/threat_engine/requirements.txt /app/requirements.txt

# Install python dependencies
RUN pip install --no-cache-dir -e /app/common && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy service source code
COPY services/threat_engine/src /app/src

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "src.worker"]
