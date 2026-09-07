FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy common library and service requirements
COPY common /app/common
COPY services/api_gateway/requirements.txt /app/requirements.txt

# Install python dependencies
RUN pip install --no-cache-dir -e /app/common && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy service source code
COPY services/api_gateway/src /app/src

EXPOSE 8080

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
