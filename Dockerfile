FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY aegislab/ aegislab/
COPY policies/ policies/

RUN mkdir -p logs keys

EXPOSE 8000
CMD ["uvicorn", "aegislab.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
