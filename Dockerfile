FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-worker.txt .
RUN pip install --no-cache-dir -r requirements-worker.txt

COPY worker_entrypoint.py .

ENTRYPOINT ["python3", "worker_entrypoint.py"]
