FROM python:3.11-slim

WORKDIR /app

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:${PORT:-8080}"]
