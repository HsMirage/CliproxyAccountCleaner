FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY CliproxyAccountCleaner.py /app/
COPY cliproxy_web_mode.py /app/
COPY config.example.json /app/config.json

RUN pip install --no-cache-dir requests aiohttp

EXPOSE 8765

CMD ["sh", "-c", "if [ -f /etc/secrets/config.json ]; then cp /etc/secrets/config.json /app/config.json; fi; exec python CliproxyAccountCleaner.py --host 0.0.0.0 --port ${PORT:-8765} --no-browser"]
