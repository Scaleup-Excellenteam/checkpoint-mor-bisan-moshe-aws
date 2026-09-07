# TSPO Secret Slice Chat: server + Web UI in one container.
# Build:  docker build -t tspo-chat .
# Run:    docker run --rm -p 8000:8000 -v tspo-data:/data --env-file .env tspo-chat
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CHAT_DATABASE=/data/chat.db \
    CHAT_LOG=/data/chat.log

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py client.py cli.py ./
COPY chat_system ./chat_system
COPY config ./config
COPY static ./static

RUN useradd --create-home --uid 10001 chat && mkdir -p /data && chown chat:chat /data
USER chat
VOLUME ["/data"]

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8000"]
