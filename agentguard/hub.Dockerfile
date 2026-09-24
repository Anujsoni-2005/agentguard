FROM python:3.11-slim

WORKDIR /app

# Pre-install hub dependencies (no mitmproxy/docker SDK) at build time
COPY requirements-hub.txt /tmp/requirements-hub.txt
RUN pip install --no-cache-dir -r /tmp/requirements-hub.txt

# Copy source and install package in editable mode (just links, no re-resolve)
COPY . /app
RUN pip install --no-cache-dir --no-deps -e /app

ENV PYTHONPATH=/app/src

CMD ["python", "-m", "uvicorn", "agentguard.hub.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
