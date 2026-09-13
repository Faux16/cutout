# One image, five services — the command in docker-compose.yml selects which app runs.
FROM python:3.11-slim

WORKDIR /app

# Install deps first for layer caching.
COPY pyproject.toml README.md ./
COPY cutout ./cutout
COPY cutout_range ./cutout_range
RUN pip install --no-cache-dir ".[range]"

# Default: print usage. Compose overrides `command:` per service.
CMD ["python", "-c", "print('set a service command, e.g. uvicorn cutout_range.service.servers.orchestrator:app')"]
