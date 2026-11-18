FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src

# pyproject.toml is the single source of truth for dependencies. The BuildKit
# cache mount keeps rebuilds fast without baking a pip cache into the image.
COPY pyproject.toml README.md ./
COPY app ./app
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && pip install .

RUN useradd --create-home --uid 10001 appuser
USER appuser
# The package lives in site-packages, so the working directory is incidental.
# Use the home dir rather than /app so nothing can shadow the `app` package.
WORKDIR /home/appuser

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
