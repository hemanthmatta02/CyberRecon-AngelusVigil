FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY . .

RUN python -m pip install --upgrade pip \
    && python -m pip install .

EXPOSE 8000
CMD ["python", "-m", "app"]
