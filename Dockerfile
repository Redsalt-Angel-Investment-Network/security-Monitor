# One image for both the collector and the web checker.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ collector/
COPY agent/ agent/

# Never run as root: if the app is ever compromised, the attacker gets an
# unprivileged user, not the container's root.
RUN useradd --create-home --uid 10001 monitor \
    && mkdir -p /app/data \
    && chown monitor /app/data
USER monitor

EXPOSE 8000
CMD ["uvicorn", "collector.main:app", "--host", "0.0.0.0", "--port", "8000"]
