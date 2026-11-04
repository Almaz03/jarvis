# syntax=docker/dockerfile:1
# The same image runs the offline tests and the explicitly enabled live services.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN --mount=type=secret,id=proxy_ca,required=false \
    if [ -f /run/secrets/proxy_ca ]; then \
      PIP_CERT=/run/secrets/proxy_ca pip install --no-cache-dir -r /app/requirements.txt; \
    else \
      pip install --no-cache-dir -r /app/requirements.txt; \
    fi
COPY stand /app/stand
COPY tests /app/tests
COPY fixtures /app/fixtures
COPY slack-app-manifest.json /app/slack-app-manifest.json
RUN chmod -R a=rX /app/stand /app/tests /app/fixtures /app/slack-app-manifest.json
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
# No EXPOSE, credentials, package install, network client, or live transport.
CMD ["python", "-m", "stand", "demo"]
