# Local offline demo only. Build requires access to the base image registry.
FROM python:3.12-slim
WORKDIR /app
COPY stand /app/stand
COPY tests /app/tests
COPY fixtures /app/fixtures
RUN chmod -R a=rX /app/stand /app/tests /app/fixtures
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
# No EXPOSE, credentials, package install, network client, or live transport.
CMD ["python", "-m", "stand", "demo"]
