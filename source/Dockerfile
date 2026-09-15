# ============================
# Base image
# ============================
FROM python:3.12-slim

# ============================
# Runtime environment settings
# ============================
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/caage/.local/bin:${PATH}"

# ============================
# Create a standard non-privileged user
# Using 10001 is a common convention to avoid overlap with host users.
# Not a system account (no -r): useradd reserves system UIDs for 100-999, and
# passing -r alongside -u 10001 makes it warn that the two disagree. 10001 is
# above UID_MIN (1000), so a regular account is the correct classification.
# ============================
RUN groupadd -g 10001 caage && \
    useradd -u 10001 -g caage -m -s /sbin/nologin caage

# ============================
# Working directory (set to home for permission safety)
# ============================
WORKDIR /home/caage/app

# ============================
# Install Python dependencies
# ============================
COPY --chown=caage:caage requirements.txt /tmp/requirements.txt
COPY --chown=caage:caage wheels /tmp/wheels

# Install as the user to ~/.local/bin
USER caage
RUN pip install --no-cache-dir --no-index --user \
    --find-links=/tmp/wheels -r /tmp/requirements.txt

# ============================
# Copy application source
# ============================
COPY --chown=caage:caage app /home/caage/app

# ============================
# Expose HTTPS port
# ============================
EXPOSE 8443

# ============================
# Container health check (TLS endpoint, self-signed cert => -k)
# ============================
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',8443),3); s.close()"]

# ============================
# Start CAAGE with TLS
# ============================
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile", "/certs/server.key", \
     "--ssl-certfile", "/certs/server.crt"]
