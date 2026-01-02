CAAGE

Configuration Assessment for Air-Gapped Environments

CAAGE (Configuration Assessment for Air-Gapped Environments) is an offline, self-hosted security configuration assessment tool for Palo Alto Networks NGFW configurations.
It evaluates firewall configuration XML files against best-practice and CIS-aligned controls without sending any data off the system.

🔒 Key Features

- Fully offline / air-gapped
- No data egress — all processing happens locally
- Open source & auditable
- Containerized for easy deployment
- Rule-level findings with expandable details
- Designed for regulated and classified environments

⚠️ Important Notice

This is not an official Palo Alto Networks best practice assessment tool. The supported solution is available in Strata Cloud Manager: https://www.paloaltonetworks.com/network-security/strata-cloud-manager

CAAGE provides guidance only. Results must be validated against your organization’s security requirements and controls.

🛑 Data Privacy & Offline Operation

CAAGE is designed for high-assurance environments:

No telemetry - No cloud dependencies - No outbound network calls - No external APIs

All files remain on the local system for the duration of analysis.

📦 Repository Structure
```graphql
panw-ngfw-bpa-airgap
└── panw-ngfw-bpa
    ├── app
    │   ├── assets
    │   │   ├── CAAGE.png
    │   │   ├── panw-logo.svg
    │   │   └── stig-shield.svg
    │   ├── controls
    │   │   ├── panw_policy.yaml
    │   │   └── registry.yaml
    │   ├── engine
    │   │   ├── checks.py
    │   │   ├── evaluator.py
    │   │   ├── loader.py
    │   │   └── registry.py
    │   ├── main.py
    │   └── templates
    │       └── index.html
    ├── Dockerfile
    ├── python-3.12-slim.tar
    ├── requirements.txt
    └── wheels
        ├── annotated_doc-0.0.4-py3-none-any.whl
        ├── annotated_types-0.7.0-py3-none-any.whl
        ├── anyio-4.12.0-py3-none-any.whl
        ├── click-8.3.1-py3-none-any.whl
        ├── fastapi-0.126.0-py3-none-any.whl
        ├── h11-0.16.0-py3-none-any.whl
        ├── idna-3.11-py3-none-any.whl
        ├── jinja2-3.1.6-py3-none-any.whl
        ├── lxml-6.0.2-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl
        ├── markupsafe-3.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
        ├── pydantic-2.12.5-py3-none-any.whl
        ├── pydantic_core-2.41.5-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
        ├── python_multipart-0.0.21-py3-none-any.whl
        ├── starlette-0.50.0-py3-none-any.whl
        ├── typing_extensions-4.15.0-py3-none-any.whl
        ├── typing_inspection-0.4.2-py3-none-any.whl
        └── uvicorn-0.38.0-py3-none-any.whl
```
🧱 Air-Gapped Build Overview

CAAGE supports fully offline container builds using:

- Pre-downloaded Python base image
- Local Python wheels
- No PyPI access
- No Debian repo access

🧰 Prerequisites (Target System)

Ubuntu 20.04+ / 22.04+ / 24.04+

Docker installed (docker.io or equivalent)

No internet access required

📁 Step 1 — Extract the Air-Gap Package
```bash
tar -xzf panw-ngfw-bpa-airgap.tar.gz
cd panw-ngfw-bpa
```
🐍 Step 2 — Load the Python Base Image (Offline)

The package includes a pre-downloaded Python base image.
```bash
sudo docker load < python-3.12-slim.tar
```

Verify:
```bash
sudo docker images | grep python
```
🔐 Step 3 — Create TLS Certificates (Outside the Container)

CAAGE expects certificates to be mounted at runtime, not baked into the image.
```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=caage.local"
```
🏗️ Step 4 — Build the Container Image (Offline)
```bash
sudo docker build \
  --no-cache \
  --network=none \
  -t caage:latest .
```

▶️ Step 5 — Run CAAGE with TLS Enabled
```bash
sudo docker run -d \
  --name caage \
  -p 8443:8443 \
  -v $(pwd)/certs:/certs:ro \
  caage:latest
```

Access the UI:
```bash

https://<host-ip>:8443
```
⏹️ Stopping the Container
```bash
sudo docker stop caage
sudo docker rm caage
```
