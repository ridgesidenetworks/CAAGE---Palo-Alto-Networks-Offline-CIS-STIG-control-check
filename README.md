CAAGE

Configuration Assessment for Air-Gapped Environments

CAAGE (Configuration Assessment for Air-Gapped Environments) is an offline, self-hosted security configuration assessment tool for Palo Alto Networks NGFW configurations.
It evaluates firewall configuration XML files against best-practice and CIS-aligned controls without sending any data off the system.

🔒 Key Features

Fully offline / air-gapped

No data egress — all processing happens locally

Open source & auditable

TLS-enabled UI

Containerized for easy deployment

Rule-level findings with expandable details

Designed for regulated and classified environments

⚠️ Important Notice

This is not an official Palo Alto Networks best practice assessment tool.
The supported solution is available in Strata Cloud Manager:
https://www.paloaltonetworks.com/network-security/strata-cloud-manager

CAAGE provides guidance only. Results must be validated against your organization’s security requirements and controls.

🛑 Data Privacy & Offline Operation

CAAGE is designed for high-assurance environments:

No telemetry

No cloud dependencies

No outbound network calls

No configuration uploads

No external APIs

All files remain on the local system for the duration of analysis.

📦 Repository Structure
```graphql
panw-ngfw-bpa/
├── app/                    # Application source code
│   ├── main.py             # FastAPI entry point
│   ├── engine/             # Evaluation logic
│   ├── controls/           # Control registry (YAML)
│   ├── templates/          # Jinja2 HTML UI
│   └── assets/             # Logos and static files
├── wheels/                 # Offline Python dependencies
├── certs/                  # TLS certificates (external mount)
├── Dockerfile              # Container build definition
├── requirements.txt        # Python dependencies
├── python-3.12-slim.tar    # Preloaded Python base image
└── README.md
```
🧱 Air-Gapped Build Overview

CAAGE supports fully offline container builds using:

Pre-downloaded Python base image

Local Python wheels

No PyPI access

No Debian repo access

This is suitable for:

Classified networks

Restricted environments

Customer-managed security enclaves

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

This build:

Uses local wheels only

Makes zero external network calls

Is fully deterministic

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
