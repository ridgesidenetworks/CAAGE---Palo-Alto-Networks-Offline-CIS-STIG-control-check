<p align="center">
  <img src="CAAGE.png" alt="CAAGE" width="300" />
</p>

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

CAAGE provides guidance only. Results must be validated against your organization’s security requirements and controls.  CAAGE can make mistakes and thus proper verification should take place.

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
    │   │   └── stig-shield.svg
    │   ├── controls
    │   │   ├── panw_policy.yaml
    │   │   └── registry.yaml
    │   ├── engine
    │   │   ├── checks.py
    │   │   ├── evaluator.py
    │   │   ├── loader.py
    │   │   └── registry.py
    │   ├── templates
    │   │   └── index.html
    │   └── main.py
    ├── Dockerfile
    ├── python-3.12-slim.tar
    ├── requirements.txt
    └── wheels
        ├── annotated_doc-0.0.4-py3-none-any.whl
        ├── annotated_types-0.7.0-py3-none-any.whl
        ├── anyio-4.13.0-py3-none-any.whl
        ├── click-8.3.2-py3-none-any.whl
        ├── fastapi-0.136.0-py3-none-any.whl
        ├── h11-0.16.0-py3-none-any.whl
        ├── idna-3.12-py3-none-any.whl
        ├── jinja2-3.1.6-py3-none-any.whl
        ├── lxml-6.1.0-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl
        ├── markupsafe-3.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
        ├── pydantic-2.13.3-py3-none-any.whl
        ├── pydantic_core-2.46.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
        ├── python_multipart-0.0.26-py3-none-any.whl
        ├── starlette-1.0.0-py3-none-any.whl
        ├── typing_extensions-4.15.0-py3-none-any.whl
        ├── typing_inspection-0.4.2-py3-none-any.whl
        └── uvicorn-0.45.0-py3-none-any.whl
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

Step 1 - Download tar.gz package from the release page here: 
```text
https://github.com/ridgesidenetworks/CAAGE---Palo-Alto-Networks-Offline-CIS-STIG-control-check/releases/download/v1.2/caage.tar.gz
```

To download directly onto a linux host use the following
```bash
wget https://github.com/ridgesidenetworks/CAAGE---Palo-Alto-Networks-Offline-CIS-STIG-control-check/releases/download/V1.1/caage.tar.gz
```

📁 Step 2 — Extract the Air-Gap Package
```bash
tar -xzf caage.tar.gz
cd caage
```
🐍 Step 3 — Load the Python Base Image (Offline)

The package includes a pre-downloaded Python base image.
```bash
sudo docker load < python-3.12-slim.tar
```

Verify:
```bash
sudo docker images | grep python
```
🔐 Step 4 — Create TLS Certificates (Outside the Container)

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
🏗️ Step 5 — Adjust certificate permisions so container user can read them (UID/GID 10001)
```bash
# Change the group to match the container's internal ID
sudo chgrp -R 10001 certs/

# Secure the directory and key file
sudo chmod 750 certs/             # Allows container to enter the directory
sudo chmod 640 certs/server.key   # Allows container to read the key
sudo chmod 644 certs/server.crt   # Standard read access for the cert
```

🏗️ Step 5 — Build the Container Image (Offline)
```bash
sudo docker build \
  --no-cache \
  --network=none \
  -t caage:latest .
```

▶️ Step 6 — Run CAAGE with TLS Enabled
```bash
sudo docker run -d \
  --name caage \
  -p 8443:8443 \
  -v $(pwd)/certs:/certs:ro \
  caage:latest
```
Note! If you get errors its likely that the container cannot mount your certs directory.  The below will run the container as your current user which likely made the cert files.
***ONLY RUN THIS IF THE ABOVE DOCKER RUN FAILED***
```bash
sudo docker run -d \
  --name caage \
  --user $(id -u):$(id -g) \
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



==========FAQ========
```text
Q:  Why are you making me build the container, why can't you put it in a container repo like a normal person.
A:  Building the container image yourself provides users the ability to scan and review all the components of the container prior to build.
    This was done on purpose for high security environments.  Everything is transparent.

Q: Whats with all the cert permision commands, I don't normally do this when I run a container
A: For security reasons the container does not run as root so we have to be explicit about permisions, your other containers probably run as root and they should feel bad

Q: Why do I have to make my own cert?
A: Shipping pre-made private keys exposed is not ideal, you can generate your own self signed certs as per the intructions or
   bring in your own trusted keys.

Q: One of my checks is not working!
A: This tool is built as an opensource best effort tool to help the community.  Feel free to reach out to me and I can see if I can resolve the issue and provide an update.
Source code is also available and you can add/modify any checks you want.
```
