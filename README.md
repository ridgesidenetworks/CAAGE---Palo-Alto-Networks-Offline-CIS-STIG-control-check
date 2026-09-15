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

You do not have to take that on trust. To confirm it yourself:
```bash
# CAAGE serves normally with no network attached at all.
sudo docker run --rm -d --name caage-audit --network none \
  -v $(pwd)/certs:/certs:ro caage:latest
```
Or watch for traffic while running a real assessment:
```bash
sudo tcpdump -i docker0 -n 'not host 127.0.0.1' -c 50
```
No outbound packets should be observed. The application imports no HTTP client
library, the XML parser runs with entity resolution and network access disabled
so a malicious configuration file cannot trigger a callout, and the UI loads no
external scripts, fonts or stylesheets.

📦 Package Structure

The release tarball extracts to `caage/`:
```text
caage
├── README.md              deployment guide (this file, shipped offline too)
├── CHANGELOG.md           what changed in this release
├── LICENSE                Apache-2.0
├── VERSION                bundle version
├── Dockerfile
├── requirements.txt       all 17 dependencies pinned, direct and transitive
├── python-3.12-slim.tar   pre-downloaded base image
├── wheels/                all Python dependencies as wheels
└── app
    ├── main.py
    ├── engine/            checks.py, evaluator.py, registry.py
    ├── templates/         index.html
    └── assets/            CAAGE.png, stig-shield.svg
```
The `source/` directory in this repository mirrors the application code in the
current release, so you can review it here before downloading anything.

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

📥 Step 1 — Download the Package

This URL always resolves to the most recent release:
```text
https://github.com/ridgesidenetworks/CAAGE---Palo-Alto-Networks-Offline-CIS-STIG-control-check/releases/latest/download/caage.tar.gz
```

To download directly onto a linux host, along with its checksum file:
```bash
wget https://github.com/ridgesidenetworks/CAAGE---Palo-Alto-Networks-Offline-CIS-STIG-control-check/releases/latest/download/caage.tar.gz
wget https://github.com/ridgesidenetworks/CAAGE---Palo-Alto-Networks-Offline-CIS-STIG-control-check/releases/latest/download/SHA256SUMS
```

🔎 Step 1a — Verify Before It Crosses the Air Gap

Do this on the internet-connected host, **before** transferring:
```bash
sha256sum -c SHA256SUMS
```
Expect `caage.tar.gz: OK`. If it does not match, stop — do not carry the file
across. The expected digest is also printed in the release notes, so you can
confirm it from a second source.

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
Replace `10.0.0.50` below with the IP address or DNS name you will actually
browse to:
```bash
mkdir certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=caage.local" \
  -addext "subjectAltName=DNS:caage.local,IP:10.0.0.50"
```
> ⚠️ The `-addext subjectAltName` line is required. Chrome, Edge and Firefox
> reject certificates that carry only a Common Name, and will refuse to connect
> with `ERR_CERT_COMMON_NAME_INVALID`. You will still see the usual
> self-signed warning, which is expected.

🔑 Step 5 — Adjust certificate permisions so container user can read them (UID/GID 10001)
```bash
# Change the group to match the container's internal ID
sudo chgrp -R 10001 certs/

# Secure the directory and key file
sudo chmod 750 certs/             # Allows container to enter the directory
sudo chmod 640 certs/server.key   # Allows container to read the key
sudo chmod 644 certs/server.crt   # Standard read access for the cert
```

🏗️ Step 6 — Build the Container Image (Offline)
```bash
sudo docker build \
  --no-cache \
  --network=none \
  -t caage:latest .
```

▶️ Step 7 — Run CAAGE with TLS Enabled
```bash
sudo docker run -d \
  --name caage \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  -p 8443:8443 \
  -v $(pwd)/certs:/certs:ro \
  caage:latest
```
To restrict access to the local host only, use `-p 127.0.0.1:8443:8443`.

Note! If you get errors its likely that the container cannot mount your certs directory.  The below will run the container as your current user which likely made the cert files.
***ONLY RUN THIS IF THE ABOVE DOCKER RUN FAILED***

> ⚠️ Run this from your normal user shell, never from a root shell. `$(id -u)`
> is expanded by your shell before `sudo` runs, so from a root prompt it becomes
> `--user 0:0` and the container runs as root, defeating the non-root design.
> Fixing the Step 5 permissions is always the better answer.
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
