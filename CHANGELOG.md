# Changelog

## v1.3 — 2026-09-15

Security and dependency refresh. **No changes to control logic** — all 106
checks evaluate identically to v1.2 (verified by byte-for-byte comparison of
full reports across 1k, 5k and 20k rule configurations).

### Fixed

- **Outbound requests from the UI.** FastAPI's `/docs` and `/redoc` routes were
  enabled by default. Both serve pages that instruct the browser to fetch
  assets from `cdn.jsdelivr.net`, `fastapi.tiangolo.com` and
  `fonts.googleapis.com`. On an offline-only tool this could generate egress
  from the analyst's workstation. All three routes (`/docs`, `/redoc`,
  `/openapi.json`) are now disabled.
- **Unbounded upload buffering.** The upload size cap was enforced from the
  `Content-Length` header, which is absent on chunked requests, so an
  oversized chunked upload was fully buffered into memory before rejection.
  Uploads are now read in bounded chunks and abort at the cap. Measured peak
  RSS for a 41 MB chunked upload dropped from +38 MB to +5.4 MB.
- **Non-reproducible reports.** `check_default_policy_logging` iterated a set
  literal, so finding order varied with Python's per-process hash seed and the
  same configuration could produce differently-ordered reports between runs.
  Reports are now deterministic.

### Changed

- Version is single-sourced from the `VERSION` file rather than hardcoded in
  the page template.
- `README.md`, `LICENSE`, `VERSION` and `CHANGELOG.md` now ship inside the
  release tarball, so the operator deploying inside the enclave has the
  documentation and licence without needing to reach GitHub.
- `requirements.txt` now pins transitive dependencies as well as direct ones,
  so the offline build resolves nothing implicitly.
- Dropped `-r` from the `useradd` call in the Dockerfile. It requested a system
  account while `-u 10001` asked for a UID outside the system range (100-999),
  so every build emitted `useradd warning: caage's uid 10001 is greater than
  SYS_UID_MAX 999`. The resulting account is unchanged -- same UID, GID, home
  directory and shell -- the build log is simply clean now.

### Dependencies

| Package | v1.2 | v1.3 |
|---|---|---|
| fastapi | 0.137.1 | 0.141.1 |
| starlette | 1.3.1 | 1.6.0 |
| uvicorn | 0.38.0 | 0.53.0 |
| lxml | 6.1.1 | 6.1.3 |
| pydantic | 2.12.5 | 2.13.5 |
| pydantic-core | 2.41.5 | 2.46.5 |
| anyio | 4.14.0 | 4.15.1 |
| click | 8.4.1 | 8.5.0 |
| idna | 3.18 | 3.19 |
| typing-extensions | 4.15.0 | 4.16.0 |
| typing-inspection | 0.4.2 | 0.4.4 |
| annotated-types | 0.7.0 | 0.8.0 |
| annotated-doc | 0.0.4 | 0.0.5 |
| jinja2, markupsafe, h11, python-multipart | unchanged | unchanged |

### Base image

Refreshed `python:3.12-slim` from 2026-06-11 to 2026-09-01
(Python 3.12.13 -> 3.12.14). Multi-arch index digest:

    sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

14 Debian packages upgraded, no packages added or removed:

| Package | v1.2 | v1.3 |
|---|---|---|
| openssl, openssl-provider-legacy, libssl3t64 | 3.5.6-1~deb13u2 | 3.5.7-1~deb13u2 |
| util-linux, mount, bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1, liblastlog2-2 | 2.41-5 | 2.41.5-0+deb13u1 |
| login | 1:4.16.0-2+really2.41-5 | 1:4.16.0-2+really2.41.5-0+deb13u1 |
| liblzma5 | 5.8.1-1 | 5.8.1-1+deb13u1 |
| base-files | 13.8+deb13u5 | 13.8+deb13u6 |

## v1.2

Added 20 checks. Updated wheels packages.
