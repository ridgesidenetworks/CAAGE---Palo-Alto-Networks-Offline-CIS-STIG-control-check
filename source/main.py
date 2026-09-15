import os

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from lxml import etree

from engine.evaluator import evaluate_controls, SECURITY_RULE_XPATH
from engine.checks import _profile_groups, _rule_profile_name

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024

# Resolve asset/template directories relative to this file so the app works
# regardless of the process working directory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _read_version():
    """Read the bundle version from the VERSION file shipped alongside the app.

    Single-sources the version so the git tag, the release tarball and the
    string rendered in the UI cannot drift apart.
    """
    for candidate in (
        os.path.join(BASE_DIR, "VERSION"),
        os.path.join(os.path.dirname(BASE_DIR), "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
            if value:
                return value
        except OSError:
            continue
    return "unknown"


VERSION = _read_version()

# The docs routes are disabled deliberately. FastAPI's Swagger UI and ReDoc
# pages load JS/CSS from cdn.jsdelivr.net, fastapi.tiangolo.com and
# fonts.googleapis.com, which would make an offline-only tool generate
# outbound requests from the analyst's browser. CAAGE has no API consumers --
# its only client is the form in index.html -- so the schema has no use here.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount(
    "/assets",
    StaticFiles(directory=os.path.join(BASE_DIR, "assets")),
    name="assets",
)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def render(request: Request, **context):
    """Render the index template with safe defaults for every context key."""
    defaults = {
        "request": request,
        "controls": [],
        "grouped_controls": [],
        "coverage": None,
        "upload_error": None,
        "version": VERSION,
    }
    defaults.update(context)
    # Starlette >=1.0 signature: request first, then template name, then context.
    return templates.TemplateResponse(request, "index.html", defaults)


def group_controls(controls):
    groups = {}
    manual_controls = []
    for control in controls:
        if control.get("status") == "manual":
            manual_controls.append(control)
            continue
        framework = control.get("framework", "PANW")
        section = control.get("section", "Other")
        groups.setdefault((framework, section), []).append(control)

    framework_order = {"PANW": 0, "CIS": 1, "STIG": 2}
    grouped = []
    for (framework, section), items in sorted(
        groups.items(),
        key=lambda x: (framework_order.get(x[0][0], 99), x[0][1]),
    ):
        grouped.append({
            "framework": framework,
            "section": section,
            "controls": sorted(items, key=lambda c: c.get("id", "")),
        })

    if manual_controls:
        grouped.append({
            "framework": "Manual",
            "section": "Manual Review Required",
            "controls": sorted(manual_controls, key=lambda c: c.get("id", "")),
            "manual": True,
        })

    return grouped


def validate_and_parse(xml_bytes: bytes):
    """Validate uploaded bytes and parse them with a hardened XML parser.

    Returns ``(xml_root, None)`` on success or ``(None, error_message)`` when
    the upload is rejected. Entity resolution and network access are disabled,
    and DOCTYPE/ENTITY declarations are refused outright to block XXE and
    entity-expansion ("billion laughs") attacks.
    """
    if len(xml_bytes) > MAX_UPLOAD_BYTES:
        return None, "File is too large for processing."

    if not xml_bytes.lstrip().startswith(b"<") or b"<config" not in xml_bytes:
        return None, "Uploaded file does not look like a PAN-OS XML config."

    if b"<!DOCTYPE" in xml_bytes.upper() or b"<!ENTITY" in xml_bytes.upper():
        return None, "XML with DOCTYPE or ENTITY declarations is not allowed."

    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        xml_root = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError:
        return None, "Invalid XML file. Please upload a PAN-OS config."

    return xml_root, None


async def read_capped(upload, limit: int):
    """Read an upload into memory, stopping as soon as it exceeds ``limit``.

    ``UploadFile.read()`` with no argument buffers the whole body regardless of
    size. A client that omits Content-Length (chunked transfer encoding) skips
    the header pre-check in ``assess``, so that unbounded read is reachable by
    an unauthenticated caller. Reading in bounded chunks caps the allocation at
    ``limit`` plus one chunk. Returns ``None`` when the upload is too large.
    """
    chunks = []
    total = 0
    while True:
        chunk = await upload.read(UPLOAD_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def compute_policy_coverage(xml_root):
    rules = xml_root.xpath(SECURITY_RULE_XPATH)
    allow_rules = [r for r in rules if r.findtext("./action") == "allow"]
    total = len(allow_rules)

    groups = _profile_groups(xml_root)
    counters = {
        "Anti-Virus": 0,
        "Anti-Spyware": 0,
        "Vulnerability": 0,
        "URL Filtering": 0,
        "WildFire": 0,
        "Log at End": 0,
    }

    for rule in allow_rules:
        if _rule_profile_name(rule, groups, "virus"):
            counters["Anti-Virus"] += 1
        if _rule_profile_name(rule, groups, "spyware"):
            counters["Anti-Spyware"] += 1
        if _rule_profile_name(rule, groups, "vulnerability"):
            counters["Vulnerability"] += 1
        if _rule_profile_name(rule, groups, "url-filtering"):
            counters["URL Filtering"] += 1
        if _rule_profile_name(rule, groups, "wildfire-analysis"):
            counters["WildFire"] += 1
        if rule.findtext("./log-end") == "yes":
            counters["Log at End"] += 1

    metrics = []
    for label, count in counters.items():
        percent = int(round((count / total) * 100)) if total else 0
        metrics.append({
            "label": label,
            "count": count,
            "total": total,
            "percent": percent,
        })

    return {
        "total_allow": total,
        "metrics": metrics,
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return render(request)


@app.post("/assess", response_class=HTMLResponse)
async def assess(request: Request, file: UploadFile = File(...)):
    # Reject oversized uploads before buffering the whole body into memory.
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                return render(request, upload_error="File is too large for processing.")
        except ValueError:
            pass

    if not file.filename:
        return render(
            request,
            upload_error="Please upload a PAN-OS XML configuration file.",
        )

    # Bounded read: the Content-Length pre-check above is absent on chunked
    # requests, so the cap has to be enforced while reading, not after.
    xml_bytes = await read_capped(file, MAX_UPLOAD_BYTES)
    if xml_bytes is None:
        return render(request, upload_error="File is too large for processing.")

    # Parse exactly once, with entity resolution and network access disabled,
    # then reuse this hardened root everywhere downstream.
    xml_root, error = validate_and_parse(xml_bytes)
    if error is not None:
        return render(request, upload_error=error)

    controls = evaluate_controls(xml_root)
    grouped_controls = group_controls(controls)
    coverage = compute_policy_coverage(xml_root)

    return render(
        request,
        controls=controls,
        grouped_controls=grouped_controls,
        coverage=coverage,
    )
