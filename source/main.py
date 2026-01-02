from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from lxml import etree

from engine.evaluator import evaluate_controls
from engine.checks import _profile_groups, _rule_profile_name

SECURITY_RULE_XPATH = (
    "/config/devices/entry/vsys/entry"
    "/rulebase/security/rules/entry"
)

app = FastAPI()
app.mount("/assets", StaticFiles(directory="assets"), name="assets")
templates = Jinja2Templates(directory="templates")


def summarize(controls):
    summary = {"pass": 0, "fail": 0, "na": 0}
    for c in controls:
        if c["status"] == "pass":
            summary["pass"] += 1
        elif c["status"] == "fail":
            summary["fail"] += 1
        else:
            summary["na"] += 1
    return summary


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


def compute_policy_coverage(xml_bytes: bytes):
    xml_root = etree.XML(xml_bytes)
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
    # IMPORTANT: always pass empty defaults
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "controls": [],
            "grouped_controls": [],
            "summary": None,
            "coverage": None,
        },
    )


@app.post("/assess", response_class=HTMLResponse)
async def assess(request: Request, file: UploadFile = File(...)):
    xml_bytes = await file.read()

    controls = evaluate_controls(xml_bytes)
    summary = summarize(controls)
    grouped_controls = group_controls(controls)
    coverage = compute_policy_coverage(xml_bytes)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "controls": controls,
            "grouped_controls": grouped_controls,
            "summary": summary,
            "coverage": coverage,
        },
    )
