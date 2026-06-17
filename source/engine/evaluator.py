from engine.registry import CONTROL_REGISTRY

SECURITY_RULE_XPATH = (
    "/config/devices/entry/vsys/entry"
    "/rulebase/security/rules/entry"
)

def compute_status(findings, *, manual=False, error=False):
    """Map a check's findings to a UI status.

    Empty findings means the control passed. A real failure (explicit "fail"
    or an un-tagged finding) always wins over "warn" or "na" so mixed results
    are never silently downgraded.
    """
    if error:
        return "error"
    if manual:
        return "manual"
    if not findings:
        return "pass"

    severities = [f.get("severity") for f in findings]
    if any(sev == "fail" or sev is None for sev in severities):
        return "fail"
    if any(sev == "warn" for sev in severities):
        return "warn"
    if any(sev == "na" for sev in severities):
        return "na"
    return "fail"


def evaluate_controls(xml_root):
    """
    Core evaluation engine:
    - Receives a parsed (and already-hardened) XML root
    - Extracts security rules once
    - Runs each control check, isolating per-check failures
    - Returns UI-ready control objects
    """

    # Extract all security rules once
    rules = xml_root.xpath(SECURITY_RULE_XPATH)
    allow_rules = [r for r in rules if r.findtext("./action") == "allow"]
    allow_count = len(allow_rules)
    ha_enabled = bool(xml_root.xpath(
        "/config/devices/entry/deviceconfig/high-availability/enabled[text()='yes'] | "
        "/config/devices/entry/deviceconfig/high-availability/enable[text()='yes'] | "
        "/config/devices/entry/deviceconfig/high-availability/group/enabled[text()='yes']"
    ))
    ha_control_ids = {"CIS-PA-3.1", "CIS-PA-3.2", "CIS-PA-3.3"}

    results = []

    for control in CONTROL_REGISTRY:
        check_fn = control["check"]

        # Isolate each check: one misbehaving check must not blank the whole
        # report. On any failure the control is surfaced with an "error" status
        # so the operator knows it could not be evaluated.
        check_error = None
        try:
            findings = check_fn(xml_root, rules) or []
        except Exception as e:  # noqa: BLE001 - intentional per-check isolation
            findings = []
            check_error = f"{type(e).__name__}: {e}"

        if control["id"] in ha_control_ids and not ha_enabled and check_error is None:
            findings = [{
                "setting": "high-availability",
                "expected": "enabled",
                "actual": "not enabled",
                "severity": "na",
                "reason": "High availability is not enabled.",
            }]

        if check_error is not None:
            findings = [{
                "setting": control["id"],
                "expected": "check to evaluate",
                "actual": "error",
                "severity": "error",
                "reason": f"This check could not be evaluated: {check_error}",
            }]

        status = compute_status(
            findings,
            manual=control.get("manual", False),
            error=check_error is not None,
        )

        results.append({
            "id": control["id"],
            "display_id": control.get("display_id", control["id"]),
            "title": control["title"],
            "category": control["category"],
            "severity": control["severity"],
            "framework": control.get("framework", "PANW"),
            "frameworks": control.get("frameworks"),
            "section": control.get("section", "Other"),
            "cis_level": control["cis_level"],
            "recommendation": control["recommendation"],
            "status": status,
            "findings": findings,
            "stig_ids": control.get("stig_ids", []),
            "stig_level": control.get("stig_level"),
            "cis_ids": control.get("cis_ids", []),
            "rule_count": allow_count,
            "scope": control.get("scope", "config"),
        })

    severity_map = {"Low": 1, "Medium": 2, "High": 3}

    for result in results:
        frameworks = result.get("frameworks")
        if not frameworks:
            frameworks = [result.get("framework", "PANW")]
        if result.get("stig_ids"):
            if "STIG" not in frameworks:
                frameworks.append("STIG")
        if result.get("cis_ids"):
            if "CIS" not in frameworks:
                frameworks.append("CIS")
        result["frameworks"] = frameworks
        if result.get("stig_level") is None and "STIG" in frameworks:
            result["stig_level"] = severity_map.get(result.get("severity"))

    return results
