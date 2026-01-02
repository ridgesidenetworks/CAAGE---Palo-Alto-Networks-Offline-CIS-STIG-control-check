from lxml import etree
from engine.registry import CONTROL_REGISTRY

SECURITY_RULE_XPATH = (
    "/config/devices/entry/vsys/entry"
    "/rulebase/security/rules/entry"
)

def evaluate_controls(xml_bytes: bytes):
    """
    Core evaluation engine:
    - Parses XML
    - Extracts security rules once
    - Runs each control check
    - Returns UI-ready control objects
    """

    xml_root = etree.XML(xml_bytes)

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

        try:
            findings = check_fn(xml_root, rules)
        except TypeError as e:
            raise RuntimeError(
                f"Check function signature mismatch for {control['id']}: {e}"
            )

        # Normalize findings
        findings = findings or []
        if control["id"] in ha_control_ids and not ha_enabled:
            findings = [{
                "setting": "high-availability",
                "expected": "enabled",
                "actual": "not enabled",
                "severity": "na",
                "reason": "High availability is not enabled.",
            }]

        if control.get("manual"):
            status = "manual"
        else:
            if len(findings) == 0:
                status = "pass"
            else:
                severities = [f.get("severity") for f in findings]
                if any(sev == "na" for sev in severities):
                    status = "na"
                elif any(sev == "fail" or sev is None for sev in severities):
                    status = "fail"
                elif any(sev == "warn" for sev in severities):
                    status = "warn"
                else:
                    status = "fail"

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
        result["frameworks"] = frameworks
        if result.get("stig_level") is None and "STIG" in frameworks:
            result["stig_level"] = severity_map.get(result.get("severity"))

    return results
