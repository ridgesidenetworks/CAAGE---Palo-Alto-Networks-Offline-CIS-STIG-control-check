from typing import List, Dict, Any
import ipaddress


def _rule_base(rule) -> Dict[str, Any]:
    """Common rule fields for UI rendering"""
    vsys_name = None
    current = rule
    while current is not None:
        if current.tag == "entry" and current.getparent() is not None:
            parent = current.getparent()
            if parent is not None and parent.tag == "vsys":
                vsys_name = current.get("name")
                break
        current = current.getparent()
    return {
        "name": rule.get("name"),
        "vsys": vsys_name,
        "from": [z.text for z in rule.findall("./from/member")],
        "to": [z.text for z in rule.findall("./to/member")],
        "application": [a.text for a in rule.findall("./application/member")],
        "service": [s.text for s in rule.findall("./service/member")],
        "action": rule.findtext("./action"),
    }

def _xpath_text(root, path: str):
    result = root.xpath(path)
    if not result:
        return None
    node = result[0]
    if isinstance(node, str):
        return node
    return node.text

def _xpath_exists(root, path: str) -> bool:
    return bool(root.xpath(path))

def _any_xpath_exists(root, paths) -> bool:
    return any(_xpath_exists(root, path) for path in paths)

def _first_xpath_text(root, paths):
    for path in paths:
        value = _xpath_text(root, path)
        if value is not None:
            return value
    return None

def _setting_finding(
    setting: str,
    expected: str,
    actual: str,
    severity: str | None = None,
    reason: str | None = None,
) -> Dict[str, Any]:
    if reason is None:
        reason = f"Expected {expected}; actual {actual if actual else 'not set'}."
    return {
        "setting": setting,
        "expected": expected,
        "actual": actual if actual is not None else "",
        "severity": severity,
        "reason": reason,
    }


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def check_manual(xml_root, rules):
    return []

def _password_complexity_enabled(xml_root) -> str:
    return _first_xpath_text(
        xml_root,
        [
            "/config/mgt-config/password-complexity/enabled",
            "/config/devices/entry/mgt-config/password-complexity/enabled",
        ],
    )

def _password_complexity_value(xml_root, field: str) -> str:
    return _first_xpath_text(
        xml_root,
        [
            f"/config/mgt-config/password-complexity/{field}",
            f"/config/devices/entry/mgt-config/password-complexity/{field}",
        ],
    )


# -------------------------------------------------------------------
# POLICY CONTROLS
# -------------------------------------------------------------------

def check_app_any(xml_root, rules):
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        apps = [a.text for a in rule.findall("./application/member")]
        if "any" in apps:
            rule_info = _rule_base(rule)
            rule_info["reason"] = "Application is set to any on an allow rule."
            failures.append(rule_info)

    return failures  # [] == PASS


def check_service_any(xml_root, rules):
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        services = [s.text for s in rule.findall("./service/member")]
        if "any" in services:
            rule_info = _rule_base(rule)
            rule_info["reason"] = "Service is set to any on an allow rule."
            failures.append(rule_info)

    return failures


def check_zone_any(xml_root, rules):
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        from_zones = [z.text for z in rule.findall("./from/member")]
        to_zones = [z.text for z in rule.findall("./to/member")]

        if "any" in from_zones or "any" in to_zones:
            rule_info = _rule_base(rule)
            rule_info["reason"] = "Source or destination zone is set to any."
            failures.append(rule_info)

    # 🔑 THIS IS THE FIX:
    # No failures == PASS, not None
    return failures


def check_log_end(xml_root, rules):
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        log_end = rule.findtext("./log-end")
        if log_end != "yes":
            rule_info = _rule_base(rule)
            rule_info["reason"] = "Log at session end is not enabled."
            failures.append(rule_info)

    return failures


# -------------------------------------------------------------------
# SECURITY PROFILE CONTROLS
# -------------------------------------------------------------------

def _profile_check(rules, profile_xpath, label):
    # Accept either direct profile assignment or profile-group mapping.
    # Profile groups live under /config/devices/entry/vsys/entry/profile-group.
    groups = _profile_groups(rules[0].getroottree().getroot()) if rules else {}
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        profile = rule.find(profile_xpath)
        rule_info = _rule_base(rule)

        if profile is None:
            # If a profile-group is used, treat it as compliant when it
            # supplies the required profile type.
            profile_type = profile_xpath.split("/")[-1]
            group_profile = _rule_profile_name(rule, groups, profile_type)
            if group_profile:
                rule_info["profile_status"] = {label: True}
                continue
            rule_info["profile_status"] = {label: False}
            rule_info["reason"] = f"{label} profile is not set."
            failures.append(rule_info)
        else:
            rule_info["profile_status"] = {label: True}

    return failures


def check_missing_av_profile(xml_root, rules):
    return _profile_check(
        rules,
        "./profile-setting/profiles/virus",
        "Anti-Virus",
    )


def check_missing_as_profile(xml_root, rules):
    return _profile_check(
        rules,
        "./profile-setting/profiles/spyware",
        "Anti-Spyware",
    )


def check_missing_vp_profile(xml_root, rules):
    return _profile_check(
        rules,
        "./profile-setting/profiles/vulnerability",
        "Vulnerability Protection",
    )


# -------------------------------------------------------------------
# DEVICE MANAGEMENT CONTROLS (CIS)
# -------------------------------------------------------------------

def check_mgmt_http_telnet_disabled(xml_root, rules):
    failures = []

    disable_http = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/service/disable-http"
    )
    disable_telnet = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/service/disable-telnet"
    )
    http_enabled = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/service/http"
    )
    telnet_enabled = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/service/telnet"
    )

    if http_enabled == "yes" or disable_http == "no":
        failures.append(_setting_finding(
            "deviceconfig/system/service/http",
            "not enabled",
            "http=yes" if http_enabled == "yes" else "disable-http=no",
        ))

    if telnet_enabled == "yes" or disable_telnet == "no":
        failures.append(_setting_finding(
            "deviceconfig/system/service/telnet",
            "not enabled",
            "telnet=yes" if telnet_enabled == "yes" else "disable-telnet=no",
        ))

    return failures


def check_mgmt_profile_http_telnet_disabled(xml_root, rules):
    failures = []

    profiles = xml_root.xpath(
        "/config/devices/entry/network/profiles/interface-management-profile/entry"
    )
    for profile in profiles:
        name = profile.get("name", "unknown")
        http_enabled = profile.findtext("./http") == "yes"
        telnet_enabled = profile.findtext("./telnet") == "yes"

        if http_enabled or telnet_enabled:
            details = []
            if http_enabled:
                details.append("http=yes")
            if telnet_enabled:
                details.append("telnet=yes")

            failures.append(_setting_finding(
                f"interface-management-profile {name}",
                "http=no, telnet=no",
                ", ".join(details),
            ))

    return failures


def check_mgmt_ssl_tls_certificate_set(xml_root, rules):
    profile_name = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/ssl-tls-service-profile",
            "/config/mgt-config/ssl-tls-service-profile",
        ],
    )

    if not profile_name:
        return [_setting_finding(
            "ssl-tls-service-profile",
            "set",
            "",
            reason=(
                "No SSL/TLS service profile is configured for the management interface. "
                "Also verify that the certificate is valid and trusted."
            ),
        )]

    profile = None
    profile_paths = [
        f"/config/shared/ssl-tls-service-profile/entry[@name='{profile_name}']",
        f"/config/devices/entry/ssl-tls-service-profile/entry[@name='{profile_name}']",
    ]
    for path in profile_paths:
        match = xml_root.xpath(path)
        if match:
            profile = match[0]
            break

    if profile is None:
        return [_setting_finding(
            "ssl-tls-service-profile",
            "valid profile",
            profile_name,
            reason=(
                "The SSL/TLS service profile referenced by management is missing. "
                "Also verify that the certificate is valid and trusted."
            ),
        )]

    cert_name = profile.findtext("./certificate")
    if not cert_name:
        return [_setting_finding(
            f"ssl-tls-service-profile {profile_name} certificate",
            "set",
            "",
            reason=(
                "No certificate is configured in the SSL/TLS service profile. "
                "Also verify that the certificate is valid and trusted."
            ),
        )]

    return []

def check_login_banner_dod(xml_root, rules):
    banner = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/login-banner",
            "/config/mgt-config/login-banner",
        ],
    )

    approved_long = (
        "You are accessing a U.S. Government (USG) Information System (IS) "
        "that is provided for USG-authorized use only. "
        "By using this IS (which includes any device attached to this IS), "
        "you consent to the following conditions: "
        "-The USG routinely intercepts and monitors communications on this IS "
        "for purposes including, but not limited to, penetration testing, "
        "COMSEC monitoring, network operations and defense, personnel "
        "misconduct (PM), law enforcement (LE), and counterintelligence (CI) "
        "investigations. -At any time, the USG may inspect and seize data "
        "stored on this IS. -Communications using, or data stored on, this IS "
        "are not private, are subject to routine monitoring, interception, "
        "and search, and may be disclosed or used for any USG-authorized "
        "purpose. -This IS includes security measures (e.g., authentication "
        "and access controls) to protect USG interests--not for your personal "
        "benefit or privacy. -Notwithstanding the above, using this IS does "
        "not constitute consent to PM, LE or CI investigative searching or "
        "monitoring of the content of privileged communications, or work "
        "product, related to personal representation or services by "
        "attorneys, psychotherapists, or clergy, and their assistants. Such "
        "communications and work product are private and confidential. See "
        "User Agreement for details."
    )
    approved_short = "I've read & consent to terms in IS user agreem't."
    approved_notice = (
        "Approved banner text (long): " + approved_long + " "
        "Approved banner text (short): " + approved_short
    )

    if not banner or not banner.strip():
        return [_setting_finding(
            "login-banner",
            "DoD-approved banner",
            "",
            reason=(
                "No banner is configured. "
                + approved_notice
            ),
        )]

    normalized = _normalize_whitespace(banner)
    allowed = {
        _normalize_whitespace(approved_long),
        _normalize_whitespace(approved_short),
    }

    if normalized not in allowed:
        return [_setting_finding(
            "login-banner",
            "DoD-approved banner",
            banner.strip(),
            severity="warn",
            reason=(
                "A banner is configured but does not exactly match the STIG "
                "approved text. " + approved_notice
            ),
        )]

    return []


def check_admin_lockout_failed_attempts_3(xml_root, rules):
    value = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/setting/management/"
            "admin-lockout/failed-attempts",
            "/config/mgt-config/admin-lockout/failed-attempts",
        ],
    )

    try:
        attempts = int(value) if value is not None else None
    except ValueError:
        attempts = None

    if attempts != 3:
        return [_setting_finding(
            "admin-lockout/failed-attempts",
            "3",
            value,
        )]

    return []


def check_only_one_local_admin(xml_root, rules):
    users = xml_root.xpath("/config/mgt-config/users/entry")

    local_users = []
    for user in users:
        if user.find("./phash") is None:
            continue
        if user.findtext("./disabled") == "yes":
            continue
        local_users.append(user.get("name", "unknown"))

    if len(local_users) > 1:
        return [_setting_finding(
            "local admin accounts",
            "1 account of last resort",
            f"{len(local_users)} accounts",
        )]

    return []


def _interface_entry_name(elem) -> str:
    current = elem
    while current is not None and current.tag != "entry":
        current = current.getparent()
    if current is None:
        return "unknown"
    return current.get("name") or "unknown"


def check_mgmt_interface_permitted_ips(xml_root, rules):
    entries = xml_root.xpath(
        "/config/devices/entry/deviceconfig/system/permitted-ip/entry"
    )
    ip_netmask = xml_root.xpath(
        "/config/devices/entry/deviceconfig/system/permitted-ip/ip-netmask"
    )

    if entries or ip_netmask:
        return []

    return [_setting_finding(
        "deviceconfig/system/permitted-ip",
        "configured",
        "not set",
    )]


def check_admin_profiles_on_dp_interfaces(xml_root, rules):
    findings = []

    profile_map = {
        entry.get("name"): entry
        for entry in xml_root.xpath(
            "/config/devices/entry/network/profiles/interface-management-profile/entry"
        )
        if entry.get("name")
    }

    profile_refs = []
    profile_refs.extend(xml_root.xpath(
        "/config/devices/entry/network/interface/ethernet"
        "//interface-management-profile"
    ))
    profile_refs.extend(xml_root.xpath(
        "/config/devices/entry/network/interface/aggregate-ethernet"
        "//interface-management-profile"
    ))
    profile_refs.extend(xml_root.xpath(
        "/config/devices/entry/network/interface/vlan"
        "//interface-management-profile"
    ))
    profile_refs.extend(xml_root.xpath(
        "/config/devices/entry/network/interface/loopback"
        "//interface-management-profile"
    ))
    profile_refs.extend(xml_root.xpath(
        "/config/devices/entry/network/interface/tunnel"
        "//interface-management-profile"
    ))

    if not profile_refs:
        return []

    for profile_ref in profile_refs:
        profile_name = (profile_ref.text or "").strip()
        if not profile_name:
            continue

        interface_name = _interface_entry_name(profile_ref)
        profile = profile_map.get(profile_name)
        if profile is None:
            continue

        http_enabled = profile.findtext("./http") == "yes"
        telnet_enabled = profile.findtext("./telnet") == "yes"
        https_enabled = profile.findtext("./https") == "yes"
        ssh_enabled = profile.findtext("./ssh") == "yes"

        if http_enabled or telnet_enabled:
            details = []
            if http_enabled:
                details.append("http=yes")
            if telnet_enabled:
                details.append("telnet=yes")
            findings.append(_setting_finding(
                f"interface {interface_name}",
                "http/telnet disabled",
                f"{profile_name} ({', '.join(details)})",
                "fail",
            ))
        elif https_enabled or ssh_enabled:
            details = []
            if https_enabled:
                details.append("https=yes")
            if ssh_enabled:
                details.append("ssh=yes")
            findings.append(_setting_finding(
                f"interface {interface_name}",
                "no management profile",
                f"{profile_name} ({', '.join(details)})",
                "warn",
            ))

    return findings


# -------------------------------------------------------------------
# PASSWORD CONTROLS (CIS)
# -------------------------------------------------------------------

def check_password_complexity_enabled(xml_root, rules):
    enabled = _password_complexity_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "mgt-config/password-complexity/enabled",
            "yes",
            enabled,
        )]
    return []


def check_password_min_length_12(xml_root, rules):
    enabled = _password_complexity_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "mgt-config/password-complexity/enabled",
            "yes",
            enabled,
        )]

    min_length = _password_complexity_value(xml_root, "minimum-length")
    try:
        value = int(min_length) if min_length is not None else None
    except ValueError:
        value = None

    if value is None or value < 12:
        return [_setting_finding(
            "mgt-config/password-complexity/minimum-length",
            ">=12",
            min_length,
        )]

    return []


def check_password_min_length_15(xml_root, rules):
    enabled = _password_complexity_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "mgt-config/password-complexity/enabled",
            "yes",
            enabled,
        )]

    min_length = _password_complexity_value(xml_root, "minimum-length")
    try:
        value = int(min_length) if min_length is not None else None
    except ValueError:
        value = None

    if value is None or value < 15:
        return [_setting_finding(
            "mgt-config/password-complexity/minimum-length",
            ">=15",
            min_length,
        )]

    return []


def _password_min_value_check(xml_root, field: str, minimum: int, label: str):
    enabled = _password_complexity_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "mgt-config/password-complexity/enabled",
            "yes",
            enabled,
        )]

    value_text = _password_complexity_value(xml_root, field)
    try:
        value = int(value_text) if value_text is not None else None
    except ValueError:
        value = None

    if value is None or value < minimum:
        return [_setting_finding(
            f"mgt-config/password-complexity/{field}",
            f">={minimum}",
            value_text,
        )]

    return []


def _password_max_value_check(xml_root, field: str, maximum: int, label: str):
    enabled = _password_complexity_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "mgt-config/password-complexity/enabled",
            "yes",
            enabled,
        )]

    value_text = _password_complexity_value(xml_root, field)
    try:
        value = int(value_text) if value_text is not None else None
    except ValueError:
        value = None

    if value is None or value > maximum:
        return [_setting_finding(
            f"mgt-config/password-complexity/{field}",
            f"<={maximum}",
            value_text,
        )]

    return []


def _profile_groups(xml_root):
    groups = {}
    for group in xml_root.xpath(
        "/config/devices/entry/vsys/entry/profile-group/entry"
    ):
        name = group.get("name")
        if not name:
            continue
        groups[name] = {
            "virus": group.findtext("./virus/member"),
            "spyware": group.findtext("./spyware/member"),
            "vulnerability": group.findtext("./vulnerability/member"),
            "url-filtering": group.findtext("./url-filtering/member"),
            "data-filtering": group.findtext("./data-filtering/member"),
            "wildfire-analysis": group.findtext("./wildfire-analysis/member"),
        }
    return groups


def _rule_profile_name(rule, groups, profile_type):
    profile = rule.findtext(f"./profile-setting/profiles/{profile_type}/member")
    if profile:
        return profile

    group_name = rule.findtext("./profile-setting/group/member")
    if group_name:
        return groups.get(group_name, {}).get(profile_type)

    return None


def _action_value(action_elem):
    if action_elem is None:
        return ""
    if len(action_elem) > 0:
        return action_elem[0].tag
    return action_elem.text or ""


def _profile_entries(xml_root, profile_type):
    entries = []
    entries.extend(xml_root.xpath(
        f"/config/devices/entry/vsys/entry/profiles/{profile_type}/entry"
    ))
    entries.extend(xml_root.xpath(
        f"/config/shared/profiles/{profile_type}/entry"
    ))
    return entries


def _profile_entry_map(xml_root, profile_type):
    return {
        entry.get("name"): entry for entry in _profile_entries(xml_root, profile_type)
        if entry.get("name")
    }


def _auth_profile_map(xml_root):
    profiles = []
    profile_paths = [
        "/config/devices/entry/deviceconfig/system/authentication-profile/entry",
        "/config/shared/authentication-profile/entry",
        "/config/devices/entry/authentication-profile/entry",
    ]
    for path in profile_paths:
        profiles.extend(xml_root.xpath(path))
    return {p.get("name"): p for p in profiles if p.get("name")}

def _zone_entries(xml_root):
    return xml_root.xpath("/config/devices/entry/vsys/entry/zone/entry")


def _zone_protection_profile_map(xml_root):
    profiles = xml_root.xpath(
        "/config/devices/entry/network/profiles/zone-protection-profile/entry"
    )
    return {p.get("name"): p for p in profiles if p.get("name")}


def _untrusted_zones(xml_root):
    zones = []
    for zone in _zone_entries(xml_root):
        # Treat layer3/tap zones as untrusted candidates.
        network = zone.find("./network")
        if network is None:
            continue
        if network.find("./layer3") is not None or network.find("./tap") is not None:
            zones.append(zone)
    return zones


def check_password_min_uppercase_1(xml_root, rules):
    return _password_min_value_check(
        xml_root, "minimum-uppercase-letters", 1, "Minimum Uppercase Letters"
    )


def check_password_min_lowercase_1(xml_root, rules):
    return _password_min_value_check(
        xml_root, "minimum-lowercase-letters", 1, "Minimum Lowercase Letters"
    )


def check_password_min_numeric_1(xml_root, rules):
    return _password_min_value_check(
        xml_root, "minimum-numeric-letters", 1, "Minimum Numeric Letters"
    )


def check_password_min_special_1(xml_root, rules):
    return _password_min_value_check(
        xml_root, "minimum-special-characters", 1, "Minimum Special Characters"
    )


def check_password_change_period_max_90(xml_root, rules):
    value_text = _first_xpath_text(
        xml_root,
        [
            "/config/mgt-config/password-change/expiration-period",
            "/config/devices/entry/deviceconfig/system/password-change/expiration-period",
            "//password-change/expiration-period",
        ],
    )
    try:
        value = int(value_text) if value_text is not None else None
    except ValueError:
        value = None

    if value is None or value > 90:
        return [_setting_finding(
            "password-change/expiration-period",
            "<=90",
            value_text,
        )]

    return []


def check_password_differs_3(xml_root, rules):
    return _password_min_value_check(
        xml_root, "new-password-differs-by-characters", 3,
        "New Password Differs By Characters"
    )


def check_password_differs_8(xml_root, rules):
    return _password_min_value_check(
        xml_root, "new-password-differs-by-characters", 8,
        "New Password Differs By Characters"
    )


def check_password_reuse_24(xml_root, rules):
    return _password_min_value_check(
        xml_root, "prevent-password-reuse-limit", 24,
        "Prevent Password Reuse Limit"
    )


def check_password_profiles_absent(xml_root, rules):
    profile_paths = [
        "/config/devices/entry/deviceconfig/system/password-profile/entry",
        "/config/shared/password-profile/entry",
        "//password-profile/entry",
    ]

    if _any_xpath_exists(xml_root, profile_paths):
        return [_setting_finding(
            "password-profile",
            "none",
            "present",
        )]

    return []


# -------------------------------------------------------------------
# VPN SETTINGS (CIS)
# -------------------------------------------------------------------

def check_ikev2_post_quantum_enabled(xml_root, rules):
    failures = []
    gateways = xml_root.xpath(
        "/config/devices/entry/network/ike/gateway/entry"
    )

    for gw in gateways:
        name = gw.get("name", "unknown")
        ikev2 = gw.find("./protocol/ikev2")
        if ikev2 is None:
            continue

        pq_ppk = ikev2.findtext("./pq-ppk/enabled")
        if pq_ppk is None:
            pq_ppk = ikev2.findtext("./pq-ppk/enable")

        pq_kem = ikev2.findtext("./pq-kem/enable")
        if pq_kem is None:
            pq_kem = ikev2.findtext("./pq-kem/enabled")

        pq_enabled = pq_ppk == "yes" or pq_kem == "yes"
        if not pq_enabled:
            failures.append(_setting_finding(
                f"ike gateway {name} pq",
                "enabled",
                "disabled",
            ))

    return failures


# -------------------------------------------------------------------
# DEVICE SERVICES CONTROLS (CIS)
# -------------------------------------------------------------------

def check_ntp_redundant_servers(xml_root, rules):
    primary = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/ntp-servers/"
        "primary-ntp-server/ntp-server-address"
    )
    secondary = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/system/ntp-servers/"
        "secondary-ntp-server/ntp-server-address"
    )

    failures = []
    if not primary:
        failures.append(_setting_finding(
            "deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address",
            "set",
            primary,
        ))
    if not secondary:
        failures.append(_setting_finding(
            "deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address",
            "set",
            secondary,
        ))

    return failures


def check_timezone_utc_gmt(xml_root, rules):
    timezone = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/timezone",
            "/config/mgt-config/timezone",
        ],
    )

    if timezone not in ("UTC", "GMT"):
        return [_setting_finding(
            "timezone",
            "UTC or GMT",
            timezone,
        )]

    return []


def check_ntp_authentication_enabled(xml_root, rules):
    auth_paths = {
        "primary": (
            "/config/devices/entry/deviceconfig/system/ntp-servers/"
            "primary-ntp-server/authentication-type"
        ),
        "secondary": (
            "/config/devices/entry/deviceconfig/system/ntp-servers/"
            "secondary-ntp-server/authentication-type"
        ),
    }

    failures = []
    for name, path in auth_paths.items():
        has_sym = _xpath_exists(xml_root, f"{path}/symmetric-key")
        has_auto = _xpath_exists(xml_root, f"{path}/autokey")
        has_none = _xpath_exists(xml_root, f"{path}/none")

        if has_none or not (has_sym or has_auto):
            failures.append(_setting_finding(
                f"ntp-servers {name} authentication-type",
                "symmetric-key or autokey",
                "none" if has_none else "",
            ))

    return failures


# -------------------------------------------------------------------
# LOGGING CONTROLS (CIS)
# -------------------------------------------------------------------

def check_syslog_configured(xml_root, rules):
    failures = []

    profile_paths = [
        "/config/devices/entry/deviceconfig/system/syslog/entry",
        "/config/devices/entry/deviceconfig/system/server-profiles/syslog/entry",
        "/config/shared/log-settings/syslog/entry",
        "/config/shared/server-profiles/syslog/entry",
    ]
    log_settings = xml_root.xpath("//*[local-name()='log-settings']")
    required_sections = ["system", "config", "userid", "hipmatch", "iptag"]

    if not _any_xpath_exists(xml_root, profile_paths):
        failures.append(_setting_finding(
            "syslog profile",
            "configured",
            "",
        ))

    for section in required_sections:
        members = set()
        for node in log_settings:
            members.update(
                [m.text for m in node.xpath(
                    f"./{section}/match-list/entry/send-syslog/member"
                ) if m.text]
            )

        if not members:
            failures.append(_setting_finding(
                f"log-settings {section}",
                "send-syslog configured",
                "not set",
            ))

    return failures


def check_syslog_hostname_or_fqdn(xml_root, rules):
    value = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/setting/management/"
            "hostname-type-in-syslog",
            "/config/mgt-config/hostname-type-in-syslog",
        ],
    )

    if not value or not value.strip():
        return [_setting_finding(
            "hostname-type-in-syslog",
            "hostname or FQDN",
            "",
        )]

    normalized = value.strip().lower()
    if normalized in ("fqdn", "hostname"):
        return []

    return [_setting_finding(
        "hostname-type-in-syslog",
        "hostname or FQDN",
        value.strip(),
    )]


def check_admin_lockout_requires_release(xml_root, rules):
    failures = []
    profiles = _auth_profile_map(xml_root)
    auth_profile = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/authentication-profile",
            "/config/mgt-config/authentication-profile",
        ],
    )

    if not auth_profile:
        return [_setting_finding(
            "management authentication-profile",
            "configured",
            "",
        )]

    profile = profiles.get(auth_profile)
    if profile is None:
        return [_setting_finding(
            "management authentication-profile",
            "valid profile",
            auth_profile,
        )]

    lockout_time = _first_xpath_text(
        profile,
        [
            "./lockout/lockout-time",
            "./lockout-time",
        ],
    )
    if lockout_time is None or lockout_time.strip() == "":
        return []

    if lockout_time != "0":
        failures.append(_setting_finding(
            f"authentication-profile {auth_profile}",
            "lockout-time=0",
            lockout_time,
        ))

    return failures

def check_log_high_dp_load_enabled(xml_root, rules):
    value = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/setting/management/"
            "enable-log-high-dp-load",
            "/config/mgt-config/setting/management/enable-log-high-dp-load",
        ],
    )

    if value != "yes":
        return [_setting_finding(
            "enable-log-high-dp-load",
            "yes",
            value,
        )]

    return []


def check_login_banner_set(xml_root, rules):
    banner = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/login-banner",
            "/config/mgt-config/login-banner",
        ],
    )

    if banner and banner.strip():
        return []

    return [_setting_finding(
        "login-banner",
        "set",
        banner,
    )]


def check_alarms_enabled(xml_root, rules):
    value = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/setting/management/"
            "common-criteria-alarm-generation/enable-alarm-generation",
            "/config/devices/entry/deviceconfig/setting/management/"
            "common-criteria-alarm-generation/enable-web-alarm-notification",
        ],
    )

    if value != "yes":
        return [_setting_finding(
            "alarm-generation",
            "enabled",
            value,
        )]

    return []


def check_audit_storage_alarms_75(xml_root, rules):
    failures = []

    base = (
        "/config/devices/entry/deviceconfig/setting/management/"
        "common-criteria-alarm-generation"
    )

    if not _xpath_exists(xml_root, base):
        return [_setting_finding(
            "common-criteria-alarm-generation",
            "configured",
            "default",
        )]

    alarm_enabled = _xpath_text(xml_root, f"{base}/enable-alarm-generation")
    web_alarm_enabled = _xpath_text(xml_root, f"{base}/enable-web-alarm-notification")

    if alarm_enabled != "yes":
        failures.append(_setting_finding(
            "common-criteria-alarm-generation/enable-alarm-generation",
            "yes",
            alarm_enabled,
        ))

    if web_alarm_enabled != "yes":
        failures.append(_setting_finding(
            "common-criteria-alarm-generation/enable-web-alarm-notification",
            "yes",
            web_alarm_enabled,
        ))

    threshold_base = f"{base}/log-databases-alarm-threshold"
    threshold_fields = [
        "traffic",
        "threat",
        "config",
        "system",
        "alarm",
        "hipmatch",
        "userid",
        "iptag",
        "auth",
        "gtp",
        "sctp",
        "decryption",
    ]

    for field in threshold_fields:
        value = _xpath_text(xml_root, f"{threshold_base}/{field}")
        if value != "75":
            failures.append(_setting_finding(
                f"log-databases-alarm-threshold/{field}",
                "75",
                value,
            ))

    return failures


def check_packet_buffer_protection_enabled(xml_root, rules):
    failures = []
    zones = xml_root.xpath("/config/devices/entry/vsys/entry/zone/entry")
    for zone in zones:
        name = zone.get("name", "unknown")
        value = zone.findtext("./network/enable-packet-buffer-protection")
        if value == "no":
            failures.append(_setting_finding(
                f"zone {name} enable-packet-buffer-protection",
                "not disabled",
                value,
            ))

    return failures


def check_log_forwarding_threat_auth(xml_root, rules):
    failures = []
    profiles = []
    profile_paths = [
        "/config/shared/log-settings/profiles/entry",
        "/config/devices/entry/vsys/entry/log-settings/profiles/entry",
    ]

    for path in profile_paths:
        profiles.extend(xml_root.xpath(path))

    if not profiles:
        failures.append(_setting_finding(
            "log-settings/profiles",
            "configured",
            "",
        ))
        return failures

    required_types = {"threat", "auth"}
    matched_types = set()

    for profile in profiles:
        entries = profile.xpath(".//match-list/entry")
        for entry in entries:
            log_type = entry.findtext("./log-type")
            if log_type not in required_types:
                continue

            send_to_panorama = entry.findtext("./send-to-panorama") == "yes"
            send_to_logging_service = entry.findtext(
                "./send-to-logging-service"
            ) == "yes"
            send_syslog = entry.find("./send-syslog") is not None
            send_email = entry.find("./send-email") is not None

            if send_to_panorama or send_to_logging_service or send_syslog or send_email:
                matched_types.add(log_type)

    missing = required_types - matched_types
    if missing:
        failures.append(_setting_finding(
            "log-forwarding profiles",
            "threat/auth forwarded",
            f"missing: {', '.join(sorted(missing))}",
        ))

    return failures


def _zone_profile_for_zone(zone, profile_map):
    profile_name = zone.findtext("./network/zone-protection-profile")
    if not profile_name:
        return None, None
    return profile_name, profile_map.get(profile_name)


def check_zone_protection_syn_cookies(xml_root, rules):
    profile_map = _zone_protection_profile_map(xml_root)
    failures = []
    has_syn_cookies = False

    for zone in xml_root.xpath("/config/devices/entry/vsys/entry/zone/entry"):
        zone_name = zone.get("name", "unknown")
        profile_name, profile = _zone_profile_for_zone(zone, profile_map)
        if profile is None:
            failures.append(_setting_finding(
                f"zone {zone_name}",
                "zone protection profile with SYN cookies",
                "not set",
                severity="warn",
                reason=(
                    "This check will return a warning even when applied because "
                    "administrator should validate its applied to the needed "
                    "untrusted intefaces and values should be custimized to the "
                    "organization. Verify Alert is appropriate for org. Verify "
                    "Activate is 50% of maximum for firewall model. Verify "
                    "Maximum is appropriate for org."
                ),
            ))
            continue

        tcp_syn = profile.find("./flood/tcp-syn")
        action_syn_cookie = False
        if tcp_syn is not None:
            action_syn_cookie = tcp_syn.find("./action/syn-cookie") is not None
        enabled = tcp_syn is not None and tcp_syn.findtext("./enable") == "yes"
        syn_enabled = action_syn_cookie or enabled
        if syn_enabled:
            has_syn_cookies = True

        failures.append(_setting_finding(
            f"zone {zone_name} profile {profile_name}",
            "SYN cookies enabled",
            "enabled" if syn_enabled else "disabled",
            severity="warn",
            reason=(
                "This check will return a warning even when applied because "
                "administrator should validate its applied to the needed "
                "untrusted intefaces and values should be custimized to the "
                "organization. Verify Alert is appropriate for org. Verify "
                "Activate is 50% of maximum for firewall model. Verify "
                "Maximum is appropriate for org."
            ),
        ))

    if not has_syn_cookies:
        return [_setting_finding(
            "zone protection profiles",
            "SYN cookies enabled",
            "not enabled",
        )]

    return failures


def check_zone_protection_flood_enabled(xml_root, rules):
    profile_map = _zone_protection_profile_map(xml_root)
    failures = []
    has_flood = False

    flood_types = ["tcp-syn", "icmp", "icmpv6", "other-ip", "udp"]

    for zone in xml_root.xpath("/config/devices/entry/vsys/entry/zone/entry"):
        zone_name = zone.get("name", "unknown")
        profile_name, profile = _zone_profile_for_zone(zone, profile_map)
        if profile is None:
            failures.append(_setting_finding(
                f"zone {zone_name}",
                "zone protection profile with flood protection",
                "not set",
                severity="warn",
                reason=(
                    "This check will return a warning even when applied because administrator "
                    "should validate its applied to the needed untrusted intefaces and values "
                    "should be custimized to the organization."
                ),
            ))
            continue

        ok = True
        for flood_type in flood_types:
            enabled = profile.findtext(f"./flood/{flood_type}/enable")
            if enabled != "yes":
                ok = False
                failures.append(_setting_finding(
                    f"zone {zone_name} profile {profile_name}",
                    f"{flood_type} flood protection enabled",
                    enabled,
                    severity="warn",
                    reason=(
                        "This check will return a warning even when applied because administrator "
                        "should validate its applied to the needed untrusted intefaces and values "
                        "should be custimized to the organization."
                    ),
                ))

        if ok:
            has_flood = True
            failures.append(_setting_finding(
                f"zone {zone_name} profile {profile_name}",
                "flood protection enabled",
                "enabled",
                severity="warn",
                reason=(
                    "This check will return a warning even when applied because administrator "
                    "should validate its applied to the needed untrusted intefaces and values "
                    "should be custimized to the organization."
                ),
            ))

    if not has_flood:
        return [_setting_finding(
            "zone protection profiles",
            "flood protection enabled",
            "not enabled",
        )]

    return failures


def check_zone_protection_recon_enabled(xml_root, rules):
    profile_map = _zone_protection_profile_map(xml_root)
    failures = []

    for zone in _untrusted_zones(xml_root):
        zone_name = zone.get("name", "unknown")
        profile_name, profile = _zone_profile_for_zone(zone, profile_map)
        if profile is None:
            failures.append(_setting_finding(
                f"zone {zone_name}",
                "zone protection profile with reconnaissance protection",
                "not set",
            ))
            continue

        scan_entries = profile.xpath("./scan/entry")
        has_action = any(entry.find("./action") is not None for entry in scan_entries)
        if not scan_entries or not has_action:
            failures.append(_setting_finding(
                f"zone {zone_name} profile {profile_name}",
                "reconnaissance protection enabled",
                "disabled",
            ))

    return failures


def check_zone_protection_drop_special(xml_root, rules):
    profile_map = _zone_protection_profile_map(xml_root)
    failures = []
    has_drop = False

    for zone in xml_root.xpath("/config/devices/entry/vsys/entry/zone/entry"):
        zone_name = zone.get("name", "unknown")
        profile_name, profile = _zone_profile_for_zone(zone, profile_map)
        if profile is None:
            failures.append(_setting_finding(
                f"zone {zone_name}",
                "zone protection profile with packet drop settings",
                "not set",
                severity="warn",
                reason=(
                    "This check will return a warning even when applied because administrator "
                    "should validate its applied to the needed untrusted intefaces and values "
                    "should be custimized to the organization."
                ),
            ))
            continue

        checks = {
            "discard-ip-spoof": "yes",
            "discard-malformed-option": "yes",
        }
        ok = True
        for field, expected in checks.items():
            actual = profile.findtext(f"./{field}")
            if actual != expected:
                ok = False
                failures.append(_setting_finding(
                    f"zone {zone_name} profile {profile_name}",
                    f"{field}={expected}",
                    actual,
                    severity="warn",
                    reason=(
                        "This check will return a warning even when applied because administrator "
                        "should validate its applied to the needed untrusted intefaces and values "
                        "should be custimized to the organization."
                    ),
                ))

        if ok:
            has_drop = True
            failures.append(_setting_finding(
                f"zone {zone_name} profile {profile_name}",
                "drop special packets enabled",
                "enabled",
                severity="warn",
                reason=(
                    "This check will return a warning even when applied because administrator "
                    "should validate its applied to the needed untrusted intefaces and values "
                    "should be custimized to the organization."
                ),
            ))

    if not has_drop:
        return [_setting_finding(
            "zone protection profiles",
            "drop special packets enabled",
            "not enabled",
        )]

    return failures


def check_snmpv3_traps_configured(xml_root, rules):
    failures = []

    profile_paths = [
        "/config/devices/entry/deviceconfig/system/log-settings/snmptrap/entry",
        "/config/shared/log-settings/snmptrap/entry",
        "/config/devices/entry/deviceconfig/system/snmp-trap/entry",
        "/config/devices/entry/deviceconfig/system/server-profiles/snmp-trap/entry",
        "/config/shared/server-profiles/snmp-trap/entry",
    ]

    profiles = []
    for path in profile_paths:
        profiles.extend(xml_root.xpath(path))

    v3_profiles = set()
    legacy_profiles = set()
    for profile in profiles:
        name = profile.get("name")
        if not name:
            continue
        has_v3 = profile.find("./version/v3") is not None
        has_legacy = profile.find("./version/v1") is not None
        has_legacy = has_legacy or profile.find("./version/v2") is not None
        has_legacy = has_legacy or profile.find("./version/v2c") is not None
        if has_v3:
            v3_profiles.add(name)
        if has_legacy:
            legacy_profiles.add(name)

    if not profiles or not v3_profiles:
        failures.append(_setting_finding(
            "SNMP trap profile",
            "configured with v3",
            "not set",
        ))
    elif legacy_profiles:
        failures.append(_setting_finding(
            "SNMP trap profile",
            "v3 only",
            ", ".join(sorted(legacy_profiles)),
        ))

    log_settings = xml_root.xpath("//*[local-name()='log-settings']")
    required_sections = ["system", "config", "userid", "hipmatch", "iptag"]

    for section in required_sections:
        members = set()
        for node in log_settings:
            members.update(
                [m.text for m in node.xpath(
                    f"./{section}/match-list/entry/send-snmptrap/member"
                ) if m.text]
            )

        if not members:
            failures.append(_setting_finding(
                f"log-settings {section}",
                "SNMPv3 trap profile",
                "not set",
            ))
            continue

        invalid = sorted(m for m in members if m not in v3_profiles)
        if invalid:
            failures.append(_setting_finding(
                f"log-settings {section}",
                "SNMPv3 trap profile",
                ", ".join(invalid),
            ))

    return failures


# -------------------------------------------------------------------
# USER-ID CONTROLS (CIS)
# -------------------------------------------------------------------

def _user_id_enabled_zones(xml_root):
    zones = xml_root.xpath(
        "/config/devices/entry/vsys/entry/zone/entry"
    )
    enabled = []
    for zone in zones:
        if zone.findtext("./enable-user-identification") == "yes":
            members = [m.text for m in zone.findall("./network/layer3/member")]
            enabled.append({
                "zone": zone.get("name", "unknown"),
                "interfaces": members,
            })
    return enabled


def check_ip_user_mapping_configured(xml_root, rules):
    mapping_paths = [
        "/config/devices/entry/deviceconfig/system/user-id/agent/entry",
        "/config/devices/entry/deviceconfig/system/user-id-agent/entry",
        "/config/devices/entry/deviceconfig/system/user-id/terminal-services/entry",
        "/config/devices/entry/deviceconfig/system/terminal-services/entry",
        "/config/devices/entry/vsys/entry/redistribution-agent/entry[ip-user-mappings='yes']",
    ]

    if _any_xpath_exists(xml_root, mapping_paths):
        failures = []
        for agent in xml_root.xpath(
            "/config/devices/entry/vsys/entry/redistribution-agent/entry"
        ):
            if agent.findtext("./disabled") == "yes":
                name = agent.get("name", "unknown")
                failures.append(_setting_finding(
                    f"redistribution-agent {name}",
                    "enabled",
                    "disabled",
                ))
        return failures

    return [_setting_finding(
        "user-id mapping sources",
        "configured",
        "",
    )]


def check_wmi_probing_disabled(xml_root, rules):
    probing_paths = [
        "/config/devices/entry/deviceconfig/system/user-id/enable-probing",
        "/config/devices/entry/deviceconfig/system/user-id/agent/enable-probing",
        "/config/devices/entry/deviceconfig/system/user-id-agent/enable-probing",
        "//enable-probing",
    ]

    enabled = None
    for path in probing_paths:
        value = _xpath_text(xml_root, path)
        if value is not None:
            enabled = value
            break

    if enabled == "yes":
        return [_setting_finding(
            "user-id probing (WMI)",
            "disabled",
            "enabled",
        )]

    return []


def check_user_id_only_on_trusted(xml_root, rules):
    enabled_zones = _user_id_enabled_zones(xml_root)
    if not enabled_zones:
        return []

    failures = []
    reason = (
        "User-ID is enabled on this zone. Validate that it is a trusted zone "
        "and confirm User-ID is only enabled where appropriate."
    )

    for zone in enabled_zones:
        name = zone["zone"]
        interfaces = zone["interfaces"]
        findings = _setting_finding(
            f"zone {name} user-id",
            "review required",
            "enabled",
            severity="warn",
            reason=reason,
        )
        findings["interfaces"] = interfaces
        failures.append(findings)

    return failures


def check_user_id_include_exclude_configured(xml_root, rules):
    enabled_zones = _user_id_enabled_zones(xml_root)
    if not enabled_zones:
        return []

    include_exclude_paths = [
        "/config/devices/entry/deviceconfig/system/user-id/include-exclude",
        "/config/devices/entry/deviceconfig/system/user-id/include-exclude-networks",
        "/config/devices/entry/deviceconfig/system/user-id/user-mapping/include-exclude",
        "/config/devices/entry/deviceconfig/system/user-id/user-mapping/include-exclude-networks",
        "/config/devices/entry/vsys/entry/user-id-collector/include-exclude-network",
        "/config/devices/entry/vsys/entry/user-id-collector/include-exclude-network/entry",
        "/config/shared/user-id-collector/include-exclude-network",
        "/config/shared/user-id-collector/include-exclude-network/entry",
        "/config/mgt-config/user-id/user-mapping/include-exclude-networks",
        "/config/devices/entry/mgt-config/user-id/user-mapping/include-exclude-networks",
    ]

    if _any_xpath_exists(xml_root, include_exclude_paths):
        return []

    return [_setting_finding(
        "user-id include/exclude networks",
        "configured",
        "",
    )]


# -------------------------------------------------------------------
# HIGH AVAILABILITY (CIS)
# -------------------------------------------------------------------

def _ha_enabled(xml_root):
    if not _xpath_exists(
        xml_root,
        "/config/devices/entry/deviceconfig/high-availability",
    ):
        return "no"

    for path in [
        "/config/devices/entry/deviceconfig/high-availability/enabled",
        "/config/devices/entry/deviceconfig/high-availability/enable",
        "/config/devices/entry/deviceconfig/high-availability/group/enabled",
    ]:
        if _xpath_text(xml_root, path) == "yes":
            return "yes"

    return "no"


def check_ha_peer_configured(xml_root, rules):
    enabled = _ha_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "high-availability",
            "enabled",
            enabled,
            severity="na",
            reason="High availability is not enabled.",
        )]

    keep_alive = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/high-availability/group/"
            "state-synchronization/ha2-keep-alive/enabled",
            "/config/devices/entry/deviceconfig/high-availability/group/entry/"
            "state-synchronization/ha2-keep-alive/enabled",
            "/config/devices/entry/deviceconfig/high-availability/"
            "state-synchronization/ha2-keep-alive/enabled",
        ],
    )
    if keep_alive != "yes":
        return [_setting_finding(
            "ha2-keep-alive",
            "enabled",
            keep_alive,
        )]

    return []


def check_ha_link_or_path_monitoring(xml_root, rules):
    enabled = _ha_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "high-availability",
            "enabled",
            enabled,
            severity="na",
            reason="High availability is not enabled.",
        )]

    interfaces = xml_root.xpath(
        "/config/devices/entry/deviceconfig/high-availability/group/"
        "monitoring/link-monitoring/link-group/entry/interface/member"
    )
    interfaces += xml_root.xpath(
        "/config/devices/entry/deviceconfig/high-availability/group/entry/"
        "monitoring/link-monitoring/link-group/entry/interface/member"
    )

    if not interfaces:
        return [_setting_finding(
            "link monitoring",
            "configured with interface",
            "",
        )]

    return []


def check_ha_passive_link_state_preemptive(xml_root, rules):
    enabled = _ha_enabled(xml_root)
    if enabled != "yes":
        return [_setting_finding(
            "high-availability",
            "enabled",
            enabled,
            severity="na",
            reason="High availability is not enabled.",
        )]

    passive_state = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/high-availability/group/entry/"
            "mode/active-passive/passive-link-state",
            "/config/devices/entry/deviceconfig/high-availability/group/"
            "mode/active-passive/passive-link-state",
            "/config/devices/entry/deviceconfig/high-availability/passive-link-state",
            "//*[local-name()='passive-link-state']",
        ],
    )
    preemptive = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/high-availability/group/entry/"
            "election-option/preemptive",
            "/config/devices/entry/deviceconfig/high-availability/group/entry/"
            "election-settings/preemptive",
            "/config/devices/entry/deviceconfig/high-availability/preemptive",
            "//*[local-name()='preemptive']",
        ],
    )

    if passive_state != "auto":
        return [_setting_finding(
            "passive-link-state",
            "auto",
            passive_state,
        )]

    if preemptive == "yes":
        return [_setting_finding(
            "preemptive",
            "disabled",
            preemptive,
        )]

    return []


# -------------------------------------------------------------------
# DYNAMIC UPDATES (CIS)
# -------------------------------------------------------------------

def check_antivirus_updates_hourly(xml_root, rules):
    action = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/update-schedule/"
            "anti-virus/recurring/hourly/action",
            "/config/devices/entry/deviceconfig/system/update-schedule/"
            "anti-virus/recurring/hourly/download-and-install",
        ],
    )
    has_hourly = _xpath_exists(
        xml_root,
        "/config/devices/entry/deviceconfig/system/update-schedule/"
        "anti-virus/recurring/hourly",
    )

    if not has_hourly:
        return [_setting_finding(
            "anti-virus update schedule",
            "hourly",
            "",
        )]

    if action is not None and action != "download-and-install":
        return [_setting_finding(
            "anti-virus update action",
            "download-and-install",
            action,
        )]

    return []


def check_threats_updates_daily_or_better(xml_root, rules):
    base = "/config/devices/entry/deviceconfig/system/update-schedule/threats/recurring"
    allowed = ["daily", "hourly", "every-30-mins", "every-30-minutes"]
    has_recurrence = any(
        _xpath_exists(xml_root, f"{base}/{name}") for name in allowed
    )

    if not has_recurrence:
        return [_setting_finding(
            "applications and threats update schedule",
            "daily or better",
            "",
        )]

    action = _first_xpath_text(
        xml_root,
        [
            f"{base}/daily/action",
            f"{base}/hourly/action",
            f"{base}/every-30-mins/action",
            f"{base}/every-30-minutes/action",
        ],
    )
    if action is not None and action != "download-and-install":
        return [_setting_finding(
            "applications and threats update action",
            "download-and-install",
            action,
        )]

    return []


# -------------------------------------------------------------------
# WILDFIRE (CIS)
# -------------------------------------------------------------------

def check_wildfire_file_size_limits(xml_root, rules):
    required = {
        "pe": 16,
        "apk": 10,
        "pdf": 3072,
        "ms-office": 16384,
        "jar": 5,
        "flash": 5,
        "MacOSX": 10,
        "archive": 50,
        "linux": 50,
        "script": 20,
    }

    entries = xml_root.xpath(
        "/config/devices/entry/deviceconfig/setting/wildfire/"
        "file-size-limit/entry"
    )
    if not entries:
        return []

    size_map = {}
    for entry in entries:
        name = entry.get("name")
        value = entry.findtext("./size-limit")
        if name and value is not None:
            size_map[name] = value

    failures = []
    for name, minimum in required.items():
        value_text = size_map.get(name)
        try:
            value = int(value_text) if value_text is not None else None
        except ValueError:
            value = None

        if value is None or value < minimum:
            failures.append(_setting_finding(
                f"wildfire file-size-limit {name}",
                f">={minimum}",
                value_text,
            ))

    return failures


def check_wildfire_analysis_on_rules(xml_root, rules):
    failures = []
    groups = {}

    for group in xml_root.xpath(
        "/config/devices/entry/vsys/entry/profile-group/entry"
    ):
        name = group.get("name")
        has_wf = group.find("./wildfire-analysis/member") is not None
        if name:
            groups[name] = has_wf

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        wf_profile = rule.find("./profile-setting/profiles/wildfire-analysis/member")
        if wf_profile is not None:
            continue

        group_member = rule.findtext("./profile-setting/group/member")
        if group_member:
            if groups.get(group_member):
                continue
            rule_info = _rule_base(rule)
            rule_info["reason"] = "WildFire analysis profile is not set."
            failures.append(rule_info)
            continue

        rule_info = _rule_base(rule)
        rule_info["reason"] = "WildFire analysis profile is not set."
        failures.append(rule_info)

    return failures


def check_wildfire_forward_decrypted_content(xml_root, rules):
    values = xml_root.xpath("//ssl-decrypt/allow-forward-decrypted-content/text()")
    if not values:
        return [_setting_finding(
            "allow-forward-decrypted-content",
            "yes",
            "",
        )]

    failures = []
    for value in values:
        if value != "yes":
            failures.append(_setting_finding(
                "allow-forward-decrypted-content",
                "yes",
                value,
            ))

    return failures


def check_wildfire_session_info_settings(xml_root, rules):
    exclude_fields = [
        "exclude-src-ip",
        "exclude-src-port",
        "exclude-dest-ip",
        "exclude-dest-port",
        "exclude-vsys-id",
        "exclude-app-name",
        "exclude-username",
        "exclude-url",
        "exclude-filename",
        "exclude-email-sender",
        "exclude-email-recipient",
        "exclude-email-subject",
    ]
    base_paths = [
        "/config/devices/entry/deviceconfig/setting/wildfire/session-info-select",
        "/config/devices/entry/deviceconfig/setting/wildfire/session-information",
        "/config/devices/entry/deviceconfig/setting/wildfire/session-info",
    ]

    failures = []
    found_any = False
    for field in exclude_fields:
        value = None
        for base in base_paths:
            value = _xpath_text(xml_root, f"{base}/{field}")
            if value is not None:
                found_any = True
                break
        if value == "yes":
            failures.append(_setting_finding(
                f"wildfire session-info {field}",
                "not excluded",
                value,
            ))

    if not found_any:
        return []

    return failures


def check_wildfire_alerts_enabled(xml_root, rules):
    has_wildfire_log = _xpath_exists(
        xml_root,
        "//*[local-name()='log-settings']"
        "//*[local-name()='log-type' and text()='wildfire']"
    ) or _xpath_exists(
        xml_root,
        "//*[local-name()='log-forwarding']"
        "//*[local-name()='log-type' and text()='wildfire']"
    )

    if not has_wildfire_log:
        return [_setting_finding(
            "wildfire alerts",
            "enabled",
            "",
        )]

    return []


def check_wildfire_update_realtime(xml_root, rules):
    has_realtime = _xpath_exists(
        xml_root,
        "/config/devices/entry/deviceconfig/system/update-schedule/"
        "wildfire/recurring/real-time"
    )
    if not has_realtime:
        return [_setting_finding(
            "wildfire update schedule",
            "real-time",
            "",
        )]

    return []


def check_wildfire_public_cloud_region(xml_root, rules):
    region = _xpath_text(
        xml_root,
        "/config/devices/entry/deviceconfig/setting/wildfire/public-cloud-server"
    )
    region_map = {
        "wildfire.paloaltonetworks.com": "United States",
        "eu.wildfire.paloaltonetworks.com": "Europe",
        "jp.wildfire.paloaltonetworks.com": "Japan",
        "sg.wildfire.paloaltonetworks.com": "Singapore",
        "uk.wildfire.paloaltonetworks.com": "United Kingdom",
        "ca.wildfire.paloaltonetworks.com": "Canada",
        "au.wildfire.paloaltonetworks.com": "Australia",
        "de.wildfire.paloaltonetworks.com": "Germany",
        "in.wildfire.paloaltonetworks.com": "India",
        "ch.wildfire.paloaltonetworks.com": "Switzerland",
        "pl.wildfire.paloaltonetworks.com": "Poland",
        "id.wildfire.paloaltonetworks.com": "Indonesia",
        "tw.wildfire.paloaltonetworks.com": "Taiwan",
        "fr.wildfire.paloaltonetworks.com": "France",
        "qatar.wildfire.paloaltonetworks.com": "Qatar",
        "kr.wildfire.paloaltonetworks.com": "South Korea",
        "il.wildfire.paloaltonetworks.com": "Israel",
        "sa.wildfire.paloaltonetworks.com": "Saudi Arabia",
        "es.wildfire.paloaltonetworks.com": "Spain",
        "wildfire.gov.paloaltonetworks.com": "Fedramp / Gov",
    }
    host = (region or "").strip()
    if not host:
        host = "wildfire.paloaltonetworks.com"
    region_name = region_map.get(host, "Unknown")

    return [_setting_finding(
        "wildfire public cloud region",
        "review",
        host,
        severity="warn",
        reason=f"WildFire public cloud region: {region_name}.",
    )]


def check_wildfire_inline_cloud_analysis(xml_root, rules):
    has_inline = _xpath_exists(
        xml_root,
        "//*[local-name()='wildfire-analysis']"
        "//*[local-name()='cloud-inline-analysis' or "
        "local-name()='inline-cloud-analysis'][text()='yes']"
    )

    if not has_inline:
        return [_setting_finding(
            "wildfire inline cloud analysis",
            "enabled",
            "",
        )]

    return []


# -------------------------------------------------------------------
# THREAT PREVENTION (CIS)
# -------------------------------------------------------------------

def check_av_reset_both_decoders(xml_root, rules):
    failures = []
    profiles = _profile_entries(xml_root, "virus")

    for profile in profiles:
        name = profile.get("name", "unknown")
        for decoder in profile.xpath("./decoder/entry"):
            decoder_name = decoder.get("name", "")
            if decoder_name in {"imap", "pop3"}:
                continue
            action = decoder.findtext("./action")
            if action != "reset-both":
                failures.append(_setting_finding(
                    f"antivirus profile {name} decoder {decoder_name}",
                    "reset-both",
                    action,
                ))

    return failures


def check_spyware_blocks_all_severities(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "spyware")
    required = {"critical", "high", "medium", "low"}
    block_actions = {"reset-both", "block", "reset-client", "reset-server"}

    failures = []
    used_profiles = set()
    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "spyware")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"anti-spyware profile {name}",
                "present",
                "missing",
            ))
            continue

        covered = set()
        for entry in profile.xpath("./rules/entry"):
            action = _action_value(entry.find("./action"))
            if action not in block_actions:
                continue
            for sev in entry.findall("./severity/member"):
                if sev.text:
                    covered.add(sev.text)

        if not required.issubset(covered):
            missing = ", ".join(sorted(required - covered))
            failures.append(_setting_finding(
                f"anti-spyware profile {name}",
                "block critical/high/medium/low",
                f"missing: {missing}",
            ))

    return failures


def check_spyware_dns_sinkhole(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "spyware")

    failures = []
    used_profiles = set()
    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "spyware")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"anti-spyware profile {name}",
                "present",
                "missing",
            ))
            continue

        has_sinkhole = profile.findtext("./botnet-domains/sinkhole/ipv4-address")
        if not has_sinkhole:
            actions = profile.xpath(
                "./botnet-domains//action[text()='sinkhole']"
            )
            if not actions:
                failures.append(_setting_finding(
                    f"anti-spyware profile {name} sinkhole",
                    "enabled",
                    "",
                ))

    return failures


def check_vp_blocks_critical_high(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "vulnerability")
    required = {"critical", "high"}
    block_actions = {"reset-both", "block", "reset-client", "reset-server"}

    failures = []
    used_profiles = set()
    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "vulnerability")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"vulnerability profile {name}",
                "present",
                "missing",
            ))
            continue

        covered = set()
        for entry in profile.xpath("./rules/entry"):
            action = _action_value(entry.find("./action"))
            if action not in block_actions:
                continue
            for sev in entry.findall("./severity/member"):
                if sev.text:
                    covered.add(sev.text)

        if not required.issubset(covered):
            missing = ", ".join(sorted(required - covered))
            failures.append(_setting_finding(
                f"vulnerability profile {name}",
                "block critical/high",
                f"missing: {missing}",
            ))

    return failures


def check_url_filtering_on_rules(xml_root, rules):
    groups = _profile_groups(xml_root)
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        profile = _rule_profile_name(rule, groups, "url-filtering")
        if not profile:
            rule_info = _rule_base(rule)
            rule_info["reason"] = "URL filtering profile is not set."
            failures.append(rule_info)

    return failures


def check_url_filtering_block_override_categories(xml_root, rules):
    required = {
        "adult",
        "hacking",
        "command-and-control",
        "copyright-infringement",
        "extremism",
        "malware",
        "ransomware",
        "phishing",
        "proxy-avoidance-and-anonymizers",
        "parked",
    }

    groups = _profile_groups(xml_root)
    profile_map = _profile_entry_map(xml_root, "url-filtering")
    used_profiles = set()

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        profile = _rule_profile_name(rule, groups, "url-filtering")
        if profile:
            used_profiles.add(profile)

    if not used_profiles:
        return [_setting_finding(
            "url-filtering profiles",
            "in use",
            "",
        )]

    failures = []
    for name in sorted(used_profiles):
        profile = profile_map.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"url-filtering profile {name}",
                "present",
                "missing",
            ))
            continue

        block = {m.text for m in profile.findall("./block/member") if m.text}
        override = {m.text for m in profile.findall("./override/member") if m.text}
        covered = block | override
        missing = sorted(required - covered)
        if missing:
            failures.append(_setting_finding(
                f"url-filtering profile {name}",
                "block/override required categories",
                f"missing: {', '.join(missing)}",
            ))

    return failures


def check_url_filtering_no_allow_categories(xml_root, rules):
    groups = _profile_groups(xml_root)
    profile_map = _profile_entry_map(xml_root, "url-filtering")
    used_profiles = set()

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        profile = _rule_profile_name(rule, groups, "url-filtering")
        if profile:
            used_profiles.add(profile)

    if not used_profiles:
        return [_setting_finding(
            "url-filtering profiles",
            "in use",
            "",
        )]

    failures = []
    for name in sorted(used_profiles):
        profile = profile_map.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"url-filtering profile {name}",
                "present",
                "missing",
            ))
            continue

        allow = [m.text for m in profile.findall("./allow/member") if m.text]
        if allow:
            failures.append(_setting_finding(
                f"url-filtering profile {name}",
                "no categories set to allow",
                f"allow: {', '.join(sorted(allow))}",
            ))

    return failures


def check_url_http_header_logging(xml_root, rules):
    profiles = _profile_entries(xml_root, "url-filtering")
    failures = []

    for profile in profiles:
        name = profile.get("name", "unknown")
        ua = profile.findtext("./log-http-hdr-user-agent")
        ref = profile.findtext("./log-http-hdr-referer")
        xff = profile.findtext("./log-http-hdr-xff")

        if ua != "yes" or ref != "yes" or xff != "yes":
            failures.append(_setting_finding(
                f"url-filtering profile {name} http-headers",
                "user-agent, referer, xff enabled",
                f"user-agent={ua}, referer={ref}, xff={xff}",
            ))

    return failures


def check_vp_inline_cloud_analysis(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "vulnerability")
    failures = []
    used_profiles = set()

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "vulnerability")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"vulnerability profile {name}",
                "present",
                "missing",
            ))
            continue

        if profile.findtext("./cloud-inline-analysis") != "yes":
            failures.append(_setting_finding(
                f"vulnerability profile {name} inline cloud analysis",
                "enabled",
                profile.findtext("./cloud-inline-analysis"),
            ))

    return failures


def check_url_cloud_inline_categorization(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "url-filtering")
    failures = []
    used_profiles = set()

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "url-filtering")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"url-filtering profile {name}",
                "present",
                "missing",
            ))
            continue

        if profile.findtext("./cloud-inline-cat") != "yes":
            failures.append(_setting_finding(
                f"url-filtering profile {name} cloud inline categorization",
                "enabled",
                profile.findtext("./cloud-inline-cat"),
            ))

    return failures


def check_spyware_inline_cloud_analysis(xml_root, rules):
    groups = _profile_groups(xml_root)
    profiles = _profile_entry_map(xml_root, "spyware")
    failures = []
    used_profiles = set()

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue
        name = _rule_profile_name(rule, groups, "spyware")
        if name:
            used_profiles.add(name)

    for name in sorted(used_profiles):
        profile = profiles.get(name)
        if profile is None:
            failures.append(_setting_finding(
                f"anti-spyware profile {name}",
                "present",
                "missing",
            ))
            continue

        if profile.findtext("./cloud-inline-analysis") != "yes":
            failures.append(_setting_finding(
                f"anti-spyware profile {name} inline cloud analysis",
                "enabled",
                profile.findtext("./cloud-inline-analysis"),
            ))

    return failures


# -------------------------------------------------------------------
# SECURITY POLICIES (CIS)
# -------------------------------------------------------------------

def _is_untrusted_zone(name: str) -> bool:
    if not name:
        return False
    return name.lower() in {
        "untrust", "untrusted", "internet", "external", "outside", "wan", "public"
    }


def _is_trusted_zone(name: str) -> bool:
    if not name:
        return False
    return name.lower() not in {
        "untrust", "untrusted", "internet", "external", "outside", "wan", "public"
    }


def check_app_specific_untrusted_to_trusted(xml_root, rules):
    failures = []

    for rule in rules:
        if rule.findtext("./action") != "allow":
            continue

        from_zones = [z.text for z in rule.findall("./from/member")]
        to_zones = [z.text for z in rule.findall("./to/member")]

        if not any(_is_untrusted_zone(z) for z in from_zones):
            continue
        if not any(_is_trusted_zone(z) for z in to_zones):
            continue

        apps = [a.text for a in rule.findall("./application/member")]
        if "any" in apps:
            failures.append(_rule_base(rule))

    return failures


def check_malicious_ip_deny_rules(xml_root, rules):
    keywords = [
        "known malicious",
        "high risk",
        "tor",
        "bulletproof",
        "palo alto networks",
        "panw",
    ]

    to_rule = False
    from_rule = False

    for rule in rules:
        action = rule.findtext("./action")
        if action not in {"deny", "drop", "block"}:
            continue

        src_members = [m.text or "" for m in rule.findall("./source/member")]
        dst_members = [m.text or "" for m in rule.findall("./destination/member")]

        if any(any(k in s.lower() for k in keywords) for s in dst_members):
            to_rule = True
        if any(any(k in s.lower() for k in keywords) for s in src_members):
            from_rule = True

    failures = []
    if not to_rule:
        failures.append(_setting_finding(
            "deny to malicious IPs rule",
            "present",
            "",
        ))
    if not from_rule:
        failures.append(_setting_finding(
            "deny from malicious IPs rule",
            "present",
            "",
        ))

    return failures


def check_default_policy_logging(xml_root, rules):
    target = {"intrazone-default", "interzone-default"}
    found = {name: False for name in target}
    failures = []

    default_rules = xml_root.xpath(
        "/config/devices/entry/vsys/entry/rulebase/"
        "default-security-rules/rules/entry"
    )
    if not default_rules:
        default_rules = rules

    for rule in default_rules:
        name = rule.get("name")
        if name not in target:
            continue
        found[name] = True
        log_start = rule.findtext("./log-start")
        log_end = rule.findtext("./log-end")
        if log_start != "yes" and log_end != "yes":
            failures.append(_setting_finding(
                f"default policy {name} log-end",
                "log-start or log-end enabled",
                f"log-start={log_start}, log-end={log_end}",
            ))

    for name, seen in found.items():
        if not seen:
            failures.append(_setting_finding(
                f"default policy {name}",
                "present",
                "missing",
            ))

    return failures


# -------------------------------------------------------------------
# AUTHENTICATION SETTINGS (CIS)
# -------------------------------------------------------------------

def check_idle_timeout_max_10(xml_root, rules):
    idle_timeout = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/idle-timeout",
            "/config/devices/entry/deviceconfig/system/management/idle-timeout",
            "/config/devices/entry/deviceconfig/setting/management/idle-timeout",
            "/config/mgt-config/idle-timeout",
            "/config/devices/entry/mgt-config/idle-timeout",
        ],
    )

    try:
        value = int(idle_timeout) if idle_timeout is not None else None
    except ValueError:
        value = None

    if value is None or value > 10:
        return [_setting_finding(
            "idle-timeout",
            "<=10",
            idle_timeout,
        )]

    return []


def check_auth_profile_lockout_configured(xml_root, rules):
    profiles = []
    profile_paths = [
        "/config/devices/entry/deviceconfig/system/authentication-profile/entry",
        "/config/shared/authentication-profile/entry",
        "/config/devices/entry/authentication-profile/entry",
    ]

    for path in profile_paths:
        profiles.extend(xml_root.xpath(path))

    if not profiles:
        return [_setting_finding(
            "authentication profile",
            "failed-attempts and lockout-time set",
            "",
        )]

    failures = []
    for profile in profiles:
        name = profile.get("name", "unknown")
        failed_attempts = _first_xpath_text(
            profile,
            [
                "./failed-attempts",
                "./lockout/failed-attempts",
            ],
        )
        lockout_time = _first_xpath_text(
            profile,
            [
                "./lockout-time",
                "./lockout/lockout-time",
            ],
        )

        try:
            failed_value = int(failed_attempts) if failed_attempts is not None else 0
        except ValueError:
            failed_value = 0

        try:
            lockout_value = int(lockout_time) if lockout_time is not None else 0
        except ValueError:
            lockout_value = 0

        if failed_value <= 0 or lockout_value <= 0:
            failures.append(_setting_finding(
                f"authentication-profile {name}",
                "failed-attempts>0 and lockout-time>0",
                f"failed-attempts={failed_attempts}, lockout-time={lockout_time}",
            ))

    return failures


# -------------------------------------------------------------------
# SNMP POLLING (CIS)
# -------------------------------------------------------------------

def check_snmp_v1_v2_disabled(xml_root, rules):
    legacy_paths = [
        "/config/devices/entry/deviceconfig/system/snmp-setting/"
        "access-setting/version/v1",
        "/config/devices/entry/deviceconfig/system/snmp-setting/"
        "access-setting/version/v2",
        "/config/devices/entry/deviceconfig/system/snmp-setting/"
        "access-setting/version/v2c",
        "/config/devices/entry/deviceconfig/system/snmp/setting/"
        "access-setting/version/v1",
        "/config/devices/entry/deviceconfig/system/snmp/setting/"
        "access-setting/version/v2",
        "/config/devices/entry/deviceconfig/system/snmp/setting/"
        "access-setting/version/v2c",
    ]

    if _any_xpath_exists(xml_root, legacy_paths):
        return [_setting_finding(
            "snmp-setting/access-setting/version",
            "v3 only",
            "v1/v2 present",
        )]

    return []

def check_snmp_polling_v3(xml_root, rules):
    v3_paths = [
        "/config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v3",
        "/config/devices/entry/deviceconfig/system/snmp/setting/access-setting/version/v3",
    ]
    legacy_paths = [
        "/config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v1",
        "/config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v2",
        "/config/devices/entry/deviceconfig/system/snmp-setting/access-setting/version/v2c",
        "/config/devices/entry/deviceconfig/system/snmp/setting/access-setting/version/v1",
        "/config/devices/entry/deviceconfig/system/snmp/setting/access-setting/version/v2",
        "/config/devices/entry/deviceconfig/system/snmp/setting/access-setting/version/v2c",
    ]

    v3_present = _any_xpath_exists(xml_root, v3_paths)
    legacy_present = _any_xpath_exists(xml_root, legacy_paths)

    if not v3_present:
        return [_setting_finding(
            "snmp-setting/access-setting/version",
            "v3",
            "",
        )]

    if legacy_present:
        return [_setting_finding(
            "snmp-setting/access-setting/version",
            "v3 only",
            "v1/v2 present",
        )]

    return []


# -------------------------------------------------------------------
# DEVICE SERVICES (CIS)
# -------------------------------------------------------------------

def check_verify_update_server_identity(xml_root, rules):
    value = _first_xpath_text(
        xml_root,
        [
            "/config/devices/entry/deviceconfig/system/verify-update-server-identity",
            "/config/devices/entry/deviceconfig/system/verify-update-server",
            "/config/devices/entry/deviceconfig/system/verify-update-server-identity/enable",
            "/config/devices/entry/deviceconfig/system/update-server/verify-identity",
            "/config/devices/entry/deviceconfig/system/update-server/server-verification",
            "/config/devices/entry/deviceconfig/system/server-verification",
        ],
    )

    if value == "no":
        return [_setting_finding(
            "verify-update-server-identity",
            "yes",
            value,
        )]

    return []
