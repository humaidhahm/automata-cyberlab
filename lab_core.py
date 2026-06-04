from __future__ import annotations

from dataclasses import dataclass
from math import log10, log2
from urllib.parse import unquote

CRACK_GUESSES_PER_SECOND = 10_000_000_000

DEFAULT_TRACE = [
    "Ready.",
    "Pick any checker to evaluate the current input.",
    "Open a DFA diagram only when you need it.",
]

SQLI_SIGNATURES = [
    ("SQL comment", "--"),
    ("Statement chaining", ";"),
    ("OR always true", "or 1=1"),
    ("UNION extraction", "union select"),
    ("DROP TABLE", "drop table"),
    ("EXEC command", "xp_cmdshell"),
    ("Tautology quote", "' or '"),
    ("Tautology quote", '" or "'),
]

XSS_SIGNATURES = [
    ("Script tag", "<script"),
    ("Encoded script tag", "%3cscript"),
    ("Javascript URI", "javascript:"),
    ("Event handler", "onerror="),
    ("Event handler", "onload="),
    ("DOM cookie access", "document.cookie"),
    ("Alert payload", "alert("),
]

RULES = {
    "email": {
        "title": "Validate Email Rules",
        "text": "- Local part starts with a letter or digit\n- Local part may contain letters, digits, and '.'\n- Must include '@' after local part\n- Domain part uses letters and one '.' before TLD\n- TLD uses letters only",
    },
    "phone": {
        "title": "Validate Phone Rules",
        "text": "- Exactly 10 characters\n- Every character must be a digit (0-9)",
    },
    "password": {
        "title": "Validate Password Rules",
        "text": "- Length must be at least 8\n- At least one uppercase letter\n- At least one lowercase letter\n- At least one digit\n\nThis checker also shows an estimated brute-force crack time.",
    },
    "ipv4": {
        "title": "Validate IPv4 Rules",
        "text": "- Format must be A.B.C.D\n- Exactly 4 octets\n- Each octet is numeric only\n- Each octet value must be 0 to 255\n- Leading zeros are not allowed (except single 0)",
    },
    "sqli": {
        "title": "SQL Injection Detector Rules",
        "text": "- Normalizes case and spacing\n- Looks for signatures such as '--', 'or 1=1', 'union select', and 'drop table'\n- Flags odd number of single quotes\n- ALERT means indicators were found",
    },
    "xss": {
        "title": "XSS Detector Rules",
        "text": "- URL-decodes payload before scanning\n- Looks for '<script', 'javascript:', event handlers, and script-like payloads\n- ALERT means indicators were found",
    },
}

CHECKERS = ("email", "phone", "password", "ipv4", "sqli", "xss")


@dataclass(slots=True)
class CheckResult:
    ok: bool
    trace: list[str]
    summary: str


def safe_decode(text: str) -> str:
    try:
        return unquote(text)
    except Exception:
        return text


def format_duration_from_log10_seconds(log10_seconds: float) -> str:
    if log10_seconds < 0:
        return "less than 1 second"

    units = [
        ("second", 0.0),
        ("minute", log10(60)),
        ("hour", log10(3600)),
        ("day", log10(86400)),
        ("year", log10(31557600)),
    ]

    unit_name = "second"
    unit_log = 0.0
    for name, threshold in units:
        if log10_seconds >= threshold:
            unit_name = name
            unit_log = threshold

    value_log = log10_seconds - unit_log
    if value_log <= 6:
        value = 10 ** value_log
        if value >= 100:
            value_text = f"{value:,.0f}"
        elif value >= 10:
            value_text = f"{value:.1f}"
        else:
            value_text = f"{value:.2f}"
    else:
        value_text = f"10^{value_log:.2f}"

    plural = "" if value_text == "1" else "s"
    return f"{value_text} {unit_name}{plural}"


def estimate_password_crack_time(password: str) -> tuple[str, list[str]]:
    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)

    pool_size = 0
    categories: list[str] = []

    if has_lower:
        pool_size += 26
        categories.append("lowercase")
    if has_upper:
        pool_size += 26
        categories.append("uppercase")
    if has_digit:
        pool_size += 10
        categories.append("digits")
    if has_symbol:
        pool_size += 33
        categories.append("symbols")

    if pool_size == 0:
        return "Estimated crack time: not available", ["Input has no usable characters."]

    entropy_bits = len(password) * log2(pool_size)
    log10_seconds = (entropy_bits - 1 - log2(CRACK_GUESSES_PER_SECOND)) / log2(10)
    details = [
        f"Assumed attacker speed: {CRACK_GUESSES_PER_SECOND:,} guesses/second",
        f"Character pool size: {pool_size} ({', '.join(categories)})",
        f"Estimated entropy: {entropy_bits:.1f} bits",
        "Model: pure brute-force search (real-world cracking can be faster or slower).",
    ]

    summary = f"Estimated crack time: about {format_duration_from_log10_seconds(log10_seconds)}"
    return summary, details


def validate_email(email: str) -> CheckResult:
    trace: list[str] = []
    state = "q0"

    for ch in email:
        if state == "q0":
            if ch.isalnum():
                trace.append(f"q0 -- {ch} --> q1")
                state = "q1"
            else:
                trace.append(f"q0 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid local part start.")
        elif state == "q1":
            if ch.isalnum() or ch == ".":
                trace.append(f"q1 -- {ch} --> q1")
            elif ch == "@":
                trace.append("q1 -- @ --> q2")
                state = "q2"
            else:
                trace.append(f"q1 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid local part character.")
        elif state == "q2":
            if ch.isalpha():
                trace.append(f"q2 -- {ch} --> q3")
                state = "q3"
            else:
                trace.append(f"q2 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid domain start.")
        elif state == "q3":
            if ch.isalpha():
                trace.append(f"q3 -- {ch} --> q3")
            elif ch == ".":
                trace.append("q3 -- . --> q4")
                state = "q4"
            else:
                trace.append(f"q3 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid domain character.")
        elif state == "q4":
            if ch.isalpha():
                trace.append(f"q4 -- {ch} --> q5")
                state = "q5"
            else:
                trace.append(f"q4 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid TLD start.")
        elif state == "q5":
            if ch.isalpha():
                trace.append(f"q5 -- {ch} --> q5")
            else:
                trace.append(f"q5 -- {ch} --> reject")
                return CheckResult(False, trace, "Rejected: invalid TLD character.")

    if state == "q5":
        return CheckResult(True, trace, "Accepted: valid email string.")
    return CheckResult(False, trace, "Rejected: incomplete email format.")


def validate_phone(phone: str) -> CheckResult:
    trace: list[str] = []
    state = 0

    for ch in phone:
        if ch.isdigit() and state < 10:
            trace.append(f"q{state} -- {ch} --> q{state + 1}")
            state += 1
        else:
            trace.append(f"q{state} -- {ch} --> reject")
            return CheckResult(False, trace, "Rejected: phone must contain exactly 10 digits.")

    if state == 10:
        return CheckResult(True, trace, "Accepted: valid 10-digit phone number.")
    return CheckResult(False, trace, "Rejected: phone must contain exactly 10 digits.")


def validate_password(password: str) -> CheckResult:
    trace: list[str] = []
    has_upper = False
    has_lower = False
    has_digit = False

    for ch in password:
        if ch.isupper():
            has_upper = True
            trace.append(f"Read {ch}: uppercase")
        elif ch.islower():
            has_lower = True
            trace.append(f"Read {ch}: lowercase")
        elif ch.isdigit():
            has_digit = True
            trace.append(f"Read {ch}: digit")
        else:
            trace.append(f"Read {ch}: special character")

    trace.append("")
    trace.append(f"Length >= 8: {'yes' if len(password) >= 8 else 'no'}")
    trace.append(f"Contains uppercase: {'yes' if has_upper else 'no'}")
    trace.append(f"Contains lowercase: {'yes' if has_lower else 'no'}")
    trace.append(f"Contains digit: {'yes' if has_digit else 'no'}")

    ok = len(password) >= 8 and has_upper and has_lower and has_digit
    if ok:
        return CheckResult(True, trace, "Accepted: password matches all conditions.")
    return CheckResult(False, trace, "Rejected: password does not meet all conditions.")


def validate_ipv4(ip_address: str) -> CheckResult:
    trace: list[str] = []
    octets = ip_address.split(".")

    if len(octets) != 4:
        trace.append("q0 -- invalid-octet-count --> reject")
        return CheckResult(False, trace, "Rejected: IPv4 address must have 4 octets.")

    for index, octet in enumerate(octets):
        source = f"q{index}"
        target = f"q{index + 1}"

        if not octet:
            trace.append(f"{source} -- empty-octet --> reject")
            return CheckResult(False, trace, "Rejected: empty IPv4 octet is not allowed.")

        if not octet.isdigit():
            trace.append(f"{source} -- {octet} --> reject")
            return CheckResult(False, trace, "Rejected: IPv4 octets must be numeric.")

        if len(octet) > 1 and octet.startswith("0"):
            trace.append(f"{source} -- {octet} --> reject")
            return CheckResult(False, trace, "Rejected: leading zeros are not allowed in IPv4 octets.")

        value = int(octet, 10)
        if value < 0 or value > 255:
            trace.append(f"{source} -- {octet} --> reject")
            return CheckResult(False, trace, "Rejected: each IPv4 octet must be in range 0-255.")

        trace.append(f"{source} -- {octet} --> {target}")

    return CheckResult(True, trace, "Accepted: valid IPv4 address.")


def detect_sqli_pattern(payload: str) -> CheckResult:
    trace: list[str] = []
    normalized = " ".join(payload.lower().split())

    trace.append("q0 -- normalize-input --> q1")

    hits: list[str] = []
    for rule_name, signature in SQLI_SIGNATURES:
        if signature in normalized:
            hits.append(f"{rule_name}: {signature}")
            trace.append(f"q1 -- signature({signature}) --> q_alert")

    quote_count = payload.count("'")
    if quote_count % 2 == 1:
        hits.append("Unbalanced single quote")
        trace.append("q1 -- odd single quote count --> q_alert")

    if hits:
        trace.append("")
        trace.append("Indicators detected:")
        trace.extend(f"- {hit}" for hit in hits)
        return CheckResult(False, trace, "Alert: potential SQL injection signature detected.")

    trace.append("q1 -- no-signature --> q_safe")
    return CheckResult(True, trace, "Safe: no obvious SQL injection signature detected.")


def detect_xss_pattern(payload: str) -> CheckResult:
    trace: list[str] = []
    decoded = safe_decode(safe_decode(payload))
    normalized = " ".join(decoded.lower().split())

    trace.append("q0 -- decode-and-normalize --> q1")

    hits: list[str] = []
    for rule_name, signature in XSS_SIGNATURES:
        if signature in normalized:
            hits.append(f"{rule_name}: {signature}")
            trace.append(f"q1 -- signature({signature}) --> q_alert")

    if hits:
        trace.append("")
        trace.append("Indicators detected:")
        trace.extend(f"- {hit}" for hit in hits)
        return CheckResult(False, trace, "Alert: potential XSS payload signature detected.")

    trace.append("q1 -- no-signature --> q_safe")
    return CheckResult(True, trace, "Safe: no obvious XSS signature detected.")


def run_check(kind: str, value: str) -> CheckResult:
    if kind == "email":
        return validate_email(value)
    if kind == "phone":
        return validate_phone(value)
    if kind == "password":
        return validate_password(value)
    if kind == "ipv4":
        return validate_ipv4(value)
    if kind == "sqli":
        return detect_sqli_pattern(value)
    if kind == "xss":
        return detect_xss_pattern(value)
    raise ValueError(f"Unknown checker: {kind}")


def diagram_text(kind: str) -> str:
    if kind == "email":
        return "\n".join(
            [
                "Email DFA",
                "",
                "start -> q0 -> q1 -> q2 -> q3 -> q4 -> q5 [accept]",
                "q0: first character must be alphanumeric",
                "q1: alphanumeric or '.'; '@' moves to q2",
                "q2: domain must start with a letter",
                "q3: letters only; '.' moves to q4",
                "q4: TLD must start with a letter",
                "q5: letters only, accept state",
            ]
        )
    if kind == "phone":
        return "\n".join(
            [
                "Phone DFA",
                "",
                "start -> q0 -> q1 -> q2 -> q3 -> q4 -> q5 -> q6 -> q7 -> q8 -> q9 -> q10 [accept]",
                "Each transition consumes exactly one digit.",
                "Any non-digit or shorter/longer input is rejected.",
            ]
        )
    if kind == "ipv4":
        return "\n".join(
            [
                "IPv4 DFA",
                "",
                "start -> q0 -> q1 -> q2 -> q3 -> q4 [accept]",
                "Each state consumes one dotted octet.",
                "Each octet must be numeric and in the range 0-255.",
                "Leading zeros are rejected unless the octet is exactly 0.",
            ]
        )
    raise ValueError(f"Unknown diagram: {kind}")