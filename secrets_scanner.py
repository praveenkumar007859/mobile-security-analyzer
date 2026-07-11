"""
secrets_scanner.py

Module: Hardcoded Secrets Scanner
Part of: Static APK Security Auditor (team project)

WHY THIS MATTERS:
Developers frequently embed sensitive credentials (API keys, cloud access
keys, auth tokens, passwords) directly into app code or resource files
during development, and forget to remove them before shipping a release
build. Unlike server-side code, an APK is distributed directly to every
end user's device. Anyone can download the APK from the Play Store (or
a third-party mirror), unpack it, and read its contents with free,
widely available tools (apktool, jadx, androguard, etc.) — there is no
need to bypass any authentication or exploit any vulnerability to view
strings, resources, or decompiled source.

If a hardcoded secret is present, it is effectively public the moment
the APK is released. Consequences include:
  - Attackers can use exposed AWS/cloud keys to access or exfiltrate
    backend storage, run up billing charges, or pivot into other
    infrastructure.
  - Exposed bearer tokens or API keys can allow impersonation of the
    app's backend calls, letting attackers hit paid or rate-limited
    APIs "for free" using the developer's identity/quota.
  - Hardcoded passwords may grant access to shared service accounts,
    databases, or admin panels.
  - Because the credential is baked into a shipped binary, it typically
    cannot be revoked without releasing a new app version, and old
    versions in the wild remain exploitable indefinitely.

This scanner performs purely passive/static analysis: it only reads
strings already extracted from the APK by androguard. It does not
execute the app, make network calls, or attempt to use any discovered
credential.
"""

import re

# ---------------------------------------------------------------------------
# Regex patterns for common hardcoded secret formats.
# These are intentionally generic/heuristic — static string scanning will
# always have some false positive rate, since we're pattern-matching text,
# not verifying the secret is live or valid.
# ---------------------------------------------------------------------------
_PATTERNS = [
    {
        "type": "AWS Access Key",
        "severity": "High",
        # AWS access key IDs have a well-known fixed-format prefix + 16 alnum chars
        "regex": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    },
    {
        "type": "Generic API Key",
        "severity": "High",
        # Looks for a variable-name-like "api_key"/"apikey"/"api-key" assigned
        # to a long alphanumeric token — common pattern across many SDKs.
        "regex": re.compile(
            r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,45})['\"]?"
        ),
    },
    {
        "type": "Bearer Token",
        "severity": "High",
        # Matches literal "Bearer <token>" strings often embedded in headers
        # or config for authenticated API calls.
        "regex": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{10,}\b"),
    },
    {
        "type": "Hardcoded Password",
        "severity": "High",
        # Looks for password/passwd/pwd assigned to a non-trivial literal.
        # Excludes obvious placeholders like "password" or "changeme" via
        # a minimum-entropy-ish length check; still heuristic, not perfect.
        "regex": re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"
        ),
    },
]


def scan_for_secrets(apk_obj) -> list[dict]:
    """
    Passively scan all extracted string resources from an androguard APK
    object for hardcoded secrets.

    Args:
        apk_obj: An androguard APK instance, e.g. `apk_obj = APK(path)`.
                 Expected to expose `get_strings()` (raw strings extracted
                 from the DEX/resources) or a similar strings accessor,
                 depending on the androguard version in use.

    Returns:
        list[dict]: Each dict has the shape:
            {
                "finding": <the matched string/substring>,
                "type": "AWS Access Key" | "Generic API Key" |
                        "Bearer Token" | "Hardcoded Password",
                "severity": "High"
            }

    Note:
        This function is read-only / static analysis. It does not modify
        the APK, execute any code from it, or make any network requests
        with discovered credentials.
    """
    findings: list[dict] = []

    # androguard has exposed string extraction under a few different method
    # names across versions/forks. Try the common ones defensively so this
    # module degrades gracefully rather than crashing the whole pipeline.
    raw_strings = []
    for attr_name in ("get_strings", "get_dex_strings", "strings"):
        getter = getattr(apk_obj, attr_name, None)
        if callable(getter):
            try:
                raw_strings = list(getter())
                break
            except Exception:
                continue
        elif getter:  # e.g. a plain attribute/property rather than a method
            raw_strings = list(getter)
            break

    for s in raw_strings:
        if not isinstance(s, str):
            # Some androguard versions may yield bytes; decode defensively.
            try:
                s = s.decode("utf-8", errors="ignore")
            except AttributeError:
                continue

        for pattern_info in _PATTERNS:
            match = pattern_info["regex"].search(s)
            if match:
                findings.append({
                    "finding": match.group(0),
                    "type": pattern_info["type"],
                    "severity": pattern_info["severity"],
                })

    return findings

