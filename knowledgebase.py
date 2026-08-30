#!/usr/bin/env python3
"""
knowledgebase.py — Vulnerability knowledge base.

Every finding the scanner can raise is defined here ONCE, keyed by a short id.
Each entry carries the mappings and the human explanation the report needs:

  cwe            : CWE id(s) (also covers SANS/CWE Top 25 where relevant)
  owasp          : OWASP category (Web Top 10 / Mobile Top 10 / Cloud)
  severity       : high | medium | low | info
  title          : short human title
  description    : what the issue IS (samajhne ke liye)
  attack         : how an attacker would exploit it (attack scenario)
  patch          : how to fix it (remediation / patch)

Scanners emit findings by id + evidence; the reporter enriches them from here.
This keeps explanations consistent and lets us cover a lot of ground without
duplicating text across web / mobile / cloud scanners.
"""

from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# KB: id -> entry
# ---------------------------------------------------------------------------
KB: dict[str, dict] = {
    # ========================= WEB (OWASP Top 10 / CWE Top 25) =============
    "web.sqli": {
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-66"],
        "root_cause": "Untrusted input concatenated into a SQL statement instead of using "
        "parameterized queries / prepared statements.",
        "severity": "high",
        "title": "SQL Injection",
        "description": "User input is concatenated into an SQL query without parameterization, "
        "so an attacker can alter the query's logic.",
        "attack": "Attacker submits a crafted parameter like `' OR '1'='1` or a UNION/boolean/time-based "
        "payload. sqlmap automates this to dump databases, bypass login, or (with stacked queries) "
        "write files / run OS commands.",
        "patch": "Use parameterized queries / prepared statements (never string concatenation). "
        "Apply least-privilege DB accounts, an allow-list input validation, and an ORM where possible.",
    },
    "web.xss.reflected": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection (XSS)",
        "capec": ["CAPEC-63", "CAPEC-591"],
        "root_cause": "Request input echoed into the response without context-aware output encoding.",
        "severity": "medium",
        "title": "Reflected Cross-Site Scripting (XSS)",
        "description": "Request input is echoed back into the HTML response without output encoding.",
        "attack": "Attacker crafts a URL containing `<script>...</script>` and tricks a victim into clicking it. "
        "The script runs in the victim's session — stealing cookies/tokens, performing actions as the user, "
        "or keylogging.",
        "patch": "Context-aware output encoding (HTML/JS/attribute/URL), a strict Content-Security-Policy, "
        "and framework auto-escaping (e.g. Jinja, React). Validate and sanitize input server-side.",
    },
    "web.header.csp": {
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Missing Content-Security-Policy",
        "description": "No CSP header, so the browser has no policy restricting where scripts/resources load from.",
        "attack": "If any XSS sink exists, absence of CSP means injected scripts and external payloads execute "
        "freely; also enables data exfiltration to attacker domains.",
        "patch": "Set a restrictive `Content-Security-Policy` (e.g. `default-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'`). Avoid `unsafe-inline`/`unsafe-eval`; use nonces/hashes.",
    },
    "web.header.hsts": {
        "cwe": "CWE-319",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "medium",
        "title": "Missing HTTP Strict-Transport-Security",
        "description": "No HSTS header, so browsers may connect over plaintext HTTP.",
        "attack": "On a shared/hostile network, an attacker performs SSL-strip / man-in-the-middle, downgrading "
        "the victim to HTTP and intercepting credentials and session cookies.",
        "patch": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` over HTTPS and "
        "redirect all HTTP to HTTPS.",
    },
    "web.header.xfo": {
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
        "description": "Page can be embedded in an iframe by any site.",
        "attack": "Attacker frames the site invisibly over a decoy UI (clickjacking) so the victim's clicks trigger "
        "sensitive actions (transfers, permission grants) without realizing it.",
        "patch": "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and/or CSP `frame-ancestors 'none'`.",
    },
    "web.header.nosniff": {
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "low",
        "title": "Missing X-Content-Type-Options: nosniff",
        "description": "Browser may MIME-sniff responses instead of trusting the declared Content-Type.",
        "attack": "An uploaded/user-controlled file served with a benign type can be sniffed and executed as HTML/JS, "
        "leading to stored XSS.",
        "patch": "Send `X-Content-Type-Options: nosniff` on all responses.",
    },
    "web.header.referrer": {
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "description": "Full URLs (possibly with tokens) may be leaked in the Referer header to third parties.",
        "attack": "Sensitive query-string data (session ids, reset tokens) leaks to external analytics/ad domains "
        "via Referer.",
        "patch": "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
    },
    "web.header.permissions": {
        "cwe": "CWE-693",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "description": "Powerful browser features (camera, mic, geolocation) are not restricted.",
        "attack": "A compromised third-party script or XSS can silently access device features.",
        "patch": "Set a `Permissions-Policy` disabling unused features, e.g. `geolocation=(), camera=(), microphone=()`.",
    },
    "web.cookie.flags": {
        "cwe": "CWE-614",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Insecure cookie flags",
        "description": "Session cookie missing Secure / HttpOnly / SameSite attributes.",
        "attack": "Missing HttpOnly lets XSS read the cookie; missing Secure lets it leak over HTTP; missing "
        "SameSite enables CSRF. Combined, the session can be hijacked.",
        "patch": "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`). Scope with `Path`/`Domain` and "
        "short expiry.",
    },
    "web.infoleak": {
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "low",
        "title": "Technology/version disclosure",
        "description": "Response headers reveal server software and versions (Server, X-Powered-By).",
        "attack": "Attacker fingerprints exact versions and looks up matching public CVEs/exploits to target the stack.",
        "patch": "Remove/obfuscate version banners (`server_tokens off;`, unset `X-Powered-By`).",
    },
    "web.fileupload": {
        "cwe": "CWE-434",
        "owasp": "A04:2021 Insecure Design / A05 Misconfiguration",
        "severity": "medium",
        "title": "Unrestricted file upload surface",
        "description": "A file-upload endpoint exists; if server-side validation is weak it is dangerous.",
        "attack": "Attacker uploads a web shell (e.g. `.php`, `.jsp`) or a polyglot file; if stored in a web-served "
        "path and executed, they gain remote code execution.",
        "patch": "Validate type by content (magic bytes) not extension, store outside webroot, randomize names, "
        "serve with `Content-Disposition: attachment`, scan with AV, and cap size.",
    },
    "web.tls.weak": {
        "cwe": "CWE-326",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "high",
        "title": "Weak TLS/SSL configuration",
        "description": "Deprecated protocols/ciphers (SSLv3, TLS 1.0/1.1, RC4) or expired/invalid certificate.",
        "attack": "Attacker exploits protocol/cipher weaknesses (POODLE, BEAST) or an invalid cert to intercept or "
        "decrypt traffic via MITM.",
        "patch": "Enable only TLS 1.2/1.3 with strong ciphers (AEAD), valid cert with full chain, OCSP stapling, and "
        "HSTS.",
    },
    "web.open_port": {
        "cwe": "CWE-668",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "info",
        "title": "Exposed network service",
        "description": "An open port/service was discovered and its version fingerprinted.",
        "attack": "Attacker maps the attack surface and probes exposed services (DB, admin, RDP) for default creds "
        "or version-specific CVEs.",
        "patch": "Close unused ports, firewall/allow-list management services, put behind VPN, and patch service "
        "versions.",
    },
    "web.cve": {
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "severity": "high",
        "title": "Known CVE / vulnerable component",
        "description": "A scanner template matched a known CVE or a vulnerable/outdated component.",
        "attack": "Attacker uses the public exploit/PoC for the matched CVE to compromise the component directly.",
        "patch": "Upgrade the affected component to a fixed version; apply vendor advisories; track with SCA/SBOM.",
    },

    # ============================ MOBILE (OWASP MASVS/Mobile Top 10) =======
    "mobile.cleartext": {
        "cwe": "CWE-319",
        "owasp": "M5: Insecure Communication",
        "severity": "high",
        "title": "Cleartext traffic allowed",
        "description": "App manifest allows cleartext (HTTP) traffic (`usesCleartextTraffic=true` / permissive "
        "network security config).",
        "attack": "On any shared network the attacker MITMs the app, reading/modifying API traffic, tokens, and PII.",
        "patch": "Disable cleartext (`android:usesCleartextTraffic=\"false\"`), enforce a strict network security "
        "config, and pin certificates for sensitive APIs.",
    },
    "mobile.exported": {
        "cwe": "CWE-926",
        "owasp": "M8: Security Misconfiguration",
        "severity": "medium",
        "title": "Exported component without permission",
        "description": "An Activity/Service/Receiver/Provider is exported and reachable by other apps without a "
        "signature/permission guard.",
        "attack": "A malicious app on the device sends intents to the exported component to trigger privileged "
        "actions, leak data, or bypass authentication screens.",
        "patch": "Set `android:exported=\"false\"` unless required; protect with signature-level permissions and "
        "validate all incoming intents.",
    },
    "mobile.debuggable": {
        "cwe": "CWE-489",
        "owasp": "M8: Security Misconfiguration",
        "severity": "high",
        "title": "Debuggable build",
        "description": "App manifest has `android:debuggable=\"true\"`.",
        "attack": "Attacker with device access attaches a debugger (jdb) to the running app, inspects memory, and "
        "extracts secrets or manipulates logic.",
        "patch": "Ship release builds with `debuggable=false`; strip debug flags in the release build type.",
    },
    "mobile.backup": {
        "cwe": "CWE-530",
        "owasp": "M9: Insecure Data Storage",
        "severity": "medium",
        "title": "Application backup allowed",
        "description": "`android:allowBackup=\"true\"` lets app data be extracted via adb backup.",
        "attack": "With USB debugging, an attacker runs `adb backup` to pull the app's private data (tokens, DBs) "
        "off the device.",
        "patch": "Set `android:allowBackup=\"false\"` or define a strict backup rules set excluding sensitive files.",
    },
    "mobile.secrets": {
        "cwe": "CWE-798",
        "owasp": "M1: Improper Credential Usage / M10 Extraneous Functionality",
        "severity": "high",
        "title": "Hardcoded secret / API key",
        "description": "A credential, API key, or private key is embedded in the app package.",
        "attack": "Attacker unzips/decompiles the APK/IPA (apktool/jadx) and extracts the secret, then abuses the "
        "backend API, cloud account, or signing key.",
        "patch": "Never ship secrets in the client; fetch short-lived tokens from a backend, use the platform "
        "keystore/keychain, and rotate any exposed keys immediately.",
    },
    "mobile.perms": {
        "cwe": "CWE-250",
        "owasp": "M8: Security Misconfiguration",
        "severity": "low",
        "title": "Excessive / dangerous permissions",
        "description": "App requests broad or dangerous permissions beyond its apparent need.",
        "attack": "If the app is compromised (or malicious), the granted permissions expand impact — reading SMS, "
        "location tracking, contact exfiltration.",
        "patch": "Request the minimum permissions, justify each, and prefer runtime permissions with clear scope.",
    },

    # ============================ CLOUD (OWASP Cloud / CIS) ================
    "cloud.public_bucket": {
        "cwe": "CWE-732",
        "owasp": "Cloud: Insecure Storage / A01 Broken Access Control",
        "severity": "high",
        "title": "Publicly accessible storage bucket",
        "description": "Object storage (S3/GCS/Blob) is world-readable or world-writable.",
        "attack": "Attacker enumerates the bucket and downloads all objects (data breach) or uploads malicious "
        "content; public write can enable defacement or malware hosting.",
        "patch": "Block public access at account+bucket level, use least-privilege bucket policies/IAM, and enable "
        "access logging + encryption at rest.",
    },
    "cloud.open_sg": {
        "cwe": "CWE-284",
        "owasp": "Cloud: Broken Access Control",
        "severity": "high",
        "title": "Security group open to the world (0.0.0.0/0)",
        "description": "A firewall/security-group rule exposes a sensitive port to the entire internet.",
        "attack": "Attacker directly reaches exposed SSH/RDP/DB ports and brute-forces credentials or hits "
        "version-specific CVEs.",
        "patch": "Restrict ingress to known CIDRs/bastion, close DB/admin ports publicly, and use a VPN or "
        "zero-trust access.",
    },
    "cloud.unencrypted": {
        "cwe": "CWE-311",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "medium",
        "title": "Unencrypted data store / volume",
        "description": "A database, volume, or bucket lacks encryption at rest.",
        "attack": "If the underlying storage/snapshot is exposed or stolen, data is readable in plaintext.",
        "patch": "Enable encryption at rest (KMS-managed keys), enforce via policy (SCP/Config rules), and encrypt "
        "snapshots/backups.",
    },
    "cloud.iam_wildcard": {
        "cwe": "CWE-269",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
        "title": "Over-permissive IAM policy (wildcard)",
        "description": "An IAM policy grants `Action:*` and/or `Resource:*` (admin-equivalent).",
        "attack": "If any principal/key with this policy is phished or leaked, the attacker gains full account "
        "control — privilege escalation and lateral movement.",
        "patch": "Apply least privilege: scope actions and resources, use permission boundaries, and review with "
        "IAM Access Analyzer.",
    },
    "cloud.public_ip": {
        "cwe": "CWE-668",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "medium",
        "title": "Instance/DB with public IP",
        "description": "A compute instance or managed DB is directly internet-exposed.",
        "attack": "Attacker scans the public IP, fingerprints services, and attacks exposed management/DB ports.",
        "patch": "Place workloads in private subnets, use NAT/bastion for egress, and expose only via a load "
        "balancer/WAF.",
    },
    "cloud.no_mfa": {
        "cwe": "CWE-308",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "severity": "high",
        "title": "MFA not enforced on privileged accounts",
        "description": "Root/admin or IAM users lack multi-factor authentication.",
        "attack": "A single leaked/phished password gives the attacker full console access with no second factor.",
        "patch": "Enforce MFA for all human accounts (especially root/admin), prefer SSO/federation, and disable "
        "unused long-lived access keys.",
    },
    "cloud.logging_off": {
        "cwe": "CWE-778",
        "owasp": "A09:2021 Security Logging & Monitoring Failures",
        "severity": "medium",
        "title": "Audit logging disabled",
        "description": "Cloud audit logging (CloudTrail / Cloud Audit Logs / Activity Log) is off or incomplete.",
        "attack": "Attacker operates without leaving traces, and the breach goes undetected and un-investigable.",
        "patch": "Enable multi-region audit logging to an immutable, access-controlled bucket with alerting on "
        "sensitive events.",
    },

    # ============================ NETWORK / HOST / INFRA ===================
    "network.vuln_service": {
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "severity": "high",
        "title": "Vulnerable network service (nmap NSE)",
        "description": "An nmap 'vuln' NSE script flagged a network service as vulnerable to a known issue.",
        "attack": "Attacker targets the exact service/version with the matching public exploit to gain access or "
        "crash/abuse the service.",
        "patch": "Patch/upgrade the affected service to a fixed version, restrict network exposure, and re-scan to "
        "confirm remediation.",
    },
    "network.exposed_service": {
        "cwe": "CWE-668",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "info",
        "title": "Exposed network service",
        "description": "An open port and its service/version were discovered on the host.",
        "attack": "Attacker maps the attack surface and probes exposed services (DB, RDP, SMB, admin panels) for "
        "default creds or version CVEs.",
        "patch": "Close unused ports, firewall/allow-list management services, and put sensitive services behind a "
        "VPN/bastion.",
    },
    "network.exploit_known": {
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "severity": "high",
        "title": "Component with a known public exploit / actively exploited CVE",
        "description": "A detected component matches a CVE that is actively exploited (CISA KEV) or has a public "
        "exploit entry.",
        "attack": "Because a working public exploit exists (and may be used in real-world attacks), an attacker can "
        "compromise the component with minimal effort. These are top-priority.",
        "patch": "Treat as urgent: apply the vendor patch immediately, isolate the host until patched, and verify "
        "against the CVE advisory.",
    },

    # ============================ SOURCE CODE / DEPENDENCIES (SCA) =========
    "code.dep_cve": {
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "severity": "high",
        "title": "Vulnerable dependency (SCA)",
        "description": "A third-party library/package in the project has a known CVE.",
        "attack": "Attacker exploits the known flaw in the bundled dependency (e.g. RCE/deserialization) via input "
        "that reaches the vulnerable code path.",
        "patch": "Upgrade to the fixed version indicated by the advisory; pin versions, enable Dependabot/renovate, "
        "and track an SBOM.",
    },
    "code.secret": {
        "cwe": "CWE-798",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "severity": "high",
        "title": "Secret committed in source",
        "description": "A credential, token, or private key was found committed in the source tree/history.",
        "attack": "Attacker scrapes the repo (or its git history) and uses the leaked secret to access the backend, "
        "cloud account, or signing infrastructure.",
        "patch": "Revoke and rotate the secret immediately, remove it from history (git filter-repo/BFG), and move "
        "secrets to a vault / environment injection.",
    },
    "code.sast": {
        "cwe": "CWE-710",
        "owasp": "A04:2021 Insecure Design",
        "severity": "medium",
        "title": "Insecure code pattern (SAST)",
        "description": "Static analysis flagged an insecure coding pattern (e.g. injection sink, weak crypto, unsafe "
        "deserialization).",
        "attack": "Depending on the sink, an attacker supplies crafted input to trigger injection, RCE, or data "
        "exposure through the flagged code path.",
        "patch": "Refactor the flagged pattern per the analyzer's guidance (parameterize, validate, use safe APIs) "
        "and add a regression test.",
    },

    # ============================ CONTAINER IMAGES =========================
    "container.cve": {
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable & Outdated Components",
        "severity": "high",
        "title": "Vulnerable OS/package in container image",
        "description": "The container image ships OS or language packages with known CVEs.",
        "attack": "Attacker exploits a vulnerable package inside a running container to escalate, break out, or move "
        "laterally within the cluster.",
        "patch": "Rebuild on an updated/minimal base image, upgrade affected packages, and gate builds on an image "
        "scan (fail on High/Critical).",
    },
    "container.misconfig": {
        "cwe": "CWE-250",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Container misconfiguration",
        "description": "The image/Dockerfile has a risky setting (runs as root, secrets in layers, no USER, etc.).",
        "attack": "Running as root magnifies the impact of any in-container compromise, easing container breakout "
        "and host access.",
        "patch": "Add a non-root USER, drop capabilities, avoid embedding secrets in layers, and use read-only root "
        "filesystems.",
    },

    # ============================ RECON / ATTACK SURFACE (bug bounty) ======
    "recon.subdomain": {
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control / Recon",
        "severity": "info",
        "title": "Discovered subdomain / asset",
        "description": "A live subdomain or host belonging to the target was discovered during enumeration.",
        "attack": "Attackers map every asset first; forgotten/staging/admin subdomains often have weaker security "
        "than the main site and become the entry point.",
        "patch": "Maintain an asset inventory, decommission unused hosts, and apply the same security baseline "
        "(auth, patching, WAF) to every subdomain.",
    },
    "recon.subdomain_takeover": {
        "cwe": "CWE-350",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "high",
        "title": "Subdomain takeover (dangling DNS)",
        "description": "A subdomain's DNS points to a de-provisioned third-party service (S3, GitHub Pages, Heroku, "
        "Azure, etc.) that can be claimed.",
        "attack": "Attacker registers the unclaimed service resource and serves their own content on your subdomain "
        "— phishing, cookie theft, or bypassing same-site protections.",
        "patch": "Remove the dangling DNS record immediately, or re-claim the resource. Audit CNAMEs regularly and "
        "delete records when services are torn down.",
    },
    "recon.exposed_panel": {
        "cwe": "CWE-284",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "medium",
        "title": "Exposed admin / login / management panel",
        "description": "An administrative or management interface is reachable from the internet.",
        "attack": "Attacker finds the panel, then brute-forces credentials, uses default creds, or hits panel-"
        "specific CVEs to gain privileged access.",
        "patch": "Restrict panels to VPN/allow-listed IPs, enforce strong auth + MFA, rename default paths, and "
        "monitor login attempts.",
    },
    "recon.dir_listing": {
        "cwe": "CWE-548",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Directory listing / exposed files",
        "description": "The server returns directory indexes or content discovery found sensitive files/paths.",
        "attack": "Attacker browses exposed directories to harvest backups, configs, source, or credentials that "
        "shouldn't be public.",
        "patch": "Disable autoindex, remove sensitive files from web roots, and return 404 for non-public paths.",
    },
    "recon.js_secret": {
        "cwe": "CWE-615",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "severity": "high",
        "title": "Secret / endpoint leaked in client-side JS",
        "description": "Front-end JavaScript exposes API keys, tokens, or internal endpoints.",
        "attack": "Attacker reads bundled JS, extracts keys/endpoints, and calls internal APIs or abuses the leaked "
        "credential directly.",
        "patch": "Never embed secrets client-side; proxy sensitive calls through a backend, rotate exposed keys, and "
        "restrict keys by origin/scope.",
    },
    "recon.interesting_url": {
        "cwe": "CWE-200",
        "owasp": "Recon / Information Disclosure",
        "severity": "info",
        "title": "Interesting URL / parameter",
        "description": "Crawling / archive collection surfaced URLs or parameters worth manual review.",
        "attack": "Attackers mine historical and crawled URLs for parameters vulnerable to injection, IDOR, open "
        "redirect, or SSRF.",
        "patch": "Review and validate all parameters server-side; retire legacy endpoints; enforce authorization "
        "checks on every object reference.",
    },
    "recon.waf": {
        "cwe": "N/A",
        "owasp": "Recon",
        "severity": "info",
        "title": "WAF / security control detected",
        "description": "A Web Application Firewall or protective control was fingerprinted in front of the target.",
        "attack": "Attackers profile the WAF to craft bypasses; its presence also tells them which payloads to "
        "obfuscate.",
        "patch": "Keep WAF rules tuned and updated; do not rely on it as the only control (defense in depth).",
    },

    # ============================ API (OWASP API Security Top 10) ==========
    "api.no_auth": {
        "cwe": "CWE-306",
        "owasp": "API2:2023 Broken Authentication",
        "severity": "high",
        "title": "API endpoint reachable without authentication",
        "description": "An API endpoint returned data/functionality without requiring credentials.",
        "attack": "Attacker calls the endpoint directly (no token) to read or modify data — the classic broken-"
        "authentication / missing-authZ API bug.",
        "patch": "Require authentication on every non-public endpoint; enforce authorization server-side per object "
        "(prevent BOLA/IDOR); deny by default.",
    },
    "api.cors": {
        "cwe": "CWE-942",
        "owasp": "API8:2023 Security Misconfiguration",
        "severity": "medium",
        "title": "Overly permissive CORS",
        "description": "The API reflects arbitrary Origins or allows credentials with a wildcard origin.",
        "attack": "A malicious site makes credentialed cross-origin requests and reads the responses, exfiltrating "
        "the victim's API data.",
        "patch": "Allow-list specific trusted origins; never combine `Access-Control-Allow-Origin: *` with "
        "`Allow-Credentials: true`.",
    },
    "api.verb": {
        "cwe": "CWE-650",
        "owasp": "API8:2023 Security Misconfiguration",
        "severity": "low",
        "title": "Dangerous HTTP methods enabled",
        "description": "The endpoint advertises state-changing methods (PUT/DELETE/TRACE) via OPTIONS/Allow.",
        "attack": "Attacker uses an unexpected verb to modify/delete resources or leverages TRACE for XST.",
        "patch": "Disable unused methods; restrict PUT/DELETE to authenticated, authorized callers; disable TRACE.",
    },
    "api.graphql_introspection": {
        "cwe": "CWE-200",
        "owasp": "API8:2023 Security Misconfiguration",
        "severity": "medium",
        "title": "GraphQL introspection enabled",
        "description": "The GraphQL endpoint answers introspection queries, exposing the full schema.",
        "attack": "Attacker downloads the schema to map every type/mutation, accelerating discovery of sensitive "
        "queries and injection points.",
        "patch": "Disable introspection in production; enforce auth, depth/complexity limits, and field-level "
        "authorization.",
    },
    "api.docs_exposed": {
        "cwe": "CWE-200",
        "owasp": "API9:2023 Improper Inventory Management",
        "severity": "low",
        "title": "API documentation / spec exposed",
        "description": "A Swagger/OpenAPI/GraphQL doc endpoint is publicly reachable.",
        "attack": "Attacker reads the spec to enumerate every endpoint, parameter, and auth requirement — a recon "
        "goldmine.",
        "patch": "Restrict docs to authenticated internal users or non-production; keep an accurate API inventory.",
    },

    # ============================ KUBERNETES (CIS / NSA-CISA) ==============
    "k8s.privileged": {
        "cwe": "CWE-250",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "high",
        "title": "Privileged container",
        "description": "A workload runs with `securityContext.privileged: true` (or allowPrivilegeEscalation).",
        "attack": "A compromised privileged container has near-host capabilities — attacker escapes to the node and "
        "pivots across the cluster.",
        "patch": "Set `privileged: false`, `allowPrivilegeEscalation: false`, drop capabilities, and enforce via "
        "Pod Security Admission / policy.",
    },
    "k8s.hostpath": {
        "cwe": "CWE-552",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "high",
        "title": "hostPath volume mount",
        "description": "A pod mounts a path from the host filesystem.",
        "attack": "Attacker in the pod reads/writes host files (e.g. mounts `/` or docker socket) to escape to the "
        "node and take over the host.",
        "patch": "Avoid hostPath; use PVCs/ephemeral volumes; forbid hostPath via admission policy.",
    },
    "k8s.rbac_wildcard": {
        "cwe": "CWE-269",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "high",
        "title": "Wildcard RBAC permissions",
        "description": "A Role/ClusterRole grants `*` verbs or resources (admin-equivalent).",
        "attack": "If a bound service account is compromised, the attacker gains cluster-admin — full workload and "
        "secret access, lateral movement everywhere.",
        "patch": "Apply least-privilege RBAC (explicit verbs/resources); avoid `cluster-admin` bindings; audit with "
        "`kubectl auth can-i`.",
    },
    "k8s.no_netpol": {
        "cwe": "CWE-668",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "medium",
        "title": "No NetworkPolicy (flat pod network)",
        "description": "Namespace workloads have no NetworkPolicy, so any pod can talk to any pod.",
        "attack": "After compromising one pod, the attacker moves laterally to every other service unrestricted.",
        "patch": "Adopt default-deny NetworkPolicies and allow-list only required flows.",
    },
    "k8s.hostnet": {
        "cwe": "CWE-668",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "medium",
        "title": "hostNetwork / hostPID / hostIPC enabled",
        "description": "A pod shares the host network/PID/IPC namespace.",
        "attack": "Attacker sniffs node traffic, sees host processes, and bypasses network segmentation.",
        "patch": "Disable hostNetwork/hostPID/hostIPC unless strictly required; enforce via admission policy.",
    },

    # ============================ AVAILABILITY / RESILIENCE (safe, passive) =
    "availability.no_rate_limit": {
        "cwe": "CWE-770",
        "owasp": "API4:2023 Unrestricted Resource Consumption",
        "severity": "low",
        "title": "No rate-limiting observed",
        "description": "No rate-limit headers (X-RateLimit-*, RateLimit-*, Retry-After) were seen in "
        "responses. This is a passive signal, not proof — limits may exist without headers.",
        "attack": "Absent throttling makes credential brute-force, scraping, and resource-exhaustion (DoS) "
        "easier and cheaper for an attacker.",
        "patch": "Enforce rate limiting / quotas at the edge (WAF/API gateway) and per-account; return "
        "429 with Retry-After. Load-test capacity under authorization.",
    },
    "availability.no_edge_protection": {
        "cwe": "CWE-1188",
        "owasp": "Cloud: Security Misconfiguration",
        "severity": "info",
        "title": "No WAF/CDN edge protection detected",
        "description": "No CDN/WAF fingerprints (Cloudflare, Akamai, Fastly, AWS, etc.) were observed in "
        "response headers. Passive signal only.",
        "attack": "Without an edge layer, the origin is directly exposed to volumetric and application-layer "
        "abuse and has less absorption capacity.",
        "patch": "Front the service with a CDN/WAF that provides caching, rate limiting, and DDoS absorption; "
        "restrict the origin to the edge.",
    },
    # ============================ LINUX HOST (local privilege / config) ====
    "linux.suid": {
        "cwe": "CWE-250", "owasp": "Host Security",
        "capec": ["CAPEC-69"],
        "root_cause": "A SUID/SGID binary runs with elevated privileges; if it is a known GTFOBins "
        "binary or custom/unexpected, it can be abused to escalate.",
        "severity": "high", "title": "Dangerous SUID/SGID binary",
        "description": "A setuid/setgid binary that is known-abusable (GTFOBins) or unexpected was found.",
        "attack": "Attacker with a local shell invokes the SUID binary in its documented abuse pattern to "
        "run commands as root (local privilege escalation).",
        "patch": "Remove the setuid bit (`chmod u-s`) where not required; replace abusable binaries; "
        "restrict with AppArmor/SELinux; audit against a known-good baseline.",
    },
    "linux.sudo": {
        "cwe": "CWE-250", "owasp": "Host Security",
        "root_cause": "sudoers grants NOPASSWD or a command that can spawn a shell / write arbitrary files.",
        "severity": "high", "title": "Risky sudo configuration",
        "description": "sudo rules allow passwordless or shell-capable commands (privilege escalation vector).",
        "attack": "Attacker runs the permitted command's escape (e.g. `sudo vi`/`less`/`find -exec`) to obtain "
        "a root shell without a password.",
        "patch": "Remove NOPASSWD, avoid shell-capable commands in sudoers, scope to specific args, and "
        "review with `sudo -l` audits.",
    },
    "linux.world_writable": {
        "cwe": "CWE-732", "owasp": "Host Security",
        "root_cause": "A privileged/executed path is world-writable, allowing tampering.",
        "severity": "medium", "title": "World-writable privileged path",
        "description": "A world-writable file/dir in a sensitive/executed location was found.",
        "attack": "Attacker overwrites a script/binary that a privileged process executes, gaining code "
        "execution at higher privilege.",
        "patch": "Tighten permissions (remove world-write), set correct ownership, and monitor sensitive paths.",
    },
    "linux.cron": {
        "cwe": "CWE-732", "owasp": "Host Security",
        "root_cause": "A cron/systemd job runs a writable script or as root from an insecure path.",
        "severity": "medium", "title": "Insecure scheduled job",
        "description": "A cron/systemd job references a writable script or runs from a world-writable location.",
        "attack": "Attacker edits the writable job target so their code runs at the job's (often root) privilege.",
        "patch": "Ensure job targets are root-owned and not writable; use absolute paths; least-privilege the job.",
    },
    "linux.ssh_config": {
        "cwe": "CWE-1188", "owasp": "Host Security",
        "root_cause": "sshd permits root login or password authentication.",
        "severity": "medium", "title": "Weak SSH server configuration",
        "description": "sshd_config allows PermitRootLogin yes and/or PasswordAuthentication yes.",
        "attack": "Attacker brute-forces credentials or logs in directly as root over SSH.",
        "patch": "Set `PermitRootLogin no`, prefer key-based auth (`PasswordAuthentication no`), and rate-limit.",
    },
    "linux.capabilities": {
        "cwe": "CWE-250", "owasp": "Host Security",
        "root_cause": "A binary carries a powerful Linux capability (e.g. cap_setuid, cap_dac_override).",
        "severity": "high", "title": "Dangerous file capability",
        "description": "A file has a capability that enables privilege escalation.",
        "attack": "Attacker abuses the capability (e.g. cap_setuid+python) to elevate to root.",
        "patch": "Remove unneeded capabilities (`setcap -r`); grant the minimum capability required.",
    },
    "linux.kernel_outdated": {
        "cwe": "CWE-1035", "owasp": "A06:2021 Vulnerable & Outdated Components",
        "root_cause": "The kernel/package versions map to known local-privesc CVEs.",
        "severity": "high", "title": "Outdated kernel / vulnerable packages",
        "description": "Kernel or package versions correspond to known vulnerabilities.",
        "attack": "Attacker uses a matching public local-privesc exploit for the kernel/package version.",
        "patch": "Patch/upgrade the kernel and packages; enable unattended security updates; reboot as needed.",
    },

    # ============================ WINDOWS HOST (local privilege / exposure) =
    "windows.unquoted_service": {
        "cwe": "CWE-428", "owasp": "Host Security",
        "capec": ["CAPEC-471"],
        "root_cause": "A service binary path contains spaces and is unquoted, and an earlier path "
        "segment is writable.",
        "severity": "high", "title": "Unquoted service path",
        "description": "A Windows service has an unquoted binary path with a writable parent directory.",
        "attack": "Attacker plants a malicious executable at the earlier path segment; the service starts "
        "it as SYSTEM (local privilege escalation).",
        "patch": "Quote all service ImagePath values and remove write access on service directories.",
    },
    "windows.weak_service_perms": {
        "cwe": "CWE-732", "owasp": "Host Security",
        "root_cause": "A non-admin principal can modify a service's binary or configuration.",
        "severity": "high", "title": "Weak service permissions",
        "description": "A service's binary/config is writable by non-privileged users.",
        "attack": "Attacker replaces the service binary or reconfigures it to run their payload as SYSTEM.",
        "patch": "Restrict service binary/config ACLs to administrators; audit with accesschk.",
    },
    "windows.smb_exposed": {
        "cwe": "CWE-668", "owasp": "Network Exposure",
        "root_cause": "SMB (445) is reachable, possibly with SMBv1 or signing disabled.",
        "severity": "high", "title": "SMB exposed / weakly configured",
        "description": "SMB is reachable; SMBv1 enabled or signing not required.",
        "attack": "Attacker relays authentication (NTLM relay) or exploits SMBv1 (e.g. EternalBlue-class) "
        "for code execution / lateral movement.",
        "patch": "Disable SMBv1, require SMB signing, restrict 445 to management networks, patch.",
    },
    "windows.rdp_exposed": {
        "cwe": "CWE-668", "owasp": "Network Exposure",
        "root_cause": "RDP (3389) is reachable, possibly without NLA.",
        "severity": "medium", "title": "RDP exposed",
        "description": "RDP is reachable; Network Level Authentication may be disabled.",
        "attack": "Attacker brute-forces/relays RDP or exploits RDP CVEs for access and lateral movement.",
        "patch": "Require NLA, restrict RDP to VPN/bastion + MFA, and patch RDP CVEs.",
    },
    "windows.winrm_exposed": {
        "cwe": "CWE-668", "owasp": "Network Exposure",
        "root_cause": "WinRM (5985/5986) is reachable and usable for remote execution.",
        "severity": "medium", "title": "WinRM exposed",
        "description": "WinRM management endpoint is reachable.",
        "attack": "With valid/relayed credentials, attacker runs commands remotely (lateral movement).",
        "patch": "Restrict WinRM to management hosts, require HTTPS + strong auth, and monitor usage.",
    },
    "windows.credential_exposure": {
        "cwe": "CWE-522", "owasp": "A07:2021 Identification & Authentication Failures",
        "root_cause": "Credentials cached/stored insecurely (LSASS, autologon, unattend, cpassword).",
        "severity": "high", "title": "Credential exposure",
        "description": "Cached/stored credentials or credential material are recoverable.",
        "attack": "Attacker dumps LSASS or reads autologon/unattend/GPP cpassword to harvest credentials "
        "for privilege escalation and lateral movement.",
        "patch": "Enable Credential Guard/LSASS protection, remove autologon/unattend secrets, rotate exposed creds.",
    },
    "windows.patch_missing": {
        "cwe": "CWE-1035", "owasp": "A06:2021 Vulnerable & Outdated Components",
        "root_cause": "Missing security updates map to known exploitable CVEs.",
        "severity": "high", "title": "Missing security patches",
        "description": "The host is missing patches that correspond to known vulnerabilities.",
        "attack": "Attacker uses a public exploit for the unpatched vulnerability to gain code execution/privesc.",
        "patch": "Apply the missing security updates; establish a patch cadence; verify with a re-scan.",
    },

    "availability.amplification_surface": {
        "cwe": "CWE-406",
        "owasp": "Availability",
        "severity": "info",
        "title": "Potential amplification/abuse surface",
        "description": "An endpoint/parameter may allow expensive operations or reflection that amplify load.",
        "attack": "Attackers abuse expensive endpoints (search, export, unbounded queries) to exhaust resources "
        "with modest effort.",
        "patch": "Add pagination/limits, cache expensive responses, and require auth on costly operations; "
        "monitor and cap concurrency.",
    },

    # ============================ WEB — INJECTION & LOGIC (extended) =======
    "web.ssrf": {
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "capec": ["CAPEC-664"],
        "root_cause": "The server fetches a URL/host that is (wholly or partly) attacker-controlled, "
        "without validating the destination against an allow-list.",
        "severity": "high",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "A server-side feature (URL fetcher, webhook, PDF/image renderer, importer) makes "
        "requests to a destination the attacker can influence.",
        "attack": "Attacker points the parameter at internal addresses (169.254.169.254 cloud metadata, "
        "127.0.0.1, internal admin services) to steal IAM credentials, reach internal APIs, or pivot "
        "into the private network.",
        "patch": "Validate destinations against a strict allow-list, resolve+pin DNS, block link-local/"
        "private/loopback ranges, disable unused URL schemes/redirects, and require IMDSv2 in the cloud.",
    },
    "web.ssti": {
        "cwe": "CWE-1336",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-242"],
        "root_cause": "User input is embedded into a server-side template that is then rendered, so the "
        "input is evaluated as template code rather than data.",
        "severity": "high",
        "title": "Server-Side Template Injection (SSTI)",
        "description": "Untrusted input reaches a template engine (Jinja2, Twig, Freemarker, Velocity) as "
        "part of the template itself.",
        "attack": "Attacker submits template expressions (e.g. `{{7*7}}` then sandbox-escape payloads) that "
        "the engine evaluates, frequently escalating to remote code execution on the server.",
        "patch": "Never build templates from user input; pass user data only as bound variables, use a "
        "logic-less/sandboxed template engine, and validate input.",
    },
    "web.idor": {
        "cwe": "CWE-639",
        "owasp": "A01:2021 Broken Access Control",
        "capec": ["CAPEC-180"],
        "root_cause": "Authorization is not enforced per object; the app trusts a client-supplied "
        "identifier without checking the caller owns/may access that object.",
        "severity": "high",
        "title": "Insecure Direct Object Reference (IDOR)",
        "description": "An object is selected by a client-controlled id (e.g. `?invoice=1043`) without a "
        "server-side ownership/authorization check.",
        "attack": "Attacker increments/guesses ids to read or modify other users' records — invoices, "
        "messages, accounts — a classic broken-access-control data breach.",
        "patch": "Enforce object-level authorization on every access; use unguessable identifiers, scope "
        "queries to the authenticated principal, and deny by default.",
    },
    "web.open_redirect": {
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "capec": ["CAPEC-194"],
        "root_cause": "A redirect/forward target is taken from user input without validating it points to "
        "an allowed same-site destination.",
        "severity": "medium",
        "title": "Open redirect",
        "description": "A parameter (e.g. `next`, `url`, `returnTo`) controls a redirect target without "
        "allow-listing, so the app will bounce users to arbitrary external sites.",
        "attack": "Attacker crafts a trusted-looking link on your domain that redirects victims to a "
        "phishing/credential-harvesting site; also used to bypass SSRF/OAuth redirect allow-lists.",
        "patch": "Redirect only to a server-side allow-list or relative paths; validate the target host, "
        "and show an interstitial for off-site links.",
    },
    "web.xxe": {
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "capec": ["CAPEC-221"],
        "root_cause": "An XML parser resolves external entities / DTDs from untrusted XML input.",
        "severity": "high",
        "title": "XML External Entity (XXE) injection",
        "description": "The application parses attacker-supplied XML with external-entity resolution "
        "enabled.",
        "attack": "Attacker defines an external entity to read local files (`file:///etc/passwd`), perform "
        "SSRF to internal services, or cause entity-expansion DoS.",
        "patch": "Disable DTDs and external entities in the XML parser (`FEATURE_SECURE_PROCESSING`, "
        "`disallow-doctype-decl`); prefer JSON or a hardened parser.",
    },
    "web.path_traversal": {
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "capec": ["CAPEC-126"],
        "root_cause": "A file path is built from user input without canonicalizing and confining it to an "
        "intended base directory.",
        "severity": "high",
        "title": "Path traversal / directory traversal",
        "description": "A filename/path parameter reaches the filesystem without normalization, allowing "
        "`../` sequences to escape the intended directory.",
        "attack": "Attacker uses `../../etc/passwd` (or encoded variants) to read arbitrary files — configs, "
        "keys, source — outside the intended folder.",
        "patch": "Canonicalize the resolved path and verify it stays within an allow-listed base dir; map "
        "user input to opaque ids instead of raw paths.",
    },
    "web.lfi": {
        "cwe": "CWE-98",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-252"],
        "root_cause": "A dynamic include/require uses a user-controlled path resolving to a local file.",
        "severity": "high",
        "title": "Local File Inclusion (LFI)",
        "description": "A server-side include mechanism loads a local file chosen by user input.",
        "attack": "Attacker includes local files to read source/secrets, or chains log-poisoning / PHP "
        "wrappers to achieve remote code execution.",
        "patch": "Never include files by user input; use a fixed allow-list/switch of permitted modules and "
        "disable remote/stream wrappers.",
    },
    "web.rfi": {
        "cwe": "CWE-98",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-193"],
        "root_cause": "A dynamic include allows a remote URL as the include source.",
        "severity": "high",
        "title": "Remote File Inclusion (RFI)",
        "description": "The include mechanism will fetch and execute a file from a remote URL supplied by "
        "the user.",
        "attack": "Attacker hosts a malicious script and supplies its URL, causing the server to fetch and "
        "execute it — direct remote code execution.",
        "patch": "Disable remote includes (`allow_url_include=Off`), use a fixed allow-list of local "
        "modules, and validate all input.",
    },
    "web.command_injection": {
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-88"],
        "root_cause": "User input is passed to an OS shell/command interpreter without safe argument "
        "handling.",
        "severity": "critical",
        "title": "OS command injection",
        "description": "Untrusted input is concatenated into a shell command or passed through a shell.",
        "attack": "Attacker appends shell metacharacters (`; rm -rf`, `$(...)`, backticks) to run arbitrary "
        "OS commands as the web process — typically full server compromise.",
        "patch": "Avoid the shell; call binaries directly with an argument array and no shell interpolation, "
        "validate/allow-list inputs, and run with least privilege.",
    },
    "web.deserialization": {
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software & Data Integrity Failures",
        "capec": ["CAPEC-586"],
        "root_cause": "Untrusted data is deserialized into objects by an unsafe deserializer that can "
        "instantiate arbitrary types / invoke gadget chains.",
        "severity": "critical",
        "title": "Insecure deserialization",
        "description": "The app deserializes attacker-controlled data with an unsafe mechanism (Java "
        "serialization, Python pickle, PHP unserialize, .NET BinaryFormatter).",
        "attack": "Attacker crafts a serialized object / gadget chain that, on deserialization, executes "
        "code or tampers with application state — frequently remote code execution.",
        "patch": "Never deserialize untrusted data with unsafe deserializers; use data-only formats (JSON) "
        "with strict schemas, sign/verify serialized blobs, and allow-list types.",
    },
    "web.request_smuggling": {
        "cwe": "CWE-444",
        "owasp": "A05:2021 Security Misconfiguration",
        "capec": ["CAPEC-33"],
        "root_cause": "A front-end proxy and back-end server disagree on request boundaries "
        "(Content-Length vs Transfer-Encoding), letting a request be split.",
        "severity": "high",
        "title": "HTTP request smuggling",
        "description": "Inconsistent parsing of ambiguous request framing between chained HTTP servers.",
        "attack": "Attacker smuggles a hidden request that poisons the next user's response, bypasses "
        "front-end access controls, or performs cache poisoning / credential capture.",
        "patch": "Normalize/reject ambiguous framing at the edge, use HTTP/2 end-to-end where possible, "
        "and keep proxy + origin parsing consistent and patched.",
    },
    "web.prototype_pollution": {
        "cwe": "CWE-1321",
        "owasp": "A08:2021 Software & Data Integrity Failures",
        "severity": "high",
        "title": "Prototype pollution (JavaScript)",
        "description": "User-controlled keys (`__proto__`, `constructor.prototype`) are merged into objects, "
        "polluting the base prototype.",
        "attack": "Attacker injects properties onto Object.prototype to tamper with application logic, "
        "bypass checks, or (with a suitable gadget) achieve XSS or RCE.",
        "patch": "Reject/strip `__proto__`/`prototype`/`constructor` keys, use Map or null-prototype "
        "objects, and use safe deep-merge libraries.",
    },
    "web.csrf": {
        "cwe": "CWE-352",
        "owasp": "A01:2021 Broken Access Control",
        "capec": ["CAPEC-62"],
        "root_cause": "A state-changing request is accepted using only ambient credentials (cookies) with "
        "no unpredictable anti-CSRF token or SameSite protection.",
        "severity": "medium",
        "title": "Cross-Site Request Forgery (CSRF)",
        "description": "State-changing endpoints rely on cookies alone and lack anti-CSRF tokens.",
        "attack": "Attacker lures a logged-in victim to a page that auto-submits a forged request, "
        "performing actions (transfer, email change) as the victim.",
        "patch": "Require per-request anti-CSRF tokens (or double-submit), set `SameSite=Lax/Strict` "
        "cookies, and require re-auth for sensitive actions.",
    },
    "web.cache_poisoning": {
        "cwe": "CWE-524",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "high",
        "title": "Web cache poisoning",
        "description": "Unkeyed request inputs (headers) influence a cached response served to other users.",
        "attack": "Attacker sends a request whose unkeyed header injects malicious content; the response is "
        "cached and served to every subsequent visitor (stored XSS / redirect at scale).",
        "patch": "Include all response-affecting inputs in the cache key, sanitize/normalize headers, and "
        "avoid reflecting unkeyed input into cacheable responses.",
    },
    "web.nosql_injection": {
        "cwe": "CWE-943",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-676"],
        "root_cause": "User input is placed into a NoSQL query/operator structure without type checking or "
        "parameterization.",
        "severity": "high",
        "title": "NoSQL injection",
        "description": "Untrusted input is interpolated into a NoSQL query (e.g. MongoDB operators).",
        "attack": "Attacker submits operator objects (`{\"$ne\": null}`, `{\"$gt\": \"\"}`) to bypass "
        "authentication or extract data via boolean/timing oracles.",
        "patch": "Validate/cast input types, reject object-valued fields where scalars are expected, and use "
        "the driver's parameterized query APIs.",
    },
    "web.ldap_injection": {
        "cwe": "CWE-90",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-136"],
        "root_cause": "User input is concatenated into an LDAP filter without escaping.",
        "severity": "high",
        "title": "LDAP injection",
        "description": "Untrusted input is placed into an LDAP search filter unescaped.",
        "attack": "Attacker injects filter metacharacters (`*)(uid=*`) to bypass authentication or "
        "enumerate/exfiltrate directory data.",
        "patch": "Escape LDAP special characters per RFC 4515, use parameterized filter builders, and "
        "validate input.",
    },
    "web.xpath_injection": {
        "cwe": "CWE-643",
        "owasp": "A03:2021 Injection",
        "capec": ["CAPEC-83"],
        "root_cause": "User input is concatenated into an XPath expression without parameterization.",
        "severity": "medium",
        "title": "XPath injection",
        "description": "Untrusted input alters an XPath query used against XML data.",
        "attack": "Attacker injects XPath syntax to bypass authentication or read nodes they should not "
        "access from the XML store.",
        "patch": "Use parameterized/precompiled XPath with variable binding and validate input.",
    },
    "web.host_header": {
        "cwe": "CWE-644",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "medium",
        "title": "Host header injection",
        "description": "The application trusts the client-supplied Host/X-Forwarded-Host header to build "
        "absolute URLs (links, password-reset links).",
        "attack": "Attacker sets a malicious Host so password-reset or verification links point to their "
        "domain, capturing tokens; can also enable cache poisoning.",
        "patch": "Validate Host against an allow-list of expected domains, build URLs from server config "
        "(not the request), and ignore untrusted forwarding headers.",
    },
    "web.jwt_weak": {
        "cwe": "CWE-347",
        "owasp": "A02:2021 Cryptographic Failures",
        "capec": ["CAPEC-475"],
        "root_cause": "JWT signature verification is weak or optional (accepts `alg:none`, weak HMAC secret, "
        "or algorithm confusion RS256->HS256).",
        "severity": "high",
        "title": "Weak / unverified JWT",
        "description": "Tokens are accepted without robust signature verification or with a guessable key.",
        "attack": "Attacker forges tokens by setting `alg:none`, brute-forcing a weak HMAC secret, or "
        "abusing RS256/HS256 confusion — impersonating any user, including admins.",
        "patch": "Pin the expected algorithm server-side, reject `none`, use strong keys, verify "
        "signature+claims (iss/aud/exp), and rotate keys.",
    },
    "web.oauth_misconfig": {
        "cwe": "CWE-346",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "severity": "high",
        "title": "OAuth / OIDC misconfiguration",
        "description": "OAuth flow has weak redirect_uri validation, missing state/PKCE, or leaks tokens in "
        "the URL fragment/referrer.",
        "attack": "Attacker abuses a loose redirect_uri or missing state (CSRF) to steal authorization "
        "codes/tokens and take over accounts.",
        "patch": "Exact-match registered redirect URIs, require `state` + PKCE, use short-lived codes, and "
        "never expose tokens in URLs/logs.",
    },
    "web.mass_assignment": {
        "cwe": "CWE-915",
        "owasp": "A08:2021 Software & Data Integrity Failures",
        "severity": "high",
        "title": "Mass assignment / auto-binding",
        "description": "The framework binds request fields directly to internal objects, so clients can set "
        "fields they shouldn't (e.g. `role`, `isAdmin`).",
        "attack": "Attacker adds unexpected fields to the request body to elevate privileges or overwrite "
        "protected attributes.",
        "patch": "Bind only explicit allow-listed fields (DTOs/strong params), never expose internal model "
        "attributes, and enforce authorization on sensitive fields.",
    },
    "web.xss.stored": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection (XSS)",
        "capec": ["CAPEC-592"],
        "root_cause": "User-supplied content is stored and later rendered to other users without "
        "context-aware output encoding.",
        "severity": "high",
        "title": "Stored Cross-Site Scripting (XSS)",
        "description": "Persisted input (comments, profiles) is rendered to other users without encoding.",
        "attack": "Attacker stores a script that executes in every viewer's session — mass session "
        "hijacking, worming, or admin-panel takeover when staff view the content.",
        "patch": "Context-aware output encoding on render, a strict CSP, framework auto-escaping, and "
        "server-side sanitization of stored HTML.",
    },
    "web.xss.dom": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection (XSS)",
        "severity": "medium",
        "title": "DOM-based Cross-Site Scripting (XSS)",
        "description": "Client-side JS writes untrusted data (location.hash, postMessage) into a dangerous "
        "sink (innerHTML, eval) without sanitization.",
        "attack": "Attacker crafts a URL/fragment that the page's own JavaScript writes into the DOM, "
        "executing script in the victim's session — no server round-trip needed.",
        "patch": "Use safe sinks (textContent), sanitize with Trusted Types/DOMPurify, avoid eval/innerHTML "
        "with untrusted data, and validate message origins.",
    },

    # ============================ API (extended — OWASP API Top 10) ========
    "api.bola": {
        "cwe": "CWE-639",
        "owasp": "API1:2023 Broken Object Level Authorization",
        "capec": ["CAPEC-180"],
        "root_cause": "The API does not verify that the caller is authorized for the specific object id in "
        "the request.",
        "severity": "high",
        "title": "Broken Object Level Authorization (BOLA)",
        "description": "An API endpoint returns/modifies an object by id without checking the caller may "
        "access that object (the API equivalent of IDOR).",
        "attack": "Attacker swaps the object id (e.g. `/api/orders/{id}`) to read or change other tenants' "
        "records — the #1 API risk and a common mass-data-breach vector.",
        "patch": "Enforce per-object authorization on every request against the authenticated principal; "
        "use unguessable ids and centralized access checks.",
    },
    "api.bfla": {
        "cwe": "CWE-285",
        "owasp": "API5:2023 Broken Function Level Authorization",
        "severity": "high",
        "title": "Broken Function Level Authorization (BFLA)",
        "description": "Privileged functions/methods are reachable by users without the required role "
        "(e.g. an admin action callable by a normal user).",
        "attack": "Attacker calls administrative endpoints or uses unexpected HTTP methods to perform "
        "privileged operations they should not have access to.",
        "patch": "Deny by default; enforce role/permission checks on every function and method server-side, "
        "and keep admin routes behind explicit authorization.",
    },
    "api.excessive_data": {
        "cwe": "CWE-213",
        "owasp": "API3:2023 Broken Object Property Level Authorization",
        "severity": "medium",
        "title": "Excessive data exposure",
        "description": "An API returns full objects and relies on the client to filter, leaking properties "
        "the caller shouldn't see.",
        "attack": "Attacker inspects raw API responses to harvest sensitive fields (emails, tokens, internal "
        "flags) that the UI hides but the API still returns.",
        "patch": "Return only the fields each consumer needs (server-side response shaping/DTOs); never rely "
        "on client-side filtering.",
    },
    "api.graphql_dos": {
        "cwe": "CWE-770",
        "owasp": "API4:2023 Unrestricted Resource Consumption",
        "severity": "medium",
        "title": "GraphQL query depth/complexity not limited",
        "description": "The GraphQL endpoint accepts arbitrarily deep/nested or batched queries without "
        "depth or cost limits.",
        "attack": "Attacker sends deeply nested or aliased/batched queries that amplify backend work, "
        "exhausting resources (an application-layer DoS with a single request).",
        "patch": "Enforce query depth + complexity/cost limits, disable unbounded batching/aliasing, add "
        "timeouts and per-client rate limits.",
    },

    # ============================ DATABASE / DATA STORES ===================
    "db.exposed": {
        "cwe": "CWE-668",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "high",
        "title": "Database service exposed to the network",
        "description": "A database port (MySQL 3306, Postgres 5432, MongoDB 27017, Redis 6379, "
        "Elasticsearch 9200) is reachable beyond its intended network.",
        "attack": "Attacker connects directly to the DB and attempts default/no credentials, known CVEs, or "
        "unauthenticated data dumps (common for exposed Mongo/Redis/Elastic).",
        "patch": "Bind DBs to private interfaces, firewall/allow-list access, require authentication + TLS, "
        "and never expose data stores to the internet.",
    },
    "db.default_creds": {
        "cwe": "CWE-1392",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "capec": ["CAPEC-70"],
        "severity": "high",
        "title": "Default or weak service credentials",
        "description": "A service/DB/admin panel accepts default or trivially weak credentials.",
        "attack": "Attacker logs in with vendor defaults (admin/admin, root/no-password) to gain immediate "
        "privileged access.",
        "patch": "Change all default credentials on deployment, enforce strong password policy + MFA, and "
        "scan for defaults in CI/CD and asset onboarding.",
    },

    # ============================ CRYPTOGRAPHY =============================
    "crypto.weak_hash": {
        "cwe": "CWE-916",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "medium",
        "title": "Weak password hashing / algorithm",
        "description": "Passwords stored with fast/broken hashes (MD5, SHA1, unsalted) or data protected by "
        "deprecated algorithms.",
        "attack": "If the store leaks, attacker cracks weak/unsalted hashes at scale (GPU/rainbow tables) "
        "and reuses credentials elsewhere.",
        "patch": "Use a memory-hard password hash (argon2id, scrypt, bcrypt) with per-user salt; migrate "
        "off MD5/SHA1 for integrity/signatures.",
    },
    "crypto.weak_random": {
        "cwe": "CWE-338",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "medium",
        "title": "Insecure randomness for security tokens",
        "description": "Security-sensitive values (tokens, session ids, reset codes) use a non-cryptographic "
        "PRNG (e.g. rand()/Math.random()).",
        "attack": "Attacker predicts or brute-forces the values (session ids, reset tokens) to hijack "
        "sessions or take over accounts.",
        "patch": "Generate security tokens from a CSPRNG (secrets, crypto.randomBytes, SecureRandom) with "
        "sufficient entropy.",
    },

    # ============================ SUPPLY CHAIN =============================
    "supplychain.dependency_confusion": {
        "cwe": "CWE-427",
        "owasp": "A08:2021 Software & Data Integrity Failures",
        "severity": "high",
        "title": "Dependency confusion / unclaimed internal package",
        "description": "An internal package name is not reserved on the public registry, so a public package "
        "of the same name could be pulled during builds.",
        "attack": "Attacker publishes a malicious public package with the internal name and higher version; "
        "the build resolves to it, executing attacker code in CI/dev (supply-chain compromise).",
        "patch": "Reserve internal names on public registries, pin/scoped registries with an explicit "
        "index, use lockfiles + integrity hashes, and verify package provenance.",
    },
}


def get(finding_id: str) -> dict:
    """Return the KB entry for an id, or a safe generic fallback."""
    return KB.get(
        finding_id,
        {
            "cwe": "N/A",
            "owasp": "N/A",
            "severity": "info",
            "title": finding_id,
            "description": "See evidence.",
            "attack": "N/A",
            "patch": "Review manually.",
        },
    )
