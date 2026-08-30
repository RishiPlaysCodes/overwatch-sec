# Security & Safe-Use Policy

vulnscan is an **authorized security-assessment** platform. Use it only against
systems, applications, and accounts you **own** or have **explicit written
permission** to test. Unauthorized scanning is illegal in most jurisdictions.

## What the platform will NOT do

- **No auto-exploitation.** It detects and (where a policy permits) performs
  *controlled, safe* validation — it does not weaponize findings, pop shells,
  or run post-exploitation (privilege escalation execution, lateral movement,
  persistence, C2).
- **No DoS/DDoS.** No flooding or uncontrolled load. A *DoS-resilience
  assessment* (checking rate limiting / WAF / autoscaling config) is the only
  DoS-adjacent capability, and it is passive.
- **No mass targeting / no third-party social engineering.** Any
  social-engineering module is simulation-only and requires explicit opt-in.

## Safety model

Every test maps to a safety level:

```
passive  →  safe_active  →  validation  →  intrusive  →  destructive
```

Defaults (all profiles): **passive + safe_active only**. Validation is enabled
only in deeper/authorized profiles. **Intrusive** requires a `red_team`/`lab`/
`authorized_pentest` policy; **destructive** requires a `lab` policy and is
never enabled by default. A hard clamp in `core.policy` enforces this even if a
config file is malformed.

An **authorization gate** requires confirmation before active testing (bypass
with `--yes` only for assets you own / CI).

## Handling of secrets

- Credentials passed via `--token`, `--cookie`, `--header`, `--api-key`, etc.
  are **redacted** from evidence, logs, and reports.
- No secrets are committed to the repo. Feed data downloaded is public only.

## Self-hardening

- Subprocesses are executed with argument lists (no shell string interpolation)
  and hard timeouts.
- Reports/evidence are HTML-escaped in the HTML output.
- Tool availability and versions are detected, never assumed.

## Reporting issues

If you find a vulnerability in the scanner itself, please open an issue (do not
include exploit details for third-party systems).
