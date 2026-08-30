# programs/ — bug-bounty program configs

Drop a YAML here per program, then run one command — the engine reads it and
**auto-respects the program's rules** so you don't manage flags by hand:

```bash
python3 overwatch.py https://TARGET --profile bugbounty --program programs/NAME.yaml --yes
```

What a program config controls:

| Key | Effect |
|---|---|
| `scope` | in-scope hosts/domains/CIDRs (wildcards + `!exclusions`). Discovered out-of-scope assets are dropped. |
| `out_of_scope` | extra host patterns to exclude. |
| `headers` | required request headers (e.g. `X-Request-Purpose`) — sent on **every** built-in request and passed to supporting tools. |
| `rate_per_min` | polite request rate cap (throttles all built-in traffic). |
| `exclude_findings` | finding-id patterns the program declares **out of scope / not rewarded** (e.g. `web.header*`). Kept but labelled, and excluded from the score/CI-gate so results focus on what pays. |
| `focus_findings` | finding-id patterns to prioritize (tagged `program:focus`). |
| `notes` | free text shown in context. |

### Make your own (copy the template)

```yaml
name: My Program
scope:
  - example.com
  - "*.example.com"
  - "!admin.example.com"
headers:
  X-Request-Purpose: BugcrowdResearch
rate_per_min: 20
exclude_findings:
  - web.header*
  - web.cookie*
  - availability*
focus_findings:
  - web.sqli
  - web.xss*
```

A plain scope `.txt` (one entry per line) also works as a minimal program
(`--program scope.txt`) — it applies a sensible default out-of-scope list.

> ⚠️ A program config encodes the program's **rules** — it does **not** grant you
> authorization. Only test targets/accounts you are permitted to, per the brief.
> The automated pass is **recon + low-hanging detection**; high-value bugs need
> manual research and a written PoC (many programs reject AI-generated reports).
