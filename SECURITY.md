# Security Policy

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| 0.2.x   | Yes |
| < 0.2   | No  |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Preferred channels:

1. **GitHub Security Advisories** — open a private advisory via the repo's **Security** tab → **Report a vulnerability**.
2. **Email** — `doug@dougjohnson.me`.

Include, where possible:

- A description of the issue and the impact you observed.
- Steps to reproduce, including the PowerShell version, Windows version, and AD topology shape (number of NCs, approximate object count).
- Relevant JSONL log excerpts. Redact real DNs, SIDs, and trustee names before sharing.
- Any proof-of-concept code or AD object configuration that demonstrates the issue.

You should receive an acknowledgement within 7 days. Confirmed issues will be fixed or mitigated within 30 days, and a security advisory will be published when the fix ships.

## In scope

- Anything in the script that could enable unintended directory reads or writes beyond what the running principal already has.
- Sensitive data (credentials, secrets, real principal identifiers) leaking into log output, error messages, or CSV columns in a way the operator could not reasonably anticipate.
- Privilege-escalation paths arising from how the script handles its own runspace state, credential parameter, or output files.
- Tampering vectors against the produced CSV/JSONL artifacts that would mislead a downstream reviewer.

## Out of scope

- Misuse of the tool with permissions that have already been granted to the running principal. The tool inherits the directory rights of whoever runs it — using it to enumerate a directory you are not authorized to enumerate is a permissions issue, not a vulnerability in this tool.
- Findings produced by the tool (e.g., a Domain User holding `WriteDacl` on a sensitive object). Those are operational findings about the target directory, not tool defects.
- Issues that require an attacker who already has Domain Admin or equivalent on the target directory.
