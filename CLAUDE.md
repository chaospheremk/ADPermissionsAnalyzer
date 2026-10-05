> **Note for external readers**: This file documents internal Claude Code
> session conventions used by the maintainer. References to `../bugs.md`,
> `../decisions.md`, `../key-facts.md`, and `../issues.md` point to a private
> developer notebook that lives outside this repository; those paths do not
> resolve in a fresh clone. If you are contributing, see
> [CONTRIBUTING.md](CONTRIBUTING.md) instead.

# Code Session — `AD Permissions Analyzer`

The shared code-session protocol (context, startup, memory protocols, Serena,
handoff, generic rules) is loaded from `10-Projects/CLAUDE.md`. This file holds
only what is specific to this repo.

The original implementation specification is at `docs/AD-Permissions-Analyzer-Plan.md`; current state is in `../issues.md`.

## Vault Memory Writes

When editing parent vault files (`..\bugs.md`, `..\decisions.md`, `..\key-facts.md`, `..\issues.md`), use Edit/Write only — never MCPVault write tools (`mcp__secondbrain__write_note`, `patch_note`, `update_frontmatter`). Vault hooks don't run in code sessions, so set any `modified:` field yourself. The `obsidian-markdown` skill (user-level) enforces wikilink/callout/properties syntax. The `vault-conventions` skill (user-level) restates the MCP-read / Edit-Write-write contract for this code session.

## Branching

Trunk-based, unlike the shared `dev` → `main` default: short-lived `feat/`,
`fix/`, `chore/` branches off `main`, PR into `main`, delete after merge. Never
commit directly to `main`. See [CONTRIBUTING.md](CONTRIBUTING.md).

Pre-commit hooks must be installed: `pip install pre-commit && pre-commit install`
