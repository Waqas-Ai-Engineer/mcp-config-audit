# mcp-config-audit

> Security-lint your MCP server config in one command. Finds hardcoded API keys, unpinned `npx` packages, `curl | sh` launchers, root-filesystem mounts and insecure URLs **before** your AI agent runs them.

![python](https://img.shields.io/badge/python-3.9%2B-blue) ![deps](https://img.shields.io/badge/dependencies-zero-brightgreen) ![license](https://img.shields.io/badge/license-MIT-lightgrey) ![tests](https://img.shields.io/badge/tests-14%20passing-brightgreen)

MCP (Model Context Protocol) servers run with your credentials and your filesystem. A single copy-pasted config line can leak a token or execute whatever a package publishes next. `mcp-config-audit` reads your config, scores it 0-100, and tells you exactly what to change.

## Quickstart (under 2 minutes, no install)

```bash
git clone https://github.com/Waqas-Ai-Engineer/mcp-config-audit
cd mcp-config-audit
python mcp_audit.py --demo                 # offline demo on a deliberately risky config
python mcp_audit.py ~/.cursor/mcp.json     # audit your real config
```

Works with `claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json` (`servers` key) and any file using `mcpServers`.

## Sample output

```
examples/risky_mcp.json: 6 server(s), score 0/100 (grade F)
  CRITICAL MCP001 [github] Hardcoded secret in config
           env.GITHUB_PERSONAL_ACCESS_TOKEN = ghp_****
           fix: Move it to an env var / secret manager and reference it (e.g. ${GITHUB_TOKEN}).
  CRITICAL MCP007 [installer] Pipes remote content into a shell
  HIGH     MCP005 [filesystem] Filesystem access to a very broad path
  HIGH     MCP006 [crm-remote] Insecure or credential-bearing URL
  ...
```

Full output: [examples/sample_output.txt](examples/sample_output.txt). Secrets are always masked in the report.

## Rules

| ID | Severity | Catches |
|---|---|---|
| MCP001 | critical | Hardcoded secrets in `env`, `headers` or args (key names + token patterns) |
| MCP007 | critical | `curl ... \| sh` style launchers |
| MCP004 | high | `bash -c` / `cmd /c` / PowerShell command-string wrappers |
| MCP005 | high | Filesystem server pointed at `/`, `~`, `C:\`, etc. |
| MCP006 | high | Plain-HTTP remotes, credentials in the URL query |
| MCP008 | high | Docker `--privileged`, host-root mounts, `--net=host` |
| MCP002 | medium | Unpinned `npx` / `uvx` / `pipx` packages |
| MCP010 | medium | Remote URL without an Authorization header |
| MCP003 | low | `npx -y` auto-install |
| MCP009 | low | Entry with neither `command` nor `url` |

## CI usage

```bash
python mcp_audit.py mcp.json --fail-on high      # exit 1 on high/critical
python mcp_audit.py mcp.json --format json       # machine-readable
python mcp_audit.py mcp.json --format markdown   # paste into a PR comment
```

Exit codes: `0` clean at threshold, `1` findings at/above `--fail-on`, `2` unreadable file.

## How it works

```
config JSON -> parse (// comments tolerated) -> per-server rule checks -> severity-weighted score -> text | json | markdown
```

Static analysis only: nothing is executed, nothing leaves your machine. Heuristics can have false positives, so treat results as a review checklist, not a guarantee. Run tests with `python -m unittest discover -s tests`.

## Topics

`mcp` `model-context-protocol` `security` `ai-agents` `linter` `python` `cli` `devsecops`

## Hire me / Need this built?

I'm **Muhammad Waqas**, AI Agents & Business Automation: lead-gen pipelines, WhatsApp/email automation, AI receptionists and reporting for service businesses (roofing, HVAC, clinics, salons, real estate). Need an agent or n8n workflow built safely? Reach me via my [GitHub profile](https://github.com/Waqas-Ai-Engineer).

## License

MIT
