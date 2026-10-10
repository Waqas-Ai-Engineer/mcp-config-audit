#!/usr/bin/env python3
"""mcp-config-audit: zero-dependency security linter for MCP server configs.

Audits claude_desktop_config.json / .cursor/mcp.json / .vscode/mcp.json style files
for hardcoded secrets, unpinned packages, shell wrappers, risky mounts and insecure URLs.
"""
import argparse
import json
import os
import re
import sys

__version__ = "1.0.0"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_PENALTY = {"info": 0, "low": 3, "medium": 8, "high": 18, "critical": 30}

SECRET_NAME = re.compile(r"(api[_-]?key|secret|token|passw(or)?d|private[_-]?key|credential|auth)", re.I)
SECRET_VALUE = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    re.compile(r"postgres(ql)?://[^:/\s]+:[^@\s]+@"),
]
ENV_REF = re.compile(r"^\s*(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\$\{input:[^}]+\})\s*$")
SHELLS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
BROAD_PATHS = {"/", "~", "$HOME", "%USERPROFILE%", "/home", "/Users", "/etc", "/root", "C:\\", "C:/", "c:\\", "c:/", "C:\\Users", "."}
RULES = {
    "MCP001": ("critical", "Hardcoded secret in config", "Move it to an env var / secret manager and reference it (e.g. ${GITHUB_TOKEN})."),
    "MCP002": ("medium", "Unpinned package (runs whatever is latest)", "Pin a version: npx pkg@1.2.3 / uvx pkg==1.2.3."),
    "MCP003": ("low", "Auto-confirm install flag (-y/--yes)", "Install and review the package once, then run it by pinned version."),
    "MCP004": ("high", "Shell wrapper executes a command string", "Launch the server binary directly with args instead of sh/cmd -c."),
    "MCP005": ("high", "Filesystem access to a very broad path", "Scope the server to one project directory."),
    "MCP006": ("high", "Insecure or credential-bearing URL", "Use https:// and send tokens in headers from env vars, not the URL."),
    "MCP007": ("critical", "Pipes remote content into a shell", "Never curl|sh in a server launcher. Vendor and pin the script."),
    "MCP008": ("high", "Privileged container / host mount", "Drop --privileged and mount only the needed folder read-only."),
    "MCP009": ("low", "Server defines neither command nor url", "Remove the dead entry or fix its definition."),
    "MCP010": ("medium", "Remote server URL with no auth header", "Add an Authorization header sourced from an env var."),
}


def finding(rule, server, detail, where=""):
    sev, title, fix = RULES[rule]
    return {"rule": rule, "severity": sev, "server": server, "title": title,
            "detail": detail, "location": where, "fix": fix}


def is_ref(v):
    return isinstance(v, str) and bool(ENV_REF.match(v))


def mask(v):
    v = str(v)
    return v[:4] + "…" + "*" * 4 if len(v) > 8 else "****"


def audit_server(name, cfg):
    out = []
    if not isinstance(cfg, dict):
        return [finding("MCP009", name, "Entry is not an object")]
    cmd = cfg.get("command")
    args = [str(a) for a in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
    url = cfg.get("url") or cfg.get("serverUrl")
    if not cmd and not url:
        out.append(finding("MCP009", name, "No 'command' or 'url' key"))
    base = os.path.basename(str(cmd)).lower() if cmd else ""

    # secrets in env / headers
    for section in ("env", "headers"):
        block = cfg.get(section)
        if isinstance(block, dict):
            for k, v in block.items():
                if not isinstance(v, str) or not v.strip() or is_ref(v):
                    continue
                if SECRET_NAME.search(k) or any(p.search(v) for p in SECRET_VALUE):
                    if v.lower().startswith("bearer ") and is_ref(v[7:]):
                        continue
                    out.append(finding("MCP001", name, f"{section}.{k} = {mask(v)}", f"{section}.{k}"))
    for i, a in enumerate(args):
        if any(p.search(a) for p in SECRET_VALUE):
            out.append(finding("MCP001", name, f"args[{i}] looks like a credential: {mask(a)}", f"args[{i}]"))

    # unpinned packages
    if base in ("npx", "npx.cmd", "uvx", "pipx", "bunx", "pnpx") or (base in ("pnpm", "yarn") and args[:1] == ["dlx"]):
        pkg = next((a for a in args if not a.startswith("-") and a != "dlx" and a != "run"), None)
        if pkg:
            nm = pkg[1:] if pkg.startswith("@") else pkg
            pinned = ("@" in nm) or ("==" in nm)
            if not pinned and not pkg.startswith((".", "/", "git+", "http")):
                out.append(finding("MCP002", name, f"{base} {pkg}", "args"))
        if any(a in ("-y", "--yes") for a in args):
            out.append(finding("MCP003", name, f"{base} {' '.join(args[:2])}", "args"))

    # shell wrappers / curl|sh
    joined = " ".join([str(cmd or "")] + args)
    if base in SHELLS and any(a in ("-c", "/c", "/k", "-Command", "-command", "-EncodedCommand") for a in args):
        out.append(finding("MCP004", name, f"{base} {' '.join(args)[:80]}", "command"))
    if re.search(r"(curl|wget|iwr|Invoke-WebRequest)[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|iex|python3?)\b", joined, re.I):
        out.append(finding("MCP007", name, joined[:90], "args"))

    # broad paths
    if "filesystem" in joined.lower() or "file" in name.lower():
        for a in args:
            if a.strip().rstrip("\\/") in {p.rstrip("\\/") for p in BROAD_PATHS} or a.strip() in BROAD_PATHS:
                out.append(finding("MCP005", name, f"path argument '{a}'", "args"))

    # docker risks
    if base in ("docker", "podman", "docker.exe"):
        if "--privileged" in args or any(re.fullmatch(r"-v|--volume", a) for a in args) and any(
                re.match(r"^(/|[A-Za-z]:[\\/]?):", a) for a in args):
            out.append(finding("MCP008", name, "docker run uses --privileged or mounts the host root", "args"))
        for a in args:
            if a.startswith("--cap-add") or a in ("--pid=host", "--net=host", "--network=host"):
                out.append(finding("MCP008", name, f"flag {a}", "args"))

    # urls
    if url:
        u = str(url)
        local = re.match(r"^http://(localhost|127\.0\.0\.1|\[::1\])", u)
        if u.startswith("http://") and not local:
            out.append(finding("MCP006", name, f"plain-HTTP remote: {u}", "url"))
        if re.search(r"[?&](api[_-]?key|token|key|secret|access_token)=[^&]+", u, re.I):
            out.append(finding("MCP006", name, "credential in query string", "url"))
        hdrs = cfg.get("headers") or {}
        if not local and not any(str(k).lower() in ("authorization", "x-api-key") for k in hdrs) \
                and not re.search(r"[?&](api[_-]?key|token|key)=", u, re.I):
            out.append(finding("MCP010", name, f"{u} has no Authorization header", "url"))
    return out


def load(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        text = f.read()
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)  # tolerate // comments (VS Code)
    return json.loads(text)


def audit_doc(doc):
    servers = {}
    if isinstance(doc, dict):
        for key in ("mcpServers", "servers", "mcp_servers"):
            if isinstance(doc.get(key), dict):
                servers.update(doc[key])
        if not servers and isinstance(doc.get("mcp"), dict) and isinstance(doc["mcp"].get("servers"), dict):
            servers.update(doc["mcp"]["servers"])
    findings = []
    for n, c in servers.items():
        findings.extend(audit_server(n, c))
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["server"], f["rule"]))
    score = max(0, 100 - sum(SEV_PENALTY[f["severity"]] for f in findings))
    return {"servers": len(servers), "findings": findings, "score": score}


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"


def render_text(path, res, color):
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    cols = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}
    lines = [c("1", f"{path}: {res['servers']} server(s), score {res['score']}/100 (grade {grade(res['score'])})")]
    for f in res["findings"]:
        sev = f["severity"].upper().ljust(8)
        lines.append(f"  {c(cols[f['severity']], sev)} {f['rule']} [{f['server']}] {f['title']}")
        lines.append(f"           {f['detail']}")
        lines.append(f"           fix: {f['fix']}")
    if not res["findings"]:
        lines.append("  No issues found.")
    return "\n".join(lines)


def render_md(path, res):
    out = [f"## MCP config audit: `{path}`", "",
           f"**Score {res['score']}/100 (grade {grade(res['score'])})** across {res['servers']} server(s).", ""]
    if res["findings"]:
        out += ["| Severity | Rule | Server | Issue | Fix |", "|---|---|---|---|---|"]
        for f in res["findings"]:
            out.append(f"| {f['severity']} | {f['rule']} | {f['server']} | {f['title']}: {f['detail']} | {f['fix']} |".replace("\n", " "))
    else:
        out.append("No issues found.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcp-config-audit", description="Security-lint MCP server configs.")
    ap.add_argument("files", nargs="*", help="MCP config JSON file(s)")
    ap.add_argument("--demo", action="store_true", help="audit the bundled risky example")
    ap.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    ap.add_argument("--fail-on", choices=list(SEV_ORDER), default="high", help="exit 1 at/above this severity (default high)")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    files = list(a.files)
    if a.demo:
        files.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples", "risky_mcp.json"))
    if not files:
        ap.error("give at least one file or use --demo")
    worst, results = -1, {}
    for p in files:
        try:
            res = audit_doc(load(p))
        except (OSError, ValueError) as e:
            print(f"error: cannot read {p}: {e}", file=sys.stderr)
            return 2
        results[p] = res
        for f in res["findings"]:
            worst = max(worst, SEV_ORDER[f["severity"]])
    if a.format == "json":
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty() and a.format == "text"
        for p, r in results.items():
            print(render_md(p, r) if a.format == "markdown" else render_text(p, r, color))
            print()
    return 1 if worst >= SEV_ORDER[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
