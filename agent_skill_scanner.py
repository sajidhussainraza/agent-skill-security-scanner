#!/usr/bin/env python3
"""Agent Skill Security Scanner.

Audits an AI-agent skill / plugin package before it is installed:
a SKILL.md, an optional manifest (skill.json / manifest.json) and
any helper scripts it ships. A skill runs with the agent's own
privileges, so a malicious one can read secrets, exfiltrate data
or run shell commands while looking like a harmless helper.

The scanner reads the package (it never executes anything), checks
it against 10 rules, and reports a risk score from 0 to 100 with a
verdict of OK, REVIEW or BLOCK.

Usage:
    python agent_skill_scanner.py <skill-dir>
    python agent_skill_scanner.py <skill-dir> --json report.json
    python agent_skill_scanner.py <skill-dir> --fail-above 25
    python agent_skill_scanner.py <skill-dir> --min-severity high
    python agent_skill_scanner.py --list-rules

Exit code: 0 = risk score at or below --fail-above (default 60),
1 = score above it, 2 = usage/input error.
"""

import ast
import base64
import json
import re
import sys
from pathlib import Path

VERSION = "1.0.0"

WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES = {
    "S01": ("critical",
            "Instruction override / prompt injection in skill text",
            "Remove the override language. A skill may instruct the "
            "agent on its own task, never on the agent's system "
            "instructions, and never tell it to hide anything."),
    "S02": ("critical",
            "Credential / secret access",
            "Do not read .env files, API keys, tokens, passwords or "
            "SSH keys. Ask the user to supply credentials through "
            "the agent's own secure channel instead."),
    "S03": ("high",
            "Outbound data-send channel in helper code",
            "A POST, upload or webhook call can exfiltrate whatever "
            "the skill read. Remove it, or declare the exact "
            "endpoint and payload in SKILL.md and get approval."),
    "S04": ("high",
            "Shell command execution in helper code",
            "Avoid subprocess, os.system, eval and exec. If a shell "
            "call is unavoidable, pin the command and its arguments "
            "and never build it from untrusted input."),
    "S05": ("high",
            "Network egress in helper code",
            "Declare every host the skill contacts in SKILL.md. "
            "A skill that phones home with no declared endpoint is "
            "an exfiltration risk."),
    "S06": ("high",
            "Destructive file operation in helper code",
            "File deletion (unlink, remove, rmtree, rm -rf) must be "
            "explicit, scoped to paths the user chose, and confirmed "
            "before it runs."),
    "S07": ("medium",
            "Sensitive path read",
            "Do not read SSH keys, cloud credentials, browser "
            "profiles or /etc/passwd. Scope file access to the "
            "working directory the skill declares."),
    "S08": ("medium",
            "Obfuscated or encoded payload",
            "Base64 / hex blobs decoded and executed at runtime hide "
            "what the skill really does. Ship readable code only."),
    "S09": ("medium",
            "Unscoped or wildcard tool permissions",
            "Declare the exact tools the skill needs. A wildcard "
            "(\"*\") or a missing tools list hands the skill every "
            "capability the agent has."),
    "S10": ("low",
            "Missing skill metadata (name, version or description)",
            "Add name, version and description to the manifest (or "
            "a top-level heading in SKILL.md) so the package can "
            "be identified and reviewed."),
}

# --- text patterns -------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|earlier) instructions",
    r"disregard (your )?(system )?(instructions|prompt)",
    r"override (your )?(system )?(instructions|prompt)",
    r"you are now (a|an|the|in)",
    r"new system prompt",
    r"do not (tell|mention|reveal|inform) the user",
    r"keep this (secret|hidden|confidential)",
    r"never (mention|reveal|disclose|tell)",
    r"forget (your|all|the) (instructions|rules|guidelines)",
    r"act as if (you are|you have)",
    r"repeat (this|the) (instruction|prompt) to",
]

SECRET_PATTERNS = [
    r"\.env\b",
    r"api[_-]?key",
    r"secret[_-]?key",
    r"access[_-]?token",
    r"private[_-]?key",
    r"password",
    r"\.ssh/",
    r"credentials\.json",
    r"aws_secret",
    r"bearer [a-z0-9]",
]

SENSITIVE_PATH_PATTERNS = [
    r"~\/\.ssh",
    r"~\/\.aws",
    r"~\/\.config\/gcloud",
    r"\/etc\/passwd",
    r"\/etc\/shadow",
    r"credentials\.json",
    r"\.git\/config",
    r"Login Data",
    r"keychain",
]

B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _findings():
    return []


def _add(findings, rule, path, detail):
    severity, title, remediation = RULES[rule]
    findings.append({
        "rule": rule,
        "severity": severity,
        "title": title,
        "file": str(path),
        "detail": detail,
        "remediation": remediation,
    })


# --- file collection -----------------------------------------------------

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules"}
TEXT_SUFFIXES = {".md", ".txt", ".py", ".js", ".ts", ".sh", ".json",
                 ".yaml", ".yml", ".toml", ".cfg", ".ini"}


def collect_files(root):
    """Return the text files of a skill package, skipping junk dirs."""
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {
                "SKILL.md", "skill.json", "manifest.json"}:
            files.append(path)
    return files


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# --- markdown / text checks ----------------------------------------------

def check_text_file(path, text, findings):
    """S01, S02, S07 over prose and config text (SKILL.md etc.)."""
    for pattern in INJECTION_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            _add(findings, "S01", path,
                 "instruction-override language: %r" % match.group(0))
            break
    for pattern in SECRET_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            _add(findings, "S02", path,
                 "references secrets/credentials: %r" % match.group(0))
            break
    for pattern in SENSITIVE_PATH_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            _add(findings, "S07", path,
                 "references sensitive path: %r" % match.group(0))
            break


# --- Python AST checks ----------------------------------------------------

SHELL_CALLS = {("subprocess", "run"), ("subprocess", "call"),
               ("subprocess", "Popen"), ("subprocess", "check_output"),
               ("os", "system"), ("os", "popen")}
SEND_CALLS = {("requests", "post"), ("requests", "put"),
              ("requests", "patch"), ("urllib.request", "urlopen"),
              ("http.client", "request")}
NET_IMPORTS = {"requests", "urllib", "urllib.request", "socket",
               "http.client", "httpx", "aiohttp"}
DESTRUCTIVE_CALLS = {("os", "remove"), ("os", "unlink"),
                     ("os", "rmdir"), ("shutil", "rmtree"),
                     ("pathlib", "unlink")}


def _dotted(node):
    """Dotted name of a call target, e.g. subprocess.run, or ''."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def check_python_file(path, text, findings):
    """S03-S06, S08 over Python helper scripts via the AST."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    has_send = has_shell = has_net = has_destructive = False
    has_b64_exec = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in NET_IMPORTS:
                    has_net = True
                if alias.name == "base64":
                    has_b64_exec = has_b64_exec or _uses_b64_exec(tree)
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in NET_IMPORTS:
                has_net = True
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            base = name.rsplit(".", 1)[0] if "." in name else name
            if (base, name.rsplit(".", 1)[-1]) in SHELL_CALLS or \
                    name in {"eval", "exec", "os.system", "os.popen"}:
                has_shell = True
            if (base, name.rsplit(".", 1)[-1]) in SEND_CALLS or \
                    name in {"requests.post", "requests.put",
                             "requests.patch"}:
                has_send = True
            if (base, name.rsplit(".", 1)[-1]) in DESTRUCTIVE_CALLS or \
                    name in {"os.remove", "os.unlink", "os.rmdir",
                             "shutil.rmtree"}:
                has_destructive = True
            if name in {"eval", "exec"}:
                has_b64_exec = True
    # S08: long base64 blob that is decoded (and possibly executed).
    # Split string literals can leave a chunk without its padding,
    # so re-pad before decoding and require printable output.
    for match in B64_RE.finditer(text):
        blob = match.group(0)
        if len(blob) >= 40:
            padded = blob + "=" * (-len(blob) % 4)
            try:
                decoded = base64.b64decode(padded, validate=True)
            except Exception:
                continue
            if decoded and all(32 <= b < 127 or b in (9, 10, 13)
                               for b in decoded):
                _add(findings, "S08", path,
                     "long base64 blob (%d chars) decoded at runtime"
                     % len(blob))
                break
    if has_shell:
        _add(findings, "S04", path,
             "executes shell commands (subprocess / os.system / "
             "eval / exec)")
    if has_send:
        _add(findings, "S03", path,
             "sends data outbound (requests.post / urlopen / "
             "http.client.request)")
    if has_net:
        _add(findings, "S05", path,
             "imports a network library (requests / urllib / "
             "socket / http.client)")
    if has_destructive:
        _add(findings, "S06", path,
             "deletes files or directories (remove / unlink / "
             "rmtree)")


def _uses_b64_exec(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func) in {
                "eval", "exec"}:
            return True
    return False


# --- shell / other script checks ------------------------------------------

SHELL_SEND_RE = re.compile(r"\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b")
SHELL_EXEC_RE = re.compile(r"\beval\b|\bexec\b|\$\(.*\)|`[^`]+`")
SHELL_DELETE_RE = re.compile(r"\brm\s+(-[a-z]*r[a-z]*\s+|--recursive\b)")


def check_script_file(path, text, findings):
    """S03-S06 over .sh / .js / .ts helpers by pattern."""
    if SHELL_SEND_RE.search(text):
        _add(findings, "S03", path,
             "sends data outbound (curl / wget / netcat)")
        _add(findings, "S05", path,
             "makes network calls (curl / wget / netcat)")
    if SHELL_EXEC_RE.search(text):
        _add(findings, "S04", path,
             "executes shell commands (eval / exec / command "
             "substitution)")
    if SHELL_DELETE_RE.search(text):
        _add(findings, "S06", path,
             "deletes files recursively (rm -r)")


# --- manifest checks -------------------------------------------------------

def check_manifest(path, rel, findings):
    """S09, S10 over skill.json / manifest.json."""
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError:
        _add(findings, "S10", rel, "manifest is not valid JSON")
        return
    if not isinstance(data, dict):
        _add(findings, "S10", rel, "manifest is not a JSON object")
        return
    missing = [k for k in ("name", "version", "description")
               if not data.get(k)]
    if missing:
        _add(findings, "S10", rel,
             "missing metadata field(s): %s" % ", ".join(missing))
    tools = data.get("tools")
    if tools is None:
        _add(findings, "S09", rel,
             "no tools list declared: permissions are unscoped")
    elif tools == "*" or (isinstance(tools, list) and "*" in tools):
        _add(findings, "S09", rel,
             "wildcard tool permission (\"*\") grants every "
             "capability")


# --- top level --------------------------------------------------------------

def scan_skill(root):
    """Audit a skill package directory; return the report dict."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError("not a directory: %s" % root)
    files = collect_files(root)
    findings = []
    manifest = None
    skill_md = None
    for path in files:
        text = read_text(path)
        rel = path.relative_to(root)
        if path.name in {"skill.json", "manifest.json"}:
            manifest = path
            check_manifest(path, rel, findings)
        if path.name.upper() == "SKILL.MD":
            skill_md = path
        check_text_file(rel, text, findings)
        if path.suffix.lower() == ".py":
            check_python_file(rel, text, findings)
        elif path.suffix.lower() in {".sh", ".js", ".ts"}:
            check_script_file(rel, text, findings)
    if manifest is None and skill_md is not None:
        text = read_text(skill_md)
        heading = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        if not heading:
            _add(findings, "S10", skill_md.relative_to(root),
                 "SKILL.md has no top-level heading (no name)")
    name = root.name
    if manifest is not None:
        try:
            name = json.loads(read_text(manifest)).get("name", name)
        except (json.JSONDecodeError, AttributeError):
            pass
    score = min(100, sum(WEIGHTS[f["severity"]] for f in findings))
    if score >= 60 or any(f["severity"] == "critical" for f in findings):
        verdict = "BLOCK"
    elif score >= 25:
        verdict = "REVIEW"
    else:
        verdict = "OK"
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in WEIGHTS}
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                 f["rule"], f["file"]))
    return {
        "skill": name,
        "path": str(root),
        "files_scanned": len(files),
        "score": score,
        "verdict": verdict,
        "counts": counts,
        "findings": findings,
    }


def format_report(report):
    lines = [
        "Skill: %s (%d file(s))" % (report["skill"],
                                    report["files_scanned"]),
        "Risk score: %d/100 (%d finding(s)) -> %s"
        % (report["score"], len(report["findings"]), report["verdict"]),
        "  critical: %d, high: %d, medium: %d, low: %d"
        % (report["counts"]["critical"], report["counts"]["high"],
           report["counts"]["medium"], report["counts"]["low"]),
    ]
    for f in report["findings"]:
        lines.append("  [%s] %s %s: %s"
                     % (f["severity"].upper(), f["rule"], f["file"],
                        f["detail"]))
    return "\n".join(lines)


def list_rules():
    lines = ["Agent skill security rules:"]
    for rule in sorted(RULES):
        severity, title, remediation = RULES[rule]
        lines.append("  %s [%s] %s\n      Fix: %s"
                     % (rule, severity, title, remediation))
    return "\n".join(lines)


def main(argv):
    args = []
    opts = []
    i = 0
    while i < len(argv):
        if argv[i] == "--json" and i + 1 < len(argv):
            opts.append("--json=" + argv[i + 1])
            i += 2
        elif argv[i].startswith("--"):
            opts.append(argv[i])
            i += 1
        else:
            args.append(argv[i])
            i += 1
    fail_above = 60
    min_severity = None
    json_out = None
    if "--list-rules" in opts:
        print(list_rules())
        return 0
    for opt in opts:
        if opt.startswith("--fail-above="):
            try:
                fail_above = int(opt.split("=", 1)[1])
            except ValueError:
                print("error: --fail-above needs an integer", file=sys.stderr)
                return 2
        elif opt.startswith("--min-severity="):
            min_severity = opt.split("=", 1)[1].lower()
            if min_severity not in SEVERITY_ORDER:
                print("error: unknown severity %r" % min_severity,
                      file=sys.stderr)
                return 2
        elif opt.startswith("--json="):
            json_out = opt.split("=", 1)[1]
        elif opt == "--json":
            print("error: --json needs a path (--json=report.json)",
                  file=sys.stderr)
            return 2
        else:
            print("error: unknown option %r" % opt, file=sys.stderr)
            return 2
    if len(args) != 1:
        print("usage: agent_skill_scanner.py <skill-dir> "
              "[--json=report.json] [--fail-above=N] "
              "[--min-severity=SEV] [--list-rules]", file=sys.stderr)
        return 2
    try:
        report = scan_skill(args[0])
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if min_severity is not None:
        report = dict(report)
        report["findings"] = [f for f in report["findings"]
                              if SEVERITY_ORDER[f["severity"]]
                              <= SEVERITY_ORDER[min_severity]]
    print(format_report(report))
    if json_out:
        Path(json_out).write_text(json.dumps(report, indent=2) + "\n",
                                  encoding="utf-8")
        print("Report written to %s" % json_out)
    return 0 if report["score"] <= fail_above else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
