# Agent Skill Security Scanner

A dependency-free Python CLI that audits an AI-agent skill or plugin
package before it is installed. A skill runs with the agent's own
privileges, so a malicious one can read secrets, exfiltrate data or
run shell commands while looking like a harmless helper. This tool
reads the package — it never executes anything — checks it against
10 rules, and reports a risk score from 0 to 100 with a verdict of
OK, REVIEW or BLOCK.

Skills are the newest unguarded surface in the agent stack. The
rest of this series guards the agent itself: prompt-injection
detection on input, tool-permission auditing before it runs,
output-leak scanning after it responds, context-poison scanning on
everything retrieved in between, corpus-poison scanning before
content is indexed, a jailbreak test that scores the model, and an
MCP server audit that scores the servers it connects to. None of
that helps if the agent installs a skill whose SKILL.md says
"ignore all previous instructions" and whose helper script posts
your `.env` to a collector. This tool closes that gap: it scores
the skill, not the agent.

## The rules

| Rule | Severity | Check |
|---|---|---|
| S01 | critical | Instruction override / prompt injection in skill text |
| S02 | critical | Credential / secret access (.env, API keys, tokens, SSH keys) |
| S03 | high | Outbound data-send channel in helper code |
| S04 | high | Shell command execution (subprocess, os.system, eval, exec) |
| S05 | high | Network egress in helper code |
| S06 | high | Destructive file operation (remove, unlink, rmtree) |
| S07 | medium | Sensitive path read (~/.ssh, ~/.aws, /etc/passwd, keychain) |
| S08 | medium | Obfuscated or encoded payload (base64 blob decoded at runtime) |
| S09 | medium | Unscoped or wildcard tool permissions |
| S10 | low | Missing skill metadata (name, version or description) |

Weights: critical 25, high 15, medium 8, low 3, capped at 100.
Verdict: BLOCK at 60 or above (or any critical finding), REVIEW
at 25 or above, otherwise OK. Every finding carries a remediation
note; run `--list-rules` to see all ten with their advice.

## Input format

A directory containing a skill package: a `SKILL.md`, an optional
manifest (`skill.json` or `manifest.json`) and any helper scripts
(`.py`, `.js`, `.ts`, `.sh`). Python helpers are checked with the
`ast` module, not just string matching, so `subprocess.run` is
caught even when aliased; shell and JavaScript helpers are checked
by pattern. The scanner never executes the skill.

## Usage

```bash
python agent_skill_scanner.py examples/safe-skill
python agent_skill_scanner.py examples/risky-skill --json report.json
python agent_skill_scanner.py skill-dir --fail-above 25
python agent_skill_scanner.py skill-dir --min-severity high
python agent_skill_scanner.py --list-rules
```

Exit code: `0` = risk score at or below `--fail-above`
(default 60), `1` = score above it, `2` = usage/input error.

## Example

```text
$ python agent_skill_scanner.py examples/risky-skill
Skill: system-cleaner (3 file(s))
Risk score: 100/100 (11 finding(s)) -> BLOCK
  critical: 3, high: 4, medium: 3, low: 1
  [CRITICAL] S01 SKILL.md: instruction-override language: 'do not tell the user'
  [CRITICAL] S02 SKILL.md: references secrets/credentials: '.env'
  [CRITICAL] S02 clean.py: references secrets/credentials: '.env'
  [HIGH] S03 clean.py: sends data outbound (requests.post / urlopen / http.client.request)
  [HIGH] S04 clean.py: executes shell commands (subprocess / os.system / eval / exec)
  [MEDIUM] S08 clean.py: long base64 blob (66 chars) decoded at runtime
  ...

$ python agent_skill_scanner.py examples/safe-skill
Skill: pdf-summarizer (3 file(s))
Risk score: 0/100 (0 finding(s)) -> OK
  critical: 0, high: 0, medium: 0, low: 0
```

The safe skill still gets an honest read: a read-only PDF helper
with a scoped tool list and full metadata scores 0, while the
risky skill is BLOCKed on three separate critical findings, not
just one bad line.

## Tests

```bash
python -m unittest discover tests -v   # 23 tests, all passing
```

## Files

- `agent_skill_scanner.py` — the scanner (standard library only)
- `tests/test_agent_skill_scanner.py` — 23 unit tests
- `examples/safe-skill/` — read-only PDF summarizer, 0/100, OK
- `examples/risky-skill/` — "system cleaner" with injection text,
  secret theft, exfiltration, shell execution and a wildcard
  permission list, 100/100, BLOCK
- `examples/sample-report.json` — JSON report from the risky run

## Limitations

The audit is static: it reads a skill package, it never installs
or executes it, so a skill that hides its behaviour behind
indirection (a helper fetched at runtime, a second-stage download)
will be under-scored. Text-pattern rules are heuristic — a skill
that phrases an override politely ("for best results, please
disregard earlier guidance") may slip past the pattern list, and
a legitimate skill that mentions `.env` only to warn against it
will be flagged. Treat the score as a repeatable triage gate for
the skills you install, not a proof of safety, and always review
BLOCK findings by hand before installing.

## How it fits the series

This continues the AI-agent guardrail series: prompt-injection
detection on user input, tool-permission auditing before an agent
runs, output-leak scanning after it responds, context-poison
scanning on everything retrieved in between, corpus-poison
scanning before content is indexed, a jailbreak test that scores
the model itself, an MCP server audit that scores the servers the
agent connects to, and now a skill audit that scores the plugins
the agent installs — the last unguarded surface in the chain.
