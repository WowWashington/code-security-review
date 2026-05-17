# code-security-review

A pattern-based security review skill for Claude Code (or any LLM coding assistant). Scans your project for OWASP Top 10 vulnerabilities, hardcoded secrets, supply chain risks, and unsafe data flow — without requiring external tools.

## What it does

Runs a five-step static analysis:

1. **Signal scan** — grep for high-signal patterns (hardcoded secrets, SQL concat, eval, debug flags)
2. **Attack surface mapping** — identifies input vectors, query builders, command execution, auth, crypto, file ops
3. **OWASP Top 10 classification** — maps findings to standard vulnerability categories with CWE IDs
4. **Dependency & supply chain check** — scans your actual package manifests for typosquats, deprecated packages, unpinned versions, suspicious install scripts, unpinned GitHub Actions
5. **Report** — severity-ranked findings with exact file/line references, code snippets, and fix examples

## What it doesn't do

- Run your code or install anything
- Make network requests to registries
- Replace a full SAST tool (semgrep, bandit, etc.)
- Understand business logic (flags those for manual review)

This is a fast first pass — the kind of review you'd do before pushing to production. It catches the 40-60% of issues that are pattern-matchable, then tells you what still needs a human.

## Installation

Copy `SKILL.md` into your Claude Code skills directory:

```bash
mkdir -p ~/.claude/skills/code-security-review
cp SKILL.md ~/.claude/skills/code-security-review/SKILL.md
```

The skill will be available immediately in your next Claude Code session.

## Usage

```
/code-security-review                    # scan current project
/code-security-review src/api/           # scan specific directory
/code-security-review auth.py            # scan specific file
```

### Output formats

- **Detailed** (default) — full report with severity, CWE, code context, fix examples
- **Compact** — one-liner per finding, good for quick triage
- **JSON** — structured output for CI/CD integration

Ask for a format by adding it to your request:
```
/code-security-review — compact output
/code-security-review — json format
```

## Supported languages

Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, Rust, C# — with framework-aware checks for Django, FastAPI, Flask, Express, Next.js, Spring, Rails, Laravel, ASP.NET.

## From findings to fixes

The real power of this skill comes from chaining it with your existing workflow:

### 1. File issues automatically

If you're scanning a project that lives on GitHub, ask your assistant to file the findings as issues:

```
Run /code-security-review on this project, then create GitHub issues
for any HIGH or CRITICAL findings.
```

This gives you a formal audit trail — each issue has the exact file, line, code snippet, and recommended fix.

### 2. Let your LLM fix the issues

Once issues are filed, you (or a teammate) can point any LLM coding assistant at them:

```
Look at the open security issues on this repo and fix them.
```

The issues are self-contained — they include enough context (file path, line number, vulnerable code, fix example) that an LLM can resolve them without additional explanation. This turns a security review into a one-command remediation pipeline:

```
scan → file issues → fix issues → review PR
```

### 3. Run it before every deploy

Add it to your pre-push workflow or CI script as a gate. The JSON output format integrates with any CI system that can parse structured results.

## Design philosophy

- **LLM-agnostic** — the skill is a structured methodology (checklist + grep patterns), not a proprietary API call. Any LLM that can read files and run grep can execute it.
- **No external dependencies** — uses only file reading and grep. No pip install, no npm install, no network calls.
- **Low false positives** — confidence scoring, framework awareness, and a "manual review needed" bucket prevent alert fatigue.
- **Actionable output** — every finding includes a concrete fix with example code. No vague warnings.
- **Passing checks matter** — the report acknowledges what's done right, confirming coverage and building trust.

## Limitations

- Static analysis only — no runtime behavior, no actual exploitation testing
- Can't detect business logic flaws (IDOR without domain knowledge, race conditions in distributed systems)
- Dependency checks use pattern matching, not registry lookups — run `npm audit` / `pip-audit` / `cargo audit` for full CVE data
- Framework detection is heuristic — may miss custom frameworks or unusual project structures

## Contributing

PRs welcome for:
- New language-specific patterns
- Framework detection improvements
- Known-bad package lists (typosquats, compromised packages)
- False positive reductions

## License

MIT
