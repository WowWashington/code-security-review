# code-security-review

A security review skill for Claude Code (or any LLM coding assistant). Goes beyond pattern matching — traces data flow across files, builds auth consistency matrices, generates exploit proof-of-concepts, and explains findings in plain English. No external tools required.

Built for developers who ship fast and need a security sanity check before deploying. Especially useful for AI-generated code where common vulnerabilities accumulate quickly.

## What it does

Runs a nine-step analysis that combines grep (fast/cheap) with LLM reasoning (deep/contextual):

**Pattern layer (grep-based, catches obvious issues):**
1. **Signal scan** — grep for hardcoded secrets, SQL concat, eval, debug flags
2. **Attack surface mapping** — identifies input vectors, query builders, command execution, auth, crypto, file ops
3. **OWASP Top 10 classification** — maps findings to standard vulnerability categories with CWE IDs
4. **Dependency & supply chain check** — scans package manifests for typosquats, deprecated packages, unpinned versions, suspicious install scripts

**Reasoning layer (LLM-powered, catches what grep can't):**
5. **Taint tracing** — follows user input across files from source (HTTP request) to sink (database query, file path, command). Answers: "can an attacker actually control this value?"
6. **Auth consistency matrix** — maps every route's auth/authz status and flags inconsistencies (write is protected but read isn't, similar routes have different requirements)
7. **Exploit proof-of-concept** — generates copy-paste curl commands that demonstrate each HIGH/CRITICAL vulnerability. Makes risk undeniable.
8. **Plain-English summary** — "who can attack this, what could happen, what's protecting you, how long to fix" — no jargon, no CWE numbers
9. **Report** — severity-ranked findings with exact file/line references, code snippets, and fix examples

## Why this beats grep alone

| Technique | What grep finds | What reasoning finds |
|-----------|----------------|---------------------|
| SQL injection | `"SELECT * FROM " + input` | Input arrives in file A, passes through file B untouched, reaches query in file C |
| Missing auth | (can't) | Route X has auth, nearly-identical route Y doesn't — gap or intention? |
| IDOR | (can't) | Auth checks "is someone logged in?" but not "is this THEIR resource?" |
| Exploitability | "possible vulnerability" | `curl -X POST your-app.com/api/upload -F "file=@payload.jpg"` — proof it works |
| Impact | CWE-862 | "Anyone on the internet can delete your project photos without logging in" |

The pattern layer catches ~60% of real vulnerabilities. The reasoning layer pushes that toward 80%+ by understanding context, data flow, and system architecture.

## What it doesn't do

- Run your code or install anything
- Make network requests to registries
- Replace a full SAST tool (semgrep, bandit, etc.) for CVE-level scanning
- Perform runtime/dynamic testing
- Guarantee finding everything (no tool does — it tells you what still needs a human)

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

## From findings to fixes — the full pipeline

The real power comes from chaining this skill with what LLMs already do well. One scan becomes a complete remediation cycle:

```
┌─────────┐     ┌──────────────┐     ┌──────────┐     ┌───────────┐
│  SCAN   │ ──→ │ FILE ISSUES  │ ──→ │ LLM FIX  │ ──→ │ REVIEW PR │
│ (this)  │     │ (GitHub)     │     │ (any AI) │     │ (human)   │
└─────────┘     └──────────────┘     └──────────┘     └───────────┘
```

### 1. Scan your project

```
/code-security-review
```

You get a full report with severity, code context, and fix examples.

### 2. File issues to GitHub

If you're scanning your own repo, ask the assistant to formalize the findings:

```
Run /code-security-review on this project, then create GitHub issues
for any HIGH or CRITICAL findings.
```

Each issue gets: the exact file, line number, vulnerable code snippet, exploit PoC, and a recommended fix. This creates a formal audit trail and makes the work trackable.

### 3. Send your LLM to fix the issues

Once issues exist, you (or a teammate, or a scheduled agent) can point any LLM coding assistant at them:

```
Look at the open security issues labeled "security" on this repo and fix them.
Create a PR for each fix.
```

The issues are deliberately self-contained — they include enough context that an LLM can resolve them without reading the full conversation that produced them. The exploit PoC in each issue lets the LLM verify its fix works (the curl command should return 401 after the fix, not 201).

**This works with any AI coding tool:**
- Claude Code: `gh issue list --label security | ...`
- GitHub Copilot: reference the issue in chat
- Cursor/Windsurf: paste the issue URL
- Any agent with GitHub access

### 4. Human reviews the PR

The human's job shifts from "find the bug" to "verify the fix." Much faster. The PoC curl commands in the original issue serve as a manual test plan.

### 5. Run it again

After the fixes merge, run the scan again to confirm the findings are resolved and nothing new was introduced. The "PASSING CHECKS" section of the report confirms what's been fixed.

### Pre-deploy gate

Add it to your workflow before pushing to production. The JSON output format integrates with any CI system:

```yaml
# Example: run in CI, fail if CRITICAL findings exist
- name: Security review
  run: |
    claude "/code-security-review --json" | jq '.findings[] | select(.severity == "CRITICAL")' | grep -q . && exit 1 || exit 0
```

## Who this is for

- **Solo developers** shipping side projects who don't have a security team reviewing their code
- **Small teams** where "security review" means one person squinting at a PR diff
- **AI-heavy workflows** where code is generated fast and vulnerabilities accumulate faster
- **Students and junior devs** who want to learn security by seeing real examples in their own code
- **Anyone** who knows they should do a security review but doesn't know where to start

You don't need security training to use this. The plain-English summary tells you what matters, the exploit PoCs prove it's real, and the fix examples show you exactly what to change.

## Design philosophy

- **LLM-agnostic** — the skill is a structured methodology, not a proprietary API call. Any LLM that can read files and run grep can execute it. Works with Claude, GPT, Gemini, Llama, or whatever you're using.
- **No external dependencies** — uses only file reading and grep. No pip install, no npm install, no network calls, no accounts to create.
- **Reasoning over matching** — the taint tracing and auth matrix steps use the LLM's ability to understand code, not just regex it. This is what pushes detection beyond what static tools alone can do.
- **Low false positives** — confidence scoring, framework awareness, and a "manual review needed" bucket prevent alert fatigue. Better to miss a LOW finding than flood you with noise.
- **Actionable output** — every finding includes a concrete fix with example code. No vague "consider reviewing this area" warnings.
- **Proves the risk** — exploit PoCs make findings undeniable. A curl command that returns data it shouldn't gets fixed faster than a paragraph explaining why it's theoretically dangerous.
- **Acknowledges what's right** — the report includes passing checks. Security isn't only about what's broken.

## Limitations

- Static analysis only — no runtime behavior, no actual exploitation testing
- Taint tracing is best-effort across 2-3 file hops (won't trace through 10 layers of abstraction)
- Can't detect flaws that require business context the LLM doesn't have (but flags them for manual review)
- Dependency checks use pattern matching, not registry lookups — run `npm audit` / `pip-audit` / `cargo audit` for full CVE data
- Framework detection is heuristic — may miss custom or uncommon frameworks
- Not a replacement for a professional penetration test on high-stakes applications

## Contributing

PRs welcome for:
- New language-specific patterns
- Framework detection improvements
- Known-bad package lists (typosquats, compromised packages)
- False positive reductions
- Taint tracing examples for new frameworks

## License

MIT
