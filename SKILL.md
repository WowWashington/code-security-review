---
name: code-security-review
description: Quick security review for a project or code snippet. Scans for OWASP Top 10 patterns, hardcoded secrets, injection risks, and unsafe data flow. LLM-agnostic — uses pattern matching and checklist methodology, not external tools.
user-invocable: true
allowed-tools: Read, Bash, Glob, Grep
---

# Code Security Review

Fast, pattern-based security scan for any codebase. Finds common vulnerability patterns without requiring external SAST tools. Designed for AI-generated code and rapid prototypes where security debt accumulates fastest.

## Trigger

User says: "security review", "check for vulnerabilities", "audit this code", "find security issues", "code-security-review", or pastes code asking about safety.

## Arguments

- `$ARGUMENTS` may contain: a file path, directory, language hint, or severity filter.
- If empty, scan the current working directory (respecting .gitignore).

## Execution Flow

### Step 0: Scope Detection

Determine what to scan:

1. If user provided a specific file or snippet — scan that.
2. If user provided a directory — scan it.
3. If no argument — scan the current project root. Look for common entry points:
   - `src/`, `app/`, `lib/`, `api/`, `routes/`, `handlers/`, `views/`, `controllers/`
   - `*.py`, `*.js`, `*.ts`, `*.go`, `*.rs`, `*.java`, `*.cs`, `*.rb`, `*.php`

Detect language from file extensions. Note the primary framework if identifiable (Django, FastAPI, Flask, Express, Spring, Rails, Laravel, ASP.NET, Next.js, etc.).

Skip: `node_modules/`, `venv/`, `.git/`, `__pycache__/`, `dist/`, `build/`, `vendor/`, lock files, generated code.

### Step 1: Signal Scan (Automated Grep)

Run targeted grep/ripgrep searches for high-signal patterns. These are fast, cheap, and catch the worst offenders:

```bash
# Hardcoded secrets (high-entropy strings, known prefixes)
grep -rn --include='*.py' --include='*.js' --include='*.ts' --include='*.go' --include='*.java' --include='*.rb' --include='*.php' --include='*.cs' --include='*.rs' -E '(password|secret|token|api_key|apikey|api_secret|private_key)\s*=\s*["\x27][^"\x27]{8,}' .

# AWS/GCP/Azure key patterns
grep -rn -E '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9a-zA-Z]{36}|sk-[0-9a-zA-Z]{48})' .

# SQL string concatenation
grep -rn -E '(SELECT|INSERT|UPDATE|DELETE|DROP).*(\+|%|\.format|\$\{|f")' .

# eval/exec with variables
grep -rn -E '(eval|exec|os\.system|subprocess\.call|child_process\.exec|Runtime\.exec)\s*\(' .

# Dangerous deserialization
grep -rn -E '(pickle\.loads|yaml\.load\(|Marshal\.load|unserialize|JSON\.parse.*eval)' .

# Debug/verbose modes likely left on
grep -rn -E '(DEBUG\s*=\s*True|debug:\s*true|verbose:\s*true|NODE_ENV.*development)' .
```

Adapt patterns based on detected language. Do NOT run all patterns for all languages — only relevant ones.

### Step 2: Attack Surface Mapping (Paranoid Read)

Read the files identified in Step 1 plus key entry points (routes, handlers, main files). For each, identify and annotate:

| Category | What to find | Risk |
|----------|-------------|------|
| **Input vectors** | Request params, form data, CLI args, file reads, env vars, headers, cookies | Data enters the system |
| **Query construction** | SQL, NoSQL, GraphQL, ORM raw queries, stored procs | Injection target |
| **Command execution** | subprocess, shell, exec, eval, system() | RCE target |
| **Auth/identity** | Token generation, password handling, session management, JWT | Broken auth |
| **Crypto** | Hashing, encryption, key management, random number generation | Weak crypto |
| **Output/errors** | Exception handlers, logging, API responses, rendered templates | Info disclosure |
| **File operations** | Path construction, file writes, uploads, temp files | Path traversal |
| **Network** | HTTP requests, URL construction, redirects, SSRF vectors | SSRF/open redirect |

For each identified surface, trace the data flow: where does input arrive, what transforms are applied (or not), and where does it exit?

### Step 3: OWASP Top 10 Pattern Check

For each finding from Steps 1-2, classify against OWASP 2021 categories. Use standard metadata:

| ID | Category | Pattern Signals |
|----|----------|----------------|
| A01 | Broken Access Control | Missing authz checks, direct object references without validation, CORS misconfiguration, path traversal |
| A02 | Cryptographic Failures | MD5/SHA1 for passwords, hardcoded keys, missing TLS enforcement, weak random |
| A03 | Injection | String concat in queries, unparameterized SQL, template injection, command injection, XSS |
| A04 | Insecure Design | Missing input validation, no rate limiting, race conditions, missing business logic checks |
| A05 | Security Misconfiguration | Debug enabled, default credentials, overly permissive CORS, verbose errors in production |
| A06 | Vulnerable Components | Known-bad imports (e.g., `pickle` on untrusted), deprecated crypto functions |
| A07 | Auth Failures | No password complexity, missing MFA hooks, session without expiry, token in URL |
| A08 | Integrity Failures | Unsafe deserialization, unsigned updates, missing integrity checks |
| A09 | Logging Failures | Secrets in logs, PII logged, no audit trail for sensitive ops |
| A10 | SSRF | Unvalidated URL fetch, XML external entities, user-controlled redirect targets |

### Step 4: Dependency & Supply Chain Check

Scan the project's actual dependency manifests for supply-chain risks. Only check packages the project uses — do not speculate about packages not present.

**Locate manifests:**

```bash
# Find all dependency files in the project
find . -maxdepth 3 \( \
  -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \
  -o -name "requirements.txt" -o -name "Pipfile" -o -name "Pipfile.lock" -o -name "pyproject.toml" -o -name "poetry.lock" \
  -o -name "go.mod" -o -name "go.sum" \
  -o -name "Cargo.toml" -o -name "Cargo.lock" \
  -o -name "Gemfile" -o -name "Gemfile.lock" \
  -o -name "composer.json" -o -name "composer.lock" \
  -o -name "pom.xml" -o -name "build.gradle" \
  -o -name "*.csproj" -o -name "packages.config" \
\) -not -path "*/node_modules/*" -not -path "*/vendor/*" -not -path "*/.git/*"
```

**For each manifest found, check for:**

#### A. Typosquatting / Name Confusion

Compare package names against known typosquat targets. Flag packages that are:
- One character off from popular packages (e.g., `colourama` vs `colorama`, `reqeusts` vs `requests`)
- Hyphen/underscore variants of known packages (e.g., `python-nmap` vs `python_nmap`)
- Scope confusion in npm (e.g., `lodash` vs `@lodash/core` — are both needed?)

Known high-value typosquat targets to check against:
| Ecosystem | Commonly Targeted |
|-----------|-------------------|
| npm | express, lodash, axios, react, vue, webpack, babel, chalk, commander, inquirer, dotenv, jsonwebtoken, bcrypt, mongoose, sequelize, cors, helmet, morgan, nodemailer |
| pip | requests, flask, django, numpy, pandas, boto3, cryptography, paramiko, fabric, celery, pillow, scrapy, beautifulsoup4, sqlalchemy, pyyaml, colorama |
| Go | common paths under `github.com/` with subtle org misspellings |
| Cargo | serde, tokio, reqwest, clap, rand, hyper, actix |
| Gem | rails, devise, nokogiri, puma, sidekiq |

#### B. Known Malicious / Compromised Packages

Flag if any installed package matches recently reported supply-chain incidents:
- **npm**: packages with `preinstall`/`postinstall` scripts that exec network calls or decode base64 payloads — check `package.json` scripts section
- **pip**: packages that run arbitrary code in `setup.py` during install
- **Any ecosystem**: packages pulled from forked repos or unusual registries

Check `package.json` for suspicious install scripts:
```bash
# npm: look for install hooks that do network/exec operations
grep -A2 '"preinstall"\|"postinstall"\|"prepare"' package.json 2>/dev/null
```

#### C. Abandoned / Unmaintained Indicators

Flag dependencies that show signs of risk:
- Pinned to very old versions (2+ major versions behind when evident from manifest)
- Using deprecated package names (e.g., `request` npm package, `pycrypto` vs `pycryptodome`)
- Packages with known CVEs that have been public for 6+ months

Known deprecated/replaced packages to flag:
| Deprecated | Replacement | Ecosystem |
|-----------|-------------|-----------|
| `request` | `node-fetch`, `axios`, `undici` | npm |
| `nomnom` | `commander`, `yargs` | npm |
| `istanbul` | `nyc`, `c8` | npm |
| `pycrypto` | `pycryptodome` | pip |
| `optparse` | `argparse` (stdlib) | pip |
| `imp` | `importlib` | pip |
| `cgi` | `http.server`, frameworks | pip |

#### D. Overly Permissive Version Ranges

Flag manifests using dangerous version specifiers that could pull in compromised future versions:
- `*` or `latest` in package.json
- No pinning at all (bare package name in requirements.txt without `==`)
- `>=` without upper bound
- Git dependencies pointing to `main`/`master` branch without commit hash

```bash
# npm: find wildcard or latest versions
grep -E '"[*]"|"latest"' package.json 2>/dev/null

# pip: find unpinned deps
grep -v -E '==|~=|<' requirements.txt 2>/dev/null | grep -v '^#' | grep -v '^$'
```

#### E. Excessive Permissions / Scope

For projects that use plugins, extensions, or OAuth scopes:
- Browser extensions requesting `<all_urls>`, `tabs`, `webRequest`, `cookies` beyond their stated purpose
- GitHub Actions using third-party actions without pinning to a commit SHA
- OAuth scopes broader than needed for stated functionality
- Docker images running as root or pulling from unverified registries

```bash
# GitHub Actions: check for unpinned third-party actions
grep -rn 'uses:' .github/workflows/ 2>/dev/null | grep -v '@[a-f0-9]\{40\}' | grep -v 'actions/'

# Docker: check for root and unverified base images
grep -n 'USER root\|FROM [^/]*$' Dockerfile* 2>/dev/null
```

#### F. Dependency Report Section

Add to the output report under its own heading:

```
DEPENDENCIES (<package manager>):
  Manifest: <path to manifest>
  Total packages: <count>

  ⚠️  SUPPLY CHAIN RISKS:
    [SC-01] Typosquat suspect: "<pkg>" — similar to "<known_pkg>" (verify intended package)
    [SC-02] Deprecated package: "<pkg>" — replaced by "<replacement>" (known vulnerabilities)
    [SC-03] Unpinned dependency: "<pkg>" with range "<range>" — could auto-update to compromised version
    [SC-04] Suspicious install script: "<pkg>" runs "<script>" on install
    [SC-05] Unmaintained: "<pkg>" — last release >2 years ago (if evident)
    [SC-06] Excessive permissions: GitHub Action "<action>" not pinned to commit SHA
    [SC-07] Overprivileged: extension/plugin requests "<permission>" beyond stated need

  ✓ PASSING:
    ✓ No known typosquats detected
    ✓ Dependencies pinned to specific versions
    ✓ No suspicious install scripts
    ✓ All GitHub Actions pinned to SHA
```

#### Rules for Dependency Checks

1. **Only check what's in the project.** Never speculate about packages not listed in a manifest.
2. **Don't run install commands.** Never `npm install`, `pip install`, etc. Read manifests only.
3. **Don't hit registries.** No network calls to npm/PyPI/crates.io. Use pattern matching and known-bad lists.
4. **Confidence matters.** Typosquat detection is fuzzy — mark as MEDIUM confidence unless the name is a known reported incident.
5. **Suggest tooling.** After the check, recommend the user run `npm audit`, `pip-audit`, `cargo audit`, or `bundler-audit` for CVE-level data that requires registry lookups.

### Step 5: Taint Tracing (Cross-File Data Flow)

This step goes beyond grep. Read the code and trace user-controlled input from entry to exit. This catches vulnerabilities that span multiple files — the kind that pattern matching alone will never find.

**How to execute:**

1. Identify all **sources** (where untrusted data enters the system):
   - HTTP request parameters, headers, cookies, body
   - File uploads (filename, content, metadata)
   - Database reads that contain user-provided data from earlier requests
   - Environment variables that could be set by deployment config
   - CLI arguments, stdin
   - Webhook payloads, message queue data

2. Identify all **sinks** (where data could cause harm):
   - SQL/NoSQL queries
   - Shell commands, process spawning
   - File system paths (read, write, delete)
   - HTML/template rendering (XSS)
   - HTTP responses with sensitive data
   - Redirect targets (open redirect)
   - Logging calls (secrets in logs)
   - Serialization/deserialization

3. For each source, **trace forward** through the code:
   - Does the data pass through any validation/sanitization function?
   - Does it get assigned to a new variable and lose its "tainted" identity?
   - Does it cross a file boundary (exported function, shared module, API call)?
   - Does it reach a sink? If yes — is the sink protected (parameterized query, escaped template, etc.)?

4. For each finding, document the **full path**:

```
TAINT TRACE:
  Source: req.body.userId (src/app/api/users/route.ts:15)
    → passed to getUser(userId) (src/app/api/users/route.ts:18)
    → parameter used in db.select().where(eq(users.id, userId)) (src/db/queries.ts:7)
  Sink: Drizzle ORM eq() — PARAMETERIZED ✓ (safe)
  Result: NOT VULNERABLE — ORM handles escaping

TAINT TRACE:
  Source: req.query.redirect (src/app/api/auth/callback/route.ts:5)
    → passed directly to NextResponse.redirect(redirect) (line 22)
    → NO validation of URL scheme or domain
  Sink: HTTP redirect target — OPEN REDIRECT ✗
  Result: VULNERABLE — attacker controls redirect destination
  Fix: Validate redirect is relative path or matches allowed domains
```

**What makes this valuable:** Pattern matching finds `eval(x)` but can't tell whether `x` came from user input or a hardcoded config. Taint tracing answers: "can an attacker actually control this value?" That distinction is the difference between a false positive and a real exploit.

**Focus areas for tracing (in priority order):**
1. Any data that flows from HTTP request → database query
2. Any data that flows from HTTP request → file path construction
3. Any data that flows from HTTP request → command execution
4. Any data that flows from HTTP request → HTTP redirect or URL construction
5. Any data from database that contains user-submitted content → HTML rendering
6. Any data from HTTP request → another HTTP request (SSRF)

### Step 6: Auth Consistency Matrix

Build a complete picture of authentication and authorization across the application. This is not a per-file check — it's a system-level analysis that catches gaps by comparing what protection exists on similar routes.

**How to execute:**

1. **List every route/endpoint** in the application with:
   - HTTP method (GET, POST, PUT, DELETE)
   - Path pattern
   - What auth check is present (if any)
   - What role/permission is required (if any)
   - What data it exposes or mutates

2. **Build the matrix:**

```
AUTH CONSISTENCY MATRIX:
┌─────────────────────────────────────────────────────────────────────────┐
│ Route                          │ Method │ Auth? │ Role     │ Action     │
├─────────────────────────────────────────────────────────────────────────┤
│ /api/users                     │ GET    │ ✓     │ owner    │ list users │
│ /api/users                     │ POST   │ ✓     │ owner    │ create     │
│ /api/users/:id                 │ GET    │ ✗     │ —        ��� read user  │ ← INCONSISTENT
│ /api/users/:id                 │ PUT    │ ✓     │ varies   │ update     │
│ /api/users/:id                 │ DELETE │ ✓     │ owner    │ delete     │
│ /api/projects                  │ GET    │ ✓     │ worker+  │ list       │
│ /api/projects/:id              │ GET    │ ✗     │ —        │ read       │ ← INTENTIONAL?
│ /api/projects/:id              │ PUT    │ ✓     │ worker+  │ update     │
│ /api/projects/:id              │ DELETE │ ✓     │ coord+   │ delete     │
│ /api/uploads/:path             │ GET    │ ✗     │ —        │ serve file │ ← INTENTIONAL (static)
│ /api/photos/:id                │ PUT    │ ✗     │ —        │ edit photo │ ← GAP
│ /api/photos/:id                │ DELETE │ ✗     │ —        │ delete     │ ← GAP
└─────────────────────────────────────────────────────────────────────────┘
```

3. **Flag inconsistencies:**
   - Same resource has auth on write but not read (might be intentional, might be a gap)
   - Similar resources have different auth levels (one CRUD set is protected, another isn't)
   - Data mutation (POST/PUT/DELETE) without any auth (almost always a bug)
   - Admin/owner operations accessible at lower role levels

4. **Check ownership patterns (IDOR analysis):**
   - When a route takes an `:id` parameter, does the handler verify the authenticated user owns/can-access that resource?
   - Or does it just check "is someone logged in?" without checking "are they allowed to see THIS specific item?"
   - Common IDOR pattern: auth check passes, but any authenticated user can access any other user's data by guessing IDs

```
IDOR ANALYSIS:
  /api/users/:id (GET) — returns user data for ANY id, no ownership check
    Risk: Any authenticated user can read any other user's profile
    Question: Is this intended? (crew app where everyone sees everyone = OK)

  /api/projects/:id (PUT) — checks auth but not "does this user belong to this project?"
    Risk: Worker A could modify Worker B's project
    Question: Is there project-level access control?
```

5. **Report format:**

```
AUTH CONSISTENCY FINDINGS:

  GAPS (unauthenticated mutation):
    ✗ POST /api/activities/:id/photos — file upload, no auth
    ✗ DELETE /api/photos/:id — file deletion, no auth

  INCONSISTENCIES (different auth on same resource):
    ⚠️  /api/users/:id — PUT requires owner/coord, GET requires nothing

  IDOR CANDIDATES (auth present but no ownership check):
    ? GET /api/users/:id — any session can read any user
    ? PUT /api/projects/:id — session checked, ownership not checked

  CONSISTENT (properly protected):
    ✓ /api/users — all methods require owner role
    ✓ /api/settings — all methods require owner role
    ✓ /api/auth — rate limited, no enumeration
```

**Why this matters for beginners:** Most security tutorials focus on "add authentication" but forget authorization. The matrix makes the distinction visible: auth = "are you logged in?", authz = "are you allowed to do THIS specific thing?" The matrix catches both.

### Step 7: Exploit Proof-of-Concept Generation

For every HIGH and CRITICAL finding, generate a concrete, copy-paste exploit that demonstrates the vulnerability. This transforms abstract warnings into undeniable proof that something is broken.

**Rules:**
1. Generate exploits ONLY for the user's own project (this is defensive testing)
2. Use standard tools: `curl`, `fetch()`, browser DevTools, or simple scripts
3. Show the malicious request AND what the expected (bad) response would be
4. Immediately follow with the "after fix" version showing the safe behavior
5. Never generate exploits that target third-party systems
6. Keep payloads educational — demonstrate the concept without providing weaponizable tools

**Format:**

```
EXPLOIT PROOF-OF-CONCEPT:

┌─ Finding: [CWE-862] Unauthenticated File Upload ─────────────────────┐
│                                                                        │
│  VULNERABLE REQUEST:                                                   │
│  curl -X POST https://your-app.com/api/activities/any-id/photos \     │
│    -F "file=@malicious.jpg" \                                         │
│    -F "note=uploaded without login"                                    │
│                                                                        │
│  EXPECTED RESPONSE (vulnerable):                                       │
│  HTTP 201 {"id":"...","fileName":"any-id-1234567.jpg","note":"..."}   │
│                                                                        │
│  IMPACT: Anyone on the internet can fill your server's disk with      │
│  arbitrary files (within the image validation constraints).            │
│  Attack cost: zero authentication required.                            │
│                                                                        │
│  AFTER FIX:                                                            │
│  curl -X POST https://your-app.com/api/activities/any-id/photos \     │
│    -F "file=@photo.jpg"                                               │
│                                                                        │
│  EXPECTED RESPONSE (fixed):                                            │
│  HTTP 401 {"error":"Not authenticated"}                               │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

┌─ Finding: [CWE-601] Open Redirect ───────────────────────────────────┐
│                                                                        │
│  VULNERABLE REQUEST:                                                   │
│  https://your-app.com/api/auth/callback?redirect=https://evil.com     │
│                                                                        │
│  WHAT HAPPENS: User clicks what looks like a legitimate link to       │
│  your app, gets redirected to attacker's site (phishing, credential   │
│  theft). The URL bar showed your domain initially = trust.             │
│                                                                        │
│  AFTER FIX:                                                            │
│  https://your-app.com/api/auth/callback?redirect=https://evil.com     │
│  → HTTP 400 {"error":"Invalid redirect URL"}                          │
│                                                                        │
│  OR: redirect=/ (relative only) → works as expected                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘

┌─ Finding: [CWE-89] SQL Injection ────────────────────────────────────┐
│                                                                        │
│  VULNERABLE REQUEST:                                                   │
│  curl https://your-app.com/api/search?q='; DROP TABLE users; --       │
│                                                                        │
│  WHAT HAPPENS: If the query parameter is concatenated into SQL,       │
│  the attacker's payload terminates the original query and executes    │
│  an arbitrary command. In this case, deleting all user data.          │
│                                                                        │
│  DETECTION TEST (safe):                                                │
│  curl https://your-app.com/api/search?q=' OR '1'='1                  │
│  → If this returns ALL records instead of none, injection is present  │
│                                                                        │
│  AFTER FIX (parameterized):                                            │
│  curl https://your-app.com/api/search?q='; DROP TABLE users; --       │
│  → Searches literally for the string "; DROP TABLE users; --"         │
│  → Returns 0 results (treated as data, not code)                      │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**For supply chain findings, show the risk scenario:**

```
┌─ Finding: [SC-06] Unpinned GitHub Action ────────────────────────────┐
│                                                                        │
│  CURRENT CONFIG:                                                       │
│  uses: azure/docker-login@v1                                          │
│                                                                        │
│  ATTACK SCENARIO:                                                      │
│  1. Attacker compromises the azure/docker-login repo                  │
│  2. Pushes malicious code and moves the v1 tag to the new commit     │
│  3. Your next deploy pulls the compromised action                     │
│  4. Attacker's code runs with YOUR secrets (ACR_PASSWORD, etc.)       │
│  5. They now have access to your container registry and Azure creds   │
│                                                                        │
│  This has happened in the real world:                                  │
│  - tj-actions/changed-files (March 2025) — compromised tag            │
│  - codecov/codecov-action (2021) — supply chain attack via bash uploader│
│                                                                        │
│  FIX: Pin to immutable commit SHA                                     │
│  uses: azure/docker-login@f053f11ee1e8871cf4a2b4f4b93e2c1e6ffb25e3   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Why this matters:** A report that says "SQL injection possible" gets ignored. A report that includes a curl command proving the database is exposed gets fixed the same day. The PoC makes the risk tangible and undeniable — especially for teams where security isn't the primary expertise.

### Step 8: Security Posture Summary (For Non-Security People)

End the report with a plain-English summary that anyone can understand — no jargon, no CWE numbers, just "here's what this means for your app and your users."

```
PLAIN-ENGLISH SUMMARY:
═══════════════════════════════════════════════════

WHO CAN ATTACK THIS APP RIGHT NOW:
  • Anyone on the internet (no login needed) can upload files to your server
  • Anyone on the internet can delete photos from your projects
  • Anyone with a link to your app can see your team's activity history

WHAT COULD HAPPEN:
  �� Disk filled with junk files → app crashes (denial of service)
  • Project photos deleted → lost documentation of completed work
  • Business activity visible to competitors or bad actors

WHAT'S PROTECTING YOU:
  • All database queries are safe from injection (your ORM handles this)
  • No passwords or API keys are exposed in the code
  • Login has brute-force protection (locks out after 5 bad attempts)
  • File uploads are validated (can't upload malware disguised as images)

EFFORT TO FIX:
  • 3 files need a 2-line auth check added (30 minutes of work)
  • 1 file needs "secure: true" added to a cookie (5 minutes)
  • 1 file needs Math.random replaced with crypto.randomInt (5 minutes)
  • 1 config file needs SHA hashes looked up (15 minutes)

  Total estimated fix time: ~1 hour
  Difficulty: straightforward — no architecture changes needed

PRIORITY:
  Fix the unauthenticated upload/delete routes FIRST.
  Everything else is defence-in-depth (good practice, not urgent).
```

**Why this section exists:** Security reports are useless if the person reading them doesn't understand the impact. A developer who isn't a security specialist needs to know: "is this a stop-everything emergency, or a nice-to-have?" This section answers that question in one glance.

### Step 9: Report

Format findings as follows:

```
Security Review: <target>
Language: <detected> | Framework: <detected or "none identified">
Files scanned: <count> | Lines analyzed: <approx>
═══════════════════════════════════════════════════

CRITICAL (<count>):
  [CWE-<id>] <Vulnerability Name> (<file>:<line>)
  Category: <OWASP A0X>
  Severity: CRITICAL | Confidence: HIGH/MEDIUM/LOW
  Code: <exact code snippet, 1-3 lines>
  Issue: <what's wrong, one sentence>
  Fix: <specific remediation with example>

HIGH (<count>):
  ...

MEDIUM (<count>):
  ...

LOW (<count>):
  ...

───────────────────────────────────────────────────
PASSING CHECKS:
  ✓ <thing that was checked and found safe>
  ✓ ...

MANUAL REVIEW NEEDED:
  ? <thing that requires human/domain judgment>
  ? ...

───────────────────────────────────────────────────
DEPENDENCIES (<ecosystem>):
  Manifest: <path>
  Packages: <count>
  Supply chain risks: <count or "none detected">
  <findings if any, using SC-XX codes>

───────────────────────────────────────────────────
SUMMARY
  Findings: <total> (<critical> critical, <high> high, <medium> medium, <low> low)
  Supply chain: <count> issues across <count> dependencies
  Risk level: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
  Auto-fixable: <count> (can be fixed with straightforward code changes)
  Needs human: <count> (requires domain knowledge or architecture decisions)

RECOMMENDED NEXT STEPS:
  1. Fix all CRITICAL and HIGH findings before deploying
  2. Run ecosystem-specific audit tool for full CVE coverage:
     - npm/yarn/pnpm: `npm audit` or `yarn audit`
     - pip: `pip-audit` or `safety check`
     - Go: `govulncheck ./...`
     - Cargo: `cargo audit`
     - Ruby: `bundler-audit check`
     - PHP: `composer audit`
  3. Consider adding to CI: <specific tool for detected ecosystem>
```

## Severity Definitions

| Level | Meaning | Example |
|-------|---------|---------|
| CRITICAL | Exploitable with no prerequisites, high impact | SQL injection, RCE, hardcoded prod credentials |
| HIGH | Exploitable with some context, significant impact | XSS, auth bypass, info disclosure of secrets |
| MEDIUM | Requires specific conditions, moderate impact | Missing input validation, weak crypto, CSRF |
| LOW | Minor risk, defense-in-depth concern | Verbose errors, missing security headers, no rate limit |

## Confidence Definitions

| Level | Meaning |
|-------|---------|
| HIGH | Pattern is unambiguous; almost certainly a real vulnerability |
| MEDIUM | Pattern matches but context could make it safe; likely real |
| LOW | Possible issue depending on usage context; may be false positive |

## Rules

1. **Never run the code.** This is static analysis only. No execution, no network requests, no imports.
2. **Never install tools.** Use only grep, file reading, and pattern knowledge. No pip install, npm install, etc.
3. **Be specific.** Every finding must reference an exact file, line number, and code snippet.
4. **Show the fix.** Every finding must include a concrete remediation with example code.
5. **Flag uncertainty.** If confidence is LOW or you need domain context, put it in "Manual Review Needed" — don't inflate severity.
6. **Include passing checks.** Acknowledge what's done right. This builds trust and confirms coverage.
7. **Language-aware.** Python `pickle` is not the same risk as Go's `encoding/gob`. Adjust patterns to language idioms.
8. **Framework-aware.** Django ORM is parameterized by default. Express `req.params` is always a string. Don't flag safe framework patterns.
9. **No false-positive flooding.** If confidence is LOW and severity is LOW, skip it unless the user asked for "all findings."
10. **Respect scope.** Only scan what the user asked for. Don't crawl into dependencies or vendored code.

## Language-Specific Patterns

### Python
- `pickle.loads()`, `yaml.load()` without SafeLoader, `eval()`, `exec()`
- `os.system()`, `subprocess` with `shell=True`
- f-strings or `.format()` in SQL context
- `hashlib.md5()` / `hashlib.sha1()` for passwords (vs bcrypt/argon2)
- `DEBUG = True` in settings, `SECRET_KEY` hardcoded
- `request.args.get()` without validation

### JavaScript/TypeScript
- `eval()`, `Function()`, `innerHTML`, `document.write()`
- `child_process.exec()` with template literals
- `dangerouslySetInnerHTML` in React
- String concatenation in SQL (common with `mysql` package)
- `JWT` without expiry, `localStorage` for tokens
- `express` routes without input validation middleware

### Go
- `fmt.Sprintf` in SQL context (vs `db.Query` with `?`)
- `os/exec.Command` with user input
- `unsafe.Pointer` usage
- `net/http` without timeout configuration
- Template execution with unescaped user data
- `crypto/md5` or `crypto/sha1` for auth

### Java
- `Runtime.getRuntime().exec()` with concatenation
- `Statement.execute()` vs `PreparedStatement`
- `ObjectInputStream.readObject()` on untrusted data
- XML parsing without disabling external entities
- `MessageDigest.getInstance("MD5")` for passwords
- Spring `@RequestParam` without `@Valid`

### Ruby
- `system()`, backticks, `exec()` with interpolation
- `ActiveRecord` `.where("col = '#{val}'")`  (vs `.where(col: val)`)
- `YAML.load` (vs `YAML.safe_load`)
- `send()` with user-controlled method names
- ERB `<%= %>` with unescaped user data

### PHP
- `mysql_query()` with concatenation (vs PDO prepared statements)
- `eval()`, `preg_replace` with `/e` modifier
- `include()`/`require()` with user input
- `unserialize()` on untrusted data
- `$_GET`/`$_POST` used directly in SQL/HTML/commands
- `extract()` on user input

### Rust
- `unsafe` blocks (note: often legitimate, but flag for review)
- Raw SQL via string formatting (vs query builders)
- `.unwrap()` in network-facing code (panic = DoS)
- `std::process::Command` with user-derived args

### C#
- `SqlCommand` with string concatenation (vs parameterized)
- `Process.Start()` with user input
- `BinaryFormatter.Deserialize()` on untrusted data
- `HttpUtility.HtmlEncode` missing on output
- XML parsing without `DtdProcessing.Prohibit`

## Compact Output Mode

If the user asks for "compact", "quick", or "summary" output:

```
<file>:<line> CRITICAL [CWE-89] SQL injection — use parameterized query
<file>:<line> HIGH [CWE-79] XSS — escape output with framework helper
<file>:<line> MEDIUM [CWE-327] Weak hash — switch to bcrypt/argon2
📦 [SC-02] pycrypto deprecated — use pycryptodome
📦 [SC-03] requests unpinned — add ==2.31.0
✓ No hardcoded secrets | ✓ Auth present | ✓ Input validation on <route> | ✓ Deps pinned
```

## JSON Output Mode

If the user asks for "json" output:

```json
{
  "target": "<path>",
  "language": "<detected>",
  "framework": "<detected>",
  "risk_level": "HIGH",
  "findings": [
    {
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "cwe": 89,
      "owasp": "A03",
      "type": "SQL Injection",
      "file": "app/db.py",
      "line": 42,
      "code": "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")",
      "issue": "User-controlled input interpolated directly into SQL query",
      "fix": "Use parameterized query: cursor.execute(\"SELECT * FROM users WHERE id = ?\", [uid])"
    }
  ],
  "dependencies": {
    "ecosystem": "pip",
    "manifest": "requirements.txt",
    "total_packages": 14,
    "risks": [
      {
        "code": "SC-02",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "package": "pycrypto",
        "issue": "Deprecated and unmaintained — known vulnerabilities",
        "fix": "Replace with pycryptodome (drop-in replacement)"
      },
      {
        "code": "SC-03",
        "severity": "LOW",
        "confidence": "HIGH",
        "package": "requests",
        "issue": "Unpinned version (no == specifier)",
        "fix": "Pin to specific version: requests==2.31.0"
      }
    ]
  },
  "passing": ["No hardcoded secrets", "HTTPS enforced"],
  "manual_review": ["Authorization logic on /admin route needs domain review"],
  "recommended_tools": ["pip-audit", "safety check"]
}
```
