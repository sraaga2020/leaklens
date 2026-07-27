# LeakLens

LeakLens is a local static-analysis tool that scans source code and recent Git history for exposed secrets, sensitive data, and common insecure coding patterns. It organizes matches into security findings, masks sensitive values, explains the possible impact, and can safely remediate certain hard-coded credentials.

> LeakLens is a prototype and should be used as an additional security check—not as a guarantee that a project is vulnerability-free.

## What LeakLens Does

LeakLens can scan:

- The project currently running LeakLens
- A local folder path
- An uploaded text-based source file
- A remote Git repository
- Recent Git commits, when history scanning is enabled

For every finding, the dashboard can show:

- File and line number
- Git commit, when found in history
- Category and detection rule
- Severity and confidence
- A masked version of the detected value
- A plain-English description of the possible blast radius
- Automatic remediation or manual fix instructions, when available

## How Detection Works

LeakLens primarily uses deterministic security checks rather than artificial intelligence:

1. **Regular expressions:** Recognize known formats such as AWS keys, GitHub tokens, JWTs, database URLs, and private-key headers.
2. **Suspicious assignments:** Detect values written directly into variables such as `password`, `api_key`, `secret`, or `token`.
3. **Entropy analysis:** Identify long, random-looking values that may be unknown or custom secrets.
4. **Risky-code patterns:** Flag selected insecure practices such as unsafe `eval`, SQL string concatenation, disabled certificate verification, and weak cryptography.
5. **Git-history analysis:** Scan older file versions because deleting a credential from the current file does not remove it from previous commits.

The optional reviewer in `llm_review.py` can connect to a remote language model, but the main scanner does not require AI.

## Detection Categories

The rules are grouped into 21 broader categories:

1. Cloud credential
2. Source-control token
3. Messaging token
4. API key
5. Payment credential
6. Package-manager token
7. Hard-coded credentials
8. Authentication token
9. Password
10. Default credentials
11. Private key
12. Database credential
13. Weak cryptography
14. Personally identifiable information (PII)
15. Infrastructure information
16. Cryptocurrency
17. Code injection
18. Insecure deserialization
19. Configuration issue
20. Information disclosure
21. Generic secret

These are categories, not individual rules. Each category may contain several service-specific or vulnerability-specific detection rules.

## Automatic Remediation

LeakLens automatically changes only simple cases that it can isolate safely.

For example, it can change a hard-coded Python credential:

```python
API_KEY = "replace-me"
```

into an environment-variable lookup:

```python
import os

API_KEY = os.getenv("API_KEY")
```

It also:

- Creates a `.bak` backup before editing
- Adds a safe placeholder to `.env.example`
- Rescans the file before editing to reject stale findings
- Supports direct string assignments in Python and JavaScript/TypeScript files

LeakLens does not automatically rewrite private keys, complicated code, uploaded files, or Git history. Those findings receive manual remediation guidance instead.

**Important:** Moving a credential out of the code does not invalidate the exposed value. The original credential should still be revoked or rotated at its provider.

## Privacy

LeakLens runs on `127.0.0.1`, so it is available only on the local computer by default.

The application does not intentionally transmit source code unless the optional remote language-model reviewer is configured. Detected values are masked before being displayed in the dashboard.

## Requirements

- Python 3.10 or newer is recommended
- Git is required for repository cloning and Git-history scanning
- A modern Chromium-based browser is recommended for the folder-picker feature

The core application uses Python's standard library. The included `requirements.txt` contains the packaging utility used by the project environment.

## Run LeakLens

From the project folder, run:

```bash
python3 server.py
```

On Windows, this may instead be:

```bash
python server.py
```

Then open the address printed in the terminal. The default address is:

```text
http://127.0.0.1:8787
```

If port `8787` is occupied, LeakLens automatically tries the next available ports up to `8796` and prints the selected address.

To request a different starting port:

```bash
LEAKLENS_PORT=9000 python3 server.py
```

To scan a different project as the configured root:

```bash
python3 server.py /path/to/project
```

## Quick Demo

1. Start LeakLens.
2. Open the address printed in the terminal.
3. Scan `demo_vulnerable.py` or upload a small test file.
4. Review the severity, category, confidence, masked match, and impact explanation.
5. Use **Fix automatically** on a supported direct assignment.
6. Confirm that LeakLens created a backup and updated `.env.example`.
7. Scan again to verify that the current-file finding was removed.

Use only fake credentials during demonstrations. Never place a real credential in the demo file.

## Project Structure

```text
leaklens-main/
├── server.py             # Local HTTP server and API routes
├── scanner.py            # Detection rules, entropy checks, file scanning, and Git-history scanning
├── git_scanner.py        # Temporary cloning and scanning of remote Git repositories
├── remediation.py        # Conservative automatic fixes and manual instructions
├── llm_review.py         # Local review logic and optional remote LLM review
├── demo_vulnerable.py    # Intentionally vulnerable test file with fake values
├── static/
│   ├── index.html        # Dashboard structure
│   ├── app.js            # Browser interactions and API requests
│   └── styles.css        # Dashboard styling
└── README.md
```

## Main API Routes

| Route | Purpose |
|---|---|
| `POST /api/scan` | Scan the configured project root |
| `POST /api/scan-upload` | Scan uploaded text content |
| `POST /api/scan-repo` | Clone and scan a remote Git repository |
| `POST /api/scan-path` | Scan a selected local directory |
| `POST /api/review` | Review a finding for possible false positives |
| `POST /api/remediate` | Attempt a supported automatic fix |
| `POST /api/instructions` | Return manual remediation steps |

## Optional Remote AI Review

The core scanner is rule-based. To enable the optional remote review layer, configure:

```text
LEAKLENS_LLM_URL
LEAKLENS_LLM_KEY
LEAKLENS_LLM_MODEL
```

Without these values, LeakLens uses its local reviewer and does not send the finding to a remote model.

## Current Limitations

- Regex and entropy can produce false positives.
- Secrets created dynamically or split across variables may be missed.
- Scanning LeakLens's own rule definitions may flag example credential formats.
- The scanner does not prove that a detected credential is active.
- It does not decrypt encrypted content.
- Automatic remediation supports only simple direct assignments in selected languages.
- Git-history cleanup requires deliberate coordination and is not automated.
- Some insecure-code rules are broad pattern checks rather than full program analysis.

## Future Improvements

Useful next steps include:

- Add `.leaklensignore` and per-finding allowlists
- Detect sensitive files already tracked by Git, such as `.env` and private keys
- Automatically rescan after remediation and display before-and-after results
- Group duplicate findings across files and commits
- Improve the local false-positive reviewer with safely masked source context
- Add syntax-aware analysis using Python ASTs and JavaScript parsers
- Export reports as JSON, HTML, or SARIF
- Add scan IDs so multiple scans do not overwrite shared finding state
- Add specialized parsers for JSON, YAML, TOML, Terraform, Docker, and Kubernetes files

## Responsible Use

Only scan code and repositories that you own or are authorized to assess. Treat every exposed credential as potentially compromised, rotate it, review access logs, and store the replacement in an approved environment or secret-management system.
