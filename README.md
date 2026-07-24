# LeakLens

LeakLens is a dependency-free local app for finding exposed credentials in a codebase. It scans the working tree and Git history, ranks findings by severity, describes their likely impact in plain English, and can replace supported inline credentials with environment-variable references.

## Run it

```bash
python3 server.py
```

Then open `http://127.0.0.1:8787`. By default the current directory is scanned. To scan another local project:

```bash
python3 server.py /path/to/project
```

## Features

- Finds common API keys, bearer tokens, private keys, connection strings, password assignments, and high-entropy generic secrets.
- Shows file, line, commit (for history), category, confidence, and risk level.
- Scans tracked Git commits as well as current files.
- Offers one-click remediation for assignment-style current-file findings. It safely creates a `.bak` copy before changing a file.
- Uses a built-in context reviewer to suppress examples, tests, placeholders, and redacted values. Optionally configure OpenAI compatible review through `LEAKLENS_LLM_URL` and `LEAKLENS_LLM_KEY`.

The app intentionally does not transmit source code unless you configure the optional remote LLM reviewer.
