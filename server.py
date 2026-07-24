from __future__ import annotations

import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from llm_review import review
from remediation import instructions, remediate
from scanner import scan_history, scan_text, scan_worktree, serialize
import os
import errno
import git_scanner

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
APP = Path(__file__).parent.resolve()
LAST: dict[str, dict] = {}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(APP / "static"), **kwargs)
    def _json(self, payload, status=200):
        data = json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        size = int(self.headers.get("Content-Length", 0)); data = json.loads(self.rfile.read(size) or b"{}")
        if self.path == "/api/scan":
            findings = scan_worktree(ROOT)
            if data.get("history"): findings += scan_history(ROOT)
            payload = serialize(findings); LAST.clear(); LAST.update({f["id"]: f for f in payload})
            counts = {level: sum(x["severity"] == level for x in payload) for level in ("critical", "high", "medium", "low")}
            return self._json({"root": str(ROOT), "findings": payload, "counts": counts})
        if self.path == "/api/scan-upload":
            filename = str(data.get("name", "uploaded-file"))
            content = data.get("content", "")
            if not isinstance(content, str) or len(content) > 1_500_000:
                return self._json({"error": "Choose a text file smaller than 1.5 MB."}, 400)
            payload = serialize(scan_text(filename, content, "uploaded file"))
            LAST.clear(); LAST.update({f["id"]: f for f in payload})
            counts = {level: sum(x["severity"] == level for x in payload) for level in ("critical", "high", "medium", "low")}
            return self._json({"root": filename, "findings": payload, "counts": counts})
        if self.path == "/api/scan-repo":
            repo_url = data.get("repo", "")
            if not isinstance(repo_url, str) or not repo_url.strip():
                return self._json({"error": "Repo URL is required."}, 400)
            try:
                findings = git_scanner.scan_repo(repo_url.strip(), history=bool(data.get("history", True)), max_commits=60)
            except git_scanner.GitScannerError as exc:
                return self._json({"error": str(exc)}, 400)
            payload = serialize(findings)
            LAST.clear(); LAST.update({f["id"]: f for f in payload})
            counts = {level: sum(x["severity"] == level for x in payload) for level in ("critical", "high", "medium", "low")}
            return self._json({"root": repo_url, "findings": payload, "counts": counts})
        if self.path == "/api/scan-path":
            # Scan a local directory for findings. Allows absolute paths or
            # paths relative to the configured server `ROOT`.
            target = data.get("path", "")
            if not isinstance(target, str) or not target.strip():
                return self._json({"error": "Path is required."}, 400)
            try:
                t = Path(target)
                if not t.is_absolute():
                    t = (ROOT / t).resolve()
                else:
                    t = t.resolve()
                # Allow absolute paths anywhere, but require the path exists
                # and is a directory to avoid surprises.
                if not t.exists():
                    return self._json({"error": f"Path does not exist: {t}"}, 400)
                if not t.is_dir():
                    return self._json({"error": f"Path is not a directory: {t}"}, 400)
            except Exception as exc:
                return self._json({"error": f"Invalid path: {exc}"}, 400)
            try:
                findings = scan_worktree(t)
                if data.get("history"): findings += scan_history(t)
            except Exception as exc:
                return self._json({"error": str(exc)}, 400)
            payload = serialize(findings)
            LAST.clear(); LAST.update({f["id"]: f for f in payload})
            counts = {level: sum(x["severity"] == level for x in payload) for level in ("critical", "high", "medium", "low")}
            return self._json({"root": str(t), "findings": payload, "counts": counts})
        if self.path == "/api/review":
            finding = LAST.get(data.get("id")); return self._json(review(finding) if finding else {"error": "Finding expired; rescan first."}, 404 if not finding else 200)
        if self.path == "/api/remediate":
            finding = LAST.get(data.get("id")); return self._json(remediate(ROOT, finding) if finding else {"ok": False, "message": "Finding expired; rescan first."}, 404 if not finding else 200)
        if self.path == "/api/instructions":
            finding = LAST.get(data.get("id")); return self._json(instructions(finding) if finding else {"error": "Finding expired; rescan first."}, 404 if not finding else 200)
        self._json({"error": "Not found"}, 404)

if __name__ == "__main__":
    # Allow overriding the listen port with LEAKLENS_PORT (useful when port 8787
    # is already in use). If the requested port is busy, try the next few
    # ports so running multiple instances doesn't fail with an OSError.
    HOST = "127.0.0.1"
    DEFAULT_PORT = int(os.getenv("LEAKLENS_PORT", "8787"))
    MAX_PORT_TRIES = 10

    server = None
    bound_port = None
    for offset in range(MAX_PORT_TRIES):
        try_port = DEFAULT_PORT + offset
        try:
            server = ThreadingHTTPServer((HOST, try_port), Handler)
            bound_port = try_port
            break
        except OSError as exc:
            # EADDRINUSE -> address already in use
            if getattr(exc, 'errno', None) == errno.EADDRINUSE:
                print(f"Port {try_port} in use, trying next port...")
                continue
            raise

    if server is None:
        print(f"Could not bind to any port in range {DEFAULT_PORT}-{DEFAULT_PORT + MAX_PORT_TRIES - 1}.")
        print("Set LEAKLENS_PORT to an unused port and retry.")
        raise SystemExit(1)

    print(f"LeakLens scanning {ROOT}\nOpen http://{HOST}:{bound_port}")
    server.serve_forever()
