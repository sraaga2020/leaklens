"""Conservative, syntax-aware remediation for assignment-style secrets."""
from __future__ import annotations

import ast
import re
import shutil
from pathlib import Path

from scanner import scan_text

SUPPORTED_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
DIRECT_STRING_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?P<lhs>[A-Za-z_$][\w.$-]*)\s*(?P<operator>=|:)\s*)"
    r"(?P<quote>['\"])(?P<value>[^'\"\n]*)(?P=quote)"
)


def _environment_name(variable: str) -> str:
    name = re.sub(r"[^A-Z0-9]+", "_", variable.upper()).strip("_")
    return name or "LEAKLENS_ROTATED_SECRET"


def _replacement(path: Path, environment_name: str) -> str:
    if path.suffix.lower() == ".py":
        return f'os.getenv("{environment_name}")'
    return f"process.env.{environment_name}"


def _ensure_python_import(lines: list[str]) -> list[str]:
    text = "".join(lines)
    if re.search(r"^\s*(?:import\s+os\b|from\s+os\s+import\b)", text, re.MULTILINE):
        return lines
    # Keep future imports at the beginning, where Python requires them.
    insert_at = 0
    try:
        module = ast.parse(text)
        if module.body and isinstance(module.body[0], ast.Expr) and isinstance(module.body[0].value, ast.Constant) and isinstance(module.body[0].value.value, str):
            insert_at = module.body[0].end_lineno or 0
    except SyntaxError:
        pass
    for index, line in enumerate(lines):
        if line.startswith("#!") or "coding" in line[:40] or line.startswith("from __future__ import"):
            insert_at = index + 1
    return lines[:insert_at] + ["import os\n"] + lines[insert_at:]


def remediate(root: Path, finding: dict) -> dict:
    if finding.get("source") != "working tree":
        return {"ok": False, "message": "This result needs a manual fix. Revoke or rotate the value at its provider, then remove it from source code."}
    if finding.get("rule") == "private_key":
        return {"ok": False, "message": "Private keys require deliberate rotation and key-store setup. Use ‘How to fix’ for the safe manual plan."}
    path = (root / finding["file"]).resolve()
    if root not in path.parents or not path.is_file():
        return {"ok": False, "message": "The target file is unavailable."}
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        return {"ok": False, "message": "Automatic fixes support Python and JavaScript/TypeScript files. This file needs a manual fix."}

    text = path.read_text(encoding="utf-8")
    # A finding ID contains a fingerprint of the original match. Refuse to modify a stale result.
    current_ids = {item.id for item in scan_text(finding["file"], text)}
    if finding["id"] not in current_ids:
        return {"ok": False, "message": "This finding changed since the scan. Run a new scan before fixing it."}

    lines = text.splitlines(keepends=True)
    index = finding["line"] - 1
    if not 0 <= index < len(lines):
        return {"ok": False, "message": "The file changed; please rescan first."}
    match = DIRECT_STRING_ASSIGNMENT.search(lines[index])
    if not match:
        return {"ok": False, "message": "LeakLens found the secret but could not safely isolate a direct assignment. Use ‘How to fix’ for a safe manual plan."}

    environment_name = _environment_name(match.group("lhs"))
    rewritten = lines[index][:match.start()] + match.group("prefix") + _replacement(path, environment_name) + lines[index][match.end():]
    lines[index] = rewritten
    if path.suffix.lower() == ".py":
        lines = _ensure_python_import(lines)

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    path.write_text("".join(lines), encoding="utf-8")

    example = root / ".env.example"
    existing = example.read_text(encoding="utf-8") if example.exists() else ""
    if not re.search(rf"^{re.escape(environment_name)}=", existing, re.MULTILINE):
        prefix = "" if not existing or existing.endswith("\n") else "\n"
        example.write_text(existing + f"{prefix}{environment_name}=replace-with-a-rotated-value\n", encoding="utf-8")
    return {"ok": True, "message": f"Moved {match.group('lhs')} to {environment_name}, created {backup.name}, and added a safe placeholder to .env.example. Rotate the original secret before setting the new environment value."}


def instructions(finding: dict) -> dict:
    """Return a concise provider-aware plan when code cannot be changed safely."""
    source = finding.get("source", "working tree")
    if source == "git history":
        steps = [
            "Revoke or rotate the exposed credential at its provider immediately.",
            "Remove it from the current code and move the replacement into a secret manager or environment variable.",
            "Rewrite the affected Git history with git-filter-repo or BFG Repo-Cleaner, then force-push only after coordinating with collaborators.",
            "Ask everyone with a clone to re-clone or carefully reset it; old clones can reintroduce the secret.",
        ]
    elif finding.get("rule") == "private_key":
        steps = [
            "Treat the private key as compromised and generate a new key pair in the owning service or certificate authority.",
            "Revoke the old key, certificate, or deploy key so it can no longer authenticate anything.",
            "Store the replacement in a secret manager or protected key store—not as a source-code string.",
            "Remove the old key from code and Git history, then redeploy services that use it.",
        ]
    elif source == "uploaded file":
        steps = [
            "Open the original file in its project; uploaded files are scanned locally but are never edited by LeakLens.",
            "Replace the inline value with an environment-variable or secret-manager lookup appropriate to that language.",
            "Rotate the original credential at its provider and put only the replacement value in your secret store.",
            "Add the environment variable name—not its value—to the project’s .env.example or deployment configuration.",
        ]
    else:
        steps = [
            "Rotate or revoke the exposed credential at its provider; removing it from code does not invalidate it.",
            "Replace the inline value with an environment-variable or secret-manager lookup.",
            "Store the new value in your deployment secret store and update .env.example with the variable name only.",
            "Rescan the project and review provider logs for unexpected activity.",
        ]
    return {"title": f"How to fix: {finding.get('description', 'exposed credential')}", "steps": steps}
