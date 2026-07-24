"""False-positive review. Remote review is opt-in through environment variables."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

def review(finding: dict, source_line: str | None = None) -> dict[str, Any]:
    line = (source_line or "").lower()
    local_false_positive = any(marker in line for marker in ("example", "sample", "fixture", "mock", "redacted", "placeholder", "changeme"))
    result = {
        "verdict": "likely_false_positive" if local_false_positive else "likely_real",
        "reason": "The value appears in example/test/placeholder context." if local_false_positive else "The pattern and surrounding context look like a real credential.",
        "reviewer": "local context reviewer",
    }
    endpoint, api_key = os.getenv("LEAKLENS_LLM_URL"), os.getenv("LEAKLENS_LLM_KEY")
    if not endpoint or not api_key:
        return result
    prompt = "Classify this secret-scanner finding as likely_real or likely_false_positive. Return JSON with verdict and reason. Never repeat the secret.\n" + json.dumps({k: finding.get(k) for k in ("category", "description", "file", "line", "match")})
    try:
        request = urllib.request.Request(endpoint, data=json.dumps({"model": os.getenv("LEAKLENS_LLM_MODEL", "gpt-4.1-mini"), "messages": [{"role": "user", "content": prompt}], "response_format": {"type": "json_object"}}).encode(), headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=12) as response:
            body = json.loads(response.read())
        remote = json.loads(body["choices"][0]["message"]["content"])
        return {"verdict": remote.get("verdict", result["verdict"]), "reason": remote.get("reason", result["reason"]), "reviewer": "configured LLM reviewer"}
    except Exception:
        return result
