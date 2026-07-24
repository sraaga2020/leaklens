"""Git repository scanning utilities for LeakLens."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from scanner import scan_history, scan_worktree


class GitScannerError(Exception):
    pass


def _clone_repo(repo_url: str, depth: int) -> Path:
    target = Path(tempfile.mkdtemp(prefix="leaklens_git_"))
    try:
        subprocess.check_call(
            ["git", "clone", "--depth", str(depth), "--no-tags", "--quiet", repo_url, str(target)],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            timeout=120,
        )
        return target
    except (subprocess.SubprocessError, OSError) as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise GitScannerError(f"Failed to clone repository: {repo_url}") from exc


def scan_repo(repo_url: str, history: bool = True, max_commits: int = 60) -> list:
    """Clone a repo and scan its working tree and optional Git history."""
    repo_dir = _clone_repo(repo_url, max_commits or 1)
    try:
        findings = scan_worktree(repo_dir)
        if history:
            findings += scan_history(repo_dir, limit=max_commits)
        return findings
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def scan_repo_history(repo_url: str, max_commits: int = 100) -> list:
    """Clone a repo and scan its Git history."""
    return scan_repo(repo_url, history=True, max_commits=max_commits)


def scan_repo_worktree(repo_url: str, max_commits: int = 1) -> list:
    """Clone a repo and scan only its current working tree."""
    return scan_repo(repo_url, history=False, max_commits=max_commits)


def scan_local_history(repo_path: str, max_commits: int = 100) -> list:
    """Scan an existing local git repo for commit history findings."""
    return scan_history(Path(repo_path), limit=max_commits)


def scan_local_files(repo_path: str) -> list:
    """Scan only the current working tree of a local repo."""
    return scan_worktree(Path(repo_path))


if __name__ == "__main__":
    print("This module scans git repositories for secrets.")
    print("Usage: from git_scanner import scan_repo, scan_repo_history, scan_local_history")
