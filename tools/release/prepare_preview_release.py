#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = ROOT_DIR / "release_preview"
RELEASE_DRAFT_PATH = ROOT_DIR / "docs" / "github" / "preview-release-draft.md"

EXCLUDED_PRIVACY_DIRS = {
    ".git",
    ".export_runtime_cache",
    ".pytest_cache",
    ".tmp_brand_preview",
    "__pycache__",
    "exports",
    "playwright-report",
    "projects",
    "release_preview",
    "test-results",
}

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("mac_local_user_path", re.compile(r"/Users/[^/\\s]+(?:/|\\b)")),
    ("windows_local_user_path", re.compile(r"[A-Za-z]:\\\\Users\\\\[^\\\\\\s]+", re.IGNORECASE)),
    ("private_key", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
    ("github_token", re.compile(r"(?:ghp_|github_pat_)[A-Za-z0-9_]+")),
    ("api_key_assignment", re.compile(r"api[_-]?key\s*[:=]\s*['\"][^'\"]+", re.IGNORECASE)),
    ("password_assignment", re.compile(r"password\s*[:=]\s*['\"][^'\"]+", re.IGNORECASE)),
    ("secret_assignment", re.compile(r"secret\s*[:=]\s*['\"][^'\"]+", re.IGNORECASE)),
]


def run_command(args: list[str], *, cwd: Path = ROOT_DIR) -> tuple[int, str, str]:
    try:
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def current_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
    except ValueError:
        return str(path)


def git_info() -> dict[str, Any]:
    _, branch, _ = run_command(["git", "branch", "--show-current"])
    _, commit, _ = run_command(["git", "rev-parse", "HEAD"])
    _, short_commit, _ = run_command(["git", "rev-parse", "--short", "HEAD"])
    _, status, _ = run_command(["git", "status", "--short"])
    _, remote, _ = run_command(["git", "config", "--get", "remote.origin.url"])
    return {
        "branch": branch,
        "commit": commit,
        "shortCommit": short_commit,
        "remote": remote,
        "workingTreeClean": not bool(status.strip()),
        "statusLines": [line for line in status.splitlines() if line.strip()],
    }


def parse_github_repo(remote_url: str) -> str:
    remote_url = remote_url.strip()
    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
        r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, remote_url)
        if match:
            return f"{match.group('owner')}/{match.group('repo')}"
    return ""


def github_ci_status(git: dict[str, Any], *, skip_network: bool = False) -> dict[str, Any]:
    if skip_network:
        return {"checked": False, "reason": "network skipped"}
    repo = parse_github_repo(str(git.get("remote") or ""))
    if not repo:
        return {"checked": False, "reason": "remote is not a GitHub repository"}
    url = f"https://api.github.com/repos/{repo}/actions/runs?branch={git.get('branch')}&per_page=5"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            data = json.load(response)
    except Exception as exc:  # noqa: BLE001 - release prep should report, not crash.
        return {"checked": False, "reason": f"{type(exc).__name__}: {exc}"}
    commit = str(git.get("commit") or "")
    for run in data.get("workflow_runs", []):
        if run.get("head_sha") == commit:
            return {
                "checked": True,
                "name": run.get("name") or "",
                "status": run.get("status") or "",
                "conclusion": run.get("conclusion") or "",
                "url": run.get("html_url") or "",
            }
    latest = data.get("workflow_runs", [{}])[0] if data.get("workflow_runs") else {}
    return {
        "checked": True,
        "status": "not_found_for_commit",
        "conclusion": "",
        "latestRun": {
            "shortCommit": str(latest.get("head_sha") or "")[:7],
            "status": latest.get("status") or "",
            "conclusion": latest.get("conclusion") or "",
            "url": latest.get("html_url") or "",
        },
    }


def tracked_files() -> list[Path]:
    code, stdout, _ = run_command(["git", "ls-files", "-z"])
    if code != 0:
        return []
    return [ROOT_DIR / name for name in stdout.split("\0") if name]


def is_excluded(path: Path) -> bool:
    try:
        parts = path.relative_to(ROOT_DIR).parts
    except ValueError:
        parts = path.parts
    return any(part in EXCLUDED_PRIVACY_DIRS for part in parts)


def build_sensitive_patterns(extra_patterns: list[str]) -> list[tuple[str, re.Pattern[str]]]:
    patterns = list(SENSITIVE_PATTERNS)
    for index, pattern in enumerate(extra_patterns, start=1):
        pattern = pattern.strip()
        if not pattern:
            continue
        patterns.append((f"extra_sensitive_{index}", re.compile(re.escape(pattern), re.IGNORECASE)))
    return patterns


def scan_privacy(extra_patterns: list[str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    large_files: list[dict[str, Any]] = []
    patterns = build_sensitive_patterns(extra_patterns)
    for path in tracked_files():
        if is_excluded(path) or not path.is_file():
            continue
        size = path.stat().st_size
        if size > 20 * 1024 * 1024:
            large_files.append({"path": relative(path), "size": size, "sizeLabel": human_size(size)})
        if size > 2 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in patterns:
                if pattern.search(line):
                    if relative(path) == "tools/release/prepare_preview_release.py" and "re.compile" in line:
                        continue
                    findings.append(
                        {
                            "type": label,
                            "path": relative(path),
                            "line": line_number,
                            "preview": line.strip()[:180],
                        }
                    )
    return {
        "sensitiveFindings": findings,
        "largeTrackedFiles": large_files,
        "passed": not findings and not large_files,
    }


def classify_artifact(path: Path) -> str:
    text = path.as_posix().lower()
    if "editor_suite" in text:
        return "editor-suite"
    if "editor_build" in text:
        return "editor-package"
    if "native_runtime" in text:
        return "native-runtime"
    if "web_build" in text:
        return "web-runtime"
    if "windows" in text:
        return "windows-package"
    if "macos" in text:
        return "macos-package"
    if "linux" in text:
        return "linux-package"
    return "other"


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def archive_companion_dir(path: Path) -> Path:
    exports_dir = ROOT_DIR / "exports"
    if path.parent != exports_dir:
        return path.parent
    for suffix in (".tar.gz", ".tgz", ".zip"):
        if path.name.endswith(suffix):
            return path.parent / path.name[: -len(suffix)]
    return path.parent / path.stem


def artifact_metadata(path: Path) -> dict[str, Any]:
    companion_dir = archive_companion_dir(path)
    export_manifest = load_json(companion_dir / "export_manifest.json")
    suite_manifest = load_json(companion_dir / "editor_suite_manifest.json")
    release_check = load_json(companion_dir / "native-runtime-release-check.json")
    stat = path.stat()
    metadata = {
        "path": relative(path),
        "name": path.name,
        "kind": classify_artifact(path),
        "size": stat.st_size,
        "sizeLabel": human_size(stat.st_size),
        "modifiedAt": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
        "sha256": file_sha256(path),
        "manifest": relative(companion_dir / "export_manifest.json") if export_manifest else "",
        "suiteManifest": relative(companion_dir / "editor_suite_manifest.json") if suite_manifest else "",
        "releaseCheck": relative(companion_dir / "native-runtime-release-check.json") if release_check else "",
        "releaseCheckSummary": (release_check or {}).get("summary") or {},
    }
    if export_manifest:
        metadata["releaseVersion"] = (export_manifest.get("engine") or {}).get("releaseVersion") or ""
        metadata["projectTitle"] = (export_manifest.get("project") or {}).get("title") or ""
        metadata["targetLabel"] = (export_manifest.get("engine") or {}).get("exportTargetLabel") or ""
    if suite_manifest:
        metadata["releaseVersion"] = (suite_manifest.get("engine") or {}).get("releaseVersion") or ""
        metadata["targetLabel"] = (suite_manifest.get("engine") or {}).get("packageTargetLabel") or ""
    return metadata


def discover_artifacts(max_artifacts: int) -> list[dict[str, Any]]:
    exports_dir = ROOT_DIR / "exports"
    if not exports_dir.exists():
        return []
    candidates: list[Path] = []
    for path in exports_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative_parts = path.relative_to(exports_dir).parts
        except ValueError:
            continue
        if len(relative_parts) > 2:
            continue
        if path.name.endswith((".zip", ".tar.gz", ".tgz")):
            candidates.append(path)
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    return [artifact_metadata(path) for path in candidates[:max_artifacts]]


def has_release_check_errors(artifact: dict[str, Any]) -> bool:
    summary = artifact.get("releaseCheckSummary") or {}
    return int(summary.get("errors") or 0) > 0


def build_warnings(report: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    git = report["git"]
    ci = report["githubActions"]
    privacy = report["privacy"]
    if not git["workingTreeClean"]:
        warnings.append("Working tree is not clean; commit or discard local changes before tagging a release.")
    if ci.get("checked") and not (ci.get("status") == "completed" and ci.get("conclusion") == "success"):
        warnings.append("GitHub Actions is not green for the current commit.")
    if not ci.get("checked"):
        warnings.append(f"GitHub Actions status was not checked: {ci.get('reason')}")
    if privacy["sensitiveFindings"]:
        warnings.append("Privacy scan found potential sensitive strings.")
    if privacy["largeTrackedFiles"]:
        warnings.append("Tracked files larger than 20 MB were found.")
    if not report["artifacts"]:
        warnings.append("No local release artifacts were found under exports/.")
    return warnings


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    git = git_info()
    extra_sensitive = list(args.extra_sensitive or [])
    discovered_artifacts = discover_artifacts(args.max_artifacts)
    report = {
        "generatedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "git": git,
        "githubActions": github_ci_status(git, skip_network=args.skip_network),
        "privacy": scan_privacy(extra_sensitive),
        "artifacts": [artifact for artifact in discovered_artifacts if not has_release_check_errors(artifact)],
        "rejectedArtifacts": [artifact for artifact in discovered_artifacts if has_release_check_errors(artifact)],
    }
    report["warnings"] = build_warnings(report)
    report["readyForPreviewTag"] = not report["warnings"]
    return report


def render_upload_manifest(report: dict[str, Any]) -> str:
    lines = [
        "# Preview Release Upload Manifest",
        "",
        f"- Generated: `{report['generatedAt']}`",
        f"- Branch: `{report['git']['branch']}`",
        f"- Commit: `{report['git']['shortCommit']}`",
        f"- Working tree clean: `{report['git']['workingTreeClean']}`",
        "",
        "## GitHub Actions",
        "",
    ]
    ci = report["githubActions"]
    if ci.get("checked"):
        lines.extend(
            [
                f"- Status: `{ci.get('status', '')}`",
                f"- Conclusion: `{ci.get('conclusion', '')}`",
                f"- URL: {ci.get('url', '') or 'n/a'}",
            ]
        )
    else:
        lines.append(f"- Not checked: {ci.get('reason')}")
    lines.extend(["", "## Privacy Gate", ""])
    privacy = report["privacy"]
    lines.append(f"- Passed: `{privacy['passed']}`")
    lines.append(f"- Sensitive findings: `{len(privacy['sensitiveFindings'])}`")
    lines.append(f"- Large tracked files: `{len(privacy['largeTrackedFiles'])}`")
    lines.extend(["", "## Suggested Upload Artifacts", ""])
    if not report["artifacts"]:
        lines.append("- No local artifacts found. Generate fresh exports before publishing.")
    for artifact in report["artifacts"]:
        summary = artifact.get("releaseCheckSummary") or {}
        release_note = ""
        if summary:
            release_note = f" release-check errors={summary.get('errors', 0)} warnings={summary.get('warnings', 0)}"
        lines.extend(
            [
                f"### `{artifact['name']}`",
                "",
                f"- Path: `{artifact['path']}`",
                f"- Kind: `{artifact['kind']}`",
                f"- Size: `{artifact['sizeLabel']}`",
                f"- SHA256: `{artifact['sha256']}`",
                f"- Modified: `{artifact['modifiedAt']}`",
                f"- Notes:{release_note or ' n/a'}",
                "",
            ]
        )
    rejected = report.get("rejectedArtifacts") or []
    if rejected:
        lines.extend(["## Rejected Local Artifacts", ""])
        for artifact in rejected:
            summary = artifact.get("releaseCheckSummary") or {}
            lines.append(
                f"- `{artifact['path']}` rejected because release-check errors={summary.get('errors', 0)} warnings={summary.get('warnings', 0)}."
            )
        lines.append("")
    lines.extend(["## Warnings", ""])
    if report["warnings"]:
        lines.extend(f"- {warning}" for warning in report["warnings"])
    else:
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)


def render_release_body(report: dict[str, Any]) -> str:
    body = RELEASE_DRAFT_PATH.read_text(encoding="utf-8") if RELEASE_DRAFT_PATH.exists() else "# Tony Na Engine Preview\n"
    lines = [body.rstrip(), "", "## Verification", ""]
    ci = report["githubActions"]
    if ci.get("checked"):
        lines.append(f"- GitHub Actions: `{ci.get('status')}` / `{ci.get('conclusion')}`")
    else:
        lines.append(f"- GitHub Actions: not checked ({ci.get('reason')})")
    lines.append(f"- Privacy scan findings: `{len(report['privacy']['sensitiveFindings'])}`")
    lines.append(f"- Working tree clean when prepared: `{report['git']['workingTreeClean']}`")
    lines.extend(["", "## Artifact Checksums", ""])
    if not report["artifacts"]:
        lines.append("- Attach freshly generated artifacts and paste their hashes here.")
    for artifact in report["artifacts"][:8]:
        lines.append(f"- `{artifact['name']}`: `{artifact['sha256']}`")
    lines.append("")
    return "\n".join(lines)


def write_outputs(report: dict[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "preview-release-readiness.json"
    manifest_path = output_dir / "preview-release-upload-manifest.md"
    body_path = output_dir / "preview-release-body.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest_path.write_text(render_upload_manifest(report), encoding="utf-8")
    body_path.write_text(render_release_body(report), encoding="utf-8")
    return {
        "json": relative(json_path),
        "manifest": relative(manifest_path),
        "releaseBody": relative(body_path),
    }


def print_summary(report: dict[str, Any], outputs: dict[str, str]) -> None:
    print("Tony Na Engine Preview release prep")
    print(f"- Commit: {report['git']['shortCommit']}")
    print(f"- Working tree clean: {report['git']['workingTreeClean']}")
    ci = report["githubActions"]
    if ci.get("checked"):
        print(f"- GitHub Actions: {ci.get('status')} / {ci.get('conclusion')}")
    else:
        print(f"- GitHub Actions: not checked ({ci.get('reason')})")
    print(f"- Privacy findings: {len(report['privacy']['sensitiveFindings'])}")
    print(f"- Artifacts listed: {len(report['artifacts'])}")
    print(f"- Rejected artifacts: {len(report.get('rejectedArtifacts') or [])}")
    print(f"- Ready for Preview tag: {report['readyForPreviewTag']}")
    if report["warnings"]:
        print("")
        print("Warnings:")
        for warning in report["warnings"]:
            print(f"- {warning}")
    print("")
    print("Generated files:")
    for label, path in outputs.items():
        print(f"- {label}: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare Tony Na Engine Preview release notes and upload manifest")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory, default release_preview/<timestamp>")
    parser.add_argument("--max-artifacts", type=int, default=12, help="Maximum local artifacts to list from exports/")
    parser.add_argument("--skip-network", action="store_true", help="Do not query GitHub Actions status")
    parser.add_argument(
        "--extra-sensitive",
        action="append",
        default=[],
        help="Additional sensitive literal to scan for; repeat or pass via TNE_PRIVACY_EXTRA_PATTERNS",
    )
    args = parser.parse_args()
    env_patterns = [item.strip() for item in os.environ.get("TNE_PRIVACY_EXTRA_PATTERNS", "").split(",") if item.strip()]
    args.extra_sensitive.extend(env_patterns)

    output_dir = args.output_dir or (DEFAULT_OUTPUT_DIR / current_timestamp())
    report = build_report(args)
    outputs = write_outputs(report, output_dir)
    print_summary(report, outputs)
    return 0 if report["readyForPreviewTag"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
