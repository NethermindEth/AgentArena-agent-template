"""
Shared helpers for running detect-only audit scripts.
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from agent.config import Settings
from agent.services.auditor import Audit, VulnerabilityFinding

logger = logging.getLogger(__name__)

DETECTORS = {"codex", "claude", "gemini", "cursor"}
REPORT_NAME = "audit.md"
SCOPE_NAME = "AUDIT_SCOPE.md"


def _detector_script(detector: str) -> Path:
    script_name = f"run_{detector}_detect.sh"
    candidates = [
        Path("/opt/agent") / script_name,
        Path(__file__).resolve().parents[1] / "docker" / script_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Could not find detector script {script_name}")


def _detect_instructions_path() -> Path:
    candidates = [
        Path("/opt/agent/detect.md"),
        Path(__file__).resolve().with_name("detect.md"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("Could not find detect.md at /opt/agent/detect.md or agent/detect.md")


def _apply_detector_env(env: dict, detector: str, config: Settings) -> None:
    model_env = {
        "codex": "CODEX_MODEL",
        "claude": "CLAUDE_MODEL",
        "gemini": "GEMINI_MODEL",
        "cursor": "CURSOR_MODEL",
    }[detector]
    env.setdefault(model_env, config.model)

    if not config.api_key:
        return

    if detector == "codex":
        env.setdefault("OPENAI_API_KEY", config.api_key)
        env.setdefault("CODEX_API_KEY", env["OPENAI_API_KEY"])
    elif detector == "claude":
        env.setdefault("ANTHROPIC_API_KEY", config.api_key)
    elif detector == "gemini":
        env.setdefault("GEMINI_API_KEY", config.api_key)
    elif detector == "cursor":
        env.setdefault("CURSOR_API_KEY", config.api_key)


def _extract_json_report(report: str) -> str:
    stripped = report.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _aggregated_per_file_descriptions(d: list | str) -> str:
    """
    Assembles all the descriptions together. They each tackle
    a file. If this value is a string, return it as-is.
    :param d: The vulnerability description, which is an array
        or a string.
    :return: The assembled description.
    """

    if isinstance(d, str):
        return d
    else:
        texts = []
        for item in d:
            desc = item.get("desc")
            file_ = item.get("file")
            line_start, line_end = item.get("line_start"), item.get("line_end")

            if not desc:
                continue

            full_desc = []
            if file_:
                file_desc = f"In file {file_}"
                if line_start and line_end:
                    file_desc += f", from line {line_start} to line {line_end}:"
                elif line_start:
                    file_desc += f", from line {line_start}:"
                elif line_end:
                    file_desc += f", up to line {line_end}:"
                else:
                    file_desc += ":"
                full_desc.append(file_desc)

            full_desc.append(desc)
            texts.append("\n\n".join(full_desc))

        return "\n\n".join(texts)


def _description(v: dict) -> str:
    """
    Processes a description out of the vulnerability dictionary
    that was generated from the underlying AI model.
    :param v: The vulnerability dictionary.
    :return: The description.
    """

    contents = []

    # 1. If a summary is present, add it.
    summary = v.get("summary")
    if summary:
        contents.append(summary)

    # 2. Assemble the per-file description.
    descriptions = v.get("description")
    if descriptions:
        contents.append(_aggregated_per_file_descriptions(descriptions))

    # 3. Add impact, if present.
    impact = v.get("impact")
    if impact:
        contents.append(f"Impact of this vulnerability: {impact}")

    # 4. Add PoC, if present.
    proof_of_concept = v.get("proof_of_concept")
    if proof_of_concept:
        contents.append(f"Proof of concept: {proof_of_concept}")

    # Consider whether adding `remediation` makes sense or not.
    return "\n\n".join(contents)


def _audit_from_report(report_path: str) -> Audit:
    with open(report_path, "r", encoding="utf-8") as f:
        report = f.read().strip()

    if not report:
        return Audit(findings=[])

    try:
        payload = json.loads(_extract_json_report(report))
        if isinstance(payload, list):
            payload = {"findings": payload}
        if isinstance(payload, dict) and "findings" in payload:
            return Audit(**payload)
        if isinstance(payload, dict) and "vulnerabilities" in payload:
            return Audit(
                findings=[
                    VulnerabilityFinding(
                        title=vulnerability.get("title", "Untitled vulnerability"),
                        description=_description(vulnerability),
                        severity=str(vulnerability.get("severity", "info")).capitalize(),
                        file_paths=[
                            item["file"]
                            for item in vulnerability.get("description", [])
                            if isinstance(item, dict) and item.get("file")
                        ],
                    )
                    for vulnerability in payload["vulnerabilities"]
                    if isinstance(vulnerability, dict)
                ]
            )
    except json.JSONDecodeError:
        pass
    except Exception as exc:
        logger.warning("Detector report was JSON but did not match Audit schema: %s", exc)

    return Audit(
        findings=[
            VulnerabilityFinding(
                title="Detector audit report",
                description=report,
                severity="Info",
                file_paths=[],
            )
        ]
    )


def _safe_relative_path(path: str) -> Optional[Path]:
    rel_path = Path(path)
    if rel_path.is_absolute() or not rel_path.parts:
        return None
    if any(part in {"", ".", ".."} for part in rel_path.parts):
        return None
    return rel_path


def _copy_selected_paths(repo_dir: str, audit_dir: str, selected_paths: Iterable[str]) -> int:
    repo_root = Path(repo_dir).resolve()
    audit_root = Path(audit_dir)
    audit_root.mkdir(parents=True, exist_ok=True)

    copied = 0
    for selected_path in dict.fromkeys(selected_paths):
        rel_path = _safe_relative_path(selected_path)
        if rel_path is None:
            logger.warning("Ignoring unsafe selected path: %s", selected_path)
            continue

        source = (repo_root / rel_path).resolve()
        try:
            source.relative_to(repo_root)
        except ValueError:
            logger.warning("Ignoring selected path outside repository: %s", selected_path)
            continue

        if not source.exists():
            logger.warning("Selected path does not exist in repository: %s", selected_path)
            continue

        target = audit_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(
                source,
                target,
                symlinks=True,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git"),
            )
        else:
            shutil.copy2(source, target, follow_symlinks=False)
        copied += 1

    return copied


def _prepare_audit_dir(
    repo_dir: str,
    audit_dir: str,
    selected_paths: Optional[Iterable[str]],
    scope_text: Optional[str],
) -> None:
    if selected_paths is None:
        shutil.copytree(repo_dir, audit_dir, symlinks=True)
    else:
        copied = _copy_selected_paths(repo_dir, audit_dir, selected_paths)
        if copied == 0:
            raise FileNotFoundError("None of the selected files/docs exist in the repository")
        logger.info("Prepared scoped audit directory with %s selected file/doc paths", copied)

    if scope_text:
        scope_path = Path(audit_dir) / SCOPE_NAME
        scope_path.write_text(scope_text.strip() + "\n", encoding="utf-8")


def run_detector(
    repo_dir: str,
    config: Settings,
    selected_paths: Optional[Iterable[str]] = None,
    scope_text: Optional[str] = None,
) -> Audit:
    detector = config.detector.lower()
    if detector not in DETECTORS:
        raise ValueError(f"Unsupported detector '{config.detector}'. Expected one of {sorted(DETECTORS)}")

    script_path = _detector_script(detector)
    detect_md = _detect_instructions_path()

    with tempfile.TemporaryDirectory(prefix="agentarena-audit-") as work_dir:
        audit_dir = os.path.join(work_dir, "audit")
        submission_dir = os.path.join(work_dir, "submission")
        logs_dir = os.path.join(work_dir, "logs")
        os.makedirs(submission_dir, exist_ok=True)
        os.makedirs(logs_dir, exist_ok=True)

        _prepare_audit_dir(repo_dir, audit_dir, selected_paths, scope_text)

        env = os.environ.copy()
        env.update(
            {
                "HOME": work_dir,
                "AGENT_DIR": work_dir,
                "AUDIT_DIR": audit_dir,
                "SUBMISSION_DIR": submission_dir,
                "LOGS_DIR": logs_dir,
                "DETECT_MD": str(detect_md),
            }
        )
        _apply_detector_env(env, detector, config)

        logger.info("Running %s detector against copied repository %s", detector, audit_dir)
        subprocess.run(["bash", str(script_path), audit_dir], check=True, env=env)

        report_path = os.path.join(submission_dir, REPORT_NAME)
        if not os.path.isfile(report_path):
            raise FileNotFoundError(f"Detector did not create expected report: {report_path}")

        return _audit_from_report(report_path)
