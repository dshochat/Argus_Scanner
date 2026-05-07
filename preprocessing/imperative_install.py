"""v3.1 `imperative_install_detected` safety net.

Supply-chain attacks hide payloads behind code that runs during install:
`setup.py` shelling out, npm `postinstall` scripts, Python `.pth` files
that exploit `site.py` to execute arbitrary imports, build-file hooks.

S1's 2048-token triage can miss these, so we detect the pattern
deterministically. When any detector fires, the orchestrator forces
`triage.priority_score >= 4` regardless of S1's guess.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path

_DANGEROUS_CALL_TARGETS = {
    "subprocess": {
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "getoutput",
        "getstatusoutput",
    },
    "os": {
        "system",
        "popen",
        "exec",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    },
    "urllib.request": {"urlopen", "urlretrieve"},
    "urllib": {"urlopen", "urlretrieve"},
    "requests": {"get", "post", "put", "delete", "request"},
    "httpx": {"get", "post", "put", "delete", "request"},
}
_DANGEROUS_BUILTINS = {"exec", "eval"}

_NPM_LIFECYCLE_HOOKS = {
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "prepare",
    "prepack",
    "postpack",
    "preuninstall",
    "postuninstall",
}

_PTH_IMPORT = re.compile(r"^\s*import\s+", re.MULTILINE)


@dataclass
class ImperativeInstallSignal:
    detected: bool
    reasons: list[str]


def _attr_name_path(node: ast.AST) -> str:
    """Reconstruct dotted path for `a.b.c` → 'a.b.c'."""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _has_dangerous_call(tree: ast.AST) -> list[str]:
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func

        if isinstance(func, ast.Name):
            if func.id in _DANGEROUS_BUILTINS:
                hits.append(f"builtin:{func.id}")
            continue

        if isinstance(func, ast.Attribute):
            path = _attr_name_path(func)
            if "." not in path:
                continue
            module, _, attr = path.rpartition(".")
            for mod_key, attrs in _DANGEROUS_CALL_TARGETS.items():
                if (
                    module == mod_key or module.startswith(f"{mod_key}.") or module.endswith(mod_key)
                ) and attr in attrs:
                    hits.append(f"{module}.{attr}")
                    break
    return hits


def analyze_setup_py(content: str) -> ImperativeInstallSignal:
    """Flag setup.py that shells out / fetches code / execs dynamically during install."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return ImperativeInstallSignal(detected=False, reasons=[])
    reasons = _has_dangerous_call(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id == "setup") or (
                isinstance(func, ast.Attribute) and func.attr == "setup"
            ):
                for kw in node.keywords:
                    if kw.arg == "dependency_links":
                        reasons.append("setup:dependency_links")
    return ImperativeInstallSignal(detected=bool(reasons), reasons=sorted(set(reasons)))


def analyze_package_json(content: str) -> ImperativeInstallSignal:
    """Flag package.json with install-time lifecycle scripts."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return ImperativeInstallSignal(detected=False, reasons=[])
    scripts = data.get("scripts") or {}
    hits = [f"npm:{hook}" for hook in _NPM_LIFECYCLE_HOOKS if hook in scripts]
    return ImperativeInstallSignal(detected=bool(hits), reasons=sorted(hits))


def analyze_pth(content: str) -> ImperativeInstallSignal:
    """Any `.pth` line starting with `import` triggers site.py to exec it at startup."""
    if _PTH_IMPORT.search(content):
        return ImperativeInstallSignal(detected=True, reasons=["pth:import_line"])
    return ImperativeInstallSignal(detected=False, reasons=[])


def analyze_python_module(content: str) -> ImperativeInstallSignal:
    """Flag any Python file with dangerous-API calls (broader than setup.py).

    Expanded from setup.py-only to all .py files per pipeline-audit Fix 1
    (2026-05-04). The original dispatch was filename-based and missed
    supply-chain malware disguised as utility scripts (``docker_entrypoint_init.py``,
    ``*_init.py``, telemetry/audit helpers, etc.) — empirically, the file
    `docker_entrypoint_init.py` had 8 dangerous-API hits (subprocess.run,
    os.execvp, requests.post, etc.) but escaped the safety net because
    its filename wasn't ``setup.py``.

    The same AST walker (`_has_dangerous_call`) is applied; reasons are
    prefixed ``py_module:`` to distinguish from setup_py / npm / pth
    signals.

    False-positive mitigation: this signal only LIFTS ``priority_score
    >= 4`` via the orchestrator override — L1 still makes the verdict
    call. A clean utility script gets one extra L1 call but should
    still verdict clean. The cost is bounded (~$0.02 per file) and the
    benefit is L1 visibility into supply-chain payloads that S1 might
    misclassify as low-priority utilities.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return ImperativeInstallSignal(detected=False, reasons=[])
    hits = _has_dangerous_call(tree)
    if not hits:
        return ImperativeInstallSignal(detected=False, reasons=[])
    prefixed = [f"py_module:{h}" for h in hits]
    return ImperativeInstallSignal(detected=True, reasons=sorted(set(prefixed)))


def analyze_file(path: str | Path, content: str) -> ImperativeInstallSignal:
    """Dispatch by filename. Returns an empty signal for non-relevant files.

    Dispatch order (most specific first):
      * ``setup.py`` → analyze_setup_py (adds dependency_links check)
      * ``package.json`` → analyze_package_json (npm lifecycle hooks)
      * ``*.pth`` → analyze_pth (import-line detection)
      * ``*.py`` (any other Python file) → analyze_python_module
        (Fix 1, 2026-05-04: broaden to catch supply-chain payloads
        disguised as utility / init / telemetry scripts)
    """
    p = Path(path)
    name = p.name.lower()
    suffix = p.suffix.lower()

    if name == "setup.py":
        return analyze_setup_py(content)
    if name == "package.json":
        return analyze_package_json(content)
    if suffix == ".pth":
        return analyze_pth(content)
    if suffix == ".py":
        return analyze_python_module(content)
    return ImperativeInstallSignal(detected=False, reasons=[])
