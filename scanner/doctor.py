"""``argus doctor`` — preflight checks for the runtime prerequisites that
``pip`` cannot install.

A plain ``pip install argus-ai-scanner`` gives you the whole Python stack
(scanner + DAST glue + dashboard). But the DAST sandbox needs Docker + gVisor
(``runsc``) + the sandbox images, and the dashboard needs a Postgres — all
system-level things no wheel can ship. This command checks what's present and
prints the exact command to fix whatever's missing, so "what do I still need?"
has a one-shot answer.

No network/API calls beyond an optional local Postgres ping.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from dataclasses import dataclass

OK = "ok"
WARN = "warn"
FAIL = "fail"

_SYM = {OK: "[ ok ]", WARN: "[warn]", FAIL: "[FAIL]"}

_GVISOR_TIERS = (
    ("lean", "ARGUS_DAST_GVISOR_IMAGE_LEAN"),
    ("rich_python", "ARGUS_DAST_GVISOR_IMAGE_RICH_PYTHON"),
    ("ml_tools", "ARGUS_DAST_GVISOR_IMAGE_ML_TOOLS"),
)


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    fix: str = ""


def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, str(exc)


def _check_python() -> Check:
    import sys

    v = sys.version_info
    if (v.major, v.minor) >= (3, 12):
        return Check("Python", OK, f"{v.major}.{v.minor}.{v.micro}")
    return Check("Python", FAIL, f"{v.major}.{v.minor}", "Argus requires Python 3.12+")


def _check_api_key() -> Check:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return Check("ANTHROPIC_API_KEY", OK, "set")
    return Check(
        "ANTHROPIC_API_KEY",
        WARN,
        "not set",
        "export ANTHROPIC_API_KEY=... (required to run scans)",
    )


def _check_dast(runtime: str) -> list[Check]:
    if runtime == "gvisor":
        return _check_gvisor()
    if runtime == "fly":
        return _check_fly()
    return [
        Check(
            "DAST runtime",
            WARN,
            f"ARGUS_DAST_RUNTIME={runtime or '(unset)'} — DAST won't run",
            "export ARGUS_DAST_RUNTIME=gvisor for self-hosted DAST",
        )
    ]


def _check_gvisor() -> list[Check]:
    checks: list[Check] = [Check("DAST runtime", OK, "gvisor (self-hosted)")]
    docker = shutil.which("docker")
    if not docker:
        checks.append(Check("Docker", FAIL, "not found on PATH", "install Docker; see docs/dast-setup.md"))
        return checks
    checks.append(Check("Docker", OK, docker))

    rc, runtimes = _run([docker, "info", "--format", "{{json .Runtimes}}"])
    if rc != 0:
        checks.append(Check("Docker daemon", FAIL, "not reachable", "start Docker (may need sudo / Docker Desktop)"))
        return checks
    checks.append(Check("Docker daemon", OK, "reachable"))
    checks.append(
        Check("gVisor (runsc)", OK, "registered with Docker")
        if "runsc" in runtimes
        else Check(
            "gVisor (runsc)",
            FAIL,
            "not a Docker runtime",
            "runsc install && restart docker (see dast/sandbox/firecracker/_gvisor_setup.sh)",
        )
    )

    _rc, images = _run([docker, "images", "--format", "{{.Repository}}:{{.Tag}}"])
    for tier, env in _GVISOR_TIERS:
        tag = os.environ.get(env) or f"argus-dast-sandbox:{tier}"
        present = tag in images
        if present:
            checks.append(Check(f"image: {tier}", OK, tag))
        elif tier == "lean":
            checks.append(
                Check("image: lean", FAIL, "missing", "bash dast/sandbox/firecracker/build_local.sh lean")
            )
        else:
            checks.append(
                Check(
                    f"image: {tier}",
                    WARN,
                    "not built (falls back to lean)",
                    f"bash dast/sandbox/firecracker/build_local.sh {tier}",
                )
            )
    return checks


def _check_fly() -> list[Check]:
    checks: list[Check] = [Check("DAST runtime", OK, "fly (hosted)")]
    checks.append(
        Check("FLY_API_TOKEN", OK, "set")
        if os.environ.get("FLY_API_TOKEN")
        else Check("FLY_API_TOKEN", FAIL, "not set", "flyctl tokens create deploy -a argus-dast-sandbox")
    )
    if not os.environ.get("ECHO_DAST_IMAGE_LEAN"):
        checks.append(Check("ECHO_DAST_IMAGE_LEAN", WARN, "not set", "set the Fly sandbox image refs"))
    return checks


def _db_reachable(db_url: str) -> bool | None:
    """Try a short Postgres connect. None if asyncpg unavailable."""
    if importlib.util.find_spec("asyncpg") is None:
        return None
    import asyncio

    url = db_url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgres://")

    async def _try() -> bool:
        import asyncpg  # type: ignore[import-untyped]

        try:
            conn = await asyncio.wait_for(asyncpg.connect(url), timeout=5.0)
            await conn.close()
            return True
        except Exception:  # noqa: BLE001
            return False

    try:
        return asyncio.run(_try())
    except Exception:  # noqa: BLE001
        return None


def _check_dashboard() -> list[Check]:
    checks: list[Check] = []
    missing = [m for m in ("fastapi", "uvicorn", "sqlalchemy", "asyncpg") if importlib.util.find_spec(m) is None]
    checks.append(
        Check("Dashboard deps", OK, "fastapi, uvicorn, sqlalchemy, asyncpg")
        if not missing
        else Check("Dashboard deps", FAIL, f"missing: {', '.join(missing)}", "pip install --upgrade argus-ai-scanner")
    )

    db_url = os.environ.get("ARGUS_DB_URL")
    if not db_url:
        checks.append(
            Check(
                "ARGUS_DB_URL",
                WARN,
                "not set",
                "export ARGUS_DB_URL=postgresql://... (enables auto-persist + the dashboard)",
            )
        )
        return checks
    checks.append(Check("ARGUS_DB_URL", OK, "set"))
    reachable = _db_reachable(db_url)
    if reachable is True:
        checks.append(Check("Postgres", OK, "reachable"))
    elif reachable is False:
        checks.append(
            Check("Postgres", FAIL, "unreachable", "docker compose -f dashboard/docker-compose.yml up -d")
        )
    return checks


def collect_checks() -> list[Check]:
    """Run all checks and return them (no rendering — unit-testable)."""
    runtime = (os.environ.get("ARGUS_DAST_RUNTIME") or "").strip().lower()
    checks: list[Check] = [_check_python(), _check_api_key()]
    checks.extend(_check_dast(runtime))
    checks.extend(_check_dashboard())
    return checks


def run_doctor() -> int:
    """Render the preflight report. Returns 1 if any check FAILed, else 0."""
    checks = collect_checks()
    width = max((len(c.name) for c in checks), default=0)
    print("argus doctor - runtime preflight\n")
    fails = sum(1 for c in checks if c.status == FAIL)
    warns = sum(1 for c in checks if c.status == WARN)
    for c in checks:
        print(f"  {_SYM[c.status]}  {c.name.ljust(width)}  {c.detail}")
        if c.fix and c.status != OK:
            print(f"          -> {c.fix}")
    print()
    if fails:
        print(f"{fails} blocking issue(s), {warns} warning(s). Fix the [FAIL] items above.")
        return 1
    print(f"All required checks passed ({warns} warning(s)).")
    return 0
