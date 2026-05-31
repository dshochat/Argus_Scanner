"""Extract Python imports for per-scan sandbox dep installation (P2a).

When the target file under DAST scan imports third-party packages that
aren't preinstalled in the sandbox image, Phase B+ runtime probe and
Phase 3 hypotheses fail with ``ModuleNotFoundError:infra_stub``. This
module parses the target's actual imports and produces a deterministic
list of pip package names to install in the sandbox before plan
execution.

Security contract
-----------------
We pip-install packages NAMED by the malicious file we're scanning.
That's intrinsically risky. Mitigations:

  * **Imports only** — packages are extracted from ``import X`` / ``from
    X import ...`` AST nodes in the file's source. We do NOT read
    ``requirements.txt`` (attacker-controlled), ``pyproject.toml``, or
    ``package.json``.
  * **--no-deps for arbitrary names (v0.1)** — by default the
    entrypoint runs ``pip install --no-deps`` so we install ONLY the
    named packages, NEVER transitive dependencies. An attacker who
    publishes a malware package under a benign name (e.g., "requests")
    gets that one package installed, but no shipped-as-a-dependency
    surprise payload.
  * **Allowlist with bounded transitives (v0.3)** — packages whose
    PEP-503 normalized name is in ``PYPI_TOP_ALLOWLIST`` get installed
    WITH deps, since transitive resolution is bounded by the
    allowlisted package's well-known maintainer-declared graph. Cuts
    the common Phase B+ failure mode where ``selenium`` needs
    ``urllib3``/``trio`` etc. Defends against attacker-named packages
    (those still go through --no-deps); does NOT defend against
    compromised upstreams of legitimate top-PyPI packages (out of
    scope; supply-chain attack on PyPI itself is a different threat
    model).
  * **Stdlib + preinstalled filter** — anything already in the image
    or in ``sys.stdlib_module_names`` is dropped. Cuts pointless
    re-installs and the attack surface.
  * **Bounded count + name validation** — cap at 20 packages per
    scan; reject names with shell metacharacters / characters
    outside the PyPI naming rules.

API
---
  * ``extract_python_imports(source: str) -> set[str]`` — top-level
    package names from AST walk.
  * ``compute_runtime_packages(source, image_hint, *, max_packages) ->
    list[str]`` — full filter pipeline; the canonical entry point for
    the orchestrator.
  * ``partition_runtime_packages(pkgs) -> (no_deps, with_deps)`` —
    split a runtime_packages list into two install groups based on the
    top-PyPI allowlist.
  * ``normalize_pypi_name(name) -> str`` — PEP-503 canonical form.

All return empty / empty list on any parse failure (malformed input
must never crash the cascade).
"""

from __future__ import annotations

import ast
import re
import sys

# ── Per-tier preinstalled package surface ──────────────────────────────────
#
# Maps the import names (what `import X` would write) to "already there
# in the sandbox image, don't reinstall." MUST stay in sync with:
#   * dast/sandbox/firecracker/Dockerfile.lean       (pip install block)
#   * dast/sandbox/firecracker/Dockerfile.rich_python (pip install block)
#   * dast/sandbox/firecracker/Dockerfile.ml_tools    (pip install block)
#
# Bumping the Dockerfile pip list without updating this set means
# orchestrator will needlessly re-install those packages every scan
# (slows scans, costs a few seconds of pip time, otherwise harmless).
LEAN_PREINSTALLED: frozenset[str] = frozenset(
    {
        "requests",
        "flask",
        "fastapi",
        "click",
        "jinja2",
        "yaml",  # pyyaml on PyPI
        "lxml",
        "cryptography",
        "jwt",  # pyjwt on PyPI
        "sqlalchemy",
        "PIL",  # pillow on PyPI
        "gunicorn",
        "dateutil",  # python-dateutil on PyPI
        "urllib3",
        "packaging",
        "typing_extensions",
        "pandas",
        "numpy",
        "boto3",
        "botocore",
        "bs4",  # beautifulsoup4 on PyPI
        "paramiko",
        "redis",
        "pymongo",
        "magic",  # python-magic on PyPI
        "pytz",
        "tzdata",
        "mcp",
        "git",  # gitpython on PyPI
        "httpx",
        "markdownify",
        "readabilipy",
        "protego",
        "pydantic",
        "tzlocal",
    }
)

RICH_PYTHON_PREINSTALLED: frozenset[str] = LEAN_PREINSTALLED | frozenset(
    {
        "scipy",
        "sklearn",  # scikit-learn on PyPI
        "openai",
        "anthropic",
        "langchain_core",  # langchain-core on PyPI
        "aiohttp",
        "aiofiles",
        "psutil",
        "psycopg2",  # psycopg2-binary on PyPI
    }
)

ML_TOOLS_PREINSTALLED: frozenset[str] = RICH_PYTHON_PREINSTALLED | frozenset(
    {
        "torch",
        "transformers",
        "safetensors",
        "huggingface_hub",
    }
)

PREINSTALLED_BY_TIER: dict[str, frozenset[str]] = {
    "lean": LEAN_PREINSTALLED,
    "rich_python": RICH_PYTHON_PREINSTALLED,
    "ml_tools": ML_TOOLS_PREINSTALLED,
}

# ── Import name → PyPI package name mapping ────────────────────────────────
#
# Python imports use the module name, but pip installs use the
# distribution name; for some popular packages these differ. This map
# covers the common gaps. For names not in the map we assume the
# import name == pip name (true for the vast majority of packages).
IMPORT_TO_PKG: dict[str, str] = {
    "bs4": "beautifulsoup4",
    "yaml": "pyyaml",
    "PIL": "pillow",
    "dateutil": "python-dateutil",
    "magic": "python-magic",
    "git": "gitpython",
    "jwt": "pyjwt",
    "sklearn": "scikit-learn",
    "psycopg2": "psycopg2-binary",
    "langchain_core": "langchain-core",
    "cv2": "opencv-python",
    "scikit_image": "scikit-image",
}


# v15 (2026-05-20): Namespace package roots — packages whose canonical
# import path uses a dotted-prefix that ISN'T the PyPI distribution
# name itself. For ``from ruamel.yaml.X import Y``, taking just the
# first segment (``ruamel``) yields a name that ISN'T installable
# (``pip install ruamel`` fails). We must extract the 2-segment form
# (``ruamel.yaml``) which IS the real distribution name.
#
# Without this, every scan inside a namespace package triggers a
# RUNTIME_PACKAGES=<wrong-name> dep-install attempt that pip can't
# resolve. The package never gets installed, the file's
# absolute self-imports fail at runtime, and Phase B+ / Phase 3
# all come back NOT_TESTED with ``ModuleNotFoundError``.
#
# Membership rule for this set: the FIRST dotted segment of the
# import IS a namespace-marker root that's never a standalone PyPI
# distribution. When extracting imports, if the first segment is in
# here, also emit the 2-segment form.
NAMESPACE_PKG_ROOTS: frozenset[str] = frozenset({
    "ruamel",       # ruamel.yaml, ruamel.std, ruamel.yaml.clib, …
    "backports",    # backports.zoneinfo, backports.functools_lru_cache, …
    "zope",         # zope.interface, zope.component, …
    "google",       # google.cloud, google.api_core, google.auth, …
    "azure",        # azure.identity, azure.storage.blob, …
    "twisted",      # twisted.internet, twisted.web, …
    "py",           # py.path, py.test (deprecated but still used)
    "kubernetes",   # kubernetes.client, kubernetes.config, …
    "msrest",       # msrest.serialization, msrest.authentication, …
    "alibabacloud", # alibabacloud_*.client, …
    "tencent",      # tencent.cloud.*
})

# ── Validation ─────────────────────────────────────────────────────────────
#
# PyPI distribution name grammar (PEP 503 normalized): letters, digits,
# hyphens, underscores, dots. We're STRICTER here — defense against
# shell metacharacters that could escape ``pip install <name>`` if
# someone bypasses pip's own validation. No spaces, no semicolons,
# no quotes, no ``--`` (which pip would interpret as a flag).
_VALID_PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _is_safe_pkg_name(name: str) -> bool:
    """True iff name is shell-safe and matches PyPI naming conventions."""
    if not name or len(name) > 64:
        return False
    if name.startswith("-"):
        return False  # never let a name look like a pip flag
    return bool(_VALID_PKG_NAME.match(name))


# ── PEP-503 normalization ──────────────────────────────────────────────────
#
# PyPI matches distribution names case-insensitively and treats runs of
# ``.``, ``-`` and ``_`` as equivalent (PEP 503). Allowlist lookup must
# normalize the same way, otherwise "Pillow" / "scikit_learn" /
# "PyJWT" don't match their canonical forms.
_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """Return the PEP-503 normalized form of a PyPI distribution name.

    Lowercases and collapses any run of ``-``, ``_``, ``.`` into a
    single ``-``. Returns ``""`` on empty / None input.

    Example::

        >>> normalize_pypi_name("Pillow")
        'pillow'
        >>> normalize_pypi_name("scikit_learn")
        'scikit-learn'
        >>> normalize_pypi_name("zope.interface")
        'zope-interface'
    """
    if not name:
        return ""
    return _NORMALIZE_RE.sub("-", name).lower()


# ── Top-PyPI allowlist (P2a v0.3) ──────────────────────────────────────────
#
# Curated list of PyPI distribution names whose dependency graphs we
# trust enough to let ``pip install`` resolve transitives. Packages
# named by the target file that are in this list get installed WITH
# deps; everything else falls back to ``--no-deps`` (the v0.1 contract).
#
# Selection criteria:
#   * Top-of-list popularity on pypistats.org (high enough that a
#     prepared supply-chain attack would be visible)
#   * Multiple maintainers / org-backed (not a single-author hobby pkg)
#   * Reasonable transitive surface (we'd rather list a leaf pkg than
#     an ML mega-framework whose deps explode)
#
# All entries MUST be in PEP-503 normalized form (lowercase, hyphens).
# Lookup goes through ``normalize_pypi_name`` first, so callers don't
# need to pre-normalize.
#
# Conservative on purpose: a smaller, audited list is safer than a
# larger speculative one. Anything not here still installs --no-deps,
# which is the existing safe behavior.
PYPI_TOP_ALLOWLIST: frozenset[str] = frozenset(
    {
        # HTTP / networking
        "requests",
        "httpx",
        "urllib3",
        "aiohttp",
        "aiofiles",
        "httpcore",
        "websockets",
        "selenium",
        "playwright",
        # Web frameworks
        "flask",
        "fastapi",
        "starlette",
        "uvicorn",
        "gunicorn",
        "django",
        "werkzeug",
        "jinja2",
        "tornado",
        "bottle",
        # Data / numeric
        "numpy",
        "pandas",
        "scipy",
        "scikit-learn",
        "matplotlib",
        "seaborn",
        "plotly",
        "statsmodels",
        "sympy",
        "pyarrow",
        "polars",
        "duckdb",
        # ML / AI
        "openai",
        "anthropic",
        "langchain",
        "langchain-core",
        "langchain-community",
        "transformers",
        "huggingface-hub",
        "safetensors",
        "tokenizers",
        "datasets",
        "tiktoken",
        "sentence-transformers",
        "torch",
        "torchvision",
        "torchaudio",
        "tensorflow",
        "keras",
        "onnx",
        "onnxruntime",
        # Cloud SDKs
        "boto3",
        "botocore",
        "s3transfer",
        "google-cloud-storage",
        "google-cloud-core",
        "google-auth",
        "google-api-core",
        "azure-storage-blob",
        "azure-core",
        "azure-identity",
        # Databases
        "sqlalchemy",
        "alembic",
        "psycopg2-binary",
        "psycopg",
        "pymysql",
        "pymongo",
        "redis",
        "elasticsearch",
        "motor",
        # Serialization / validation
        "pydantic",
        "pydantic-core",
        "pydantic-settings",
        "marshmallow",
        "attrs",
        "cattrs",
        "msgpack",
        "orjson",
        "ujson",
        "pyyaml",
        "toml",
        "tomli",
        "tomli-w",
        # Crypto / auth
        "cryptography",
        "pyjwt",
        "bcrypt",
        "passlib",
        "pyopenssl",
        "certifi",
        "authlib",
        "python-jose",
        "argon2-cffi",
        # Parsing
        "beautifulsoup4",
        "lxml",
        "html5lib",
        "soupsieve",
        "markdownify",
        "markdown",
        "mistune",
        "pyparsing",
        # Imaging / media
        "pillow",
        "opencv-python",
        "opencv-python-headless",
        "imageio",
        # CLI / display
        "click",
        "typer",
        "rich",
        "tqdm",
        "colorama",
        "tabulate",
        "prompt-toolkit",
        "questionary",
        "blessed",
        # File / path / system
        "python-dateutil",
        "pytz",
        "tzdata",
        "tzlocal",
        "psutil",
        "watchdog",
        "filelock",
        "platformdirs",
        "send2trash",
        # SSH / network ops
        "paramiko",
        "fabric",
        "scp",
        "asyncssh",
        # Testing (often imported by targets that include tests)
        "pytest",
        "pytest-asyncio",
        "pytest-mock",
        "pytest-cov",
        "hypothesis",
        "coverage",
        "tox",
        "nox",
        # Build / metadata
        "setuptools",
        "wheel",
        "pip",
        "build",
        "packaging",
        "pyproject-hooks",
        # Type system
        "typing-extensions",
        "typing-inspect",
        "mypy",
        "mypy-extensions",
        # Async
        "anyio",
        "trio",
        "sniffio",
        "outcome",
        "h11",
        "h2",
        # Misc popular
        "six",
        "decorator",
        "wrapt",
        "lazy-object-proxy",
        "more-itertools",
        "toolz",
        "cytoolz",
        "regex",
        "charset-normalizer",
        "idna",
        "chardet",
        "click-plugins",
        "cffi",
        "pycparser",
        "pynacl",
        "greenlet",
        # MCP / agent-tooling
        "mcp",
        "mcp-server-fetch",
        "anthropic-bedrock",
        # Web scraping
        "scrapy",
        "feedparser",
        "newspaper3k",
        "readability-lxml",
        # Email / messaging
        "twilio",
        "sendgrid",
        "slack-sdk",
        "discord-py",
        # Git / VCS
        "gitpython",
        "pygit2",
        "dulwich",
        # Doc / templating
        "sphinx",
        "mkdocs",
        # Misc
        "protobuf",
        "grpcio",
        "grpcio-tools",
        "googleapis-common-protos",
        "python-magic",
        "python-dotenv",
        "environs",
        "celery",
        "kombu",
        "billiard",
        "vine",
        "amqp",
        "redis-py-cluster",
        "websocket-client",
        "stripe",
        "supabase",
        "firebase-admin",
        "pyzmq",
        "loguru",
        "structlog",
    }
)


def partition_runtime_packages(
    pkgs: list[str] | tuple[str, ...],
    *,
    own_dist_name: str | None = None,
) -> tuple[list[str], list[str]]:
    """Split a runtime_packages list into ``(no_deps, with_deps)`` groups.

    The dast-init.sh hook installs each group with different flags:
      * ``no_deps`` group: ``pip install --no-deps ...`` (the v0.1
        safe-default behavior for arbitrary attacker-named names)
      * ``with_deps`` group: ``pip install ...`` (transitive resolution
        allowed, because the top-level name is on the curated allowlist
        OR matches ``own_dist_name``)

    Allocation rule (v15.10):
      1. If ``own_dist_name`` is set AND a pkg normalizes to it →
         ``with_deps`` (the package's own declared dependencies are part
         of "what's being scanned" and we trust them — manifest-anchored,
         not attacker-controlled).
      2. Else if normalized name is in ``PYPI_TOP_ALLOWLIST`` →
         ``with_deps`` (curated safe list).
      3. Else → ``no_deps`` (attacker-controlled name space, safest).

    v15.10 (2026-05-20) rationale: the WCtesting campaign hit two
    files (readme-renderer/markdown.py, rich-rst/__init__.py) where
    Phase B Stage 1 enum died with ``ModuleNotFoundError: No module
    named 'pygments'`` / ``'rich_rst._vendor'`` because ``pip install
    --no-deps <own_dist>`` doesn't install the package's runtime
    deps. The own_dist name is manifest-declared (came from PKG-INFO
    or pyproject.toml of the file we're scanning) — its dependency
    set is a property of the package the user is intentionally
    targeting, not attacker input. Installing those deps is in scope
    and contained by the Firecracker sandbox.

    PEP-503 normalization is applied to each name for the allowlist
    lookup, so input names can be in any of the equivalent forms
    (``Pillow`` ≡ ``pillow``, ``scikit_learn`` ≡ ``scikit-learn``).
    The returned lists preserve the original-case names — the dast-init
    side passes them through to pip which does its own normalization.

    Both returned lists are sorted for deterministic plan hashing.

    Empty input → ``([], [])``.
    """
    if not pkgs:
        return [], []
    own_normalized = normalize_pypi_name(own_dist_name) if own_dist_name else None
    no_deps: list[str] = []
    with_deps: list[str] = []
    for name in pkgs:
        normalized = normalize_pypi_name(name)
        if own_normalized and normalized == own_normalized:
            with_deps.append(name)
        elif normalized in PYPI_TOP_ALLOWLIST:
            with_deps.append(name)
        else:
            no_deps.append(name)
    return sorted(no_deps), sorted(with_deps)


# ── Public API ─────────────────────────────────────────────────────────────


def _pip_name_for_import(dotted: str) -> str:
    """Convert a dotted import path to the canonical pip distribution
    name. For most packages the first segment IS the pip name. For
    namespace packages (``ruamel.yaml.X``, ``backports.zoneinfo.X``,
    ``zope.interface.X``, …) where the first segment alone isn't an
    installable distribution, return the 2-segment form.

    Examples::

        _pip_name_for_import("os.path")              -> "os"
        _pip_name_for_import("ruamel.yaml.reader")   -> "ruamel.yaml"
        _pip_name_for_import("backports.zoneinfo")   -> "backports.zoneinfo"
        _pip_name_for_import("google.cloud.storage") -> "google.cloud"
        _pip_name_for_import("google")               -> "google" (no 2nd segment)
    """
    if not dotted:
        return ""
    parts = dotted.split(".")
    root = parts[0]
    if root in NAMESPACE_PKG_ROOTS and len(parts) >= 2 and parts[1]:
        return f"{root}.{parts[1]}"
    return root


def extract_python_imports(source: str) -> set[str]:
    """Return top-level imported package names from Python source.

    Walks the AST and collects:
      * ``import X`` / ``import X.y`` / ``import X as Z`` → ``X``
      * ``from X import y`` / ``from X.y import z`` → ``X``
      * ``import ruamel.yaml.reader`` / ``from ruamel.yaml.X import Y``
        → ``ruamel.yaml`` (2-segment form for namespace package roots
        in :data:`NAMESPACE_PKG_ROOTS`)

    Relative imports (``from . import x`` / ``from ..pkg import y``)
    are NOT returned — they reference siblings within the file's
    package, not pip-installable distributions.

    Returns an empty set if the source has a SyntaxError. The cascade
    must never crash on malformed input.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    except (ValueError, TypeError):
        # ast.parse can raise ValueError on null bytes etc.
        return set()

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                pip_name = _pip_name_for_import(alias.name or "")
                if pip_name:
                    names.add(pip_name)
        elif isinstance(node, ast.ImportFrom):
            # Only absolute imports (level=0) point at pip-installable
            # distributions. Relative imports (level >= 1) reference
            # the target file's own package siblings.
            if node.level == 0 and node.module:
                pip_name = _pip_name_for_import(node.module)
                if pip_name:
                    names.add(pip_name)
    return names


def compute_runtime_packages(
    source: str,
    image_hint: str,
    *,
    max_packages: int = 20,
) -> list[str]:
    """Produce the list of pip package names to install at sandbox
    runtime, filtered for the target image tier.

    Pipeline:
      1. Extract imports via ``extract_python_imports``.
      2. Drop stdlib modules (``sys.stdlib_module_names``).
      3. Drop names already preinstalled in the requested image tier
         (``PREINSTALLED_BY_TIER``).
      4. Map import names → pip names (``IMPORT_TO_PKG``).
      5. Reject names that fail ``_is_safe_pkg_name`` (defensive
         shell-injection guard).
      6. Sort deterministically (for stable plan ID hashing).
      7. Cap at ``max_packages``.

    For unknown image tiers, falls back to the lean preinstalled set —
    so a future "rich-rust" tier added to the prompt enum but missing
    from this module's table doesn't break: it just re-installs the
    lean set's modules (wasteful but functional). v0.2 will tighten
    this to an explicit error.

    Args:
        source: Python source text of the target file. Empty / invalid
            input returns an empty list.
        image_hint: Sandbox image tier the plan will run on.
        max_packages: Upper bound on the returned list. Defaults to 20
            — empirically enough for ~95% of real-world Python files
            and bounds the install-phase cost.

    Returns:
        Sorted list of pip distribution names (each is shell-safe and
        passes the validation regex).
    """
    imports = extract_python_imports(source)
    if not imports:
        return []

    # Step 2: drop stdlib (Python 3.10+)
    imports -= set(sys.stdlib_module_names)

    # Step 3: drop preinstalled for this tier
    preinstalled = PREINSTALLED_BY_TIER.get(image_hint, LEAN_PREINSTALLED)
    imports -= preinstalled

    # Step 4: map import → pip name (default to import name itself)
    pip_names = {IMPORT_TO_PKG.get(name, name) for name in imports}

    # Step 5: reject anything that fails the shell-safe regex
    safe_names = {n for n in pip_names if _is_safe_pkg_name(n)}

    # Step 6 + 7: sort + cap
    return sorted(safe_names)[:max_packages]


def _detect_distribution_name_for_install(project_root_str: str) -> str | None:
    """Read the distribution name from PKG-INFO / pyproject.toml /
    setup.cfg for the scanned file's own package. Returns the
    canonical pip-installable name (preserving dots for namespace
    packages — ``ruamel.yaml``, ``backports.zoneinfo``) when:

      * A manifest is found at ``project_root``, AND
      * The declared name passes the shell-safe regex.

    Returns ``None`` when no manifest is found or the name is invalid.

    Use case: when DAST scans a file inside a Python distribution
    tarball (e.g. ``ruamel.yaml-0.19.1/loader.py``), pre-installing
    the file's own distribution lets the in-sandbox harness use the
    REAL package (with its C extensions, full __init__ chain, etc.)
    rather than the file-staged copy whose lazy/conditional init
    paths often break. Cuts the common Phase B+ failure mode where
    a circular __init__ in the staged copy (ruamel.yaml's
    ``version_info`` via ``ruamel.yaml.clib``) blocks Loader
    instantiation.
    """
    if not project_root_str:
        return None
    try:
        from pathlib import Path  # noqa: PLC0415
        project_root = Path(project_root_str)
    except Exception:  # noqa: BLE001
        return None
    if not project_root.is_dir():
        return None

    declared: str | None = None
    # 1. PKG-INFO is the most reliable signal in sdists.
    pkg_info = project_root / "PKG-INFO"
    if pkg_info.is_file():
        try:
            for line in pkg_info.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[:50]:
                if line.startswith("Name:"):
                    declared = line[len("Name:"):].strip()
                    break
        except OSError:
            pass

    # 2. pyproject.toml.
    if not declared:
        py_proj = project_root / "pyproject.toml"
        if py_proj.is_file():
            try:
                import tomllib  # noqa: PLC0415
                with open(py_proj, "rb") as fh:
                    data = tomllib.load(fh)
                declared = (data.get("project") or {}).get("name") or None
            except Exception:  # noqa: BLE001
                declared = None

    # 3. setup.cfg.
    if not declared:
        setup_cfg = project_root / "setup.cfg"
        if setup_cfg.is_file():
            try:
                import configparser  # noqa: PLC0415
                cp = configparser.ConfigParser()
                cp.read(setup_cfg, encoding="utf-8")
                declared = cp.get("metadata", "name", fallback=None)
            except Exception:  # noqa: BLE001
                declared = None

    if not declared:
        return None
    declared = declared.strip()
    if not _is_safe_pkg_name(declared):
        return None
    return declared


def runtime_packages_for_plan(
    *,
    file_bytes: bytes,
    file_name: str,
    image_hint: str,
    enabled: bool,
    project_root: str = "",
) -> list[str]:
    """Convenience wrapper for plan-build sites: returns the
    ``SandboxPlan.runtime_packages`` value given the orchestrator's
    state.

    Returns an empty list (= no install) when any gate fails:
      * ``enabled`` is False (config opt-out)
      * file is not Python (``.py`` / ``.pth`` suffix)
      * source can't be decoded as UTF-8
      * ``image_hint`` is ``lean`` AND no own-distribution is
        detectable (see v15.4 note below)

    Otherwise computes packages via ``compute_runtime_packages``
    (rich_python / ml_tools only) and prepends the own-distribution
    when detected.

    v15 (2026-05-20): when ``project_root`` points at a Python
    distribution tarball (PKG-INFO / pyproject.toml present), the
    file's OWN distribution name is prepended to the install list.
    This makes DAST runnable on files whose package has a complex
    __init__ chain (ruamel.yaml, backports.zoneinfo, packages
    with C extensions like lxml / cryptography) — the in-sandbox
    harness uses the properly-installed package rather than the
    file-staged copy whose lazy/conditional init paths break.

    v15.4 (2026-05-20): the lean-tier gate now applies only to the
    *imported deps* list, not to the own-distribution install. Lean
    plans for files inside a Python sdist still install that single
    own dist so Phase B Stage 1 and Phase A runtime probes can
    actually import the target module. Lean's "stays minimal"
    promise is preserved for the unbounded set (the file's imports);
    only the manifest-anchored own_dist gets through.

    The orchestrator and adversarial_loop_runner call this at every
    SandboxPlan construction site for Phase 3 Stage 2 hypotheses
    (single_function, stateful_sequence, probe kinds).
    """
    if not enabled:
        return []
    if not (file_name.endswith(".py") or file_name.endswith(".pth")):
        return []
    try:
        source = file_bytes.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return []

    # v15.4 (2026-05-20): separate the lean-tier "don't install
    # arbitrary imports" rule from the own-distribution install.
    #
    # The original v0.1 contract gated ALL of runtime_packages on
    # ``image_hint in (rich_python, ml_tools)`` because we didn't
    # want lean's "stays minimal" promise broken by installing every
    # imported package. That's still right for the IMPORTED deps —
    # an attacker-controlled file's imports can name anything.
    #
    # The OWN distribution is different: it's required for the
    # behavioral probe (Phase B Stage 1) and Phase A's runtime
    # probes to even load the target module's package context.
    # Without it, ``import <pkg>.<X>`` fails before any harness
    # logic runs, and every file inside a Python distribution
    # tarball comes back with callables_explored=0 on lean tier.
    #
    # Empirical evidence (this campaign): mako/template.py routed
    # to lean → 0 callables in runtime_behavioral_profile despite
    # Phase A finding 5 confirmed exploits. Same on ruamel-yaml,
    # likely same on every Cat-3 file. The own-dist install fixes
    # this without weakening the imports-side security stance.

    own_dist = _detect_distribution_name_for_install(project_root)
    is_rich_or_ml = image_hint in ("rich_python", "ml_tools")

    if not is_rich_or_ml and not own_dist:
        # Lean tier + no detectable own-dist → original v0.1 behavior.
        return []

    pkgs = compute_runtime_packages(source, image_hint) if is_rich_or_ml else []

    if own_dist:
        own_dist_normalized = normalize_pypi_name(own_dist)
        # Dedup: drop anything already in pkgs that normalizes to the
        # same canonical name as own_dist (e.g. if the file imports
        # `ruamel.yaml` AND we detected the project's own dist is
        # also `ruamel.yaml`, don't list it twice).
        pkgs = [
            p for p in pkgs
            if normalize_pypi_name(p) != own_dist_normalized
        ]
        # Prepend so it installs first — harness import resolution
        # then finds the real package before any sibling-staged
        # overlay would otherwise short-circuit.
        pkgs = [own_dist] + pkgs

    return pkgs


__all__ = [
    "IMPORT_TO_PKG",
    "LEAN_PREINSTALLED",
    "ML_TOOLS_PREINSTALLED",
    "PREINSTALLED_BY_TIER",
    "PYPI_TOP_ALLOWLIST",
    "RICH_PYTHON_PREINSTALLED",
    "compute_runtime_packages",
    "extract_python_imports",
    "normalize_pypi_name",
    "partition_runtime_packages",
    "runtime_packages_for_plan",
]
