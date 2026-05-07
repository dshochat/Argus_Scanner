"""Attack-vector extension flag — PREP-018.

Recognize Python packaging artifacts that are **supply-chain attack
surfaces by virtue of being installable**: ``.pth``, ``.egg``, ``.whl``,
``.spec``.

A ``.pth`` file can inject arbitrary ``import`` lines into site-packages.
A ``.whl`` is the wheel installer; malicious postinstall hooks or
``setup.py`` manipulation ride in its metadata. An ``.egg`` is the
legacy wheel equivalent. A ``.spec`` is a PyInstaller build recipe that
runs during packaging.

These extensions land here because **the existing
``imperative_install_detected`` signal is content-based** and misses
artifacts whose payload mechanism is outside the file body (e.g. a
``.pth`` listing only a path to a compromised ``sitecustomize.py``, a
``.whl`` whose RECORD points at a setup.py hook not present inline). On
extension alone we can't prove the file is malicious, but we can say
"this shape is worth a closer look" — the orchestrator forces
``priority_score >= 4`` on the match.

Returns the matched extension (without the leading dot) on a hit,
or ``None`` on a miss. The returned string is what ends up on
``Preprocessing.attack_vector_extension``.
"""

from __future__ import annotations

from pathlib import Path

# Ordered so the emitted value is deterministic when multiple extensions
# theoretically apply (e.g. a hypothetical ``foo.whl.spec`` — we pick the
# rightmost-extension convention: ``.spec`` in that case).
_ATTACK_VECTOR_EXTENSIONS: frozenset[str] = frozenset({".pth", ".egg", ".whl", ".spec"})


def detect_attack_vector_extension(path: str | Path) -> str | None:
    """Return the attack-vector extension (without leading dot) or ``None``.

    Matches on the **last** suffix only. A file named ``package.whl`` →
    ``"whl"``; ``README.md`` → ``None``; a file without an extension →
    ``None``. Case-insensitive to handle Windows-style ``.PTH``.
    """
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in _ATTACK_VECTOR_EXTENSIONS:
        return suffix.lstrip(".")
    return None
