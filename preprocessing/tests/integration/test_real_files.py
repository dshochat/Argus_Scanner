"""Integration tests: run preprocessing against real scraped files.

Pulls from `public.files` in Supabase. Gated by `@pytest.mark.integration`
so unit-only CI stays fast. Run with:

    uv run pytest preprocessing/tests/integration/ -v -m integration
"""

from __future__ import annotations

import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from preprocessing import preprocess_file
from preprocessing.imperative_install import analyze_file as analyze_imp_install
from preprocessing.language import detect_language
from preprocessing.parsers import is_manifest, parse_manifest

pytestmark = pytest.mark.integration

_CRASH_SAMPLE = 800
_LANG_SAMPLE_PER_LANG = 40
_MANIFEST_SAMPLE = 100


def _fetch(conn: Any, sql: str, params: tuple = ()) -> list[tuple]:
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchall()


def test_crash_free_on_random_sample(db_conn: Any) -> None:
    """Run preprocess_file on a random diverse sample. No exceptions allowed."""
    rows = _fetch(
        db_conn,
        """
        SELECT file_name, file_ext, language, content
        FROM public.files
        WHERE content IS NOT NULL AND length(content) < 500000
        ORDER BY random()
        LIMIT %s
        """,
        (_CRASH_SAMPLE,),
    )

    failures: list[tuple[str, str]] = []
    timings: list[float] = []
    obf_layers = Counter()
    imp_install_hits = 0

    for file_name, file_ext, _language, content in rows:
        path = Path(file_name or f"unknown{file_ext or ''}")
        t0 = time.perf_counter()
        try:
            bundle = preprocess_file(path, content.encode("utf-8", errors="replace"))
        except Exception as exc:  # pragma: no cover — intentional catch-all
            failures.append((str(path), f"{type(exc).__name__}: {exc}"))
            continue
        timings.append(time.perf_counter() - t0)
        obf_layers[bundle.preprocessing.deobfuscation_layers] += 1
        if bundle.preprocessing.imperative_install_detected:
            imp_install_hits += 1

    print(f"\n[crash-free] {len(rows)} files, {len(failures)} failures")
    if timings:
        timings.sort()
        p50 = timings[len(timings) // 2]
        p99 = timings[int(len(timings) * 0.99)]
        print(f"[crash-free] latency p50={p50 * 1000:.1f}ms p99={p99 * 1000:.1f}ms")
    print(f"[crash-free] obf_layers_histogram={dict(obf_layers)}")
    print(f"[crash-free] imperative_install_hits={imp_install_hits}")
    for path, err in failures[:10]:
        print(f"  FAIL {path}: {err}")

    assert not failures, f"{len(failures)} files crashed preprocessing"


def test_language_detection_matches_db_label(db_conn: Any) -> None:
    """For each high-volume language, detect_language() should agree with DB label."""
    top_langs = [
        row[0]
        for row in _fetch(
            db_conn,
            """
            SELECT language FROM public.files
            WHERE language IS NOT NULL AND language != 'unknown'
            GROUP BY language ORDER BY count(*) DESC LIMIT 12
            """,
        )
    ]

    per_lang_agree: Counter[str] = Counter()
    per_lang_total: Counter[str] = Counter()
    confusions: list[tuple[str, str, str]] = []

    for lang in top_langs:
        rows = _fetch(
            db_conn,
            """
            SELECT file_name, file_ext, content FROM public.files
            WHERE language = %s AND content IS NOT NULL AND length(content) > 20
            ORDER BY random() LIMIT %s
            """,
            (lang, _LANG_SAMPLE_PER_LANG),
        )
        for file_name, file_ext, content in rows:
            path = Path(file_name or f"x{file_ext or ''}")
            detected = detect_language(path, content)
            per_lang_total[lang] += 1
            if detected == lang:
                per_lang_agree[lang] += 1
            else:
                confusions.append((lang, detected, str(path)))

    print("\n[language] per-language agreement:")
    total = sum(per_lang_total.values())
    agree = sum(per_lang_agree.values())
    for lang in top_langs:
        t = per_lang_total[lang]
        if t == 0:
            continue
        pct = per_lang_agree[lang] * 100 / t
        print(f"  {lang:<14} {per_lang_agree[lang]:>3}/{t:<3} ({pct:5.1f}%)")
    overall = agree * 100 / total if total else 0
    print(f"[language] overall {agree}/{total} ({overall:.1f}%)")
    for db_lang, detected, path in confusions[:15]:
        print(f"  MISS db={db_lang!r} got={detected!r}: {path}")

    assert overall >= 85.0, f"language detection accuracy {overall:.1f}% < 85%"


_EMPTY_DEP_PATTERNS = {
    "pyproject.toml": (re.compile(r"^\s*dependencies\s*=\s*\[\s*\]\s*$", re.MULTILINE),),
    "package.json": (re.compile(r'"dependencies"\s*:\s*\{\s*\}'),),
    "package-lock.json": (re.compile(r'"packages"\s*:\s*\{\s*\}'),),
}

_DEP_HINTS = {
    "package.json": ('"dependencies"', '"devdependencies"', '"peerdependencies"'),
    "package-lock.json": ('"packages"', '"dependencies"'),
    "pyproject.toml": ("dependencies = [", "[tool.poetry.", "[tool.pdm.", "[tool.hatch."),
    "requirements.txt": ("==", ">=", "~="),
    "setup.py": ("install_requires", "setup_requires", "extras_require"),
    "go.mod": ("require ",),
    "Cargo.toml": ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"),
    "Gemfile": ("gem '", 'gem "'),
    "pom.xml": ("<dependency>", "<dependencies>"),
    "Pipfile.lock": ('"default"', '"develop"'),
    "pnpm-lock.yaml": ("packages:", "importers:"),
}


def _is_stub(name: str, content: str) -> bool:
    lowered = content.lower()
    hints = _DEP_HINTS.get(name, ())
    if not any(h.lower() in lowered for h in hints):
        return True
    # Empty-literal stubs (`dependencies = []`, `"packages": {}`, etc.) hit
    # the string hint but have no declared deps. Treat as stubs.
    for pat in _EMPTY_DEP_PATTERNS.get(name, ()):
        if pat.search(content):
            return True
    return False


def test_manifest_parsers_extract_dependencies(db_conn: Any) -> None:
    """Real manifests should extract deps for non-stub files.

    Uses deterministic ordering (content_hash) so numbers are comparable
    across runs. A "stub" is a manifest without any textual hint of deps
    (empty template, boilerplate, schema-only file); we measure extraction
    rate on non-stub files only.
    """
    manifests = [
        "package.json",
        "package-lock.json",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "go.mod",
        "Cargo.toml",
        "Gemfile",
        "pom.xml",
        "Pipfile.lock",
        "pnpm-lock.yaml",
    ]
    results: list[tuple[str, int, int, int, int]] = []
    real_misses: list[tuple[str, str, str]] = []

    for name in manifests:
        rows = _fetch(
            db_conn,
            """
            SELECT file_name, content FROM public.files
            WHERE file_name = %s
              AND content IS NOT NULL AND length(content) > 10
            ORDER BY id LIMIT %s
            """,
            (name, _MANIFEST_SAMPLE),
        )
        total = len(rows)
        if total == 0:
            continue
        non_stub = 0
        extracted = 0
        missed_on_non_stub = 0
        total_deps = 0
        for file_name, content in rows:
            path = Path(file_name)
            assert is_manifest(path), f"is_manifest failed for {path}"
            deps = parse_manifest(path, content)
            stub = _is_stub(name, content)
            if not stub:
                non_stub += 1
                if deps:
                    extracted += 1
                else:
                    missed_on_non_stub += 1
                    if len(real_misses) < 10:
                        real_misses.append((name, file_name, content[:300]))
            if deps:
                total_deps += len(deps)
        results.append((name, total, non_stub, extracted, total_deps))

    print("\n[manifests] name | sampled | non_stub | extracted_on_non_stub | total_deps | rate")
    for name, total, non_stub, extracted, total_deps in results:
        rate = f"{extracted * 100 / non_stub:5.1f}%" if non_stub else "   n/a"
        print(f"  {name:<22} {total:>4} {non_stub:>6} {extracted:>6} {total_deps:>8} {rate:>6}")

    if real_misses:
        print("\n[manifests] real misses (non-stub files that extracted 0 deps):")
        for name, fn, head in real_misses:
            print(f"  {name} / {fn}")
            print("    " + head.replace("\n", "\n    ")[:240])

    for name, _total, non_stub, extracted, _ in results:
        if non_stub >= 10:
            rate = extracted / non_stub
            assert rate >= 0.8, (
                f"{name}: only {extracted}/{non_stub} non-stub files extracted deps ({rate:.0%}) — below 80% threshold"
            )


def test_setup_py_imperative_install_recall(db_conn: Any) -> None:
    """setup.py population: detect signal on files that call subprocess/os.system/exec."""
    rows = _fetch(
        db_conn,
        """
        SELECT file_name, content FROM public.files
        WHERE lower(file_name) = 'setup.py' AND content IS NOT NULL
        ORDER BY id LIMIT 100
        """,
    )
    assert rows, "no setup.py rows found in DB — fixture precondition"

    detected = 0
    reason_counter: Counter[str] = Counter()
    samples_flagged: list[str] = []

    for file_name, content in rows:
        signal = analyze_imp_install(Path(file_name), content)
        if signal.detected:
            detected += 1
            reason_counter.update(signal.reasons)
            if len(samples_flagged) < 5:
                samples_flagged.append(f"{file_name}: {signal.reasons}")

    rate = detected / len(rows)
    print(f"\n[imp-install] {detected}/{len(rows)} setup.py files flagged ({rate:.1%})")
    print(f"[imp-install] reason frequencies: {dict(reason_counter.most_common(10))}")
    for s in samples_flagged:
        print(f"  sample: {s}")

    assert rate <= 0.3, f"flagged {rate:.0%} of random setup.py — detector too noisy, expected <30%"


def test_deobfuscation_on_inline_literal_payloads(db_conn: Any) -> None:
    """Real obfuscation has the payload inline as a string literal — peel rate should be high.

    Variable-based b64decode calls (`b64decode(param)`) are legitimate decoding of
    runtime inputs and are NOT expected to peel. The true obfuscation signature is
    `b64decode("...")` with a long literal, which is what we test here.
    """
    rows = _fetch(
        db_conn,
        """
        SELECT file_name, content FROM public.files
        WHERE content ~ %s
          AND language='python'
          AND length(content) < 50000
        ORDER BY random() LIMIT 30
        """,
        (r"b64decode\s*\(\s*[\"']",),
    )
    if not rows:
        pytest.skip("no inline-literal b64decode candidates in DB")

    peeled = 0
    for file_name, content in rows:
        bundle = preprocess_file(Path(file_name), content.encode("utf-8", errors="replace"))
        if bundle.preprocessing.deobfuscation_applied:
            peeled += 1

    pct = peeled * 100 / len(rows)
    print(f"\n[deobf] peeled {peeled}/{len(rows)} inline-literal-payload files ({pct:.1f}%)")
    assert peeled >= 1, "no inline-literal b64decode files peeled — deobfuscator regressed"
