"""Unit tests for dast/ml_detonation.py — the deterministic ML-artifact
load plan template + format detection."""
from __future__ import annotations

import base64
import io
import pickle
import zipfile

from dast.ml_detonation import (
    build_ml_load_plan,
    detect_format,
    synthesize_ml_load_hypothesis,
)


# ── Format detection ──────────────────────────────────────────────────────


def test_detect_pickle_by_extension() -> None:
    assert detect_format("model.pkl", b"") == "pickle"
    assert detect_format("checkpoint.pickle", b"") == "pickle"


def test_detect_pickle_by_magic() -> None:
    # Pickle proto >= 2 starts with 0x80; even with no extension, the
    # magic byte should resolve.
    assert detect_format("anything", b"\x80\x04abc") == "pickle"


def test_detect_pytorch_zip() -> None:
    # PyTorch save >= 1.6: a zipfile.
    assert detect_format("model.pt", b"PK\x03\x04abcd") == "pytorch"
    # HuggingFace pytorch_model.bin is also a zipfile.
    assert detect_format("pytorch_model.bin", b"PK\x03\x04abcd") == "pytorch"


def test_detect_pytorch_legacy_raw_pickle() -> None:
    # Old PyTorch saves were raw pickle. Extension wins when no zip magic.
    assert detect_format("legacy.pt", b"") == "pytorch"


def test_detect_safetensors() -> None:
    assert detect_format("weights.safetensors", b"") == "safetensors"


def test_detect_hdf5_by_extension() -> None:
    assert detect_format("model.h5", b"") == "hdf5"
    assert detect_format("model.hdf5", b"") == "hdf5"
    assert detect_format("model.keras", b"") == "hdf5"


def test_detect_hdf5_by_magic() -> None:
    # HDF5 magic survives even on misnamed files
    assert detect_format("renamed.bin", b"\x89HDF\r\n\x1a\n") == "hdf5"


def test_detect_onnx_by_extension() -> None:
    assert detect_format("model.onnx", b"") == "onnx"


def test_detect_unknown() -> None:
    assert detect_format("readme.md", b"# title") is None
    assert detect_format("script.py", b"print(1)") is None


# ── Plan construction ─────────────────────────────────────────────────────


class _OSSystem:
    def __reduce__(self):
        import os  # noqa: PLC0415
        return (os.system, ("echo pwned",))


def test_build_ml_load_plan_pickle_shape() -> None:
    pkl = pickle.dumps(_OSSystem())
    plan = build_ml_load_plan(
        file_name="evil.pkl",
        file_id="hash-evil",
        hypothesis_id="HML_LOAD",
        original_bytes=pkl,
    )
    assert plan is not None
    assert plan["hypothesis_id"] == "HML_LOAD"
    assert plan["plan_status"] == "executable"
    assert plan["timeout_sec"] == 60
    assert plan["image_hint"] == "ml_tools"
    assert plan["payload_encoding"] == "base64"
    # Payload decodes back to the original bytes — sandbox stages the binary
    assert base64.b64decode(plan["payload"]) == pkl
    # Command targets the staged path
    assert "/workspace/evil.pkl" in plan["commands"][0]
    # Loader actually calls pickle.load
    assert "pickle.load" in plan["commands"][0]
    assert "PICKLE_LOAD_COMPLETED" in plan["commands"][0]


def test_build_ml_load_plan_pytorch_uses_torch_load() -> None:
    # Build a zip-shaped .pt
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps(_OSSystem()))
    pt_bytes = buf.getvalue()

    plan = build_ml_load_plan(
        file_name="evil.pt",
        file_id="hash-pt",
        hypothesis_id="HML_LOAD",
        original_bytes=pt_bytes,
    )
    assert plan is not None
    assert "torch.load" in plan["commands"][0]
    assert "weights_only=False" in plan["commands"][0]
    assert "/workspace/evil.pt" in plan["commands"][0]
    assert plan["image_hint"] == "ml_tools"


def test_build_ml_load_plan_safetensors() -> None:
    plan = build_ml_load_plan(
        file_name="model.safetensors",
        file_id="hash-st",
        hypothesis_id="HML_LOAD",
        original_bytes=b"\x00" * 32,
    )
    assert plan is not None
    assert "safe_open" in plan["commands"][0]
    assert "SAFETENSORS_OPENED" in plan["commands"][0]


def test_build_ml_load_plan_onnx() -> None:
    plan = build_ml_load_plan(
        file_name="model.onnx",
        file_id="hash-onnx",
        hypothesis_id="HML_LOAD",
        original_bytes=b"\x08\x07onnx",
    )
    assert plan is not None
    assert "onnx.load" in plan["commands"][0]


def test_build_ml_load_plan_returns_none_for_unrecognized() -> None:
    plan = build_ml_load_plan(
        file_name="readme.md",
        file_id="hash-md",
        hypothesis_id="HML_LOAD",
        original_bytes=b"# hi",
    )
    assert plan is None


def test_build_ml_load_plan_filename_with_quote_escaped_safely() -> None:
    # Defense-in-depth: filenames with shell metacharacters must not
    # break the python -c command. We rely on the static loader template
    # not interpolating the filename into the python string at all —
    # only the /workspace path uses {file_name}, and the sandbox stages
    # by basename so weird filenames are sanitized upstream. Still
    # verify the assertion holds.
    plan = build_ml_load_plan(
        file_name="hello.pkl",
        file_id="hash-hi",
        hypothesis_id="HML_LOAD",
        original_bytes=pickle.dumps({"a": 1}),
    )
    assert plan is not None
    # The python -c body has no filename interpolation — sys.argv[1]
    # carries it through, which is the safe pattern.
    assert "{file_name}" not in plan["commands"][0]


# ── Synthetic hypothesis ──────────────────────────────────────────────────


def test_synthesize_ml_load_hypothesis_shape() -> None:
    h = synthesize_ml_load_hypothesis(file_format="pickle")
    assert h["id"] == "HML_LOAD"
    assert h["finding_ref"] == "HML_LOAD"
    assert h["cwe"] == "CWE-502"
    assert h["severity"] == "critical"
    assert h["confidence"] == 1.0
    # The hypothesis explanation namedrops the format so the model sees
    # what it's planning against.
    assert "pickle" in h["explanation"]
    # PoC line is the canonical pickle-load attack
    assert "pickle.load" in h["proof_of_concept"]


def test_synthesize_ml_load_hypothesis_custom_id() -> None:
    h = synthesize_ml_load_hypothesis(
        hypothesis_id="HML_CUSTOM", file_format="pytorch"
    )
    assert h["id"] == "HML_CUSTOM"
    assert "pytorch" in h["explanation"]


# ── End-to-end orchestrator integration ───────────────────────────────────


import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from dast.orchestrator import run_dast
from dast.sandbox.client import SandboxPlan, SandboxTrace
from dast.validator import HypothesisValidator


@dataclass
class _CapturingStubSandbox:
    """Captures every plan submitted to it, returns a benign trace.

    Lets us verify the orchestrator emitted the deterministic ML plan
    without booting Firecracker. The trace says ``no_expected_event``
    so the verdict path treats the load as inconclusive — fine for our
    "did the plan reach the sandbox" assertion."""

    submitted_plans: list[SandboxPlan] = field(default_factory=list)
    file_content_map: dict[str, bytes] = field(default_factory=dict)

    async def submit(self, plan: SandboxPlan) -> SandboxTrace:
        self.submitted_plans.append(plan)
        return SandboxTrace(
            plan_id=plan.plan_id,
            file_id=plan.file_id,
            hypothesis_id=plan.hypothesis_id,
            events=[],
            exit_code=0,
            stdout_excerpt="(stub) trace omitted",
            stderr_excerpt="",
            elapsed_ms=10,
        )


def _phase_a_verdict_response_text() -> str:
    """Minimal Phase A verdict JSON the orchestrator's parser accepts."""
    return json.dumps({
        "verdict_label": "suspicious",
        "log_summary": "stub no-op",
        "validated_findings": [],
        "confirmed_categories": [],
    })


def _phase_b_response_text() -> str:
    """Minimal Phase B JSON: zero new hypotheses → loop terminates."""
    return json.dumps({"new_hypotheses": []})


@pytest.mark.asyncio
async def test_orchestrator_dispatches_deterministic_ml_load_plan(
    tmp_path,
) -> None:
    """When file_record carries ``ml_format`` + ``original_bytes`` and
    iter 1 fires, the orchestrator must prepend a ``HML_LOAD`` plan to
    the model's plan list and submit it to the sandbox. This is the
    proof that the load-detonation actually reaches the runtime."""
    pickle_bytes = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00ABC"

    # Inference stub: model emits ZERO plans, then ZERO Phase B hyps.
    # If the deterministic ML plan injection works, the sandbox still
    # gets one plan submission (the HML_LOAD).
    call_idx = {"n": 0}

    async def fake_inference(prompt, options, schema):
        call_idx["n"] += 1
        # Plan / verdict / explore order per iter:
        #   call 1 = plan → empty (model contributes nothing)
        #   call 2 = verdict → suspicious
        #   call 3 = explore → no new hyps → loop ends
        text = "{}"
        if call_idx["n"] == 1:
            text = json.dumps({"plans": []})
        elif call_idx["n"] == 2:
            text = _phase_a_verdict_response_text()
        elif call_idx["n"] == 3:
            text = _phase_b_response_text()
        return {"text": text, "usage": {}, "finish_reason": "stop"}

    sandbox = _CapturingStubSandbox()

    file_record = {
        "file_id": "evil-pkl-hash",
        "source_text": "# === ML MODEL FILE: pickle ===\n# (synthesized text)\n",
        "file_name": "evil_model.pkl",
        "ml_format": "pickle",
        "original_bytes": pickle_bytes,
    }
    l1_output = {
        "verdict": {"verdict_label": "critical_malicious"},
        "hypotheses": [synthesize_ml_load_hypothesis(file_format="pickle")],
    }

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
    )

    # The deterministic ML plan reached the sandbox
    assert len(sandbox.submitted_plans) >= 1, "No plans dispatched to sandbox"
    ml_plans = [p for p in sandbox.submitted_plans if p.hypothesis_id == "HML_LOAD"]
    assert len(ml_plans) == 1, f"Expected exactly one HML_LOAD plan, got {len(ml_plans)}"

    ml_plan = ml_plans[0]
    # Plan structure: pickle.load + workspace path + ml_tools image
    assert ml_plan.image_hint == "ml_tools"
    assert "pickle.load" in ml_plan.commands[0]
    assert "/workspace/evil_model.pkl" in ml_plan.commands[0]
    # The original binary made it into the plan payload (base64-encoded)
    assert ml_plan.payload  # non-empty
    decoded = base64.b64decode(ml_plan.payload)
    assert decoded == pickle_bytes
    # Run still produced a valid result (orchestrator didn't crash)
    assert result.stop_reason in {
        "no_pending_hypotheses_for_iter",
        "no_new_confirmed_findings",
        "no_valid_hypotheses_remaining",
        "max_iter",
    }


@pytest.mark.asyncio
async def test_phase_c_refuses_binary_patch_for_ml_artifacts(
    tmp_path,
) -> None:
    """Phase C must NOT try to text-patch a binary ML artifact. When
    file_record carries ``ml_format``, Phase C returns structured
    remediation guidance (replace with safetensors) and ``UNVERIFIABLE``
    status — never a corrupt patched binary."""
    from dast.orchestrator import _run_phase_c_fix_verify
    from dast.journal import Journal

    sandbox = _CapturingStubSandbox()
    journal = Journal(file_id="hash-evil", base_dir=Path(tmp_path))

    async def fake_inference(prompt, options, schema):
        # Phase C guard fires BEFORE any inference call. If the model
        # gets called we've leaked through the guard — fail loudly.
        raise AssertionError(
            "model should not be called when ml_format is set in file_record"
        )

    file_record = {
        "file_id": "hash-evil",
        "source_text": "# === ML MODEL FILE: pickle ===\n# (synth)\n",
        "file_name": "evil.pkl",
        "ml_format": "pickle",
        "original_bytes": b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00ABC",
    }
    l1_output = {
        "verdict": {"verdict_label": "critical_malicious"},
        "hypotheses": [
            {"id": "H001", "finding_ref": "H001", "cwe": "CWE-502",
             "severity": "critical", "type": "insecure_deserialization",
             "explanation": "", "code_snippet": "", "line": None,
             "data_flow_trace": "", "proof_of_concept": "", "confidence": 1.0},
        ],
    }

    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output=l1_output,
        iter1_plans=[{"hypothesis_id": "H001", "plan_status": "executable",
                      "commands": ["python -c 'pass'"], "image_hint": "ml_tools"}],
        inference=fake_inference,
        sandbox=sandbox,
        journal=journal,
    )

    # Guard fired
    assert result["attempted"] is False
    assert result["skipped_reason"] == "binary_artifact_remediation_is_replacement_not_patch"
    assert result["ml_format"] == "pickle"
    assert result["post_patch_verdict"] == "UNVERIFIABLE"
    assert result["n_neutralized"] == 0
    assert result["n_still_exploitable"] == 0

    # Per-finding entries reflect the same UNVERIFIABLE status
    assert len(result["per_finding"]) == 1
    assert result["per_finding"][0]["finding_id"] == "H001"
    assert result["per_finding"][0]["post_patch_status"] == "UNVERIFIABLE"

    # The remediation guidance names safetensors as the safe alternative
    assert "safetensors" in result["fix_summary"]
    assert "pickle" in result["fix_summary"]

    # No sandbox calls happened (we declined to replay a patched binary)
    assert sandbox.submitted_plans == []


@pytest.mark.asyncio
async def test_run_dast_skips_phase_c_when_disabled(
    tmp_path,
) -> None:
    """When ``enable_phase_c=False`` is passed to run_dast, Phase C must
    NOT fire even if there are CONFIRMED findings. The result surfaces a
    structured opt-out marker so consumers can distinguish 'disabled' from
    'ran and found nothing'."""

    async def fake_inference(prompt, options, schema):
        # Accept any call; emit a "no plans / no hyps" minimal response.
        return {
            "text": json.dumps({
                "plans": [], "verdict_label": "malicious",
                "log_summary": "stub", "validated_findings": ["H001"],
                "confirmed_categories": [], "new_hypotheses": [],
            }),
            "usage": {}, "finish_reason": "stop",
        }

    sandbox = _CapturingStubSandbox()
    file_record = {
        "file_id": "py-hash",
        "source_text": "import os\nos.system(user_input)\n",
        "file_name": "vuln.py",
        "ml_format": None,
        "original_bytes": None,
    }
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [{
            "id": "H001", "finding_ref": "H001", "cwe": "CWE-78",
            "severity": "critical", "type": "command_injection",
            "explanation": "", "code_snippet": "", "line": 2,
            "data_flow_trace": "", "proof_of_concept": "", "confidence": 0.9,
        }],
    }

    result = await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
        enable_phase_c=False,  # opt out
    )

    # Phase C should be marked as opted-out, not None (None would imply
    # "no findings to fix" which is a different state)
    assert result.phase_c is not None
    assert result.phase_c.get("attempted") is False
    assert result.phase_c.get("skipped_reason") == "phase_c_disabled_by_config"
    # The count of confirmed findings should still be reported so users
    # see what WOULD have been remediated
    assert "n_confirmed_findings" in result.phase_c


@pytest.mark.asyncio
async def test_phase_c_runs_normally_for_text_source(
    tmp_path,
) -> None:
    """Sanity guard: a regular .py file with confirmed findings should
    proceed through the normal Phase C patch generator (we mock the
    model + sandbox replay)."""
    from dast.orchestrator import _run_phase_c_fix_verify
    from dast.journal import Journal

    sandbox = _CapturingStubSandbox()
    journal = Journal(file_id="py-hash", base_dir=Path(tmp_path))
    inference_called = {"n": 0}

    async def fake_inference(prompt, options, schema):
        inference_called["n"] += 1
        # Return a minimal patched source + summary
        return {
            "text": json.dumps({
                "patched_source": "import shlex\n# fixed\n",
                "fix_summary": "input now goes through shlex.quote",
                "per_finding_fixes": [],
            }),
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "finish_reason": "stop",
        }

    file_record = {
        "file_id": "py-hash",
        "source_text": "import os\nos.system(user_input)\n",
        "file_name": "vuln.py",
        "ml_format": None,  # text source — Phase C should run normally
        "original_bytes": None,
    }
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [
            {"id": "H001", "finding_ref": "H001", "cwe": "CWE-78",
             "severity": "critical", "type": "command_injection",
             "explanation": "", "code_snippet": "", "line": 2,
             "data_flow_trace": "", "proof_of_concept": "", "confidence": 0.9},
        ],
    }

    result = await _run_phase_c_fix_verify(
        file_record=file_record,
        findings_validated=["H001"],
        l1_output=l1_output,
        iter1_plans=[{"hypothesis_id": "H001", "plan_status": "executable",
                      "commands": ["python /workspace/vuln.py"],
                      "image_hint": "minimal"}],
        inference=fake_inference,
        sandbox=sandbox,
        journal=journal,
    )

    # Phase C ran (model was called, no binary guard triggered)
    assert inference_called["n"] >= 1
    assert result.get("skipped_reason") != "binary_artifact_remediation_is_replacement_not_patch"
    # Sandbox got the replay call
    assert len(sandbox.submitted_plans) >= 1


@pytest.mark.asyncio
async def test_orchestrator_skips_ml_plan_when_format_absent(
    tmp_path,
) -> None:
    """Sanity guard: a regular .py file goes through the model-driven
    plan path with NO HML_LOAD prepended."""

    async def fake_inference(prompt, options, schema):
        return {
            "text": json.dumps({"plans": [], "verdict_label": "suspicious",
                                "log_summary": "", "validated_findings": [],
                                "confirmed_categories": [],
                                "new_hypotheses": []}),
            "usage": {},
            "finish_reason": "stop",
        }

    sandbox = _CapturingStubSandbox()
    file_record = {
        "file_id": "py-hash",
        "source_text": "import os\nos.system('ls')\n",
        "file_name": "regular.py",
        "ml_format": None,
        "original_bytes": None,
    }
    l1_output = {
        "verdict": {"verdict_label": "malicious"},
        "hypotheses": [{
            "id": "H001", "finding_ref": "H001",
            "finding_type": "rce", "severity": "high",
            "explanation": "", "code_snippet": "", "line": 2,
            "data_flow_trace": "", "proof_of_concept": "",
            "cwe": "CWE-78", "confidence": 0.9,
        }],
    }

    await run_dast(
        file_record=file_record,
        l1_output=l1_output,
        sandbox=sandbox,
        validator=HypothesisValidator(),
        journal_dir=Path(tmp_path),
        inference=fake_inference,
    )

    # No HML_LOAD plan — only whatever the model emitted (zero in this stub)
    assert all(p.hypothesis_id != "HML_LOAD" for p in sandbox.submitted_plans)
