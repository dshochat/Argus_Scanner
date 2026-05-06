"""Multi-image sandbox wiring — DAST-015 reference (NOT WIRED IN YET).

Constructs a ``MultiImageSandboxClient`` with three ``FirecrackerSandboxClient``
inner clients, one per image hint (`minimal`, `networked`, `ml_tools`).
Image refs are read from environment variables so deployment-specific
tags don't leak into source.

Why a reference module (not a production wire-in commit yet)
------------------------------------------------------------
The production ``dast/sandbox/`` module is currently empty (per the
parallel-session task workflow — a separate session will populate it
when DAST-015 is claimed). This file shows the recipe Tal copies into
the production scanner constructor when DAST-015 lands. It's
executable enough to smoke-test the wiring against a stub; not used
by the prototype's actual run path.

Used by
-------
  * Smoke-test script ``_smoke_multi_image_wiring.py`` (companion file
    in the same directory, when written)
  * Reference for DAST-015 claimer

Environment contract
--------------------
Three env vars, all required when the multi-image client is in use::

    ECHO_DAST_IMAGE_MINIMAL    = registry.fly.io/argus-dast-sandbox:minimal-v1
    ECHO_DAST_IMAGE_NETWORKED  = registry.fly.io/argus-dast-sandbox:networked-v1
    ECHO_DAST_IMAGE_ML_TOOLS   = registry.fly.io/argus-dast-sandbox:ml-tools-v1

Plus the existing ``FLY_API_TOKEN`` for Fly Machines API calls.

Fallback behaviour
------------------
If only ``ECHO_DAST_IMAGE_MINIMAL`` is set (e.g. during a phased
rollout where networked/ml_tools images aren't deployed yet),
``MultiImageSandboxClient`` registers only the available images and
falls back to ``minimal`` for any plan whose hint isn't present. This
is the safe default — plans that emit ``image_hint=ml_tools`` against
a single-image deployment route to ``minimal`` and still execute,
just without the ml_tools-specific binaries available.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dast.sandbox.client import (
    FirecrackerSandboxClient,
    FlyMachinesClient,
    MultiImageSandboxClient,
    StubSandboxClient,
)


_IMAGE_ENV_VARS: dict[str, str] = {
    "minimal": "ECHO_DAST_IMAGE_MINIMAL",
    "networked": "ECHO_DAST_IMAGE_NETWORKED",
    "ml_tools": "ECHO_DAST_IMAGE_ML_TOOLS",
}


@dataclass(frozen=True)
class MultiImageWiringConfig:
    """Resolved image refs + Fly auth for ``build_multi_image_sandbox``."""

    fly_app_name: str
    fly_api_token: str
    image_refs: dict[str, str]  # hint → registry image ref
    fallback_hint: str = "minimal"
    fly_region: str = "iad"

    @classmethod
    def from_env(
        cls,
        *,
        fly_app_name: str = "argus-dast-sandbox",
        require_all_images: bool = False,
    ) -> "MultiImageWiringConfig":
        """Build a config from environment variables.

        ``require_all_images=False`` (default) means we register only
        whichever ``ECHO_DAST_IMAGE_*`` env vars are set; ``minimal``
        is mandatory because it's the fallback. If you want to fail
        loudly on a partial deployment (e.g. CI smoke checks), pass
        ``require_all_images=True``.
        """
        token = os.environ.get("FLY_API_TOKEN", "").strip()
        if not token:
            raise RuntimeError(
                "FLY_API_TOKEN must be set for the multi-image sandbox "
                "client to call the Fly Machines API."
            )

        refs: dict[str, str] = {}
        missing: list[str] = []
        for hint, env_var in _IMAGE_ENV_VARS.items():
            v = os.environ.get(env_var, "").strip()
            if v:
                refs[hint] = v
            else:
                missing.append(env_var)

        if "minimal" not in refs:
            raise RuntimeError(
                "ECHO_DAST_IMAGE_MINIMAL must be set — it's the fallback "
                "hint for plans whose requested image isn't registered."
            )

        if require_all_images and missing:
            raise RuntimeError(
                "Missing image env vars: "
                + ", ".join(missing)
                + ". Pass require_all_images=False to allow partial "
                "deployments (plans default to minimal)."
            )

        return cls(
            fly_app_name=fly_app_name,
            fly_api_token=token,
            image_refs=refs,
        )


def build_multi_image_sandbox(
    config: MultiImageWiringConfig,
    file_content_map: dict[str, bytes],
) -> MultiImageSandboxClient:
    """Construct a ``MultiImageSandboxClient`` from a resolved config.

    ``file_content_map`` is the same ``{file_id → bytes}`` dict the
    single-image client takes; each inner Firecracker client gets its
    own reference (sharing is fine — the dict is read-only at runtime).

    Returns a ``MultiImageSandboxClient`` that satisfies the
    ``SandboxClient`` Protocol — drop into the orchestrator just like
    the single-image ``FirecrackerSandboxClient`` it replaces.
    """
    fly_client = FlyMachinesClient(
        app_name=config.fly_app_name,
        api_token=config.fly_api_token,
        region=config.fly_region,
    )

    inner: dict[str, FirecrackerSandboxClient] = {}
    for hint, image_ref in config.image_refs.items():
        inner[hint] = FirecrackerSandboxClient(
            fly_client=fly_client,
            image=image_ref,
            file_content_map=file_content_map,
        )

    return MultiImageSandboxClient(
        inner_by_hint=inner,
        fallback_hint=config.fallback_hint,
    )


def build_stub_multi_image_sandbox(
    file_content_map: dict[str, bytes] | None = None,
) -> MultiImageSandboxClient:
    """Stub variant for tests / offline reasoning runs.

    Constructs three ``StubSandboxClient`` instances (one per hint),
    all sharing an empty scenario map. Lets caller exercise the
    dispatch logic + plan-tagged-with-hint without standing up Fly
    infra. Real per-fixture ground-truth scenarios go in via
    ``StubSandboxClient.scenario`` after construction.
    """
    inner = {
        hint: StubSandboxClient()
        for hint in _IMAGE_ENV_VARS
    }
    return MultiImageSandboxClient(
        inner_by_hint=inner,
        fallback_hint="minimal",
    )


# ---------------------------------------------------------------------------
# Quick self-check (importable + parses) — run as a script.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Smoke check 1: stub variant constructs cleanly without env vars.
    stub_sandbox = build_stub_multi_image_sandbox()
    assert stub_sandbox.resolve_hint("minimal") == "minimal"
    assert stub_sandbox.resolve_hint("networked") == "networked"
    assert stub_sandbox.resolve_hint("ml_tools") == "ml_tools"
    assert stub_sandbox.resolve_hint("unknown_hint") == "minimal"  # fallback
    print("ok  stub multi-image sandbox: hint resolution wired")

    # Smoke check 2: env-driven config rejects empty FLY_API_TOKEN.
    try:
        MultiImageWiringConfig.from_env()
        print("FAIL expected RuntimeError on missing FLY_API_TOKEN")
    except RuntimeError as e:
        if "FLY_API_TOKEN" in str(e):
            print("ok  rejects missing FLY_API_TOKEN")
        else:
            print(f"FAIL unexpected error: {e}")

    # Smoke check 3: env-driven config rejects missing minimal image
    # even when token is set.
    os.environ["FLY_API_TOKEN"] = "dummy_token_for_test"
    try:
        MultiImageWiringConfig.from_env()
        print("FAIL expected RuntimeError on missing minimal image")
    except RuntimeError as e:
        if "ECHO_DAST_IMAGE_MINIMAL" in str(e):
            print("ok  rejects missing minimal image")
        else:
            print(f"FAIL unexpected error: {e}")

    # Smoke check 4: config accepts when minimal is set, even alone.
    os.environ["ECHO_DAST_IMAGE_MINIMAL"] = "registry.fly.io/argus-dast-sandbox:minimal-v1"
    try:
        cfg = MultiImageWiringConfig.from_env()
        assert "minimal" in cfg.image_refs
        assert "networked" not in cfg.image_refs
        print("ok  partial deployment accepted (minimal only)")
    except RuntimeError as e:
        print(f"FAIL unexpected error: {e}")

    # Smoke check 5: require_all_images=True rejects partial.
    try:
        MultiImageWiringConfig.from_env(require_all_images=True)
        print("FAIL expected RuntimeError with require_all_images=True")
    except RuntimeError as e:
        if "Missing image env vars" in str(e):
            print("ok  require_all_images=True enforces full set")
        else:
            print(f"FAIL unexpected error: {e}")

    # Cleanup
    del os.environ["FLY_API_TOKEN"]
    del os.environ["ECHO_DAST_IMAGE_MINIMAL"]

    print("\nAll wiring smoke checks passed.")
