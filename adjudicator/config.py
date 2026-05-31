import os

# Benchmark API
BM_API_BASE = os.environ.get("BM_API_BASE", "http://127.0.0.1:5060/v1/bm")
BM_SERVICE_TOKEN = os.environ.get("BM_SERVICE_TOKEN", "bm_svc_echo_verdict_agent_2026")

# Opus for verdicts — thinking disabled for speed
VERDICT_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
VERDICT_MODEL = os.environ.get("VERDICT_MODEL", "claude-opus-4-6")

# Verdict thresholds
AUTO_APPLY_THRESHOLD = 0.85      # >= this: auto-apply verdict
SPOT_CHECK_THRESHOLD = 0.60      # >= this but < auto: apply + flag for spot-check
# Below 0.60: leave for human review, don't apply

# Agent settings
POLL_INTERVAL_SECONDS = 30
MAX_RETRIES = 2
