#!/usr/bin/env python3
"""
Verdict Agent — Automated security researcher for benchmark review queue.

Polls the benchmark review queue, picks up unresolved disagreements between
AI security scanners, sends them to Opus 4.6 (thinking disabled) for analysis,
and writes verdicts back via API.
"""

import argparse
import json
import logging
import time
from datetime import UTC, datetime

import requests
from config import (
    AUTO_APPLY_THRESHOLD,
    BM_API_BASE,
    BM_SERVICE_TOKEN,
    MAX_RETRIES,
    POLL_INTERVAL_SECONDS,
    SPOT_CHECK_THRESHOLD,
    VERDICT_API_KEY,
    VERDICT_MODEL,
)
from opus_verdict_adapter import OpusVerdictAdapter
from prompt_builder import build_batch_verdict_prompt, build_verdict_prompt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [VERDICT-AGENT] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/echo-verdict-agent.log"),
    ],
)
log = logging.getLogger("verdict-agent")


class VerdictAgent:
    def __init__(self):
        if not VERDICT_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not set — needed for Opus verdict model")

        self.verdict_model = OpusVerdictAdapter(
            api_key=VERDICT_API_KEY,
            model=VERDICT_MODEL,
        )
        self.api_base = BM_API_BASE
        self.headers = {
            "Authorization": f"Bearer {BM_SERVICE_TOKEN}",
            "Content-Type": "application/json",
        }
        self.stats = {
            "total_processed": 0,
            "auto_applied": 0,
            "spot_check": 0,
            "left_for_human": 0,
            "errors": 0,
        }

    # ── API helpers ──────────────────────────────────────────────────────

    def _get(self, path: str, params: dict = None) -> dict | list | None:
        try:
            resp = requests.get(
                f"{self.api_base}{path}",
                headers=self.headers,
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error("GET %s failed: %s", path, e)
            return None

    def _post(self, path: str, data: dict) -> dict | None:
        try:
            resp = requests.post(
                f"{self.api_base}{path}",
                headers=self.headers,
                json=data,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error("POST %s failed: %s", path, e)
            return None

    # ── Core logic ───────────────────────────────────────────────────────

    def fetch_pending_reviews(self) -> list:
        result = self._get("/review", {"pending_only": "true"})
        if result and "items" in result:
            return result["items"]
        return []

    def fetch_file_content(self, file_id: str) -> dict | None:
        return self._get(f"/files/{file_id}")

    def fetch_model_findings(self, run_id: str, file_id: str) -> list | None:
        result = self._get(f"/runs/{run_id}/files/{file_id}")
        if result and "results" in result:
            return result["results"]
        return None

    def submit_verdict(self, review_id: str, verdict: dict, auto_applied: bool) -> bool:
        result = self._post(
            f"/review/{review_id}/verdict",
            {
                "verdict": verdict["verdict"],
                "verdict_detail": {
                    "confidence": verdict["confidence"],
                    "reasoning": verdict["reasoning"],
                    "corrected_finding": verdict.get("corrected_finding"),
                    "input_tokens": verdict.get("_input_tokens", 0),
                    "output_tokens": verdict.get("_output_tokens", 0),
                    "response_time_ms": verdict.get("_response_time_ms", 0),
                    "agent": "opus-verdict-agent",
                    "model": VERDICT_MODEL,
                    "auto_applied": auto_applied,
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            },
        )
        return result is not None

    def process_review(self, review_item: dict, dry_run: bool = False):
        """Process a single review queue item."""
        review_id = review_item["id"]
        file_id = review_item["file_id"]
        run_id = review_item.get("run_id")

        log.info(
            "Processing review %s: %s — %s",
            review_id[:8],
            review_item.get("review_type", "?"),
            review_item.get("description", "")[:80],
        )

        if not run_id:
            log.warning("Review %s has no run_id, skipping", review_id[:8])
            return

        file_data = self.fetch_file_content(file_id)
        if not file_data:
            log.error("Could not fetch file %s", file_id)
            self.stats["errors"] += 1
            return

        source_code = file_data.get("content", "")
        if not source_code:
            log.warning("File %s has no content", file_id)
            self.stats["errors"] += 1
            return

        model_findings = self.fetch_model_findings(run_id, file_id)
        if not model_findings:
            log.error("Could not fetch findings for file %s in run %s", file_id, run_id)
            self.stats["errors"] += 1
            return

        system_prompt, user_message = build_verdict_prompt(review_item, source_code, model_findings)

        if dry_run:
            log.info("[DRY RUN] Would send to Opus — prompt length: %d chars", len(user_message))
            return

        verdict = self.verdict_model.get_verdict(system_prompt, user_message, max_retries=MAX_RETRIES)

        if not verdict:
            log.error("Opus failed to produce verdict for review %s", review_id[:8])
            self.stats["errors"] += 1
            return

        confidence = verdict["confidence"]
        base_verdict = verdict["verdict"]

        if confidence >= AUTO_APPLY_THRESHOLD:
            self.submit_verdict(review_id, verdict, auto_applied=True)
            log.info(
                "AUTO-APPLIED: %s (confidence: %.2f) — %s",
                base_verdict,
                confidence,
                verdict["reasoning"][:100],
            )
            self.stats["auto_applied"] += 1

        elif confidence >= SPOT_CHECK_THRESHOLD:
            verdict["verdict"] = f"{base_verdict}_SPOT_CHECK"
            self.submit_verdict(review_id, verdict, auto_applied=False)
            log.info("SPOT-CHECK: %s (confidence: %.2f)", base_verdict, confidence)
            self.stats["spot_check"] += 1

        else:
            verdict["verdict"] = f"UNCERTAIN_{base_verdict}"
            self.submit_verdict(review_id, verdict, auto_applied=False)
            log.info("LEFT FOR HUMAN: confidence too low (%.2f)", confidence)
            self.stats["left_for_human"] += 1

        self.stats["total_processed"] += 1

    @staticmethod
    def _group_by_file(items: list) -> dict:
        """Group review items by file_id."""
        by_file = {}
        for item in items:
            fid = item.get("file_id", "unknown")
            by_file.setdefault(fid, []).append(item)
        return by_file

    def _process_items(self, items: list, dry_run: bool = False):
        """Process items with batching — group by file, batch multi-item files."""
        by_file = self._group_by_file(items)
        log.info("Grouped %d reviews across %d unique files", len(items), len(by_file))

        for file_id, file_items in by_file.items():
            if len(file_items) == 1:
                self.process_review(file_items[0], dry_run=dry_run)
            else:
                self.process_batch(file_id, file_items, dry_run=dry_run)
            time.sleep(2)

    def process_batch(self, file_id: str, review_items: list, dry_run: bool = False):
        """Process multiple review items for the same file in one Opus call."""
        log.info("Batch processing %d reviews for file %s", len(review_items), file_id[:8])

        run_id = review_items[0].get("run_id")
        if not run_id:
            log.warning("No run_id for batch, skipping")
            return

        # Fetch file content ONCE
        file_data = self.fetch_file_content(file_id)
        if not file_data or not file_data.get("content"):
            log.error("Could not fetch file %s", file_id[:8])
            self.stats["errors"] += 1
            return

        # Fetch model findings ONCE
        model_findings = self.fetch_model_findings(run_id, file_id)
        if not model_findings:
            log.error("Could not fetch findings for file %s", file_id[:8])
            self.stats["errors"] += 1
            return

        # Build ONE prompt with ALL disagreements
        system_prompt, user_message = build_batch_verdict_prompt(file_data, model_findings, review_items)

        if dry_run:
            log.info("[DRY RUN] Batch — %d items, prompt %d chars", len(review_items), len(user_message))
            return

        # Larger max_tokens for batch response
        max_tokens = min(512 * len(review_items), 4096)
        result = self.verdict_model.get_verdict(
            system_prompt, user_message, max_retries=MAX_RETRIES, max_tokens=max_tokens
        )

        if not result:
            log.error("Batch verdict failed for file %s — falling back to individual", file_id[:8])
            # Fallback: process individually
            for item in review_items:
                self.process_review(item)
                time.sleep(2)
            return

        # Parse batch response — could be a batch JSON or single verdict
        verdicts = result.get("verdicts") if isinstance(result, dict) and "verdicts" in result else None

        if verdicts and isinstance(verdicts, list):
            # Map verdicts to review items by review_id or index
            verdict_map = {}
            for v in verdicts:
                rid = v.get("review_id", "")
                verdict_map[rid] = v

            applied = 0
            for item in review_items:
                v = verdict_map.get(item["id"])
                if not v:
                    # Try partial match
                    v = verdict_map.get(item["id"][:8])
                if not v:
                    # Fall back to index-based
                    idx = review_items.index(item)
                    v = verdicts[idx] if idx < len(verdicts) else None

                if v and v.get("verdict") in ("CONFIRMED", "REJECTED", "MODIFIED"):
                    confidence = v.get("confidence", 0)
                    if confidence >= AUTO_APPLY_THRESHOLD:
                        self.submit_verdict(item["id"], v, auto_applied=True)
                        log.info(
                            "BATCH AUTO-APPLIED: %s (%.2f) — %s",
                            v["verdict"],
                            confidence,
                            v.get("reasoning", "")[:80],
                        )
                        self.stats["auto_applied"] += 1
                    elif confidence >= SPOT_CHECK_THRESHOLD:
                        v["verdict"] = f"{v['verdict']}_SPOT_CHECK"
                        self.submit_verdict(item["id"], v, auto_applied=False)
                        self.stats["spot_check"] += 1
                    else:
                        v["verdict"] = f"UNCERTAIN_{v['verdict']}"
                        self.submit_verdict(item["id"], v, auto_applied=False)
                        self.stats["left_for_human"] += 1
                    self.stats["total_processed"] += 1
                    applied += 1
                else:
                    log.warning("No verdict for review %s in batch", item["id"][:8])

            log.info("Batch: applied %d/%d verdicts for file %s", applied, len(review_items), file_id[:8])
        else:
            # Single verdict returned instead of batch — apply to first, fallback rest
            log.warning("Batch returned single verdict, falling back for remaining items")
            if result.get("verdict") in ("CONFIRMED", "REJECTED", "MODIFIED"):
                self.submit_verdict(review_items[0]["id"], result, auto_applied=True)
                self.stats["auto_applied"] += 1
                self.stats["total_processed"] += 1
            for item in review_items[1:]:
                self.process_review(item)
                time.sleep(2)

    def _trigger_rebuild(self, run_id: str):
        log.info("Triggering ground truth rebuild for run %s", run_id[:8])
        result = self._post(f"/runs/{run_id}/build-ground-truth", {})
        if result:
            log.info("Ground truth rebuilt + rescored for run %s", run_id[:8])
        else:
            log.error("Failed to rebuild ground truth for run %s", run_id[:8])

    # ── Run modes ────────────────────────────────────────────────────────

    def run_daemon(self):
        """Daemon mode — process pending items, NO auto-rebuild."""
        log.info("=" * 60)
        log.info("Verdict Agent starting (daemon mode — NO auto-rebuild)")
        log.info("  API:              %s", self.api_base)
        log.info("  Model:            %s", VERDICT_MODEL)
        log.info("  Auto-apply:       >= %.0f%%", AUTO_APPLY_THRESHOLD * 100)
        log.info("  Spot-check:       >= %.0f%%", SPOT_CHECK_THRESHOLD * 100)
        log.info("  Poll interval:    %ds", POLL_INTERVAL_SECONDS)
        log.info("=" * 60)

        while True:
            try:
                pending = self.fetch_pending_reviews()

                if pending:
                    log.info("Found %d pending reviews", len(pending))
                    self._process_items(pending)
                    log.info("Stats: %s", json.dumps(self.stats))
                    # NO rebuild here — use --full-cycle for that

            except KeyboardInterrupt:
                log.info("Shutting down")
                log.info("Final stats: %s", json.dumps(self.stats))
                break
            except Exception as e:
                log.error("Unexpected error in main loop: %s", e, exc_info=True)

            time.sleep(POLL_INTERVAL_SECONDS)

    def run_once(self, dry_run: bool = False):
        """Process all pending and exit. No rebuild."""
        log.info("Verdict Agent — run-once mode%s", " (DRY RUN)" if dry_run else "")
        pending = self.fetch_pending_reviews()
        if not pending:
            log.info("No pending reviews")
            return

        log.info("Found %d pending reviews", len(pending))
        self._process_items(pending, dry_run=dry_run)
        log.info("Final stats: %s", json.dumps(self.stats))

    def run_full_cycle(self, dry_run: bool = False):
        """
        Process all reviews in waves until queue stabilizes.
        No rebuild between individual verdicts — only ONE rebuild after all verdicts.
        Max 3 waves to prevent infinite loops.
        """
        log.info("=" * 60)
        log.info("Verdict Agent — FULL CYCLE mode (max 3 waves)")
        log.info("=" * 60)
        wave = 1
        MAX_WAVES = 3

        while True:
            log.info("=== WAVE %d ===", wave)

            # Step 1: Process ALL pending reviews (no rebuild between them)
            pending = self.fetch_pending_reviews()
            if not pending:
                log.info("Queue empty after wave %d. Done.", wave)
                break

            log.info("Processing %d items in wave %d", len(pending), wave)
            affected_runs = set()
            for item in pending:
                run_id = item.get("run_id")
                if run_id:
                    affected_runs.add(run_id)
            self._process_items(pending, dry_run=dry_run)

            log.info("Wave %d stats: %s", wave, json.dumps(self.stats))

            if dry_run:
                log.info("[DRY RUN] Skipping rebuild")
                break

            # Step 2: ONE rebuild after ALL verdicts applied
            if affected_runs:
                log.info("All verdicts applied. Running ONE consensus rebuild...")
                for run_id in affected_runs:
                    self._trigger_rebuild(run_id)

            # Step 3: Check if new items appeared
            new_pending = self.fetch_pending_reviews()
            new_count = len(new_pending) if new_pending else 0

            if new_count == 0:
                log.info("No new items after rebuild. Ground truth stable.")
                break
            elif wave >= MAX_WAVES:
                log.info("Stopping after %d waves. %d items remain for human review.", wave, new_count)
                break
            else:
                log.info("%d new items after rebuild. Running wave %d...", new_count, wave + 1)
                wave += 1

        log.info("Cycle complete. Waves: %d. Final stats: %s", wave, json.dumps(self.stats))

    def run_single(self, review_id: str, dry_run: bool = False):
        log.info("Verdict Agent — single review: %s", review_id[:8])
        result = self._get(f"/review/{review_id}")
        if not result:
            log.error("Review %s not found", review_id)
            return
        self.process_review(result, dry_run=dry_run)
        log.info("Done. Stats: %s", json.dumps(self.stats))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verdict Agent — Opus 4.6 security reviewer")
    parser.add_argument("--daemon", action="store_true", help="Run as continuous daemon (no auto-rebuild)")
    parser.add_argument("--run-once", action="store_true", help="Process all pending and exit (no rebuild)")
    parser.add_argument("--full-cycle", action="store_true", help="Drain queue → rebuild → repeat (max 3 waves)")
    parser.add_argument("--review-id", type=str, help="Process a single review item")
    parser.add_argument("--dry-run", action="store_true", help="Don't submit verdicts, just log")
    args = parser.parse_args()

    agent = VerdictAgent()

    if args.review_id:
        agent.run_single(args.review_id, dry_run=args.dry_run)
    elif args.run_once:
        agent.run_once(dry_run=args.dry_run)
    elif args.full_cycle:
        agent.run_full_cycle(dry_run=args.dry_run)
    else:
        agent.run_daemon()
