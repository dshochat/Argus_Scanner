"""Test fixture for Phase 2 cross-function exploit chains (v1.6).

Contains TWO functions that look safe in isolation but combine into RCE:

1. ``parse_config(payload: str) -> dict`` — accepts a string, parses it
   as a Python literal via ``ast.literal_eval``. Reviewers see "safe
   parser, no eval" and move on. Returns a dict. Looking at this
   function alone, an attacker can produce any dict shape they want
   (including ``{"hook": "__import__('os').system('id')"}``), but
   nothing in this function executes the value — it just returns it.

2. ``apply_config(cfg: dict) -> str`` — accepts a dict, looks up the
   ``"hook"`` field, and ``eval()``s it. Reviewers see "evaluates
   config" but assume config comes from a trusted file. Looking at
   this function alone, calling it with attacker-controlled input
   would obviously be RCE — but the function expects "config" from
   the system, not from a user. The function ITSELF is not
   exploitable if you only look at what calls it.

The CHAIN ``apply_config(parse_config(payload))`` is RCE because:

* ``parse_config`` accepts ANY user input string.
* It returns a dict containing the attacker's payload string verbatim.
* ``apply_config`` then ``eval()``s that string as Python.

A single-function probe targeting EITHER function in isolation will
NOT confirm the exploit:

* Probing ``parse_config`` alone: returns a dict; no Rule 1 evidence
  signature matches (the dict structure is benign on inspection).
* Probing ``apply_config`` alone: requires synthesizing the malicious
  config — but a single-function probe doesn't reason about how
  ``parse_config`` shapes the dict.

A Phase 2 chain probe DOES confirm it: step 1 emits the payload,
step 2's input is ``<<_step1_result>>`` (the parsed dict), and the
final ``eval()`` produces ``__builtins__`` in the value preview — a
code_injection signature match.

NOT a real CVE — synthetic, intentionally vulnerable for evaluation only.
"""
from __future__ import annotations

import ast


def parse_config(payload: str) -> dict:
    """Parse a user-supplied config payload into a dict.

    Uses ``ast.literal_eval`` which is documented as safe (no code
    execution). Returns a dict for downstream consumption.

    The bug is NOT in this function. It does exactly what it claims:
    parse user input into a structured dict.
    """
    parsed = ast.literal_eval(payload)
    if not isinstance(parsed, dict):
        return {"hook": str(parsed)}
    return parsed


def apply_config(cfg: dict) -> str:
    """Apply a config dict: evaluate the ``hook`` field as Python.

    Returns the evaluated value's repr for inspection.

    The bug is NOT in this function either if you assume cfg comes from
    a trusted source (e.g., a config file written by an admin). The
    function expects internal data, not user input.

    The bug is in the SYSTEM ASSUMPTION: this function is reachable
    from user input via ``parse_config``. The chain
    ``apply_config(parse_config(user_input))`` is RCE.
    """
    hook = cfg.get("hook", "None")
    # eval the hook expression in a context that exposes builtins —
    # which is the textbook code_injection sink.
    return repr(eval(hook))  # noqa: S307
