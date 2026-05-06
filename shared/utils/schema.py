"""Label schema loader. The JSON file under docs/ is the authoritative contract."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "label_schema_v3.1.json"


@lru_cache(maxsize=4)
def load_label_schema(path: str | Path | None = None) -> dict[str, Any]:
    """Load the JSON schema dict. Cached per path.

    Feed the returned dict directly to vLLM's guided decoding — that is how
    the scanner guarantees every model output conforms to the contract.
    """
    p = Path(path) if path is not None else DEFAULT_SCHEMA_PATH
    with open(p, encoding="utf-8") as f:
        return json.load(f)
