"""Parser protocol + registry for ecosystem dependency parsers.

A parser consumes `(source_path, content)` and emits `list[Dependency]`.
Determinism and idempotence are required — same input → byte-identical
output. Parsers never make network calls.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from shared.types.preprocessing import Dependency

ParserFn = Callable[[Path, str], list[Dependency]]


class Parser(Protocol):
    def __call__(self, path: Path, content: str) -> list[Dependency]: ...


class ParserRegistry:
    """Exact-filename → parser dispatch. Lowercased match on `Path.name`."""

    def __init__(self) -> None:
        self._by_name: dict[str, ParserFn] = {}
        self._by_suffix: dict[str, ParserFn] = {}

    def register_name(self, *names: str) -> Callable[[ParserFn], ParserFn]:
        def deco(fn: ParserFn) -> ParserFn:
            for n in names:
                self._by_name[n.lower()] = fn
            return fn

        return deco

    def register_suffix(self, *suffixes: str) -> Callable[[ParserFn], ParserFn]:
        def deco(fn: ParserFn) -> ParserFn:
            for s in suffixes:
                self._by_suffix[s.lower()] = fn
            return fn

        return deco

    def find(self, path: Path) -> ParserFn | None:
        name = path.name.lower()
        if fn := self._by_name.get(name):
            return fn
        return self._by_suffix.get(path.suffix.lower())
