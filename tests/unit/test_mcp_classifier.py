"""Unit tests for mcp_scanner.classifier.

Covers the JSON-Schema → ParamClass mapping the probe layer relies on
to seed payloads. Each test asserts a single classification rule so a
regression points straight at the broken case.
"""

from __future__ import annotations

import pytest

from mcp_scanner.classifier import ParamClass, classify_param

# ── format hint (highest priority) ────────────────────────────────────


def test_format_uri_classifies_url() -> None:
    assert classify_param("payload", {"type": "string", "format": "uri"}) == ParamClass.URL


def test_format_url_classifies_url() -> None:
    assert classify_param("payload", {"format": "url"}) == ParamClass.URL


def test_format_hostname_classifies_host() -> None:
    assert classify_param("payload", {"format": "hostname"}) == ParamClass.HOST


def test_format_ipv4_classifies_host() -> None:
    assert classify_param("payload", {"format": "ipv4"}) == ParamClass.HOST


def test_format_ipv6_classifies_host() -> None:
    assert classify_param("payload", {"format": "ipv6"}) == ParamClass.HOST


def test_format_path_classifies_path() -> None:
    assert classify_param("payload", {"format": "path"}) == ParamClass.PATH


def test_format_case_insensitive() -> None:
    """Format hint uses lower()."""
    assert classify_param("payload", {"format": "URI"}) == ParamClass.URL


# ── pattern hint ──────────────────────────────────────────────────────


def test_pattern_http_classifies_url() -> None:
    assert (
        classify_param("payload", {"type": "string", "pattern": "^https?://.+"})
        == ParamClass.URL
    )


def test_pattern_https_only_classifies_url() -> None:
    assert classify_param("payload", {"pattern": "^https://"}) == ParamClass.URL


def test_pattern_non_url_falls_through_to_type() -> None:
    """A non-URL pattern shouldn't force URL — should hit the type fallback."""
    assert (
        classify_param("nonce", {"type": "string", "pattern": "^[a-z0-9]{16}$"})
        == ParamClass.FUZZ
    )


# ── name keyword matching ─────────────────────────────────────────────


def test_name_url_classifies_url() -> None:
    assert classify_param("url", {"type": "string"}) == ParamClass.URL


def test_name_webhook_url_classifies_url() -> None:
    assert classify_param("webhook_url", {"type": "string"}) == ParamClass.URL


def test_name_endpoint_classifies_url() -> None:
    assert classify_param("endpoint", {"type": "string"}) == ParamClass.URL


def test_name_callback_classifies_url() -> None:
    assert classify_param("callback", {"type": "string"}) == ParamClass.URL


def test_name_host_classifies_host() -> None:
    assert classify_param("host", {"type": "string"}) == ParamClass.HOST


def test_name_hostname_classifies_host() -> None:
    assert classify_param("hostname", {"type": "string"}) == ParamClass.HOST


def test_name_address_classifies_host() -> None:
    assert classify_param("server_address", {"type": "string"}) == ParamClass.HOST


def test_name_path_classifies_path() -> None:
    assert classify_param("path", {"type": "string"}) == ParamClass.PATH


def test_name_file_path_classifies_path() -> None:
    assert classify_param("file_path", {"type": "string"}) == ParamClass.PATH


def test_name_filename_classifies_path() -> None:
    assert classify_param("filename", {"type": "string"}) == ParamClass.PATH


def test_name_command_classifies_command() -> None:
    assert classify_param("command", {"type": "string"}) == ParamClass.COMMAND


def test_name_cmd_classifies_command() -> None:
    assert classify_param("cmd", {"type": "string"}) == ParamClass.COMMAND


def test_name_args_classifies_command() -> None:
    assert classify_param("args", {"type": "string"}) == ParamClass.COMMAND


def test_name_query_classifies_query() -> None:
    assert classify_param("query", {"type": "string"}) == ParamClass.QUERY


def test_name_sql_classifies_query() -> None:
    assert classify_param("sql_filter", {"type": "string"}) == ParamClass.QUERY


def test_name_case_insensitive() -> None:
    """Substring match should not care about case."""
    assert classify_param("ServerURL", {"type": "string"}) == ParamClass.URL


# ── type fallback ─────────────────────────────────────────────────────


def test_generic_string_classifies_fuzz() -> None:
    """No name / format / pattern signal → FUZZ for strings."""
    assert classify_param("payload", {"type": "string"}) == ParamClass.FUZZ


def test_integer_classifies_integer() -> None:
    assert classify_param("count", {"type": "integer"}) == ParamClass.INTEGER


def test_number_classifies_integer() -> None:
    """JSON-Schema ``number`` rolls into our INTEGER fuzz class."""
    assert classify_param("ratio", {"type": "number"}) == ParamClass.INTEGER


def test_boolean_classifies_boolean() -> None:
    assert classify_param("enable", {"type": "boolean"}) == ParamClass.BOOLEAN


def test_type_list_with_null_picks_string() -> None:
    """JSON Schema permits ``type: ["string", "null"]``."""
    assert classify_param("payload", {"type": ["string", "null"]}) == ParamClass.FUZZ


def test_type_list_picks_first_non_null() -> None:
    assert classify_param("payload", {"type": ["null", "integer"]}) == ParamClass.INTEGER


# ── edge cases ────────────────────────────────────────────────────────


def test_no_schema_falls_through_to_unknown() -> None:
    """Param with no schema and no name hint → UNKNOWN."""
    assert classify_param("payload", None) == ParamClass.UNKNOWN


def test_empty_schema_with_name_hint_still_classifies() -> None:
    """Name hint alone (no type, no format) should still bin the param.

    Real MCP servers don't always populate ``type`` even when they
    should; we shouldn't lose the URL classification on a partial
    schema."""
    assert classify_param("url", {}) == ParamClass.URL


def test_unrecognised_type_falls_through_to_unknown() -> None:
    """Object / array params with no name hint are UNKNOWN — probes
    don't try to fuzz nested structures in v1."""
    assert classify_param("payload", {"type": "object"}) == ParamClass.UNKNOWN


def test_priority_format_beats_name() -> None:
    """When name says PATH but format says URL, format wins.

    This matches the docstring's stated priority order: format hint is
    the strongest signal because it's explicitly schema-declared."""
    assert (
        classify_param("file_path", {"type": "string", "format": "uri"}) == ParamClass.URL
    )


def test_priority_pattern_beats_name() -> None:
    """Pattern hint beats name hint."""
    assert (
        classify_param("payload", {"type": "string", "pattern": "^https?://x"})
        == ParamClass.URL
    )


# ── enum stability (probes match against the string value) ───────────


@pytest.mark.parametrize(
    "cls,value",
    [
        (ParamClass.URL, "url"),
        (ParamClass.HOST, "host"),
        (ParamClass.PATH, "path"),
        (ParamClass.COMMAND, "command"),
        (ParamClass.QUERY, "query"),
        (ParamClass.FUZZ, "fuzz"),
        (ParamClass.INTEGER, "integer"),
        (ParamClass.BOOLEAN, "boolean"),
        (ParamClass.UNKNOWN, "unknown"),
    ],
)
def test_param_class_string_values_stable(cls: ParamClass, value: str) -> None:
    """The probe layer compares ``param.param_class == ParamClass.URL``
    AND callers may compare the string form. Both must stay stable;
    renaming any of these is a wire-shape break."""
    assert cls.value == value
