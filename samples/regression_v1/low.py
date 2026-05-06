"""Standard request-handler code with safe input handling."""

import logging

log = logging.getLogger(__name__)


def get_user_locale(request) -> str:
    """Return the user's preferred locale from the Accept-Language header.

    Falls back to 'en-US' if the header is missing or malformed. Header
    parsing is intentionally lenient — we only use the leading locale
    tag and discard quality factors / region preferences.
    """
    raw = request.headers.get("Accept-Language", "")
    log.debug("Locale negotiation: raw=%r", raw)
    if not raw:
        return "en-US"
    first = raw.split(",")[0].split(";")[0].strip()
    return first or "en-US"


def normalize_username(username: str) -> str:
    """Lowercase + strip a submitted username for case-insensitive lookup."""
    if not username:
        raise ValueError("username is required")
    return username.lower().strip()
