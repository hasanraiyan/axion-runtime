"""
Transport-level failures raised by adapters. Plain exceptions, not HTTP ones: the
Gateway maps them to the standard result statuses (SRS-07 FR-33).
"""


class UpstreamError(Exception):
    """Generic upstream failure (5xx, protocol error, malformed response)."""

    retryable = True


class UpstreamAuthError(UpstreamError):
    """Upstream rejected our credentials (401/403)."""

    retryable = False


class UpstreamRateLimited(UpstreamError):
    retryable = True


class UpstreamTimeout(UpstreamError):
    retryable = True


class UpstreamResponseTooLarge(UpstreamError):
    retryable = False


class UpstreamSessionExpired(UpstreamError):
    """The remote MCP session is gone; the pool must recreate it."""

    retryable = True


class UpstreamTargetBlocked(UpstreamError):
    """The Outbound Guard refused the target at run time (e.g. DNS now resolves to a private address)."""

    retryable = False
