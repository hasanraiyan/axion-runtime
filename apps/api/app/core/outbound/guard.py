"""
Outbound URL Guard (SRS-07 FR-40, NFR-S2).

Single, reusable gate that every outbound integration request must pass
(MCP, REST, webhook, OAuth discovery/token calls, OpenAPI fetches). It is
transport-agnostic: it validates and resolves a URL and returns a
``GuardedTarget`` whose ``pinned_ips`` the HTTP layer must connect to, so a
DNS answer cannot change between validation and connection (DNS rebinding).

Callers re-run ``check`` for every redirect hop.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol, Sequence, Tuple, Union
from urllib.parse import urlsplit

from app.core.exceptions import UrlBlockedError

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Always blocked, even when private networks are allowed (cloud metadata services).
_ALWAYS_BLOCKED_NETWORKS: Tuple[ipaddress._BaseNetwork, ...] = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),  # ECS task metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
)

# NAT64 well-known prefix: the low 32 bits embed an IPv4 address.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class HostResolver(Protocol):
    """Port: resolve a hostname to IP address strings."""

    async def resolve(self, host: str, port: int) -> List[str]: ...


class SystemHostResolver:
    """Default resolver using the event loop's getaddrinfo."""

    async def resolve(self, host: str, port: int) -> List[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        seen: List[str] = []
        for info in infos:
            address = info[4][0]
            if address not in seen:
                seen.append(address)
        return seen


@dataclass(frozen=True)
class GuardedTarget:
    """A validated destination. Connect only to ``pinned_ips``."""

    url: str
    scheme: str
    host: str
    port: int
    pinned_ips: Tuple[str, ...]


def _unwrap(ip: IPAddress) -> IPAddress:
    """Unwrap IPv4-mapped and NAT64 IPv6 addresses to the embedded IPv4."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _parse_legacy_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """Parse decimal/hex/octal/short IPv4 forms (e.g. 2130706433, 0x7f.1, 127.1)."""
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def parse_ip_literal(host: str) -> Optional[IPAddress]:
    """Return the IP for a literal host in any common encoding, else ``None``."""
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    # Strip IPv6 zone id (fe80::1%eth0)
    if "%" in candidate:
        try:
            return ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            return None
    return _parse_legacy_ipv4(candidate)


def is_always_blocked(ip: IPAddress) -> bool:
    ip = _unwrap(ip)
    return any(ip in net for net in _ALWAYS_BLOCKED_NETWORKS if net.version == ip.version)


def is_public_ip(ip: IPAddress) -> bool:
    """True only for globally routable addresses."""
    ip = _unwrap(ip)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return ip.is_global


def _host_allowed(host: str, allowed_hosts: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in allowed_hosts:
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif host == pattern:
            return True
    return False


class OutboundUrlGuard:
    """
    Validates outbound URLs and pins their resolved addresses.

    ``allow_private_networks`` is for explicit on-premises deployments only;
    cloud metadata endpoints stay blocked regardless. ``allow_insecure_http``
    permits ``http`` (development only).
    """

    def __init__(
        self,
        resolver: Optional[HostResolver] = None,
        *,
        allow_private_networks: bool = False,
        allow_insecure_http: bool = False,
    ) -> None:
        self._resolver: HostResolver = resolver if resolver is not None else SystemHostResolver()
        self._allow_private = allow_private_networks
        self._allow_http = allow_insecure_http

    async def check(
        self,
        url: str,
        *,
        allowed_hosts: Optional[Iterable[str]] = None,
    ) -> GuardedTarget:
        """
        Validate ``url`` and return a pinned target.

        ``allowed_hosts`` may only *narrow* what the guard permits: the host
        must match one of the patterns (exact, or ``*.example.com``) and still
        pass every network check.
        """
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise UrlBlockedError("invalid_url")
        if any(ch in url for ch in ("\r", "\n", "\t", " ", "\x00")):
            raise UrlBlockedError("control_characters")

        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise UrlBlockedError("invalid_url") from None

        scheme = (parts.scheme or "").lower()
        if scheme == "http":
            if not self._allow_http:
                raise UrlBlockedError("insecure_scheme")
        elif scheme != "https":
            raise UrlBlockedError("unsupported_scheme")

        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise UrlBlockedError("userinfo_not_allowed")

        host = parts.hostname
        if not host:
            raise UrlBlockedError("missing_host")
        host = host.lower().rstrip(".")
        if not host:
            raise UrlBlockedError("missing_host")

        if allowed_hosts is not None:
            patterns = list(allowed_hosts)
            if not _host_allowed(host, patterns):
                raise UrlBlockedError("host_not_allowed")

        port = port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise UrlBlockedError("invalid_port")

        literal = parse_ip_literal(host)
        if literal is not None:
            addresses: List[IPAddress] = [literal]
        else:
            try:
                resolved = await self._resolver.resolve(host, port)
            except (OSError, UnicodeError):
                raise UrlBlockedError("dns_failure") from None
            addresses = []
            for raw in resolved:
                parsed = parse_ip_literal(raw)
                if parsed is None:
                    raise UrlBlockedError("unparseable_address")
                addresses.append(parsed)
            if not addresses:
                raise UrlBlockedError("dns_failure")

        # Every resolved address must pass: one private answer poisons the host.
        for address in addresses:
            if is_always_blocked(address):
                raise UrlBlockedError("metadata_address")
            if not self._allow_private and not is_public_ip(address):
                raise UrlBlockedError("non_public_address")

        return GuardedTarget(
            url=url,
            scheme=scheme,
            host=host,
            port=port,
            pinned_ips=tuple(str(_unwrap(a)) if _unwrap(a) != a else str(a) for a in addresses),
        )


def get_outbound_url_guard() -> OutboundUrlGuard:
    """Dependency provider: guard configured from application settings."""
    from app.core.config import settings

    return OutboundUrlGuard(
        allow_private_networks=settings.OUTBOUND_ALLOW_PRIVATE_NETWORKS,
        allow_insecure_http=settings.OUTBOUND_ALLOW_INSECURE_HTTP,
    )
