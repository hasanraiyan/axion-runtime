"""
Outbound URL Guard conformance suite (SRS-07 FR-40, NFR-S2, verification scenario 3).
No network access: DNS is replaced with an in-memory fake resolver.
"""
from typing import Dict, List

import pytest

from app.core.exceptions import UrlBlockedError
from app.core.outbound import OutboundUrlGuard, is_public_ip, parse_ip_literal
import ipaddress


class FakeResolver:
    def __init__(self, table: Dict[str, List[str]] | None = None, fail: bool = False) -> None:
        self.table = table or {}
        self.fail = fail
        self.calls: List[str] = []

    async def resolve(self, host: str, port: int) -> List[str]:
        self.calls.append(host)
        if self.fail:
            raise OSError("dns failure")
        return self.table.get(host, [])


def guard(table=None, **kwargs) -> OutboundUrlGuard:
    return OutboundUrlGuard(FakeResolver(table or {"mcp.example.com": ["93.184.216.34"]}), **kwargs)


async def reason_for(url: str, g: OutboundUrlGuard | None = None, **kwargs) -> str:
    with pytest.raises(UrlBlockedError) as exc:
        await (g or guard()).check(url, **kwargs)
    return exc.value.reason


# ---------------------------------------------------------------- happy path
async def test_public_https_host_is_allowed_and_ip_is_pinned():
    target = await guard().check("https://mcp.example.com/mcp")
    assert target.host == "mcp.example.com"
    assert target.port == 443
    assert target.pinned_ips == ("93.184.216.34",)


async def test_explicit_port_is_preserved():
    target = await guard().check("https://mcp.example.com:8443/x")
    assert target.port == 8443


# ---------------------------------------------------------------- scheme / syntax
@pytest.mark.parametrize("url", ["ftp://mcp.example.com/x", "file:///etc/passwd", "gopher://mcp.example.com"])
async def test_non_http_schemes_are_rejected(url):
    assert await reason_for(url) == "unsupported_scheme"


async def test_plain_http_rejected_by_default_and_allowed_in_dev_mode():
    assert await reason_for("http://mcp.example.com/x") == "insecure_scheme"
    target = await guard(allow_insecure_http=True).check("http://mcp.example.com/x")
    assert target.port == 80


async def test_userinfo_is_rejected():
    assert await reason_for("https://user:pw@mcp.example.com/") == "userinfo_not_allowed"
    assert await reason_for("https://mcp.example.com@evil.example.com/") == "userinfo_not_allowed"


@pytest.mark.parametrize("url", ["https://mcp.example.com/\r\nHost: x", "https://mcp.example.com/a b", ""])
async def test_control_characters_and_empty_are_rejected(url):
    assert await reason_for(url) in {"control_characters", "invalid_url"}


async def test_missing_host_and_bad_port_are_rejected():
    assert await reason_for("https:///path") == "missing_host"
    assert await reason_for("https://mcp.example.com:99999/") == "invalid_url"


# ---------------------------------------------------------------- literal IPs
@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://10.0.0.5/",
        "https://172.16.4.4/",
        "https://192.168.1.10/",
        "https://0.0.0.0/",
        "https://100.64.0.1/",  # CGNAT
        "https://[::1]/",
        "https://[fe80::1]/",
        "https://[fc00::1]/",
        "https://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback
        "https://[::ffff:10.0.0.1]/",
        "https://[64:ff9b::7f00:1]/",  # NAT64 embedding 127.0.0.1
    ],
)
async def test_private_loopback_and_reserved_literals_are_blocked(url):
    assert await reason_for(url) == "non_public_address"


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data",
        "https://[::ffff:169.254.169.254]/",
        "https://[fd00:ec2::254]/",
    ],
)
async def test_cloud_metadata_addresses_are_blocked(url):
    assert await reason_for(url) == "metadata_address"


@pytest.mark.parametrize(
    "url",
    [
        "https://2130706433/",  # decimal 127.0.0.1
        "https://0x7f000001/",  # hex
        "https://0x7f.1/",  # mixed hex short form
        "https://127.1/",  # short form
        "https://017700000001/",  # octal
        "https://2852039166/",  # decimal 169.254.169.254
    ],
)
async def test_encoded_ip_tricks_are_blocked(url):
    assert await reason_for(url) in {"non_public_address", "metadata_address"}


# ---------------------------------------------------------------- DNS handling
async def test_hostname_resolving_to_private_ip_is_blocked():
    g = guard({"internal.example.com": ["10.1.2.3"]})
    assert await reason_for("https://internal.example.com/", g) == "non_public_address"


async def test_one_private_answer_poisons_a_multi_record_host():
    g = guard({"rebind.example.com": ["93.184.216.34", "127.0.0.1"]})
    assert await reason_for("https://rebind.example.com/", g) == "non_public_address"


async def test_hostname_resolving_to_metadata_ip_is_blocked():
    g = guard({"meta.example.com": ["169.254.169.254"]})
    assert await reason_for("https://meta.example.com/", g) == "metadata_address"


async def test_dns_failure_and_empty_answer_are_blocked():
    assert await reason_for("https://x.example.com/", OutboundUrlGuard(FakeResolver(fail=True))) == "dns_failure"
    assert await reason_for("https://nothing.example.com/", guard({})) == "dns_failure"


async def test_literal_ip_does_not_consult_dns():
    resolver = FakeResolver()
    g = OutboundUrlGuard(resolver)
    await reason_for("https://127.0.0.1/", g)
    assert resolver.calls == []


async def test_every_check_re_resolves_so_redirect_hops_are_revalidated():
    resolver = FakeResolver({"a.example.com": ["93.184.216.34"], "b.example.com": ["10.0.0.9"]})
    g = OutboundUrlGuard(resolver)
    await g.check("https://a.example.com/")
    with pytest.raises(UrlBlockedError):
        await g.check("https://b.example.com/")  # simulated redirect hop to a private host
    assert resolver.calls == ["a.example.com", "b.example.com"]


# ---------------------------------------------------------------- on-prem flag
async def test_private_networks_allowed_only_with_explicit_flag():
    g = guard({"intranet.example.com": ["10.0.0.7"]}, allow_private_networks=True)
    target = await g.check("https://intranet.example.com/")
    assert target.pinned_ips == ("10.0.0.7",)


async def test_metadata_addresses_stay_blocked_even_with_private_networks_allowed():
    g = guard(allow_private_networks=True)
    assert await reason_for("https://169.254.169.254/", g) == "metadata_address"


# ---------------------------------------------------------------- allow-list narrows only
async def test_allowed_hosts_exact_and_wildcard_match():
    g = guard({"api.example.com": ["93.184.216.34"], "example.com": ["93.184.216.34"]})
    assert (await g.check("https://api.example.com/", allowed_hosts=["*.example.com"])).host == "api.example.com"
    assert (await g.check("https://api.example.com/", allowed_hosts=["api.example.com"])).host == "api.example.com"
    assert await reason_for("https://example.com/", g, allowed_hosts=["*.example.com"]) == "host_not_allowed"
    assert await reason_for("https://api.example.com/", g, allowed_hosts=["other.com"]) == "host_not_allowed"


async def test_allow_list_cannot_widen_network_checks():
    g = guard({"intranet.example.com": ["10.0.0.7"]})
    assert (
        await reason_for("https://intranet.example.com/", g, allowed_hosts=["intranet.example.com"])
        == "non_public_address"
    )


# ---------------------------------------------------------------- error contract
async def test_client_message_is_generic_and_does_not_leak_reason():
    with pytest.raises(UrlBlockedError) as exc:
        await guard({"x.example.com": ["10.0.0.1"]}).check("https://x.example.com/")
    assert exc.value.code == "URL_BLOCKED"
    assert exc.value.status_code == 400
    assert "10.0.0.1" not in exc.value.message
    assert exc.value.reason == "non_public_address"


# ---------------------------------------------------------------- helpers
def test_is_public_ip_and_parse_ip_literal():
    assert is_public_ip(ipaddress.ip_address("8.8.8.8"))
    assert not is_public_ip(ipaddress.ip_address("192.168.0.1"))
    assert parse_ip_literal("example.com") is None
    assert str(parse_ip_literal("2130706433")) == "127.0.0.1"
