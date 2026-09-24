"""
Target guard for PortWatch Pro.

Every target that reaches a scanning, recon, or credential module passes
through validate_target() first. This is a safety control: it stops the
platform from being pointed at infrastructure it should never touch, whether
by mistake or by misuse.

Blocked by default:
  - loopback (127.0.0.0/8, ::1)
  - link-local (169.254.0.0/16, fe80::/10) including the cloud metadata
    endpoint 169.254.169.254
  - unspecified / reserved / multicast addresses
  - hostnames that resolve to any of the above

RFC1918 private ranges (10/8, 172.16/12, 192.168/16) are blocked by default
but can be allowed for internal engagements by setting
ALLOW_PRIVATE_TARGETS=1. Even then, loopback and metadata stay blocked.

The guard validates the shape and destination of a target. It does not grant
authorization: an in-range target still needs a project authorization whose
scope covers it (enforced separately in the API layer).
"""

import ipaddress
import os
import socket

# Cloud metadata endpoints that must never be scanned or probed.
METADATA_ADDRESSES = {
    "169.254.169.254",   # AWS, Azure, GCP, OpenStack
    "fd00:ec2::254",     # AWS IMDSv2 IPv6
    "100.100.100.200",   # Alibaba Cloud
}


class TargetRejected(ValueError):
    """Raised when a target is not permitted by the guard."""


def _allow_private():
    return os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")


def _strip_target(raw):
    """Normalize a raw target into a bare host/IP.

    Accepts bare hosts, host:port, and http(s):// URLs. Returns the host part
    lowercased and stripped. Does not accept CIDR here (see validate_cidr)."""
    t = (raw or "").strip().lower()
    if not t:
        raise TargetRejected("Empty target.")
    # Strip scheme
    for scheme in ("http://", "https://", "ftp://", "ssh://"):
        if t.startswith(scheme):
            t = t[len(scheme):]
            break
    # Strip path/query
    for sep in ("/", "?", "#"):
        if sep in t:
            t = t.split(sep, 1)[0]
    # Strip credentials in URL form user:pass@host
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    # Strip port (but keep IPv6 brackets intact)
    if t.startswith("[") and "]" in t:
        # [::1]:8080 -> ::1
        t = t[1:t.index("]")]
    elif t.count(":") == 1:
        t = t.split(":", 1)[0]
    if not t:
        raise TargetRejected("Target has no host component.")
    return t


def _ip_is_blocked(ip):
    """Return a reason string if this ip address object is blocked, else None."""
    if str(ip) in METADATA_ADDRESSES:
        return "cloud metadata endpoint"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_private and not _allow_private():
        return "private/internal address (set ALLOW_PRIVATE_TARGETS=1 for internal engagements)"
    return None


def _resolve(host):
    """Resolve a hostname to a set of IP address objects. Empty on failure."""
    ips = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            addr = sockaddr[0]
            try:
                ips.add(ipaddress.ip_address(addr.split("%")[0]))
            except ValueError:
                continue
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        pass
    return ips


def validate_target(raw, resolve=True):
    """Validate a single scan/recon/spray target.

    Returns the normalized host string on success.
    Raises TargetRejected if the target is blocked or malformed.

    If resolve is True (default), hostnames are resolved and every resolved
    address is checked, closing the DNS-rebinding / hostname-to-internal gap.
    Resolution failure is not fatal on its own (nmap may still resolve it
    later), but any address that does resolve is checked.
    """
    host = _strip_target(raw)

    # Direct IP literal? Parse first, then judge. The parse and the rejection
    # are kept separate because TargetRejected subclasses ValueError, and a
    # combined try/except would swallow the rejection as a "not an IP" signal.
    ip_literal = None
    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        pass  # It's a hostname, not an IP literal.

    if ip_literal is not None:
        reason = _ip_is_blocked(ip_literal)
        if reason:
            raise TargetRejected(f"Target '{host}' is a {reason}; refusing.")
        return host

    # Obvious loopback hostnames.
    if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
        raise TargetRejected(f"Target '{host}' is loopback; refusing.")

    if resolve:
        for ip in _resolve(host):
            reason = _ip_is_blocked(ip)
            if reason:
                raise TargetRejected(
                    f"Target '{host}' resolves to {ip} ({reason}); refusing.")

    return host


def validate_cidr(raw):
    """Validate a CIDR range for range scans. Rejects ranges that overlap
    loopback, link-local, or metadata. Rejects overly broad ranges."""
    raw = (raw or "").strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        raise TargetRejected(f"Invalid CIDR '{raw}': {e}")

    # Guard against absurdly large sweeps.
    max_hosts = int(os.environ.get("MAX_CIDR_HOSTS", "1024"))
    if net.num_addresses > max_hosts:
        raise TargetRejected(
            f"CIDR '{raw}' covers {net.num_addresses} addresses; "
            f"limit is {max_hosts}. Narrow the range.")

    for probe in (net.network_address, net.broadcast_address):
        reason = _ip_is_blocked(probe)
        if reason and "private" not in reason:
            raise TargetRejected(f"CIDR '{raw}' includes a {reason}; refusing.")
    if net.is_private and not _allow_private():
        raise TargetRejected(
            f"CIDR '{raw}' is private/internal; set ALLOW_PRIVATE_TARGETS=1 "
            f"for internal engagements.")
    return str(net)


def is_allowed(raw, resolve=False):
    """Convenience boolean wrapper."""
    try:
        validate_target(raw, resolve=resolve)
        return True
    except TargetRejected:
        return False
