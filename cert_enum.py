#!/usr/bin/env python3
"""
TLS Certificate & Pentest Recon Enumerator
Enumerates certificate attributes, correlates reuse, expands SANs,
analyses DNS configuration, and prepares evidence/report artefacts.

Optional dependency for full DNS checks (CAA, SPF, DMARC, DNSSEC, AXFR):
    pip install dnspython
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import struct
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

# ---------------------------------------------------------------------------
# Optional dnspython — needed for CAA, SPF, DMARC, DNSSEC, AXFR
# ---------------------------------------------------------------------------
try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


USE_COLOUR = sys.stdout.isatty()


class C:
    RESET   = "\033[0m"  if USE_COLOUR else ""
    BOLD    = "\033[1m"  if USE_COLOUR else ""
    DIM     = "\033[2m"  if USE_COLOUR else ""
    RED     = "\033[31m" if USE_COLOUR else ""
    GREEN   = "\033[32m" if USE_COLOUR else ""
    YELLOW  = "\033[33m" if USE_COLOUR else ""
    BLUE    = "\033[34m" if USE_COLOUR else ""
    CYAN    = "\033[36m" if USE_COLOUR else ""
    MAGENTA = "\033[35m" if USE_COLOUR else ""
    ORANGE  = "\033[38;5;208m" if USE_COLOUR else ""


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

# ---------------------------------------------------------------------------
# EKU OID lookup (avoids relying on private _name attribute)
# ---------------------------------------------------------------------------
_EKU_NAMES: Dict[str, str] = {
    "1.3.6.1.5.5.7.3.1":      "serverAuth",
    "1.3.6.1.5.5.7.3.2":      "clientAuth",
    "1.3.6.1.5.5.7.3.3":      "codeSigning",
    "1.3.6.1.5.5.7.3.4":      "emailProtection",
    "1.3.6.1.5.5.7.3.8":      "timeStamping",
    "1.3.6.1.5.5.7.3.9":      "OCSPSigning",
    "1.3.6.1.4.1.311.10.3.3": "msSGC",
    "1.3.6.1.4.1.311.10.3.4": "msEFS",
    "2.16.840.1.113730.4.1":   "nsSGC",
    "1.3.6.1.5.5.7.3.14":     "eapOverLAN",
    "1.3.6.1.5.5.7.3.21":     "sshClient",
    "1.3.6.1.5.5.7.3.22":     "sshServer",
    "2.5.29.37.0":             "anyExtendedKeyUsage",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    severity: str
    title:    str
    detail:   str


@dataclass
class TargetResult:
    target:                  str
    host:                    str
    port:                    int
    success:                 bool
    error:                   Optional[str]
    # Certificate fields
    subject:                 Optional[str]       = None
    issuer:                  Optional[str]        = None
    common_names:            Optional[List[str]]  = None
    san_entries:             Optional[List[str]]  = None
    serial_number:           Optional[str]        = None
    not_before:              Optional[str]        = None
    not_after:               Optional[str]        = None
    sha1:                    Optional[str]        = None
    sha256:                  Optional[str]        = None
    signature_algorithm:     Optional[str]        = None
    signature_algorithm_oid: Optional[str]        = None
    public_key_type:         Optional[str]        = None
    public_key_size:         Optional[str]        = None
    version:                 Optional[str]        = None
    basic_constraints:       Optional[str]        = None
    key_usage:               Optional[str]        = None
    extended_key_usage:      Optional[str]        = None
    # TLS context
    tls_version:             Optional[str]        = None
    cipher:                  Optional[str]        = None
    cipher_bits:             Optional[int]        = None
    alpn:                    Optional[str]        = None
    # Chain
    chain_subjects:          Optional[List[str]]  = None
    chain_length:            Optional[int]        = None
    chain_notes:             Optional[List[str]]  = None
    # Discovery
    ct_names:                Optional[List[str]]  = None
    discovered_san_dns:      Optional[List[str]]  = None
    # DNS resolution (--dns)
    cert_source_ip:          Optional[str]        = None
    resolved_ipv4:           Optional[List[str]]  = None
    resolved_ipv6:           Optional[List[str]]  = None
    dns_nameservers:         Optional[List[str]]  = None
    dns_mx_records:          Optional[List[str]]  = None
    ip_cert_fingerprints:    Optional[Dict[str, str]] = None
    cert_consistent:         Optional[bool]       = None
    # DNS security checks (--dns-checks)
    dns_caa_records:         Optional[List[str]]  = None
    dns_spf_record:          Optional[str]        = None
    dns_dmarc_record:        Optional[str]        = None
    dns_dnssec:              Optional[bool]       = None
    dns_zone_transfer:       Optional[str]        = None
    dns_wildcard_resolves:   Optional[bool]       = None
    # Findings
    issues:                  Optional[List[Dict[str, str]]] = None


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def banner() -> None:
    width = 72
    print(f"{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  TLS Certificate & Pentest Recon Enumerator{C.RESET}")
    print(f"{C.DIM}  Enumerates certificate attributes, correlates reuse, expands SANs,")
    print(f"  analyses DNS configuration, and prepares evidence/report artefacts.{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * width}{C.RESET}")
    print()


def good(msg: str) -> None: print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg: str) -> None: print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def bad(msg: str)  -> None: print(f"{C.RED}[-]{C.RESET} {msg}")


def sev_colour(sev: str) -> str:
    s = sev.upper()
    if s == "CRITICAL": return C.RED + C.BOLD
    if s == "HIGH":     return C.RED
    if s == "MEDIUM":   return C.YELLOW
    if s == "LOW":      return C.CYAN
    return C.DIM


def info(label: str, value: str) -> None:
    print(f"  {C.BOLD}{label:<24}{C.RESET}  {value}")


def section(title: str) -> None:
    print(f"\n  {C.DIM}{'─' * 20}  {title}  {'─' * 20}{C.RESET}")


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_target(raw: str, default_ports: List[int]) -> List[Tuple[str, int]]:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target")
    for scheme in ("https://", "http://"):
        if raw.startswith(scheme):
            raw = raw[len(scheme):]
            break
    raw = raw.split("/", 1)[0]
    if raw.startswith("[") and "]" in raw:
        host_end = raw.find("]")
        host = raw[1:host_end]
        rest = raw[host_end + 1:]
        if rest.startswith(":"):
            return [(host, int(rest[1:]))]
        return [(host, p) for p in default_ports]
    if raw.count(":") == 1:
        host, port_str = raw.rsplit(":", 1)
        return [(host.strip(), int(port_str.strip()))]
    return [(raw, p) for p in default_ports]


def load_targets(
    single: str, file_path: str, comma_list: str, default_ports: List[int]
) -> List[Tuple[str, int]]:
    raw_targets: List[str] = []
    if single:
        raw_targets.append(single)
    if comma_list:
        raw_targets.extend([x.strip() for x in comma_list.split(",") if x.strip()])
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_targets.append(line)
    if not raw_targets:
        raise ValueError("No targets supplied")
    seen:   Set[Tuple[str, int]]  = set()
    parsed: List[Tuple[str, int]] = []
    for item in raw_targets:
        for host, port in parse_target(item, default_ports):
            key = (host.lower(), port)
            if key not in seen:
                seen.add(key)
                parsed.append((host, port))
    return parsed


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

def safe_extension(cert: x509.Certificate, ext_oid):
    try:
        return cert.extensions.get_extension_for_oid(ext_oid).value
    except x509.ExtensionNotFound:
        return None


def format_name(name: x509.Name) -> str:
    return name.rfc4514_string() if name else "<none>"


def get_common_names(name: x509.Name) -> List[str]:
    seen: Set[str] = set()
    values: List[str] = []
    for attr in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        if attr.value not in seen:
            seen.add(attr.value)
            values.append(attr.value)
    return values


def get_san_entries(cert: x509.Certificate) -> List[str]:
    san = safe_extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not san:
        return []
    entries = []
    for item in san:
        if isinstance(item, x509.DNSName):
            entries.append(f"DNS:{item.value}")
        elif isinstance(item, x509.IPAddress):
            entries.append(f"IP:{item.value}")
        elif isinstance(item, x509.RFC822Name):
            entries.append(f"EMAIL:{item.value}")
        elif isinstance(item, x509.UniformResourceIdentifier):
            entries.append(f"URI:{item.value}")
        else:
            entries.append(str(item))
    return entries


def get_san_dns(cert: x509.Certificate) -> List[str]:
    san = safe_extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not san:
        return []
    seen: Set[str] = set()
    values: List[str] = []
    for item in san:
        if isinstance(item, x509.DNSName) and item.value not in seen:
            seen.add(item.value)
            values.append(item.value)
    return values


def format_dt(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_dt(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fingerprint(data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    hexed = h.hexdigest().upper()
    return ":".join(hexed[i:i + 2] for i in range(0, len(hexed), 2))


def public_key_details(pubkey) -> Tuple[str, str]:
    if isinstance(pubkey, rsa.RSAPublicKey):          return "RSA",                    f"{pubkey.key_size} bits"
    if isinstance(pubkey, ec.EllipticCurvePublicKey): return f"EC ({pubkey.curve.name})", f"{pubkey.key_size} bits"
    if isinstance(pubkey, dsa.DSAPublicKey):          return "DSA",                    f"{pubkey.key_size} bits"
    if isinstance(pubkey, ed25519.Ed25519PublicKey):  return "Ed25519",                "N/A"
    if isinstance(pubkey, ed448.Ed448PublicKey):      return "Ed448",                  "N/A"
    return type(pubkey).__name__, "Unknown"


def format_basic_constraints(cert: x509.Certificate) -> str:
    bc = safe_extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if not bc:
        return "<not present>"
    path_len = "None" if bc.path_length is None else str(bc.path_length)
    return f"CA={bc.ca}, path_length={path_len}"


def format_key_usage(cert: x509.Certificate) -> str:
    ku = safe_extension(cert, ExtensionOID.KEY_USAGE)
    if not ku:
        return "<not present>"
    flags = []
    pairs = [
        ("digital_signature",  ku.digital_signature),
        ("content_commitment", ku.content_commitment),
        ("key_encipherment",   ku.key_encipherment),
        ("data_encipherment",  ku.data_encipherment),
        ("key_agreement",      ku.key_agreement),
        ("key_cert_sign",      ku.key_cert_sign),
        ("crl_sign",           ku.crl_sign),
        ("encipher_only",      ku.encipher_only if ku.key_agreement else False),
        ("decipher_only",      ku.decipher_only if ku.key_agreement else False),
    ]
    for label, value in pairs:
        if value:
            flags.append(label)
    return ", ".join(flags) if flags else "<present but empty>"


def format_eku(cert: x509.Certificate) -> str:
    eku = safe_extension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if not eku:
        return "<not present>"
    values = []
    for oid in eku:
        name = _EKU_NAMES.get(oid.dotted_string) or getattr(oid, "_name", None) or oid.dotted_string
        values.append(f"{name} ({oid.dotted_string})" if name != oid.dotted_string else oid.dotted_string)
    return ", ".join(values) if values else "<present but empty>"


def cert_not_before(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)  # type: ignore


def cert_not_after(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)  # type: ignore


def build_cert_record(der_cert: bytes) -> Dict[str, object]:
    cert   = x509.load_der_x509_certificate(der_cert, default_backend())
    pubkey = cert.public_key()
    pubkey_type, pubkey_size = public_key_details(pubkey)
    sig_oid  = cert.signature_algorithm_oid
    sig_name = (_EKU_NAMES.get(sig_oid.dotted_string)
                or getattr(sig_oid, "_name", None)
                or sig_oid.dotted_string)
    return {
        "subject":               format_name(cert.subject),
        "issuer":                format_name(cert.issuer),
        "common_names":          get_common_names(cert.subject),
        "san_entries":           get_san_entries(cert),
        "san_dns":               get_san_dns(cert),
        "serial_number":         hex(cert.serial_number),
        "not_before":            format_dt(cert_not_before(cert)),
        "not_after":             format_dt(cert_not_after(cert)),
        "sha1":                  fingerprint(der_cert, "sha1"),
        "sha256":                fingerprint(der_cert, "sha256"),
        "signature_algorithm":   sig_name,
        "signature_algorithm_oid": sig_oid.dotted_string,
        "public_key_type":       pubkey_type,
        "public_key_size":       pubkey_size,
        "version":               f"v{cert.version.value}",
        "basic_constraints":     format_basic_constraints(cert),
        "key_usage":             format_key_usage(cert),
        "extended_key_usage":    format_eku(cert),
        "cert_obj":              cert,
    }


# ---------------------------------------------------------------------------
# Network / TLS fetch
# ---------------------------------------------------------------------------

def fetch_endpoint(
    host: str, port: int, timeout: float, want_chain: bool
) -> Dict[str, object]:
    """Connect to host:port, retrieve the leaf cert (and optionally chain),
    and return the actual IP the OS connected to."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        remote_ip = sock.getpeername()[0]
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            leaf_der = tls_sock.getpeercert(binary_form=True)
            if not leaf_der:
                raise RuntimeError("No certificate was presented by the remote server")

            tls_version = tls_sock.version()
            cipher      = tls_sock.cipher()
            alpn        = tls_sock.selected_alpn_protocol()

            chain_ders: List[bytes] = [leaf_der]
            if want_chain and hasattr(tls_sock, "get_unverified_chain"):
                try:
                    maybe_chain = tls_sock.get_unverified_chain()
                    if maybe_chain and all(isinstance(c, bytes) for c in maybe_chain):
                        chain_ders = list(maybe_chain)
                except Exception:  # get_unverified_chain internals may raise anything
                    pass

            return {
                "leaf_der":    leaf_der,
                "chain_ders":  chain_ders,
                "tls_version": tls_version,
                "cipher":      cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn":        alpn,
                "remote_ip":   remote_ip,
            }


def fetch_cert_sha256_from_ip(
    ip: str, port: int, sni_hostname: str, timeout: float
) -> Optional[str]:
    """Connect directly to a specific IP (SNI = sni_hostname) and return
    the leaf certificate SHA-256, or None on failure."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni_hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                return fingerprint(der, "sha256") if der else None
    except (ssl.SSLError, socket.timeout, OSError):
        return None


# ---------------------------------------------------------------------------
# DNS — resolution (stdlib only)
# ---------------------------------------------------------------------------

def resolve_host_ips(hostname: str) -> Tuple[List[str], List[str]]:
    """Resolve hostname to IPv4 and IPv6 address lists via the OS resolver."""
    ipv4: List[str] = []
    ipv6: List[str] = []
    for family, bucket in ((socket.AF_INET, ipv4), (socket.AF_INET6, ipv6)):
        try:
            for info in socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM):
                ip = info[4][0]
                if ip not in bucket:
                    bucket.append(ip)
        except socket.gaierror:
            pass
    return ipv4, ipv6


def check_ip_cert_consistency(
    host: str, port: int, timeout: float,
    ipv4: List[str], ipv6: List[str],
) -> Tuple[Dict[str, str], Optional[bool]]:
    """Fetch the cert fingerprint from every resolved IP and compare.
    Returns (ip→sha256_map, consistent_bool).
    consistent is None when there is only one IP (nothing to compare)."""
    all_ips = ipv4 + ipv6
    ip_fp: Dict[str, str] = {}
    for ip in all_ips:
        fp = fetch_cert_sha256_from_ip(ip, port, host, timeout)
        ip_fp[ip] = fp if fp else "<unreachable>"

    reachable_fps = {v for v in ip_fp.values() if not v.startswith("<")}
    if len(all_ips) <= 1:
        consistent = None
    else:
        consistent = len(reachable_fps) <= 1
    return ip_fp, consistent


# ---------------------------------------------------------------------------
# DNS — record queries (dnspython)
# ---------------------------------------------------------------------------

def _make_resolver(timeout: float):
    """Return a configured dns.resolver.Resolver, or None if dnspython absent."""
    if not HAS_DNSPYTHON:
        return None
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout  = timeout
    return r


def _query(resolver, name: str, rdtype: str) -> List[str]:
    """Query a single record type; return list of text representations."""
    if resolver is None:
        return []
    try:
        answers = resolver.resolve(name, rdtype)
        return [a.to_text() for a in answers]
    except Exception:  # dnspython raises many types (NXDOMAIN, Timeout, NoAnswer, etc.)
        return []


def query_ns(domain: str, resolver) -> List[str]:
    return [ns.rstrip(".") for ns in _query(resolver, domain, "NS")]


def query_mx(domain: str, resolver) -> List[str]:
    return [r.rstrip(".") for r in _query(resolver, domain, "MX")]


def query_caa(domain: str, resolver) -> List[str]:
    """Walk up the DNS hierarchy until CAA records are found (RFC 8659 §3)."""
    if resolver is None:
        return []
    labels = domain.rstrip(".").split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        records = _query(resolver, candidate, "CAA")
        if records:
            return records
    return []


def query_spf(domain: str, resolver) -> Optional[str]:
    """Return the first SPF TXT record found, or None."""
    for txt in _query(resolver, domain, "TXT"):
        t = txt.strip('"').strip()
        if t.lower().startswith("v=spf1"):
            return t
    return None


def query_dmarc(domain: str, resolver) -> Optional[str]:
    """Return the DMARC TXT record at _dmarc.<domain>, or None."""
    for txt in _query(resolver, f"_dmarc.{domain}", "TXT"):
        t = txt.strip('"').strip()
        if t.lower().startswith("v=dmarc1"):
            return t
    return None


def check_dnssec(domain: str, resolver) -> Optional[bool]:
    """Return True if DNSKEY records exist, False if explicitly absent, None on error."""
    if resolver is None:
        return None
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        return len(list(answers)) > 0
    except Exception:  # dnspython raises many types
        return False


def check_wildcard_dns(domain: str, resolver) -> Optional[bool]:
    """Return True if a random 20-char subdomain resolves (wildcard DNS)."""
    if resolver is None:
        return None
    random_label = "".join(random.choices(string.ascii_lowercase, k=20))
    try:
        resolver.resolve(f"{random_label}.{domain}", "A")
        return True
    except Exception:  # NXDOMAIN, Timeout, etc. — all mean no wildcard
        return False


def attempt_zone_transfer(
    domain: str, nameservers: List[str], timeout: float
) -> str:
    """Attempt AXFR from up to three nameservers.
    Returns a human-readable result string."""
    if not HAS_DNSPYTHON:
        return "skipped (dnspython not installed)"
    if not nameservers:
        return "skipped (no nameservers resolved)"

    for ns_host in nameservers[:3]:
        ns_ips: List[str] = []
        try:
            for addr_info in socket.getaddrinfo(ns_host, 53, socket.AF_INET, socket.SOCK_STREAM):
                ns_ips.append(addr_info[4][0])
        except OSError:
            continue

        for ns_ip in ns_ips[:1]:
            try:
                xfr_gen = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout * 2)
                zone    = dns.zone.from_xfr(xfr_gen)
                count   = sum(1 for _ in zone.iterate_rdatasets())
                return f"SUCCESS — {count} rdatasets received from {ns_host} ({ns_ip})"
            except (dns.exception.FormError, EOFError,
                    ConnectionRefusedError, ConnectionResetError):
                return f"blocked by {ns_host} ({ns_ip})"
            except Exception:  # any AXFR failure — try next nameserver
                continue

    return "blocked (all nameservers refused)"


# ---------------------------------------------------------------------------
# Hostname matching
# ---------------------------------------------------------------------------

def hostname_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip(".")
    host    = host.lower().strip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix or host == suffix:
            return False
        # RFC 6125 §6.4.3: wildcard covers exactly ONE label
        return (host.endswith("." + suffix)
                and host.count(".") == suffix.count(".") + 1)
    return False


def leaf_hostname_match(host: str, common_names: List[str], san_dns: List[str]) -> bool:
    names = san_dns if san_dns else common_names
    return any(hostname_matches(n, host) for n in names)


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

def maybe_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    m = re.search(r"(\d+)", value)
    return int(m.group(1)) if m else None


def is_self_signed(subject: Optional[str], issuer: Optional[str]) -> bool:
    return bool(subject and issuer and subject == issuer)


def internal_name_indicators(value: str) -> bool:
    v = value.lower()
    if any(v.endswith(tld) for tld in
           [".local", ".corp", ".lan", ".internal", ".intra", ".home", ".ad"]):
        return True
    if "." not in v and ":" not in v and " " not in v:
        return True
    return False


def is_private_ip_text(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_private
    except ValueError:
        return False


def format_value(value) -> str:
    if value is None:
        return "<none>"
    if isinstance(value, list):
        return ", ".join(str(x) for x in value) if value else "<none>"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


# ---------------------------------------------------------------------------
# Risk-aware colourisation — certificate fields
# ---------------------------------------------------------------------------

def _days_to_expiry(not_after_str: Optional[str]) -> Optional[int]:
    dt = parse_dt(not_after_str)
    return None if dt is None else (dt - datetime.now(timezone.utc)).days


def colorize_not_after(value: str) -> str:
    if not USE_COLOUR:
        return value
    days = _days_to_expiry(value)
    if days is None:   return value
    if days < 0:       return f"{C.RED}{C.BOLD}{value}  ✖ EXPIRED{C.RESET}"
    if days <= 14:     return f"{C.RED}{value}  ({days}d remaining){C.RESET}"
    if days <= 30:     return f"{C.ORANGE}{value}  ({days}d remaining){C.RESET}"
    if days <= 90:     return f"{C.YELLOW}{value}  ({days}d remaining){C.RESET}"
    return f"{C.GREEN}{value}{C.RESET}"


def colorize_not_before(value: str) -> str:
    if not USE_COLOUR:
        return value
    dt = parse_dt(value)
    if dt and dt > datetime.now(timezone.utc):
        return f"{C.RED}{C.BOLD}{value}  ✖ NOT YET VALID{C.RESET}"
    return value


def colorize_san_entries(entries: List[str]) -> str:
    if not entries:
        return "<none>"
    if not USE_COLOUR:
        return ", ".join(entries)
    out = []
    for entry in entries:
        if entry.startswith("DNS:*."):
            out.append(f"{C.YELLOW}{entry}  [wildcard]{C.RESET}")
        elif entry.startswith("IP:") and is_private_ip_text(entry[3:]):
            out.append(f"{C.YELLOW}{entry}  [private IP]{C.RESET}")
        elif entry.startswith("DNS:") and internal_name_indicators(entry[4:]):
            out.append(f"{C.YELLOW}{entry}  [internal]{C.RESET}")
        else:
            out.append(entry)
    return ", ".join(out)


def colorize_common_names(names: List[str]) -> str:
    if not names:
        return "<none>"
    if not USE_COLOUR:
        return ", ".join(names)
    out = []
    for name in names:
        if name.startswith("*."):
            out.append(f"{C.YELLOW}{name}  [wildcard]{C.RESET}")
        elif internal_name_indicators(name):
            out.append(f"{C.YELLOW}{name}  [internal]{C.RESET}")
        else:
            out.append(name)
    return ", ".join(out)


def colorize_issuer(subject: Optional[str], issuer: Optional[str], val: str) -> str:
    if not USE_COLOUR:
        return val
    return f"{C.YELLOW}{val}  [self-signed]{C.RESET}" if is_self_signed(subject, issuer) else val


def colorize_signature_algorithm(value: str) -> str:
    if not USE_COLOUR:
        return value
    v = value.lower()
    if "md5" in v:
        return f"{C.RED}{C.BOLD}{value}  ✖ BROKEN{C.RESET}"
    if "sha1" in v and not any(x in v for x in ("sha256", "sha384", "sha512")):
        return f"{C.YELLOW}{value}  ⚠ WEAK{C.RESET}"
    return value


def colorize_public_key(pk_type: str, pk_size_str: str) -> str:
    if not USE_COLOUR:
        return pk_size_str
    size = maybe_int(pk_size_str)
    t    = pk_type.upper()
    if t.startswith("RSA") and size is not None:
        if size < 2048:  return f"{C.RED}{C.BOLD}{pk_size_str}  ✖ WEAK{C.RESET}"
        if size == 2048: return f"{C.YELLOW}{pk_size_str}  ⚠ MINIMUM{C.RESET}"
    if t.startswith("DSA"):
        return f"{C.YELLOW}{pk_size_str}  ⚠ DSA DEPRECATED{C.RESET}"
    return pk_size_str


def colorize_tls_version(value: Optional[str]) -> str:
    if not USE_COLOUR or not value:
        return format_value(value)
    if value in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        return f"{C.RED}{C.BOLD}{value}  ✖ DEPRECATED{C.RESET}"
    if value == "TLSv1.2":
        return f"{C.YELLOW}{value}  ⚠ LEGACY{C.RESET}"
    if value == "TLSv1.3":
        return f"{C.GREEN}{value}{C.RESET}"
    return value


def colorize_cipher(value: Optional[str]) -> str:
    if not USE_COLOUR or not value:
        return format_value(value)
    if any(t in value.upper() for t in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]):
        return f"{C.RED}{C.BOLD}{value}  ✖ WEAK{C.RESET}"
    return value


def colorize_basic_constraints(value: str, rec: "TargetResult") -> str:
    if not USE_COLOUR:
        return value
    if "CA=True" in value and not is_self_signed(rec.subject, rec.issuer):
        return f"{C.RED}{C.BOLD}{value}  ✖ LEAF MARKED AS CA{C.RESET}"
    return value


# ---------------------------------------------------------------------------
# Risk-aware colourisation — DNS fields
# ---------------------------------------------------------------------------

def colorize_ip_consistency(
    ip_fp: Dict[str, str], consistent: Optional[bool]
) -> str:
    """Render the per-IP fingerprint table with mismatch highlighting."""
    if not ip_fp:
        return "<none>"
    first_fp = next((v for v in ip_fp.values() if not v.startswith("<")), None)
    lines = []
    for ip, fp in sorted(ip_fp.items()):
        fp_short = fp[:19] + "…" if len(fp) > 20 else fp
        if fp.startswith("<"):
            tag  = f" {C.DIM}({fp}){C.RESET}" if USE_COLOUR else f" ({fp})"
            line = f"{ip}{tag}"
        elif USE_COLOUR and first_fp and fp != first_fp:
            line = f"{C.RED}{ip}  →  {fp_short}  ✖ DIFFERENT CERT{C.RESET}"
        else:
            line = f"{ip}  →  {fp_short}"
        lines.append(line)
    pad = "                            "  # align under the label column
    return ("\n" + pad).join(lines)


def colorize_consistency_label(consistent: Optional[bool]) -> str:
    if consistent is True:
        return f"{C.GREEN}✔ consistent{C.RESET}" if USE_COLOUR else "consistent"
    if consistent is False:
        return f"{C.RED}{C.BOLD}✖ INCONSISTENT — different certs on different IPs{C.RESET}" if USE_COLOUR else "INCONSISTENT"
    return f"{C.DIM}N/A (single IP){C.RESET}" if USE_COLOUR else "N/A (single IP)"


def colorize_caa(records: Optional[List[str]], domain: str) -> str:
    if records is None:
        return "<not checked>"
    if not records:
        return (f"{C.YELLOW}<none>  ⚠ any CA may issue for {domain}{C.RESET}"
                if USE_COLOUR else "<none>  (no restriction)")
    return ", ".join(records)


def colorize_spf(record: Optional[str]) -> str:
    if record is None:
        return f"{C.YELLOW}<not present>  ⚠ spoofing risk{C.RESET}" if USE_COLOUR else "<not present>"
    v = record.lower()
    if "-all" in v: return f"{C.GREEN}{record}{C.RESET}"   if USE_COLOUR else record
    if "~all" in v: return f"{C.YELLOW}{record}  ⚠ softfail (~all){C.RESET}" if USE_COLOUR else record
    if "?all" in v or "+all" in v:
        return f"{C.RED}{C.BOLD}{record}  ✖ permissive{C.RESET}" if USE_COLOUR else record
    return record


def colorize_dmarc(record: Optional[str]) -> str:
    if record is None:
        return (f"{C.YELLOW}<not present>  ⚠ no enforcement policy{C.RESET}"
                if USE_COLOUR else "<not present>")
    v = record.lower()
    if "p=reject" in v:     return f"{C.GREEN}{record}{C.RESET}"   if USE_COLOUR else record
    if "p=quarantine" in v: return f"{C.YELLOW}{record}  ⚠ quarantine only{C.RESET}" if USE_COLOUR else record
    if "p=none" in v:       return f"{C.RED}{record}  ✖ p=none (no enforcement){C.RESET}" if USE_COLOUR else record
    return record


def colorize_dnssec(value: Optional[bool]) -> str:
    if value is None: return f"{C.DIM}<unknown>{C.RESET}" if USE_COLOUR else "<unknown>"
    if value:         return f"{C.GREEN}✔ enabled (DNSKEY present){C.RESET}" if USE_COLOUR else "enabled"
    return f"{C.YELLOW}✖ not detected  ⚠ cache-poisoning possible{C.RESET}" if USE_COLOUR else "not detected"


def colorize_zone_transfer(value: Optional[str]) -> str:
    if not value: return "<not attempted>"
    if USE_COLOUR and value.startswith("SUCCESS"):
        return f"{C.RED}{C.BOLD}{value}  ✖ ZONE TRANSFER OPEN{C.RESET}"
    if USE_COLOUR and "blocked" in value.lower():
        return f"{C.GREEN}{value}{C.RESET}"
    return value


def colorize_wildcard_dns(value: Optional[bool], domain: str) -> str:
    if value is None: return "<not checked>"
    if value:
        return (f"{C.YELLOW}✔ yes  ⚠ wildcard DNS active for *.{domain}{C.RESET}"
                if USE_COLOUR else f"yes (wildcard DNS active for *.{domain})")
    return f"{C.GREEN}✔ no{C.RESET}" if USE_COLOUR else "no"


# ---------------------------------------------------------------------------
# Risk analysis — certificate
# ---------------------------------------------------------------------------

def analyse_tls_context(rec: TargetResult) -> List[Issue]:
    issues: List[Issue] = []
    if rec.tls_version:
        if rec.tls_version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
            issues.append(Issue("HIGH",  "Weak TLS protocol version",    f"Negotiated: {rec.tls_version}"))
        elif rec.tls_version == "TLSv1.2":
            issues.append(Issue("LOW",   "Legacy TLS version negotiated", f"Negotiated: {rec.tls_version}"))
        else:
            issues.append(Issue("INFO",  "TLS version negotiated",        f"Negotiated: {rec.tls_version}"))
    if rec.cipher:
        if any(t in rec.cipher.upper() for t in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]):
            issues.append(Issue("HIGH",  "Weak cipher suite",  f"Negotiated: {rec.cipher}"))
        else:
            issues.append(Issue("INFO",  "Cipher suite noted", f"Negotiated: {rec.cipher}"))
    return issues


def analyse_internal_leaks(rec: TargetResult) -> List[Issue]:
    issues: List[Issue] = []
    names: List[str] = list(rec.common_names or [])
    for entry in rec.san_entries or []:
        if entry.startswith("DNS:"):
            names.append(entry[4:])
        elif entry.startswith("IP:"):
            ip = entry[3:]
            if is_private_ip_text(ip):
                issues.append(Issue("MEDIUM", "Private IP exposed in certificate SAN", ip))
    hits = sorted({n for n in names if internal_name_indicators(n)})
    if hits:
        issues.append(Issue("MEDIUM", "Internal naming leakage in certificate",
                            ", ".join(hits)))
    return issues


def analyse_leaf_risks(rec: TargetResult, now: datetime) -> List[Issue]:
    issues: List[Issue] = []
    not_after  = parse_dt(rec.not_after)
    not_before = parse_dt(rec.not_before)

    if not_after:
        if not_after < now:
            issues.append(Issue("CRITICAL", "Certificate expired", f"Expired on {rec.not_after}"))
        else:
            days_left = (not_after - now).days
            if days_left <= 14:
                issues.append(Issue("HIGH",   "Certificate expiring very soon",
                                    f"Expires {rec.not_after} ({days_left}d remaining)"))
            elif days_left <= 30:
                issues.append(Issue("MEDIUM", "Certificate expiring soon",
                                    f"Expires {rec.not_after} ({days_left}d remaining)"))

    if not_before and not_before > now:
        issues.append(Issue("HIGH", "Certificate not yet valid", f"Valid from {rec.not_before}"))

    sig = (rec.signature_algorithm or "").lower()
    if "md5" in sig:
        issues.append(Issue("CRITICAL", "Broken signature algorithm", rec.signature_algorithm or "MD5"))
    elif "sha1" in sig and not any(x in sig for x in ("sha256", "sha384", "sha512")):
        issues.append(Issue("HIGH",     "Weak signature algorithm",   rec.signature_algorithm or "SHA1"))

    pk_type = (rec.public_key_type or "").upper()
    pk_size = maybe_int(rec.public_key_size)
    if pk_type.startswith("RSA") and pk_size is not None:
        if pk_size < 2048: issues.append(Issue("HIGH", "Weak RSA key size", f"{pk_size} bits"))
        elif pk_size == 2048: issues.append(Issue("INFO", "RSA key at minimum recommended size", f"{pk_size} bits"))
    if pk_type.startswith("DSA"):
        issues.append(Issue("HIGH", "DSA key algorithm is deprecated", rec.public_key_size or ""))

    if is_self_signed(rec.subject, rec.issuer):
        issues.append(Issue("MEDIUM", "Self-signed certificate", rec.subject or "<unknown>"))

    san_dns      = rec.discovered_san_dns or []
    common_names = rec.common_names       or []
    if not leaf_hostname_match(rec.host, common_names, san_dns):
        issues.append(Issue("HIGH", "Hostname mismatch",
                            f"{rec.host!r} is not covered by CN/SAN"))
    if not san_dns and common_names:
        issues.append(Issue("MEDIUM", "No Subject Alternative Name present",
                            "Certificate relies on CN-only matching (deprecated per RFC 2818)"))

    wildcard_hits = sorted({x for x in san_dns + common_names if x.startswith("*.")})
    if wildcard_hits:
        issues.append(Issue("LOW", "Wildcard certificate", ", ".join(wildcard_hits)))
    if len(san_dns) >= 20:
        issues.append(Issue("LOW", "Broad SAN scope", f"SAN contains {len(san_dns)} DNS entries"))
    if rec.basic_constraints and "CA=True" in rec.basic_constraints:
        issues.append(Issue("HIGH", "Leaf certificate marked as CA", rec.basic_constraints))

    return issues


def analyse_chain(chain_ders: List[bytes]) -> Tuple[List[str], List[Issue]]:
    notes:  List[str]   = []
    issues: List[Issue] = []
    now = datetime.now(timezone.utc)
    chain_records  = [build_cert_record(der) for der in chain_ders]
    chain_subjects = [str(r["subject"]) for r in chain_records]
    notes.append(f"Chain length observed: {len(chain_records)}")
    for i, r in enumerate(chain_records):
        not_after = parse_dt(str(r["not_after"]))
        if not_after and not_after < now:
            label = "Leaf" if i == 0 else "Intermediate"
            issues.append(Issue("HIGH", f"{label} certificate expired in chain",
                                str(r["subject"])))
    if len(chain_records) > 1:
        for i in range(len(chain_records) - 1):
            child, parent = chain_records[i], chain_records[i + 1]
            if child["issuer"] != parent["subject"]:
                issues.append(Issue("MEDIUM", "Chain linkage anomaly",
                                    f"Issuer/subject mismatch between positions {i} and {i + 1}"))
        root = chain_records[-1]
        notes.append("Root appears self-signed (expected)" if root["subject"] == root["issuer"]
                     else "Terminal chain certificate is NOT self-signed (unexpected)")
    return notes + chain_subjects, issues


# ---------------------------------------------------------------------------
# Risk analysis — DNS
# ---------------------------------------------------------------------------

def analyse_dns_findings(rec: TargetResult) -> List[Issue]:
    """Generate pentest findings from the DNS data already stored on rec."""
    issues: List[Issue] = []
    host = rec.host

    # ── Multi-IP cert consistency ──────────────────────────────────────────
    if rec.cert_consistent is False:
        issues.append(Issue(
            "HIGH", "Inconsistent certificates across resolved IPs",
            f"Different TLS leaf certificates served by different IPs for {host}. "
            "Possible load-balancer misconfiguration, certificate management gap, "
            "or BGP/DNS hijack."
        ))
    elif rec.ip_cert_fingerprints and len(rec.ip_cert_fingerprints) > 1:
        issues.append(Issue(
            "INFO", "Multiple IPs serve a consistent certificate",
            f"{len(rec.ip_cert_fingerprints)} IP(s) checked — all returned the same leaf cert."
        ))

    # ── CAA ───────────────────────────────────────────────────────────────
    if rec.dns_caa_records is not None:
        if not rec.dns_caa_records:
            issues.append(Issue(
                "MEDIUM", "No CAA records configured",
                f"Any CA may issue a certificate for {host}. "
                "CAA records (RFC 8659) restrict issuance to approved CAs and are "
                "a defence-in-depth control against mis-issuance."
            ))
        else:
            # issuewild without a matching issue tag
            has_issuewild = any("issuewild" in r.lower() for r in rec.dns_caa_records)
            has_issue     = any("issuewild" not in r.lower() and " issue " in r.lower()
                                for r in rec.dns_caa_records)
            if has_issuewild and not has_issue:
                issues.append(Issue(
                    "LOW", "CAA issuewild present without issue restriction",
                    "issuewild restricts wildcard certs but the 'issue' property is absent, "
                    "allowing any CA to issue non-wildcard certificates."
                ))
            issues.append(Issue("INFO", "CAA records present",
                                "; ".join(rec.dns_caa_records[:5])))

    # ── SPF ───────────────────────────────────────────────────────────────
    if rec.dns_spf_record is None and rec.dns_caa_records is not None:
        # Only flag if we ran the checks
        issues.append(Issue(
            "MEDIUM", "No SPF record found",
            f"No SPF TXT record at {host}. Spoofed e-mail purporting to originate "
            "from this domain may not be rejected by receiving mail servers, "
            "facilitating phishing attacks."
        ))
    elif rec.dns_spf_record:
        spf = rec.dns_spf_record.lower()
        if "+all" in spf or "?all" in spf:
            issues.append(Issue(
                "HIGH", "Permissive SPF policy (+all / ?all)",
                f"SPF effectively authorises any sender: {rec.dns_spf_record}"
            ))
        elif "~all" in spf:
            issues.append(Issue(
                "LOW", "SPF soft-fail (~all)",
                "Receiving servers may accept e-mail from unauthorised senders "
                f"(softfail, not reject): {rec.dns_spf_record}"
            ))
        else:
            issues.append(Issue("INFO", "SPF record present", rec.dns_spf_record))

    # ── DMARC ─────────────────────────────────────────────────────────────
    if rec.dns_dmarc_record is None and rec.dns_caa_records is not None:
        issues.append(Issue(
            "MEDIUM", "No DMARC record found",
            f"No DMARC policy at _dmarc.{host}. Without DMARC, spoofed mail from "
            "this domain will not be quarantined or rejected by aligned receivers."
        ))
    elif rec.dns_dmarc_record:
        dm = rec.dns_dmarc_record.lower()
        if "p=none" in dm:
            issues.append(Issue(
                "MEDIUM", "DMARC policy is p=none (monitor only)",
                f"DMARC is present but not enforcing — spoofed mail is NOT rejected. "
                f"Policy: {rec.dns_dmarc_record}"
            ))
        elif "p=quarantine" in dm:
            issues.append(Issue(
                "LOW", "DMARC policy is quarantine, not reject",
                rec.dns_dmarc_record
            ))
        else:
            issues.append(Issue("INFO", "DMARC record present", rec.dns_dmarc_record))

    # ── DNSSEC ────────────────────────────────────────────────────────────
    if rec.dns_dnssec is False:
        issues.append(Issue(
            "LOW", "DNSSEC not enabled",
            f"No DNSKEY records found for {host}. Without DNSSEC, DNS responses "
            "cannot be cryptographically validated, enabling DNS cache-poisoning."
        ))
    elif rec.dns_dnssec is True:
        issues.append(Issue("INFO", "DNSSEC enabled",
                            f"DNSKEY records present for {host}"))

    # ── Zone transfer ──────────────────────────────────────────────────────
    if rec.dns_zone_transfer and rec.dns_zone_transfer.startswith("SUCCESS"):
        issues.append(Issue(
            "HIGH", "DNS zone transfer permitted (AXFR)",
            f"An unauthenticated AXFR request succeeded: {rec.dns_zone_transfer}. "
            "Full zone contents (all hostnames and IPs) were exposed."
        ))

    # ── Wildcard DNS ───────────────────────────────────────────────────────
    if rec.dns_wildcard_resolves is True:
        issues.append(Issue(
            "LOW", "Wildcard DNS resolution active",
            f"A randomly generated subdomain of {host} resolved to a live IP. "
            "Wildcard DNS expands the attack surface and may assist in phishing "
            "or sub-domain hijacking scenarios."
        ))

    return issues


def sort_issues(issues: List[Issue]) -> List[Issue]:
    return sorted(issues, key=lambda i: (SEV_ORDER.get(i.severity.upper(), 99), i.title))


# ---------------------------------------------------------------------------
# CT lookup
# ---------------------------------------------------------------------------

def ct_lookup(host: str, timeout: float) -> List[str]:
    q   = urllib.parse.quote(host)
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    names: Set[str] = set()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace").strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        for item in data[:100]:
            for field_name in ("common_name", "name_value"):
                value = item.get(field_name)
                if not value:
                    continue
                for entry in str(value).splitlines():
                    entry = entry.strip()
                    if entry:
                        names.add(entry)
    return sorted(names)


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_issues(issues: List[Issue]) -> None:
    if not issues:
        return
    risk_issues = [i for i in issues if i.severity.upper() != "INFO"]
    info_issues = [i for i in issues if i.severity.upper() == "INFO"]
    if risk_issues:
        print(f"\n  {C.BOLD}Findings:{C.RESET}")
        for issue in risk_issues:
            col = sev_colour(issue.severity)
            print(f"    {col}[{issue.severity:<8}]{C.RESET} {issue.title}")
            print(f"             {C.DIM}{issue.detail}{C.RESET}")
    if info_issues:
        print(f"\n  {C.DIM}Info:")
        for issue in info_issues:
            print(f"    [INFO    ]  {issue.title} — {issue.detail}{C.RESET}")


def _count_issues_by_sev(issues: Optional[List[Dict[str, str]]]) -> str:
    if not issues:
        return f"{C.GREEN}No findings{C.RESET}" if USE_COLOUR else "No findings"
    counts: Dict[str, int] = {}
    for iss in issues:
        sev = iss.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            col = sev_colour(sev)
            parts.append(f"{col}{n} {sev}{C.RESET}" if USE_COLOUR else f"{n} {sev}")
    return "  ".join(parts) if parts else (f"{C.GREEN}No findings{C.RESET}" if USE_COLOUR else "No findings")


def selected_fields(args) -> List[Tuple[str, str]]:
    base_all = [
        ("Subject",             "subject"),
        ("Issuer",              "issuer"),
        ("Common Name(s)",      "common_names"),
        ("Alt Name(s)",         "san_entries"),
        ("Version",             "version"),
        ("Serial Number",       "serial_number"),
        ("Valid From",          "not_before"),
        ("Valid To",            "not_after"),
        ("SHA1",                "sha1"),
        ("SHA256",              "sha256"),
        ("Signature Algorithm", "signature_algorithm"),
        ("Sig Algorithm OID",   "signature_algorithm_oid"),
        ("Public Key Type",     "public_key_type"),
        ("Public Key Size",     "public_key_size"),
        ("Basic Constraints",   "basic_constraints"),
        ("Key Usage",           "key_usage"),
        ("Extended Key Usage",  "extended_key_usage"),
    ]
    if args.all:
        return base_all

    chosen: List[Tuple[str, str]] = []
    attrs = [args.names, args.subject, args.issuer, args.validity, args.serial,
             args.fingerprints, args.signature, args.public_key, args.version,
             args.basic_constraints, args.key_usage, args.extended_key_usage]
    if not any(attrs):
        args.names = True

    if args.names:
        chosen += [("Subject", "subject"), ("Common Name(s)", "common_names"),
                   ("Alt Name(s)", "san_entries")]
    if args.subject and ("Subject", "subject") not in chosen:
        chosen.append(("Subject", "subject"))
    if args.issuer:            chosen.append(("Issuer", "issuer"))
    if args.version:           chosen.append(("Version", "version"))
    if args.serial:            chosen.append(("Serial Number", "serial_number"))
    if args.validity:          chosen += [("Valid From", "not_before"), ("Valid To", "not_after")]
    if args.fingerprints:      chosen += [("SHA1", "sha1"), ("SHA256", "sha256")]
    if args.signature:         chosen += [("Signature Algorithm", "signature_algorithm"),
                                           ("Sig Algorithm OID",   "signature_algorithm_oid")]
    if args.public_key:        chosen += [("Public Key Type", "public_key_type"),
                                           ("Public Key Size", "public_key_size")]
    if args.basic_constraints: chosen.append(("Basic Constraints", "basic_constraints"))
    if args.key_usage:         chosen.append(("Key Usage", "key_usage"))
    if args.extended_key_usage: chosen.append(("Extended Key Usage", "extended_key_usage"))

    seen: Set[str] = set()
    deduped: List[Tuple[str, str]] = []
    for label, key in chosen:
        if key not in seen:
            seen.add(key)
            deduped.append((label, key))
    return deduped


def _colorize_field_value(key: str, raw_value, rec: TargetResult) -> str:
    if key == "not_after":          return colorize_not_after(format_value(raw_value))
    if key == "not_before":         return colorize_not_before(format_value(raw_value))
    if key == "san_entries":        return colorize_san_entries(raw_value or [])
    if key == "common_names":       return colorize_common_names(raw_value or [])
    if key == "issuer":             return colorize_issuer(rec.subject, rec.issuer, format_value(raw_value))
    if key == "signature_algorithm": return colorize_signature_algorithm(format_value(raw_value))
    if key == "public_key_size":    return colorize_public_key(rec.public_key_type or "", format_value(raw_value))
    if key == "basic_constraints":  return colorize_basic_constraints(format_value(raw_value), rec)
    return format_value(raw_value)


def print_result(rec: TargetResult, fields: List[Tuple[str, str]], args) -> None:
    width = 72
    print(f"{C.BOLD}{C.BLUE}{'─' * width}{C.RESET}")
    if USE_COLOUR:
        status = f"{C.GREEN}✔ OK{C.RESET}" if rec.success else f"{C.RED}✖ FAILED{C.RESET}"
    else:
        status = "OK" if rec.success else "FAILED"
    print(f"{C.BOLD}  {rec.target:<40}{C.RESET}  {status}")

    if not rec.success:
        print(f"  {C.RED}Error: {rec.error or 'Unknown error'}{C.RESET}")
        print()
        return

    print()

    # ── Certificate fields ─────────────────────────────────────────────────
    for label, key in fields:
        info(label, _colorize_field_value(key, getattr(rec, key), rec))

    # ── IP addresses (always shown) ────────────────────────────────────────
    # Resolve on the fly if --dns / --pentest haven't already populated these
    _ipv4 = rec.resolved_ipv4
    _ipv6 = rec.resolved_ipv6
    if _ipv4 is None and _ipv6 is None:
        _ipv4, _ipv6 = resolve_host_ips(rec.host)
    _all_ips = (_ipv4 or []) + (_ipv6 or [])
    _src     = rec.cert_source_ip or (_all_ips[0] if _all_ips else None)
    if _all_ips:
        _ip_str = ", ".join(_all_ips)
        if _src and _src not in _all_ips:
            _ip_str += f"  {C.DIM}(cert pulled from {_src}){C.RESET}"
        info("IP Address(es)", _ip_str)
    elif _src:
        info("IP Address(es)", _src)

    # ── TLS context ────────────────────────────────────────────────────────
    if args.tls_context or args.pentest:
        section("TLS")
        info("TLS Version",  colorize_tls_version(rec.tls_version))
        info("Cipher Suite", colorize_cipher(rec.cipher))
        info("Cipher Bits",  format_value(rec.cipher_bits))
        info("ALPN",         format_value(rec.alpn))

    # ── Chain ──────────────────────────────────────────────────────────────
    if args.chain or args.pentest:
        section("Certificate Chain")
        info("Chain Length",  format_value(rec.chain_length))
        info("Chain / Notes", format_value(rec.chain_notes))

    # ── SAN expansion ──────────────────────────────────────────────────────
    if args.expand_san or args.pentest:
        info("Discovered SAN DNS", format_value(rec.discovered_san_dns))

    # ── CT ─────────────────────────────────────────────────────────────────
    if args.ct or args.pentest:
        info("CT Names", format_value(rec.ct_names))

    # ── DNS resolution ─────────────────────────────────────────────────────
    if args.dns or args.pentest:
        section("DNS Resolution")
        info("Cert Source IP",  format_value(rec.cert_source_ip))
        info("Resolved IPv4",   format_value(rec.resolved_ipv4))
        info("Resolved IPv6",   format_value(rec.resolved_ipv6))
        info("Nameservers",     format_value(rec.dns_nameservers))
        info("MX Records",      format_value(rec.dns_mx_records))

        if rec.ip_cert_fingerprints:
            print()
            info("Cert Consistency", colorize_consistency_label(rec.cert_consistent))
            info("Per-IP Cert",      colorize_ip_consistency(
                rec.ip_cert_fingerprints, rec.cert_consistent))

    # ── DNS security checks ────────────────────────────────────────────────
    if args.dns_checks or args.pentest:
        section("DNS Security")
        info("CAA Records",    colorize_caa(rec.dns_caa_records, rec.host))
        info("SPF",            colorize_spf(rec.dns_spf_record))
        info("DMARC",          colorize_dmarc(rec.dns_dmarc_record))
        info("DNSSEC",         colorize_dnssec(rec.dns_dnssec))
        info("Zone Transfer",  colorize_zone_transfer(rec.dns_zone_transfer))
        info("Wildcard DNS",   colorize_wildcard_dns(rec.dns_wildcard_resolves, rec.host))

    # ── Findings ───────────────────────────────────────────────────────────
    show_issues = (args.risk or args.internal_leaks or args.tls_context
                   or args.chain or args.pentest or args.dns_checks or args.dns)
    issues = [Issue(**x) for x in (rec.issues or [])]
    risk_issues = [i for i in issues if i.severity.upper() != "INFO"]
    if show_issues:
        if issues:
            render_issues(issues)
        else:
            print(f"\n  {C.GREEN}No pentest findings.{C.RESET}" if USE_COLOUR
                  else "\n  No pentest findings.")
        print(f"\n  {C.DIM}Summary:{C.RESET}  {_count_issues_by_sev(rec.issues)}")
    elif risk_issues:
        print()
        for issue in risk_issues:
            col = sev_colour(issue.severity)
            print(f"  {col}[{issue.severity:<8}]{C.RESET} {issue.title}")
            print(f"           {C.DIM}{issue.detail}{C.RESET}")
    print()


# ---------------------------------------------------------------------------
# Target processing
# ---------------------------------------------------------------------------

def process_target(host: str, port: int, args) -> TargetResult:
    target = f"{host}:{port}"
    try:
        want_chain = args.chain or args.pentest
        fetched    = fetch_endpoint(host, port, args.timeout, want_chain=want_chain)

        leaf = build_cert_record(fetched["leaf_der"])
        rec  = TargetResult(
            target=target, host=host, port=port, success=True, error=None,
            cert_source_ip          = str(fetched["remote_ip"]),
            subject                 = str(leaf["subject"]),
            issuer                  = str(leaf["issuer"]),
            common_names            = list(leaf["common_names"]),
            san_entries             = list(leaf["san_entries"]),
            serial_number           = str(leaf["serial_number"]),
            not_before              = str(leaf["not_before"]),
            not_after               = str(leaf["not_after"]),
            sha1                    = str(leaf["sha1"]),
            sha256                  = str(leaf["sha256"]),
            signature_algorithm     = str(leaf["signature_algorithm"]),
            signature_algorithm_oid = str(leaf["signature_algorithm_oid"]),
            public_key_type         = str(leaf["public_key_type"]),
            public_key_size         = str(leaf["public_key_size"]),
            version                 = str(leaf["version"]),
            basic_constraints       = str(leaf["basic_constraints"]),
            key_usage               = str(leaf["key_usage"]),
            extended_key_usage      = str(leaf["extended_key_usage"]),
            discovered_san_dns      = list(leaf["san_dns"]),
        )

        if args.tls_context or args.pentest:
            rec.tls_version = fetched["tls_version"]
            rec.cipher      = fetched["cipher"]
            rec.cipher_bits = fetched["cipher_bits"]
            rec.alpn        = fetched["alpn"]

        all_issues: List[Issue] = []

        # Always run leaf risk analysis so the summary badge is never misleadingly empty
        all_issues.extend(analyse_leaf_risks(rec, datetime.now(timezone.utc)))
        if args.tls_context or args.pentest:
            all_issues.extend(analyse_tls_context(rec))
        if args.internal_leaks or args.pentest:
            all_issues.extend(analyse_internal_leaks(rec))

        if args.chain or args.pentest:
            try:
                chain_notes, chain_issues = analyse_chain(fetched["chain_ders"])
                rec.chain_subjects = chain_notes
                rec.chain_length   = len(fetched["chain_ders"])
                rec.chain_notes    = chain_notes
                all_issues.extend(chain_issues)
            except Exception as chain_err:
                rec.chain_notes  = [f"<chain analysis failed: {chain_err}>"]
                rec.chain_length = 1

        if args.ct or args.pentest:
            try:
                rec.ct_names = ct_lookup(host, args.timeout)
            except Exception as e:
                rec.ct_names = [f"<CT lookup failed: {e}>"]

        # ── DNS resolution ─────────────────────────────────────────────────
        if args.dns or args.pentest:
            ipv4, ipv6 = resolve_host_ips(host)
            rec.resolved_ipv4 = ipv4
            rec.resolved_ipv6 = ipv6

            dns_timeout = min(args.timeout, 5.0)
            resolver    = _make_resolver(dns_timeout)
            rec.dns_nameservers = query_ns(host, resolver)
            rec.dns_mx_records  = query_mx(host, resolver)

            # Multi-IP cert consistency check
            if ipv4 or ipv6:
                ip_fp, consistent       = check_ip_cert_consistency(
                    host, port, args.timeout, ipv4, ipv6)
                rec.ip_cert_fingerprints = ip_fp
                rec.cert_consistent      = consistent

        # ── Deep DNS security checks ───────────────────────────────────────
        if args.dns_checks or args.pentest:
            if not HAS_DNSPYTHON:
                # Surface this per-target too
                rec.dns_caa_records = []
                rec.dns_zone_transfer = "skipped (dnspython not installed)"
            else:
                dns_timeout = min(args.timeout, 5.0)
                resolver = _make_resolver(dns_timeout)
                rec.dns_caa_records       = query_caa(host, resolver)
                rec.dns_spf_record        = query_spf(host, resolver)
                rec.dns_dmarc_record      = query_dmarc(host, resolver)
                rec.dns_dnssec            = check_dnssec(host, resolver)
                rec.dns_wildcard_resolves = check_wildcard_dns(host, resolver)
                ns_list = rec.dns_nameservers or query_ns(host, resolver)
                rec.dns_zone_transfer = attempt_zone_transfer(host, ns_list, args.timeout)

            all_issues.extend(analyse_dns_findings(rec))

        elif args.dns and rec.ip_cert_fingerprints is not None:
            # --dns only: still emit consistency finding
            all_issues.extend(analyse_dns_findings(rec))

        rec.issues = [asdict(i) for i in sort_issues(all_issues)]
        return rec

    except Exception as e:
        return TargetResult(target=target, host=host, port=port,
                            success=False, error=str(e))


# ---------------------------------------------------------------------------
# Reuse / SAN / diff helpers
# ---------------------------------------------------------------------------

def build_reuse_groups(results: List[TargetResult]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for rec in results:
        if rec.success and rec.sha256:
            groups.setdefault(rec.sha256, []).append(rec.target)
    return groups


def print_reuse_groups(groups: Dict[str, List[str]]) -> None:
    printed = False
    for fp, hosts in sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])):
        if len(hosts) < 2:
            continue
        if not printed:
            print(f"{C.BOLD}{C.MAGENTA}Certificate Reuse Correlation{C.RESET}")
            printed = True
        print(f"  {C.BOLD}Fingerprint:{C.RESET} {fp}")
        for host in sorted(hosts):
            print(f"    - {host}")
        print()
    if not printed:
        good("No certificate reuse observed across scanned targets")
        print()


def print_san_expansion(results: List[TargetResult], original_hosts: Set[str]) -> None:
    discovered: Set[str] = set()
    for rec in results:
        if rec.success:
            for name in rec.discovered_san_dns or []:
                if name.lower() not in original_hosts:
                    discovered.add(name)
    if discovered:
        print(f"{C.BOLD}{C.MAGENTA}SAN Expansion — Hosts Outside Target Set{C.RESET}")
        for name in sorted(discovered):
            flag = (f"  {C.YELLOW}[wildcard]{C.RESET}" if USE_COLOUR else "  [wildcard]") if name.startswith("*.") else ""
            print(f"  - {name}{flag}")
        print()
    else:
        good("No new hosts discovered via SAN expansion")
        print()


def load_baseline(path: str) -> Dict[str, Dict[str, object]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {item["target"]: item for item in data.get("results", []) if "target" in item}


def diff_results(
    current: List[TargetResult], baseline: Dict[str, Dict[str, object]]
) -> List[str]:
    diffs: List[str] = []
    for rec in current:
        prev = baseline.get(rec.target)
        if not prev:
            diffs.append(f"[NEW]     {rec.target} — not present in baseline")
            continue
        if rec.sha256 != prev.get("sha256"):
            diffs.append(f"[CHANGED] {rec.target} — certificate fingerprint changed")
        for added in sorted(set(rec.discovered_san_dns or []) - set(prev.get("discovered_san_dns") or [])):
            diffs.append(f"[CHANGED] {rec.target} — SAN added: {added}")
        for removed in sorted(set(prev.get("discovered_san_dns") or []) - set(rec.discovered_san_dns or [])):
            diffs.append(f"[CHANGED] {rec.target} — SAN removed: {removed}")
        if rec.not_after != prev.get("not_after"):
            diffs.append(f"[CHANGED] {rec.target} — expiry: {prev.get('not_after')} → {rec.not_after}")
        if rec.success != prev.get("success"):
            diffs.append(f"[CHANGED] {rec.target} — success: {prev.get('success')} → {rec.success}")
        # Flag DNS security record changes between runs
        for dns_field, label in [("dns_caa_records", "CAA"), ("dns_spf_record", "SPF"),
                                  ("dns_dmarc_record", "DMARC")]:
            cur_val, prev_val = getattr(rec, dns_field, None), prev.get(dns_field)
            if cur_val != prev_val and cur_val is not None and prev_val is not None:
                diffs.append(f"[CHANGED] {rec.target} — {label} record changed")
        if rec.cert_consistent is False and prev.get("cert_consistent") is not False:
            diffs.append(f"[CHANGED] {rec.target} — cert consistency newly FAILED (different certs per IP)")
    current_targets = {r.target for r in current}
    for old_target in baseline:
        if old_target not in current_targets:
            diffs.append(f"[MISSING] {old_target} — in baseline but not in current run")
    return diffs


def print_diffs(diffs: List[str]) -> None:
    if not diffs:
        good("No differences detected against baseline")
        print()
        return
    print(f"{C.BOLD}{C.MAGENTA}Baseline Diff{C.RESET}")
    for line in diffs:
        if line.startswith("[CHANGED]"):
            print(f"  {C.YELLOW}{line}{C.RESET}" if USE_COLOUR else f"  {line}")
        elif line.startswith("[NEW]"):
            print(f"  {C.CYAN}{line}{C.RESET}"   if USE_COLOUR else f"  {line}")
        elif line.startswith("[MISSING]"):
            print(f"  {C.RED}{line}{C.RESET}"     if USE_COLOUR else f"  {line}")
        else:
            print(f"  {line}")
    print()


# ---------------------------------------------------------------------------
# Aggregate summary
# ---------------------------------------------------------------------------

def print_summary(results: List[TargetResult]) -> None:
    total    = len(results)
    success  = sum(1 for r in results if r.success)
    failures = total - success

    all_counts: Dict[str, int] = {}
    for rec in results:
        for iss in rec.issues or []:
            sev = iss.get("severity", "INFO").upper()
            all_counts[sev] = all_counts.get(sev, 0) + 1

    expired      = sum(1 for r in results if r.success and (_days_to_expiry(r.not_after) or 1) < 0)
    expiring_30  = sum(1 for r in results if r.success and r.not_after
                       and 0 <= (_days_to_expiry(r.not_after) or 999) <= 30)
    inconsistent = sum(1 for r in results if r.cert_consistent is False)

    width = 72
    print(f"{C.BOLD}{C.CYAN}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}  Scan Summary{C.RESET}")
    print(f"{C.BOLD}{'─' * width}{C.RESET}")
    info("Targets scanned",   f"{total}  ({success} OK, {failures} failed)")
    if expired:
        info("Expired certs",   f"{C.RED}{C.BOLD}{expired}{C.RESET}" if USE_COLOUR else str(expired))
    if expiring_30:
        info("Expiring ≤ 30d", f"{C.YELLOW}{expiring_30}{C.RESET}" if USE_COLOUR else str(expiring_30))
    if inconsistent:
        info("IP cert mismatch", f"{C.RED}{C.BOLD}{inconsistent}{C.RESET}" if USE_COLOUR else str(inconsistent))
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = all_counts.get(sev, 0)
        if n:
            col = sev_colour(sev)
            info(f"{sev} findings", f"{col}{n}{C.RESET}" if USE_COLOUR else str(n))
    if not any(all_counts.values()):
        info("Findings", f"{C.GREEN}None{C.RESET}" if USE_COLOUR else "None")
    print()


# ---------------------------------------------------------------------------
# File export helpers
# ---------------------------------------------------------------------------

def write_json(path: str, payload: Dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_csv(path: str, results: List[TargetResult]) -> None:
    fieldnames = [
        "target", "host", "port", "success", "error",
        "subject", "issuer", "common_names", "san_entries",
        "serial_number", "not_before", "not_after", "sha1", "sha256",
        "signature_algorithm", "signature_algorithm_oid",
        "public_key_type", "public_key_size",
        "version", "basic_constraints", "key_usage", "extended_key_usage",
        "tls_version", "cipher", "cipher_bits", "alpn",
        "chain_length", "chain_notes", "discovered_san_dns", "ct_names",
        "cert_source_ip", "resolved_ipv4", "resolved_ipv6",
        "dns_nameservers", "dns_mx_records",
        "ip_cert_fingerprints", "cert_consistent",
        "dns_caa_records", "dns_spf_record", "dns_dmarc_record",
        "dns_dnssec", "dns_zone_transfer", "dns_wildcard_resolves",
        "issues",
    ]
    list_or_dict_fields = {
        "common_names", "san_entries", "chain_notes", "discovered_san_dns",
        "ct_names", "resolved_ipv4", "resolved_ipv6", "dns_nameservers",
        "dns_mx_records", "dns_caa_records", "ip_cert_fingerprints", "issues",
    }
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in results:
            row = {k: getattr(rec, k, None) for k in fieldnames}
            for key in list_or_dict_fields:
                if row.get(key) is not None:
                    row[key] = json.dumps(row[key], ensure_ascii=False)
            writer.writerow(row)


def write_markdown(
    path: str, results: List[TargetResult], reuse_groups: Dict[str, List[str]]
) -> None:
    lines = [
        "# TLS Certificate Recon Summary",
        "",
        "| Target | OK | CN | SANs | Expiry | CAA | SPF | DMARC | IPs | Cert Consistent | Findings |",
        "|---|:---:|---|---:|---|:---:|:---:|:---:|---:|:---:|---:|",
    ]
    for rec in results:
        cn        = ", ".join(rec.common_names or [])
        san_count = len(rec.san_entries or [])
        findings  = len(rec.issues or [])
        ok        = "✔" if rec.success else "✖"
        caa       = ("✔" if rec.dns_caa_records
                     else "✖" if rec.dns_caa_records is not None
                     else "—")
        spf_val   = rec.dns_spf_record or ""
        spf       = ("✔" if spf_val and "-all" in spf_val.lower()
                     else "⚠" if spf_val
                     else "✖" if rec.dns_spf_record is not None
                     else "—")
        dm_val    = rec.dns_dmarc_record or ""
        dmarc     = ("✔" if "p=reject" in dm_val.lower()
                     else "⚠" if dm_val
                     else "✖" if rec.dns_dmarc_record is not None
                     else "—")
        ip_count  = len(rec.ip_cert_fingerprints or {})
        cert_ok   = "✔" if rec.cert_consistent is True else "✖" if rec.cert_consistent is False else "—"
        lines.append(
            f"| {rec.target} | {ok} | {cn} | {san_count}"
            f" | {rec.not_after or ''} | {caa} | {spf} | {dmarc}"
            f" | {ip_count} | {cert_ok} | {findings} |"
        )
    if any(len(v) >= 2 for v in reuse_groups.values()):
        lines += ["", "## Certificate Reuse", ""]
        for fp, hosts in reuse_groups.items():
            if len(hosts) < 2:
                continue
            lines.append(f"- `{fp}`")
            for host in sorted(hosts):
                lines.append(f"  - {host}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def save_evidence(evidence_dir: str, rec: TargetResult, _args) -> None:
    base      = Path(evidence_dir)
    base.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", rec.target)
    out       = base / f"{safe_name}.txt"
    lines = [f"Target                  : {rec.target}",
             f"Success                 : {rec.success}"]
    if rec.error:
        lines.append(f"Error                   : {rec.error}")
    if rec.success:
        cert_fields = [
            ("Subject",             rec.subject),
            ("Issuer",              rec.issuer),
            ("Common Name(s)",      format_value(rec.common_names)),
            ("Alt Name(s)",         format_value(rec.san_entries)),
            ("Serial Number",       rec.serial_number),
            ("Valid From",          rec.not_before),
            ("Valid To",            rec.not_after),
            ("SHA1",                rec.sha1),
            ("SHA256",              rec.sha256),
            ("Signature Algorithm", rec.signature_algorithm),
            ("Public Key Type",     rec.public_key_type),
            ("Public Key Size",     rec.public_key_size),
            ("TLS Version",         rec.tls_version),
            ("Cipher Suite",        rec.cipher),
            ("Cipher Bits",         rec.cipher_bits),
            ("ALPN",                rec.alpn),
            ("Chain Length",        rec.chain_length),
            ("Chain / Notes",       format_value(rec.chain_notes)),
            ("Discovered SAN DNS",  format_value(rec.discovered_san_dns)),
            ("CT Names",            format_value(rec.ct_names)),
        ]
        dns_fields = [
            ("Cert Source IP",      rec.cert_source_ip),
            ("Resolved IPv4",       format_value(rec.resolved_ipv4)),
            ("Resolved IPv6",       format_value(rec.resolved_ipv6)),
            ("Nameservers",         format_value(rec.dns_nameservers)),
            ("MX Records",          format_value(rec.dns_mx_records)),
            ("Cert Consistent",     rec.cert_consistent),
            ("Per-IP Fingerprints", format_value(rec.ip_cert_fingerprints)),
            ("CAA Records",         format_value(rec.dns_caa_records)),
            ("SPF Record",          rec.dns_spf_record),
            ("DMARC Record",        rec.dns_dmarc_record),
            ("DNSSEC",              rec.dns_dnssec),
            ("Zone Transfer",       rec.dns_zone_transfer),
            ("Wildcard DNS",        rec.dns_wildcard_resolves),
        ]
        for label, value in cert_fields:
            lines.append(f"{label:<24}: {format_value(value)}")
        lines += ["", "--- DNS ---"]
        for label, value in dns_fields:
            lines.append(f"{label:<24}: {format_value(value)}")
        lines += ["", "Findings:"]
        for iss in rec.issues or []:
            lines.append(f"  [{iss['severity']:<8}] {iss['title']} — {iss['detail']}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_ports(raw: str) -> List[int]:
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("No ports specified")
    return ports



# ---------------------------------------------------------------------------
# Cipher scanning  (--ciphers)
# ---------------------------------------------------------------------------

# Comprehensive cipher list to probe, organised by security rating.
# OpenSSL cipher-string names used for set_ciphers(); TLS 1.3 suites use
# set_ciphersuites() and are probed separately.
#
# Ratings reflect 2025 industry consensus:
#   NIST SP 800-52r2, Mozilla SSL Config, IETF RFC 8996 (TLS1.0/1.1 deprecation),
#   RFC 9325, Qualys SSL Labs grading criteria, M365 Oct-2025 deprecations.

_CIPHER_RATING: Dict[str, str] = {}

# ── Cipher rating reference: Mozilla SSL Config, NIST SP 800-52r2, ────────────
# ciphersuite.info, Qualys SSL Labs (2025).
#
# BROKEN  — actively exploitable: NULL, EXPORT, RC4, anon DH/ECDH, MD5 MAC
# WEAK    — all CBC-mode suites (BEAST/Lucky13/POODLE derivatives), 3DES
#           (SWEET32), RSA key exchange (no forward secrecy), IDEA, RC2,
#           DSS, SEED, CAMELLIA-CBC, SHA-1 MAC suites, ADH.
#           Qualys labels these "WEAK" regardless of key exchange algorithm.
# STRONG  — AEAD (GCM / ChaCha20-Poly1305) + forward secrecy (ECDHE / DHE)
#           Mozilla "Modern" and "Intermediate" recommended list.

# BROKEN — never acceptable under any circumstances
_BROKEN_CIPHERS = [
    # NULL encryption
    "NULL-MD5", "NULL-SHA", "NULL-SHA256",
    "ECDHE-RSA-NULL-SHA", "ECDHE-ECDSA-NULL-SHA",
    # EXPORT / 40-bit ciphers
    "EXP-RC4-MD5", "EXP-RC4-SHA", "EXP-DES-CBC-SHA",
    "EXP-EDH-RSA-DES-CBC-SHA", "EXP-EDH-DSS-DES-CBC-SHA",
    "EXP-ADH-RC4-MD5", "EXP-ADH-DES-CBC-SHA",
    "EXP-KRB5-DES-CBC-SHA", "EXP-KRB5-RC4-SHA",
    "EXP-KRB5-DES-CBC-MD5", "EXP-KRB5-RC4-MD5",
    # RC4 — RFC 7465 prohibits
    "RC4-MD5", "RC4-SHA",
    "ECDHE-RSA-RC4-SHA", "ECDHE-ECDSA-RC4-SHA",
    "ADH-RC4-MD5",
    "KRB5-RC4-SHA", "KRB5-RC4-MD5",
    # Anonymous DH/ECDH (no authentication)
    "ADH-AES128-SHA", "ADH-AES256-SHA",
    "ADH-AES128-SHA256", "ADH-AES256-SHA256",
    "ADH-AES128-GCM-SHA256", "ADH-AES256-GCM-SHA384",
    "ADH-CAMELLIA128-SHA", "ADH-CAMELLIA256-SHA",
    "ADH-DES-CBC3-SHA", "ADH-DES-CBC-SHA",
    "AECDH-AES128-SHA", "AECDH-AES256-SHA",
    "AECDH-NULL-SHA", "AECDH-RC4-SHA",
    "AECDH-DES-CBC3-SHA",
    # MD5-MAC (collision-broken)
    "RC2-CBC-MD5",
    # OpenSSL alias strings
    "aNULL", "eNULL",
]
for _c in _BROKEN_CIPHERS:
    _CIPHER_RATING[_c] = "BROKEN"

# WEAK — includes ALL CBC suites (with or without FS), 3DES, RSA key exchange,
#        IDEA, SEED, CAMELLIA-CBC, DSS, SHA-1 MAC (aligns with Qualys "WEAK")
_WEAK_CIPHERS = [
    # ── 3DES (SWEET32 — 64-bit block, birthday attack at ~32GB) ──────────────
    "DES-CBC3-SHA",
    "EDH-RSA-DES-CBC3-SHA",   "EDH-DSS-DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA", "ECDHE-ECDSA-DES-CBC3-SHA",
    "KRB5-DES-CBC3-SHA",      "KRB5-DES-CBC3-MD5",
    # ── DES-56 / DES-40 ──────────────────────────────────────────────────────
    "DES-CBC-SHA", "DES-CBC-MD5",
    # ── IDEA ─────────────────────────────────────────────────────────────────
    "IDEA-CBC-SHA",
    # ── SEED (Korean standard, not widely trusted) ────────────────────────────
    "SEED-SHA",
    # ── RSA key exchange — no forward secrecy ────────────────────────────────
    # CBC variants
    "AES128-SHA",     "AES256-SHA",
    "AES128-SHA256",  "AES256-SHA256",
    "CAMELLIA128-SHA","CAMELLIA256-SHA",
    "CAMELLIA128-SHA256","CAMELLIA256-SHA256",
    # GCM variants (AEAD but no FS — still WEAK per Qualys)
    "AES128-GCM-SHA256", "AES256-GCM-SHA384",
    # CCM variants
    "AES128-CCM", "AES256-CCM", "AES128-CCM8", "AES256-CCM8",
    # ── DSS key exchange — DSA deprecated ────────────────────────────────────
    "DHE-DSS-AES128-SHA",    "DHE-DSS-AES256-SHA",
    "DHE-DSS-AES128-SHA256", "DHE-DSS-AES256-SHA256",
    "DHE-DSS-CAMELLIA128-SHA","DHE-DSS-CAMELLIA256-SHA",
    "DHE-DSS-CAMELLIA128-SHA256","DHE-DSS-CAMELLIA256-SHA256",
    "DHE-DSS-SEED-SHA",
    # ── ECDHE + CBC — forward secret but CBC mode (WEAK per Qualys/Mozilla) ──
    "ECDHE-RSA-AES128-SHA",    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",  "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256","ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-CAMELLIA128-SHA256","ECDHE-RSA-CAMELLIA256-SHA384",
    "ECDHE-ECDSA-CAMELLIA128-SHA256","ECDHE-ECDSA-CAMELLIA256-SHA384",
    # ── DHE + CBC — forward secret but CBC mode (WEAK per Qualys/Mozilla) ────
    "DHE-RSA-AES128-SHA",    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256", "DHE-RSA-AES256-SHA256",
    "DHE-RSA-CAMELLIA128-SHA","DHE-RSA-CAMELLIA256-SHA",
    "DHE-RSA-CAMELLIA128-SHA256","DHE-RSA-CAMELLIA256-SHA256",
    "DHE-RSA-SEED-SHA",
    # ── PSK without FS ───────────────────────────────────────────────────────
    "PSK-AES128-CBC-SHA",  "PSK-AES256-CBC-SHA",
    "PSK-3DES-EDE-CBC-SHA","PSK-RC4-SHA",
]
for _c in _WEAK_CIPHERS:
    _CIPHER_RATING[_c] = "WEAK"

# STRONG — AEAD + forward secrecy only (Mozilla Modern + Intermediate)
_STRONG_CIPHERS = [
    # ECDHE + AESGCM (recommended by Mozilla, NIST, Qualys no-badge)
    "ECDHE-RSA-AES128-GCM-SHA256",    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",  "ECDHE-ECDSA-AES256-GCM-SHA384",
    # ECDHE + ChaCha20-Poly1305
    "ECDHE-RSA-CHACHA20-POLY1305",    "ECDHE-ECDSA-CHACHA20-POLY1305",
    # DHE + AESGCM
    "DHE-RSA-AES128-GCM-SHA256",      "DHE-RSA-AES256-GCM-SHA384",
    # DHE + ChaCha20-Poly1305
    "DHE-RSA-CHACHA20-POLY1305",
    # ECDHE + CAMELLIA-GCM (STRONG — AEAD + FS, though rarely deployed)
    "ECDHE-RSA-CAMELLIA128-GCM-SHA256","ECDHE-RSA-CAMELLIA256-GCM-SHA384",
    "ECDHE-ECDSA-CAMELLIA128-GCM-SHA256","ECDHE-ECDSA-CAMELLIA256-GCM-SHA384",
    # DHE + AESGCM DSS variants
    "DHE-DSS-AES128-GCM-SHA256",      "DHE-DSS-AES256-GCM-SHA384",
]
for _c in _STRONG_CIPHERS:
    _CIPHER_RATING[_c] = "STRONG"

# TLS 1.3 suites — always STRONG (negotiated separately by OpenSSL)
# Only the 3 universally-deployed suites are included. TLS_AES_128_CCM_* are
# in the RFC but absent from virtually all real-world servers and cause most
# OpenSSL builds to abort the handshake mid-iteration, stopping enumeration early.
_TLS13_SUITES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]

# Ordered probe list for TLS ≤ 1.2 — weakest first so we report dangerously fast
_PROBE_CIPHERS = (
    _BROKEN_CIPHERS + _WEAK_CIPHERS + _STRONG_CIPHERS
)

# TLS version constants for min/max_version on PROTOCOL_TLS_CLIENT
_MINMAX_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
]


@dataclass
class CipherResult:
    tls_version: str
    cipher:      str
    rating:      str       # BROKEN / WEAK / STRONG
    bits:        Optional[int] = None


def _probe_cipher(
    host: str, port: int, tls_ver_label: str,
    tls_version: "ssl.TLSVersion", cipher: str, timeout: float
) -> Optional[CipherResult]:
    """Attempt a handshake restricted to one TLS version + one cipher.
    Returns CipherResult on success, None on failure/rejection."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        ctx.set_ciphers(cipher)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                negotiated = tls.cipher()
                bits       = negotiated[2] if negotiated else None
                rating     = _CIPHER_RATING.get(cipher, "UNKNOWN")
                return CipherResult(tls_ver_label, cipher, rating, bits)
    except (ssl.SSLError, socket.timeout, OSError):
        # ssl.SSLError  — server rejected this cipher/version (expected)
        # socket.timeout / OSError — network failure (expected)
        return None


# TLS 1.3 cipher suite wire IDs (RFC 8446 §B.4)
_TLS13_SUITE_IDS: Dict[str, bytes] = {
    "TLS_AES_128_GCM_SHA256":       bytes([0x13, 0x01]),
    "TLS_AES_256_GCM_SHA384":       bytes([0x13, 0x02]),
    "TLS_CHACHA20_POLY1305_SHA256":  bytes([0x13, 0x03]),
}

# Static x25519 public key — used for key_share in our probe ClientHellos.
# We never complete the handshake so the value just needs to be well-formed.
_X25519_PUB = bytes.fromhex(
    "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615"
)


def _build_tls13_client_hello(host: str, suite_id: bytes) -> bytes:
    """Build a minimal but spec-compliant TLS 1.3 ClientHello for one cipher.
    The record looks like TLS 1.2 on the wire for middlebox compatibility."""
    # Probe with fixed random/session so analysis is deterministic
    random_bytes = os.urandom(32)
    session_id   = os.urandom(32)    # non-empty: triggers middlebox-compat mode

    # Extensions
    # supported_versions: TLS 1.3 only
    ext_sv = (b"\x00\x2b\x00\x03\x02\x03\x04")

    # supported_groups: x25519, secp256r1, secp384r1
    groups = bytes([0x00,0x1d, 0x00,0x17, 0x00,0x18])
    ext_sg = b"\x00\x0a" + struct.pack(">H", len(groups)+2) + struct.pack(">H", len(groups)) + groups

    # key_share: x25519
    ks_entry = bytes([0x00,0x1d]) + struct.pack(">H", len(_X25519_PUB)) + _X25519_PUB
    ks_list  = struct.pack(">H", len(ks_entry)) + ks_entry
    ext_ks   = b"\x00\x33" + struct.pack(">H", len(ks_list)) + ks_list

    # signature_algorithms
    sig_algs = bytes([
        0x04,0x03,  # ecdsa_secp256r1_sha256
        0x08,0x04,  # rsa_pss_rsae_sha256
        0x04,0x01,  # rsa_pkcs1_sha256
        0x05,0x03,  # ecdsa_secp384r1_sha384
        0x08,0x05,  # rsa_pss_rsae_sha384
        0x05,0x01,  # rsa_pkcs1_sha384
        0x08,0x06,  # rsa_pss_rsae_sha512
        0x06,0x01,  # rsa_pkcs1_sha512
    ])
    ext_sa = b"\x00\x0d" + struct.pack(">H", len(sig_algs)+2) + struct.pack(">H", len(sig_algs)) + sig_algs

    # SNI
    sni_name  = host.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(sni_name)) + sni_name
    sni_list  = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_sni   = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list

    extensions = ext_sni + ext_sv + ext_sg + ext_ks + ext_sa
    ext_block  = struct.pack(">H", len(extensions)) + extensions

    # cipher_suites: target suite + SCSV
    ciphers = suite_id + b"\x00\xff"

    hello  = b"\x03\x03" + random_bytes
    hello += bytes([len(session_id)]) + session_id
    hello += struct.pack(">H", len(ciphers)) + ciphers
    hello += b"\x01\x00"   # compression: null only
    hello += ext_block

    hs  = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    return rec


def _raw_tls13_probe(host: str, port: int, suite_name: str, timeout: float) -> Optional[CipherResult]:
    """Send a raw TLS 1.3 ClientHello with a single cipher suite.
    Works entirely at the socket level — zero OpenSSL dependency.
    Returns CipherResult if the server responds with ServerHello, None on rejection."""
    suite_id = _TLS13_SUITE_IDS.get(suite_name)
    if suite_id is None:
        return None
    record = _build_tls13_client_hello(host, suite_id)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record)
            hdr = sock.recv(5)
            if len(hdr) < 5:
                return None
            if hdr[0] == 0x15:           # Alert — suite rejected
                return None
            if hdr[0] != 0x16:           # Not a handshake record
                return None
            # Read enough of the handshake to confirm ServerHello (type 0x02)
            data = b""
            while len(data) < 4:
                chunk = sock.recv(4 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) >= 1 and data[0] == 0x02:
                return CipherResult("TLSv1.3", suite_name, "STRONG", None)
            return None
    except (socket.timeout, OSError):
        return None


def _tls13_baseline(host: str, port: int, timeout: float) -> bool:
    """Return True if TLS 1.3 is accepted at all.
    Uses the same raw probe as per-suite enumeration for consistency."""
    return _raw_tls13_probe(host, port, "TLS_AES_256_GCM_SHA384", timeout) is not None




def _raw_sslv2_probe(host: str, port: int, timeout: float) -> bool:
    """Send a raw SSLv2 ClientHello and return True if the server responds
    with an SSLv2 ServerHello.  Works regardless of OS OpenSSL build."""
    # Cipher specs: 3 bytes each (the common SSLv2 suite IDs)
    cipher_specs = bytes([
        0x07, 0x00, 0xC0,  # SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        0x05, 0x00, 0x80,  # SSL_CK_IDEA_128_CBC_WITH_MD5
        0x03, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_WITH_MD5
        0x01, 0x00, 0x80,  # SSL_CK_RC4_128_WITH_MD5
        0x06, 0x00, 0x40,  # SSL_CK_DES_64_CBC_WITH_MD5
        0x04, 0x00, 0x80,  # SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        0x02, 0x00, 0x80,  # SSL_CK_RC4_128_EXPORT40_WITH_MD5
    ])
    challenge = os.urandom(16)
    body  = b"\x01"                                   # MSG-CLIENT-HELLO
    body += b"\x00\x02"                              # version: SSLv2
    body += struct.pack(">H", len(cipher_specs))
    body += b"\x00\x00"                              # session ID length: 0
    body += struct.pack(">H", len(challenge))
    body += cipher_specs + challenge
    # 2-byte record header, high bit set
    packet = struct.pack(">H", 0x8000 | len(body)) + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(packet)
            hdr = sock.recv(3)
            if len(hdr) < 3:
                return False
            # SSLv2 ServerHello: high bit set in first byte, second byte is 0x04
            if (hdr[0] & 0x80) and hdr[2] == 0x04:
                return True
            return False
    except (socket.timeout, OSError):
        return False


def _raw_sslv3_probe(host: str, port: int, timeout: float) -> bool:
    """Send a raw SSLv3 ClientHello and return True if the server responds
    with an SSLv3 ServerHello.  Works regardless of OS OpenSSL build."""
    random_bytes = os.urandom(32)
    cipher_suites = bytes([
        0x00, 0x35,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x2F,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x0A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x05,  # TLS_RSA_WITH_RC4_128_SHA
        0x00, 0x04,  # TLS_RSA_WITH_RC4_128_MD5
        0x00, 0xFF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ])
    # ClientHello body
    hello  = b"\x03\x00"                             # version: SSLv3
    hello += random_bytes
    hello += b"\x00"                                  # session ID length: 0
    hello += struct.pack(">H", len(cipher_suites)) + cipher_suites
    hello += b"\x01\x00"                             # compression: null only
    # Handshake record: type 0x01 (ClientHello) + 3-byte length
    handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    # TLS record: content type 0x16 (Handshake), version 0x0300 (SSLv3)
    record = b"\x16\x03\x00" + struct.pack(">H", len(handshake)) + handshake
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record)
            hdr = sock.recv(5)
            if len(hdr) < 5:
                return False
            # ServerHello: record type 0x16, version 0x03 0x00 = SSLv3
            if hdr[0] == 0x16 and hdr[1] == 0x03 and hdr[2] == 0x00:
                return True
            return False
    except (socket.timeout, OSError):
        return False


# ---------------------------------------------------------------------------
# Raw SSLv2 / SSLv3 cipher enumeration tables
# ---------------------------------------------------------------------------

# SSLv2 cipher IDs (3 bytes) → (name, bits)
_SSLv2_CIPHERS = [
    (bytes([0x07, 0x00, 0xC0]), "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",       112),
    (bytes([0x05, 0x00, 0x80]), "SSL_CK_IDEA_128_CBC_WITH_MD5",            128),
    (bytes([0x03, 0x00, 0x80]), "SSL_CK_RC2_128_CBC_WITH_MD5",             128),
    (bytes([0x01, 0x00, 0x80]), "SSL_CK_RC4_128_WITH_MD5",                 128),
    (bytes([0x06, 0x00, 0x40]), "SSL_CK_DES_64_CBC_WITH_MD5",               56),
    (bytes([0x04, 0x00, 0x80]), "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",     40),
    (bytes([0x02, 0x00, 0x80]), "SSL_CK_RC4_128_EXPORT40_WITH_MD5",         40),
]

# SSLv3/TLS cipher IDs (2 bytes) → (openssl-name, bits)
# Covers all suites a legacy SSLv3 server might offer
_SSLv3_CIPHERS = [
    (bytes([0x00, 0x04]), "RC4-MD5",                   128),
    (bytes([0x00, 0x05]), "RC4-SHA",                   128),
    (bytes([0x00, 0x0A]), "DES-CBC3-SHA",               112),
    (bytes([0x00, 0x2F]), "AES128-SHA",                 128),
    (bytes([0x00, 0x35]), "AES256-SHA",                 256),
    (bytes([0x00, 0x3C]), "AES128-SHA256",              128),
    (bytes([0x00, 0x3D]), "AES256-SHA256",              256),
    (bytes([0x00, 0x9C]), "AES128-GCM-SHA256",          128),
    (bytes([0x00, 0x9D]), "AES256-GCM-SHA384",          256),
    (bytes([0xC0, 0x09]), "ECDHE-ECDSA-AES128-SHA",    128),
    (bytes([0xC0, 0x0A]), "ECDHE-ECDSA-AES256-SHA",    256),
    (bytes([0xC0, 0x13]), "ECDHE-RSA-AES128-SHA",      128),
    (bytes([0xC0, 0x14]), "ECDHE-RSA-AES256-SHA",      256),
    (bytes([0xC0, 0x23]), "ECDHE-ECDSA-AES128-SHA256", 128),
    (bytes([0xC0, 0x24]), "ECDHE-ECDSA-AES256-SHA384", 256),
    (bytes([0xC0, 0x27]), "ECDHE-RSA-AES128-SHA256",   128),
    (bytes([0xC0, 0x28]), "ECDHE-RSA-AES256-SHA384",   256),
    (bytes([0xC0, 0x2B]), "ECDHE-ECDSA-AES128-GCM-SHA256", 128),
    (bytes([0xC0, 0x2C]), "ECDHE-ECDSA-AES256-GCM-SHA384", 256),
    (bytes([0xC0, 0x2F]), "ECDHE-RSA-AES128-GCM-SHA256",   128),
    (bytes([0xC0, 0x30]), "ECDHE-RSA-AES256-GCM-SHA384",   256),
    (bytes([0x00, 0x33]), "DHE-RSA-AES128-SHA",        128),
    (bytes([0x00, 0x39]), "DHE-RSA-AES256-SHA",        256),
    (bytes([0x00, 0x67]), "DHE-RSA-AES128-SHA256",     128),
    (bytes([0x00, 0x6B]), "DHE-RSA-AES256-SHA256",     256),
    (bytes([0x00, 0x09]), "DES-CBC-SHA",                56),
    (bytes([0x00, 0x06]), "EXP-RC2-CBC-MD5",            40),
    (bytes([0x00, 0x03]), "EXP-RC4-MD5",                40),
    (bytes([0xCC, 0xA8]), "ECDHE-RSA-CHACHA20-POLY1305",   256),
    (bytes([0xCC, 0xA9]), "ECDHE-ECDSA-CHACHA20-POLY1305", 256),
]


def _raw_sslv2_probe_cipher(
    host: str, port: int, cipher_bytes: bytes, timeout: float
) -> bool:
    """Send an SSLv2 ClientHello with ONE cipher and return True if accepted."""
    challenge = os.urandom(16)
    body  = b"\x01"                          # MSG-CLIENT-HELLO
    body += b"\x00\x02"                     # version: SSLv2
    body += struct.pack(">H", len(cipher_bytes))
    body += b"\x00\x00"                     # session-id length
    body += struct.pack(">H", len(challenge))
    body += cipher_bytes + challenge
    packet = struct.pack(">H", 0x8000 | len(body)) + body
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(packet)
            hdr = sock.recv(2)
            if len(hdr) < 2 or not (hdr[0] & 0x80):
                return False
            msg_len = ((hdr[0] & 0x7F) << 8) | hdr[1]
            data = b""
            while len(data) < min(msg_len, 32):
                chunk = sock.recv(min(msg_len, 32) - len(data))
                if not chunk:
                    break
                data += chunk
            return len(data) >= 1 and data[0] == 0x04  # SERVER-HELLO
    except (socket.timeout, OSError):
        return False


def _raw_sslv3_probe_cipher(
    host: str, port: int, cipher_bytes: bytes, timeout: float
) -> bool:
    """Send a raw SSLv3 ClientHello with ONE cipher and return True if server
    responds with ServerHello (not Alert).  SCSV added to avoid SCSV rejection."""
    random_bytes = os.urandom(32)
    # Offer target cipher + TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    suites = cipher_bytes + b"\x00\xff"
    hello  = b"\x03\x00"                   # version: SSLv3
    hello += random_bytes
    hello += b"\x00"                         # session-id length
    hello += struct.pack(">H", len(suites)) + suites
    hello += b"\x01\x00"                   # compression: null
    handshake = b"\x01" + struct.pack(">I", len(hello))[1:] + hello
    record    = b"\x16\x03\x00" + struct.pack(">H", len(handshake)) + handshake
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record)
            hdr = sock.recv(5)
            if len(hdr) < 5:
                return False
            if hdr[0] == 0x15:               # Alert — rejected
                return False
            if hdr[0] != 0x16:               # Not a handshake record
                return False
            rec_len = struct.unpack(">H", hdr[3:5])[0]
            data = b""
            while len(data) < min(rec_len, 64):
                chunk = sock.recv(min(rec_len, 64) - len(data))
                if not chunk:
                    break
                data += chunk
            return len(data) >= 1 and data[0] == 0x02  # ServerHello
    except (socket.timeout, OSError):
        return False

def scan_ciphers(
    host: str, port: int, timeout: float, threads: int
) -> Dict[str, List[CipherResult]]:
    """Run the full cipher probe across all TLS versions.
    Returns dict: tls_version_label -> sorted list of accepted CipherResults."""
    accepted: List[CipherResult] = []

    probe_timeout = min(timeout, 4.0)

    # ── TLS 1.3 — raw ClientHello per suite, fully parallel ─────────────────
    # Each suite is probed by sending a hand-crafted TLS 1.3 ClientHello over a
    # raw TCP socket — zero OpenSSL dependency, one independent connection per suite.
    if _tls13_baseline(host, port, probe_timeout):
        with ThreadPoolExecutor(max_workers=len(_TLS13_SUITES)) as ex:
            tls13_futs = {
                ex.submit(_raw_tls13_probe, host, port, s, probe_timeout): s
                for s in _TLS13_SUITES
            }
            tls13_results = []
            for f in as_completed(tls13_futs):
                r = f.result()
                if r:
                    tls13_results.append(r)
        # Sort into canonical IANA display order
        _order = {s: i for i, s in enumerate(_TLS13_SUITES)}
        tls13_results.sort(key=lambda x: _order.get(x.cipher, 99))
        accepted.extend(tls13_results)

    # ── SSLv2 / SSLv3 — raw per-cipher probing, no OpenSSL dependency ──────────
    # SSLv2 — raw per-cipher probing (no OpenSSL dependency)
    sslv2_supported = _raw_sslv2_probe(host, port, probe_timeout)
    if sslv2_supported:
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as ex:
            sslv2_futs = {
                ex.submit(_raw_sslv2_probe_cipher, host, port, cb, probe_timeout): (name, bits)
                for cb, name, bits in _SSLv2_CIPHERS
            }
            for f in as_completed(sslv2_futs):
                name, bits = sslv2_futs[f]
                if f.result():
                    accepted.append(CipherResult("SSLv2", name, "BROKEN", bits))

    # SSLv3 — raw per-cipher probing (no OpenSSL dependency)
    sslv3_supported = _raw_sslv3_probe(host, port, probe_timeout)
    if sslv3_supported:
        with ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
            sslv3_futs = {
                ex.submit(_raw_sslv3_probe_cipher, host, port, cb, probe_timeout): (name, bits)
                for cb, name, bits in _SSLv3_CIPHERS
            }
            for f in as_completed(sslv3_futs):
                name, bits = sslv3_futs[f]
                if f.result():
                    rating = _CIPHER_RATING.get(name, "BROKEN")
                    accepted.append(CipherResult("SSLv3", name, rating, bits))

    # TLS 1.0 – 1.2 cipher probes
    with ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
        futs = []
        for ver_label, tls_ver in _MINMAX_VERSIONS:
            if tls_ver is None or ver_label == "TLSv1.3":
                continue
            for cipher in _PROBE_CIPHERS:
                futs.append(ex.submit(
                    _probe_cipher, host, port, ver_label, tls_ver, cipher, probe_timeout
                ))
        for f in as_completed(futs):
            r = f.result()
            if r:
                accepted.append(r)

    # Deduplicate (same cipher accepted on multiple versions is tracked per-version)
    seen = set()
    unique = []
    for r in accepted:
        key = (r.tls_version, r.cipher)
        if key not in seen:
            seen.add(key)
            unique.append(r)

    # Group by version
    _RATING_ORDER = {"BROKEN": 0, "WEAK": 1, "STRONG": 2, "UNKNOWN": 3}
    _VER_ORDER    = {"SSLv2": 0, "SSLv3": 1, "TLSv1.0": 2, "TLSv1.1": 3,
                     "TLSv1.2": 4, "TLSv1.3": 5}
    grouped: Dict[str, List[CipherResult]] = {}
    for r in unique:
        grouped.setdefault(r.tls_version, []).append(r)
    for ver in grouped:
        grouped[ver].sort(key=lambda x: (_RATING_ORDER.get(x.rating, 9), x.cipher))

    return dict(sorted(grouped.items(), key=lambda kv: _VER_ORDER.get(kv[0], 9)))


def _cipher_rating_colour(rating: str) -> str:
    if not USE_COLOUR:
        return ""
    return {
        "BROKEN": C.RED + C.BOLD,
        "WEAK":   C.RED,
        "STRONG": C.GREEN,
    }.get(rating, C.DIM)


def _ver_rating_colour(ver: str) -> str:
    if not USE_COLOUR:
        return ""
    if ver in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
        return C.RED + C.BOLD
    if ver == "TLSv1.2":
        return C.YELLOW
    if ver == "TLSv1.3":
        return C.GREEN
    return ""


def print_cipher_report(host: str, port: int, grouped: Dict[str, List[CipherResult]]) -> None:
    width = 72
    print(f"{C.BOLD}{C.BLUE}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}  Cipher Scan: {host}:{port}{C.RESET}")
    print()

    if not grouped:
        print(f"  {C.DIM}No cipher combinations accepted (or all probes timed out).{C.RESET}")
        print()
        return

    # ── Protocol support summary ───────────────────────────────────────────
    # All versions in display order, newest first
    _ALL_VERSIONS = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"]
    _VER_STATUS_COLOUR = {
        # colour when ACCEPTED
        "TLSv1.3": C.GREEN,
        "TLSv1.2": C.YELLOW,
        "TLSv1.1": C.RED,
        "TLSv1.0": C.RED,
        "SSLv3":   C.RED + C.BOLD,
        "SSLv2":   C.RED + C.BOLD,
    }
    # colour when NOT accepted — TLS1.3 missing is a concern; deprecated missing is good
    _VER_NOTACCEPTED_COLOUR = {
        "TLSv1.3": C.YELLOW,   # should be supported — orange warning
        "TLSv1.2": C.GREEN,    # fine if 1.3 is present; handled by findings
        "TLSv1.1": C.GREEN,
        "TLSv1.0": C.GREEN,
        "SSLv3":   C.GREEN,
        "SSLv2":   C.GREEN,
    }
    print(f"  {C.BOLD}Protocol Support{C.RESET}")
    for ver in _ALL_VERSIONS:
        if ver in grouped:
            col    = _VER_STATUS_COLOUR.get(ver, "")
            status = f"{col}Accepted{C.RESET}" if USE_COLOUR else "Accepted"
        else:
            col    = _VER_NOTACCEPTED_COLOUR.get(ver, C.GREEN)
            status = f"{col}Not accepted{C.RESET}" if USE_COLOUR else "Not accepted"
        print(f"    {C.BOLD}{ver:<10}{C.RESET}  {status}")
    print()

    # Per-version breakdown
    _VER_NOTES = {
        "SSLv2":   "DEPRECATED — protocol broken, RFC 6176",
        "SSLv3":   "DEPRECATED — POODLE attack, RFC 7568",
        "TLSv1.0": "DEPRECATED — BEAST/POODLE, RFC 8996",
        "TLSv1.1": "DEPRECATED — RFC 8996",
        "TLSv1.2": "DEPRECATED for CBC suites — only AEAD+FS suites are acceptable",
        "TLSv1.3": "CURRENT — AEAD only, forward secrecy mandatory",
    }
    _RATING_BADGE = {
        "BROKEN": " BROKEN ",
        "WEAK":   "  WEAK  ",
        "STRONG": " STRONG ",
    }

    for ver, ciphers in grouped.items():
        vc  = _ver_rating_colour(ver)
        note = _VER_NOTES.get(ver, "")
        print(f"  {vc}{C.BOLD}{ver}{C.RESET}  {C.DIM}{note}{C.RESET}")
        for cr in ciphers:
            rc    = _cipher_rating_colour(cr.rating)
            badge = _RATING_BADGE.get(cr.rating, f"[{cr.rating}]")
            bits_str = f"  {cr.bits}-bit" if cr.bits else ""
            print(f"    {rc}[{badge}]{C.RESET}  {cr.cipher}{C.DIM}{bits_str}{C.RESET}")
        print()

    # Summary findings
    findings = []
    if any(v in grouped for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")):
        deprecated_vers = [v for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if v in grouped]
        findings.append(("HIGH", "Deprecated TLS protocol version(s) accepted",
                         ", ".join(deprecated_vers)))
    if "TLSv1.2" in grouped and not any(
        r.rating == "STRONG" for r in grouped.get("TLSv1.2", [])
    ):
        findings.append(("MEDIUM", "TLSv1.2 accepts no STRONG cipher suites",
                         "Server only offers CBC-mode or non-FS suites on TLSv1.2 — no AEAD+FS suite accepted"))
    for ver, clist in grouped.items():
        broken = [r.cipher for r in clist if r.rating == "BROKEN"]
        if broken:
            findings.append(("CRITICAL", f"Broken cipher suite(s) accepted on {ver}",
                             ", ".join(broken[:5])))
        weak = [r.cipher for r in clist if r.rating == "WEAK"]
        if weak:
            findings.append(("HIGH", f"Weak cipher suite(s) accepted on {ver}",
                             ", ".join(weak[:5])))
    if not grouped.get("TLSv1.3"):
        findings.append(("LOW", "TLSv1.3 not supported",
                         "Server does not accept TLS 1.3 connections"))

    if findings:
        print(f"  {C.BOLD}Cipher Findings:{C.RESET}")
        for sev, title, detail in sorted(findings, key=lambda x: SEV_ORDER.get(x[0], 9)):
            col = sev_colour(sev)
            print(f"    {col}[{sev:<8}]{C.RESET} {title}")
            print(f"             {C.DIM}{detail}{C.RESET}")
        print()

def print_coloured_help() -> None:
    """Print a rich, colour-coded help screen and exit."""
    W = 78
    def hdr(t):  print(f"\n{C.BOLD}{C.CYAN}{t}{C.RESET}")
    def opt(f, h, grp=""): print(f"  {C.GREEN}{f:<30}{C.RESET} {h}")
    def sub(f, h): print(f"    {C.DIM}{f:<28}{C.RESET} {h}")
    def grp_note(t): print(f"  {C.DIM}{t}{C.RESET}")

    print(f"{C.BOLD}{C.CYAN}{'═' * W}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  tlsenum  —  TLS Certificate & Pentest Recon Enumerator{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * W}{C.RESET}")

    hdr("USAGE")
    print(f"  tlsenum.py  -d HOST | -l HOST,... | -f FILE  [options]")

    hdr("TARGETS  (one required)")
    opt("-d, --domain HOST[:PORT]",  "Single domain or IP (e.g. example.com:8443)")
    opt("-l, --list  HOST,HOST,...", "Comma-separated list of targets")
    opt("-f, --file  FILE",          "File with one host[:port] per line (# = comment)")

    hdr("CONNECTION")
    opt("--ports PORTS",     "Default port(s) when not specified in target (default: 443)")
    opt("-t, --timeout SECS","Connect / DNS timeout per attempt (default: 6)")
    opt("--threads N",       "Parallel worker threads (default: 10)")

    hdr("CERTIFICATE FIELDS")
    grp_note("Individual fields — combine freely, or use --all for everything")
    sub("--names",             "Subject, Common Name(s), Alt Name(s)  [default]")
    sub("--subject",           "Full subject DN")
    sub("--issuer",            "Issuer DN")
    sub("--validity",          "Valid-From / Valid-To dates")
    sub("--serial",            "Certificate serial number")
    sub("--fingerprints",      "SHA-1 and SHA-256 fingerprints")
    sub("--signature",         "Signature algorithm + OID")
    sub("--public-key",        "Public key type and size")
    sub("--version",           "Certificate version (v1/v2/v3)")
    sub("--basic-constraints", "CA flag and path length")
    sub("--key-usage",         "Key usage extensions")
    sub("--extended-key-usage","Extended key usage extensions")
    print(f"  {C.BOLD}{C.GREEN}{'--all':<30}{C.RESET} Show ALL of the above fields")

    hdr(f"ANALYSIS  —  {C.BOLD}--pentest{C.RESET}{C.CYAN} enables everything in this group")
    grp_note("Flags below are all included when --pentest is used:")
    sub("--risk",           "Certificate risk analysis (expiry, algo, key size, hostname)")
    sub("--reuse",          "Detect the same certificate served across multiple targets")
    sub("--expand-san",     "Collect SAN hostnames outside the target set (pivot list)")
    sub("--tls-context",    "Negotiated TLS version, cipher suite, and ALPN protocol")
    sub("--chain",          "Retrieve and analyse the full certificate chain")
    sub("--ct",             "Query crt.sh Certificate Transparency log for known names")
    sub("--internal-leaks", "Flag internal hostnames / RFC-1918 IPs in cert fields")
    sub("--dns",            "Resolve A/AAAA, cert source IP, NS, MX; check cert")
    sub("  ",               "consistency across all resolved IPs")
    sub("--dns-checks",     "CAA, SPF, DMARC, DNSSEC, zone transfer, wildcard DNS")
    sub("  ",               f"(requires: {C.YELLOW}pip install dnspython{C.RESET})")
    print(f"  {C.BOLD}{C.GREEN}{'--pentest':<30}{C.RESET} {C.BOLD}All of the above combined{C.RESET}")

    hdr(f"STANDALONE TESTS  —  {C.YELLOW}NOT included in --pentest (slow / targeted){C.RESET}")
    opt("--ciphers",
        "Enumerate every accepted TLS version + cipher combination.")
    grp_note("  Probes SSLv2–TLS1.3 × all known cipher suites (like a Qualys SSL scan).")
    grp_note("  Rates each cipher: BROKEN / WEAK / STRONG  (aligned with Qualys SSL Labs).")
    grp_note("  Run time: 30s–3min per target depending on server responsiveness.")

    hdr("OUTPUT")
    opt("--json-out FILE",     "Write full structured results to a JSON file")
    opt("--csv-out FILE",      "Write results to a CSV file")
    opt("--markdown-out FILE", "Write a Markdown summary table")
    opt("--evidence-dir DIR",  "Write a per-target plain-text evidence file")
    opt("--baseline FILE",     "Diff current run against a previous --json-out file")

    hdr("EXAMPLES")
    print(f"  {C.DIM}# Quick cert check")
    print(f"  tlsenum.py -d example.com{C.RESET}")
    print(f"  {C.DIM}# Full pentest report for a list of hosts")
    print(f"  tlsenum.py -f targets.txt --pentest --json-out report.json{C.RESET}")
    print(f"  {C.DIM}# Cipher scan only")
    print(f"  tlsenum.py -d example.com --ciphers{C.RESET}")
    print(f"  {C.DIM}# Pentest + cipher scan together")
    print(f"  tlsenum.py -d example.com --pentest --ciphers{C.RESET}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Custom -h / --help
    p.add_argument("-h", "--help", action="store_true", default=False,
                   help="Show this help message and exit")

    tg = p.add_mutually_exclusive_group(required=False)
    tg.add_argument("-d", "--domain", metavar="HOST[:PORT]",   help=argparse.SUPPRESS)
    tg.add_argument("-l", "--list",   metavar="HOST,HOST,...", help=argparse.SUPPRESS)
    tg.add_argument("-f", "--file",   metavar="FILE",          help=argparse.SUPPRESS)

    p.add_argument("--ports",    default="443",    help=argparse.SUPPRESS)
    p.add_argument("-t", "--timeout", type=float, default=6.0, help=argparse.SUPPRESS)
    p.add_argument("--threads",  type=int, default=10,         help=argparse.SUPPRESS)

    # Certificate fields
    for _dest in ("names","subject","issuer","validity","serial","fingerprints",
                  "signature","version","all"):
        p.add_argument(f"--{_dest}", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--public-key",          dest="public_key",         action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--basic-constraints",   dest="basic_constraints",  action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--key-usage",           dest="key_usage",          action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--extended-key-usage",  dest="extended_key_usage", action="store_true", help=argparse.SUPPRESS)

    # Analysis
    for _dest in ("pentest","risk","reuse","ct"):
        p.add_argument(f"--{_dest}", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--expand-san",     dest="expand_san",     action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--tls-context",    dest="tls_context",    action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--chain",          action="store_true",   help=argparse.SUPPRESS)
    p.add_argument("--internal-leaks", dest="internal_leaks", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--dns",            action="store_true",   help=argparse.SUPPRESS)
    p.add_argument("--dns-checks",     dest="dns_checks",     action="store_true", help=argparse.SUPPRESS)

    # Standalone
    p.add_argument("--ciphers", action="store_true", help=argparse.SUPPRESS)

    # Output
    p.add_argument("--json-out",     metavar="FILE", help=argparse.SUPPRESS)
    p.add_argument("--csv-out",      metavar="FILE", help=argparse.SUPPRESS)
    p.add_argument("--markdown-out", metavar="FILE", help=argparse.SUPPRESS)
    p.add_argument("--evidence-dir", metavar="DIR",  help=argparse.SUPPRESS)
    p.add_argument("--baseline",     metavar="FILE", help=argparse.SUPPRESS)

    return p


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Custom coloured help
    if args.help or not (args.domain or args.list or args.file):
        print_coloured_help()
        return 0

    banner()

    if (args.dns_checks or args.pentest) and not HAS_DNSPYTHON:
        warn("dnspython is not installed — CAA, SPF, DMARC, DNSSEC, and zone transfer "
             "checks will be skipped.")
        warn("Install with:  pip install dnspython")
        print()

    try:
        ports   = parse_ports(args.ports)
        targets = load_targets(args.domain, args.file, args.list, ports)
    except Exception as e:
        bad(f"Input error: {e}")
        return 1

    fields = selected_fields(args)

    good(f"Loaded {len(targets)} target(s)")
    good(f"Using {args.threads} worker thread(s)")
    good(f"Default port(s): {', '.join(str(p) for p in ports)}")
    if args.dns or args.pentest:
        good("DNS resolution enabled — probing all A/AAAA for cert consistency")
    if args.dns_checks or args.pentest:
        status = "enabled" if HAS_DNSPYTHON else "limited (dnspython missing)"
        good(f"DNS security checks {status}")
    if args.ciphers:
        good(f"Cipher scan enabled — probing {len(_PROBE_CIPHERS)} cipher suites × 4 TLS versions")
    print()

    results: List[TargetResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        future_map = {
            executor.submit(process_target, host, port, args): (host, port)
            for host, port in targets
        }
        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda x: (x.host.lower(), x.port))

    for rec in results:
        print_result(rec, fields, args)
        if args.evidence_dir:
            save_evidence(args.evidence_dir, rec, args)

    # ── Cipher scan (--ciphers) ─────────────────────────────────────────────
    if args.ciphers:
        print(f"{C.BOLD}{C.CYAN}Cipher Scan Results{C.RESET}")
        for host, port in targets:
            warn(f"Scanning ciphers for {host}:{port} — this may take 30-180s …")
            try:
                grouped = scan_ciphers(host, port, args.timeout, args.threads)
                print_cipher_report(host, port, grouped)
            except Exception as e:
                bad(f"Cipher scan failed for {host}:{port} — {e}")

    reuse_groups: Dict[str, List[str]] = {}
    if args.reuse or args.pentest:
        reuse_groups = build_reuse_groups(results)
        print_reuse_groups(reuse_groups)

    if args.expand_san or args.pentest:
        original_hosts = {host.lower() for host, _ in targets}
        print_san_expansion(results, original_hosts)

    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
            diffs    = diff_results(results, baseline)
            print_diffs(diffs)
        except Exception as e:
            warn(f"Baseline comparison failed: {e}")

    if len(results) > 1 or (args.risk or args.pentest or args.dns or args.dns_checks):
        print_summary(results)

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "arguments":        vars(args),
        "results":          [asdict(r) for r in results],
        "reuse_groups":     reuse_groups,
    }

    try:
        if args.json_out:
            write_json(args.json_out, payload)
            good(f"Wrote JSON     → {args.json_out}")
        if args.csv_out:
            write_csv(args.csv_out, results)
            good(f"Wrote CSV      → {args.csv_out}")
        if args.markdown_out:
            write_markdown(args.markdown_out, results, reuse_groups)
            good(f"Wrote Markdown → {args.markdown_out}")
    except Exception as e:
        warn(f"Export failed: {e}")

    failures = sum(1 for r in results if not r.success)
    if failures:
        warn(f"Completed with {failures} failed target(s)")
        return 2

    good("Completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
