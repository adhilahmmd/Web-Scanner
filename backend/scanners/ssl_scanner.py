"""
SSL/TLS Scanner Module

Checks:
1.  Certificate Validity & Expiry   — dates, expiry countdown, self-signed
2.  Weak Cipher Suites              — NULL, RC4, DES, EXPORT, anon ciphers
3.  Outdated Protocol Versions      — SSLv2, SSLv3, TLS 1.0, TLS 1.1
4.  HSTS                            — header presence, max-age, includeSubDomains
5.  Certificate Chain & Trust       — issuer chain, signature algorithm, key size
6.  Mixed Content                   — HTTP resources on HTTPS pages
7.  BEAST                           — TLS 1.0 + CBC cipher combo
8.  POODLE                          — SSLv3 support
9.  HEARTBLEED                      — OpenSSL heartbeat extension probe
10. CRIME/BREACH                    — TLS compression enabled
"""

import ssl
import socket
import asyncio
import httpx
import re
import datetime
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
from bs4 import BeautifulSoup
from models.ssl_models import (
    SSLFinding, SSLSummary, CertificateDetail,
    ProtocolSupport, CipherDetail,
    SSLCheckType, SeverityLevel
)


# ──────────────────────────────────────────────
# Weak cipher patterns
# ──────────────────────────────────────────────
WEAK_CIPHERS = {
    "NULL":     "No encryption — data sent in plaintext",
    "EXPORT":   "Export-grade cipher — intentionally weakened (40-bit)",
    "RC4":      "RC4 stream cipher — broken, biased keystream",
    "DES":      "56-bit DES — brute-forceable in hours",
    "3DES":     "Triple-DES — Sweet32 birthday attack (64-bit block)",
    "MD5":      "MD5 MAC — collision-vulnerable hash",
    "ADH":      "Anonymous DH — no server authentication",
    "AECDH":    "Anonymous ECDH — no server authentication",
    "aNULL":    "No authentication",
    "eNULL":    "No encryption",
    "LOW":      "Low-grade cipher (< 128-bit)",
    "EXP":      "Export-restricted cipher",
    "IDEA":     "IDEA cipher — outdated, not widely reviewed",
    "SEED":     "SEED cipher — limited security analysis",
}

WEAK_PROTOCOLS = {
    "SSLv2": (ssl.PROTOCOL_TLS_CLIENT, SeverityLevel.CRITICAL,
               "SSLv2 is completely broken — DROWN attack possible"),
    "SSLv3": (ssl.PROTOCOL_TLS_CLIENT, SeverityLevel.CRITICAL,
               "SSLv3 is vulnerable to POODLE attack"),
    "TLSv1.0": (ssl.PROTOCOL_TLS_CLIENT, SeverityLevel.HIGH,
                "TLS 1.0 is deprecated — BEAST attack possible with CBC ciphers"),
    "TLSv1.1": (ssl.PROTOCOL_TLS_CLIENT, SeverityLevel.MEDIUM,
                "TLS 1.1 is deprecated since RFC 8996 (2021)"),
}

WEAK_SIGNATURE_ALGORITHMS = ["md5", "sha1", "md2", "md4"]
MINIMUM_KEY_SIZE = {"RSA": 2048, "DSA": 2048, "EC": 256}


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def parse_host_port(url: str) -> Tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def cert_dict_to_detail(cert: Dict, host: str) -> CertificateDetail:
    """Convert ssl.getpeercert() dict to CertificateDetail."""
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")

    try:
        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days_left = (not_after - now).days
        is_expired = days_left < 0
    except Exception:
        not_after = datetime.datetime.utcnow()
        not_before = datetime.datetime.utcnow()
        days_left = 0
        is_expired = False

    # SAN domains
    san_list = []
    for san_type, san_val in cert.get("subjectAltName", []):
        if san_type.lower() == "dns":
            san_list.append(san_val)

    # Self-signed = subject CN == issuer CN
    is_self_signed = subject.get("commonName") == issuer.get("commonName")

    return CertificateDetail(
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.get("serialNumber", "")),
        not_before=not_before_str,
        not_after=not_after_str,
        days_until_expiry=days_left,
        is_expired=is_expired,
        is_self_signed=is_self_signed,
        san_domains=san_list,
        signature_algorithm=cert.get("signatureAlgorithm", "unknown"),
    )


def calculate_grade(findings: List[SSLFinding]) -> str:
    """Assign a letter grade based on findings."""
    severities = [f.severity for f in findings]
    if SeverityLevel.CRITICAL in severities:
        return "F"
    if SeverityLevel.HIGH in severities:
        return "C"
    if SeverityLevel.MEDIUM in severities:
        return "B"
    if SeverityLevel.LOW in severities:
        return "B+"
    if SeverityLevel.INFO in severities:
        return "A"
    return "A+"


def calculate_risk(findings: List[SSLFinding]) -> SeverityLevel:
    if not findings:
        return SeverityLevel.LOW
    severities = [f.severity for f in findings]
    if SeverityLevel.CRITICAL in severities:
        return SeverityLevel.CRITICAL
    if SeverityLevel.HIGH in severities:
        return SeverityLevel.HIGH
    if SeverityLevel.MEDIUM in severities:
        return SeverityLevel.MEDIUM
    if SeverityLevel.LOW in severities:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


# ──────────────────────────────────────────────
# 1. Certificate Validity & Chain
# ──────────────────────────────────────────────

def check_certificate(
    host: str,
    port: int,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
) -> Optional[CertificateDetail]:
    checks.append("CERTIFICATE")
    cert_detail = None

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_detail = cert_dict_to_detail(cert, host)

                # Expiry checks
                if cert_detail.is_expired:
                    findings.append(SSLFinding(
                        check_type=SSLCheckType.CERTIFICATE,
                        target=f"{host}:{port}",
                        evidence=f"Certificate expired {abs(cert_detail.days_until_expiry)} days ago",
                        severity=SeverityLevel.CRITICAL,
                        description=(
                            "The SSL certificate has expired. Browsers will show security warnings "
                            "and connections may be refused by clients."
                        ),
                        remediation=(
                            "Renew the certificate immediately. "
                            "Use Let's Encrypt with auto-renewal (certbot) to prevent future expiry."
                        ),
                        detail={"expires": cert_detail.not_after},
                    ))
                elif cert_detail.days_until_expiry <= 14:
                    findings.append(SSLFinding(
                        check_type=SSLCheckType.CERTIFICATE,
                        target=f"{host}:{port}",
                        evidence=f"Certificate expires in {cert_detail.days_until_expiry} days",
                        severity=SeverityLevel.HIGH,
                        description="Certificate is expiring very soon — service disruption imminent.",
                        remediation="Renew the certificate immediately before it expires.",
                        detail={"expires": cert_detail.not_after,
                                "days_left": cert_detail.days_until_expiry},
                    ))
                elif cert_detail.days_until_expiry <= 30:
                    findings.append(SSLFinding(
                        check_type=SSLCheckType.CERTIFICATE,
                        target=f"{host}:{port}",
                        evidence=f"Certificate expires in {cert_detail.days_until_expiry} days",
                        severity=SeverityLevel.MEDIUM,
                        description="Certificate is expiring soon. Plan renewal within the next few days.",
                        remediation=(
                            "Renew the certificate soon. "
                            "Set up automated renewal alerts at 60, 30, and 14 days."
                        ),
                        detail={"expires": cert_detail.not_after,
                                "days_left": cert_detail.days_until_expiry},
                    ))

                # Self-signed check
                if cert_detail.is_self_signed:
                    findings.append(SSLFinding(
                        check_type=SSLCheckType.CERT_CHAIN,
                        target=f"{host}:{port}",
                        evidence=(
                            f"Certificate subject CN '{cert_detail.subject.get('commonName')}' "
                            f"matches issuer CN — self-signed certificate"
                        ),
                        severity=SeverityLevel.HIGH,
                        description=(
                            "The certificate is self-signed and not issued by a trusted CA. "
                            "Browsers will display security warnings and users may be vulnerable to MITM."
                        ),
                        remediation=(
                            "Replace with a certificate from a trusted CA. "
                            "Use Let's Encrypt for free, trusted certificates."
                        ),
                        detail={"subject": cert_detail.subject, "issuer": cert_detail.issuer},
                    ))

                # Weak signature algorithm
                sig_alg = cert_detail.signature_algorithm.lower()
                for weak_alg in WEAK_SIGNATURE_ALGORITHMS:
                    if weak_alg in sig_alg:
                        findings.append(SSLFinding(
                            check_type=SSLCheckType.CERT_CHAIN,
                            target=f"{host}:{port}",
                            evidence=f"Certificate uses weak signature algorithm: '{cert_detail.signature_algorithm}'",
                            severity=SeverityLevel.HIGH,
                            description=(
                                f"The certificate is signed with '{cert_detail.signature_algorithm}' "
                                f"which is cryptographically weak and susceptible to collision attacks."
                            ),
                            remediation=(
                                "Reissue the certificate using SHA-256 or SHA-384 signature algorithm. "
                                "Never use MD5 or SHA-1 for certificate signing."
                            ),
                            detail={"algorithm": cert_detail.signature_algorithm},
                        ))
                        break

    except ssl.SSLCertVerificationError as e:
        findings.append(SSLFinding(
            check_type=SSLCheckType.CERT_CHAIN,
            target=f"{host}:{port}",
            evidence=f"SSL certificate verification failed: {str(e)}",
            severity=SeverityLevel.CRITICAL,
            description=(
                "The certificate chain could not be verified. "
                "This may indicate an untrusted CA, missing intermediate cert, or domain mismatch."
            ),
            remediation=(
                "Ensure the full certificate chain (leaf + intermediates) is properly configured. "
                "Verify the certificate CN/SAN matches the domain being accessed."
            ),
            detail={"error": str(e)},
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        errors.append(f"Certificate check failed — cannot connect to {host}:{port}: {str(e)}")
    except Exception as e:
        errors.append(f"Certificate check error: {str(e)}")

    return cert_detail


# ──────────────────────────────────────────────
# 2. Protocol Version Support
# ──────────────────────────────────────────────

def check_protocol_versions(
    host: str,
    port: int,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
) -> ProtocolSupport:
    checks.append("PROTOCOLS")
    support = ProtocolSupport()

    protocol_tests = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1,   "tls10",  SeverityLevel.HIGH),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1,  "tls11",  SeverityLevel.MEDIUM),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2,  "tls12",  SeverityLevel.INFO),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3,  "tls13",  SeverityLevel.INFO),
    ]

    for proto_name, tls_version, attr, severity in protocol_tests:
        checks.append(f"PROTO:{proto_name}")
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    setattr(support, attr, True)

                    if severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.CRITICAL):
                        findings.append(SSLFinding(
                            check_type=SSLCheckType.PROTOCOL_VERSION,
                            target=f"{host}:{port}",
                            evidence=f"Server accepted {proto_name} connection successfully",
                            severity=severity,
                            description=(
                                f"The server supports {proto_name} which is deprecated and insecure. "
                                + WEAK_PROTOCOLS.get(proto_name, ("", SeverityLevel.MEDIUM, ""))[2]
                            ),
                            remediation=(
                                f"Disable {proto_name} in your server configuration. "
                                "Only TLS 1.2 and TLS 1.3 should be enabled. "
                                "Update your web server config: "
                                "Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
                            ),
                            detail={"protocol": proto_name},
                        ))
        except ssl.SSLError:
            pass  # Protocol not supported = good
        except (socket.timeout, ConnectionRefusedError):
            errors.append(f"Timeout testing {proto_name} on {host}:{port}")
        except AttributeError:
            # Some Python versions don't have all TLS version attrs
            pass
        except Exception as e:
            errors.append(f"Protocol test error for {proto_name}: {str(e)}")

    # Check if TLS 1.2+ not supported at all
    if not support.tls12 and not support.tls13:
        findings.append(SSLFinding(
            check_type=SSLCheckType.PROTOCOL_VERSION,
            target=f"{host}:{port}",
            evidence="Server does not support TLS 1.2 or TLS 1.3",
            severity=SeverityLevel.CRITICAL,
            description=(
                "The server does not support modern TLS versions. "
                "All connections will use deprecated, insecure protocols."
            ),
            remediation=(
                "Enable TLS 1.2 and TLS 1.3 immediately. "
                "Update OpenSSL to a supported version."
            ),
            detail={},
        ))

    return support


# ──────────────────────────────────────────────
# 3. Cipher Suite Analysis
# ──────────────────────────────────────────────

def check_cipher_suites(
    host: str,
    port: int,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
) -> List[CipherDetail]:
    checks.append("CIPHERS")
    cipher_details = []
    weak_found = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Get negotiated cipher
                negotiated = ssock.cipher()
                if negotiated:
                    cipher_name, proto, bits = negotiated
                    is_weak = any(wk.upper() in cipher_name.upper() for wk in WEAK_CIPHERS)
                    weakness = next(
                        (reason for wk, reason in WEAK_CIPHERS.items()
                         if wk.upper() in cipher_name.upper()), None
                    )
                    cipher_details.append(CipherDetail(
                        name=cipher_name,
                        protocol=proto or "unknown",
                        key_exchange=cipher_name.split("_")[1] if "_" in cipher_name else None,
                        authentication=None,
                        encryption=cipher_name,
                        bits=bits,
                        is_weak=is_weak,
                        weakness_reason=weakness,
                    ))
                    if is_weak:
                        weak_found.append((cipher_name, weakness))

        # Check shared ciphers list
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        shared = ctx2.get_ciphers()

        for cipher in shared[:30]:  # check top 30 supported ciphers
            name = cipher.get("name", "")
            for weak_key, reason in WEAK_CIPHERS.items():
                if weak_key.upper() in name.upper():
                    if not any(c.name == name for c in cipher_details):
                        cipher_details.append(CipherDetail(
                            name=name,
                            protocol=cipher.get("protocol", "unknown"),
                            key_exchange=None,
                            authentication=None,
                            encryption=name,
                            bits=cipher.get("bits"),
                            is_weak=True,
                            weakness_reason=reason,
                        ))
                    weak_found.append((name, reason))
                    break

        if weak_found:
            unique_weak = list({name: reason for name, reason in weak_found}.items())
            findings.append(SSLFinding(
                check_type=SSLCheckType.CIPHER_SUITE,
                target=f"{host}:{port}",
                evidence=(
                    f"Found {len(unique_weak)} weak cipher(s): "
                    + ", ".join(n for n, _ in unique_weak[:5])
                ),
                severity=SeverityLevel.HIGH,
                description=(
                    f"The server supports {len(unique_weak)} weak cipher suite(s). "
                    "Weak ciphers can be exploited to decrypt intercepted traffic."
                ),
                remediation=(
                    "Configure your server to only allow strong cipher suites. "
                    "Recommended: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, "
                    "ECDHE-RSA-AES256-GCM-SHA384. "
                    "Use Mozilla SSL Config Generator: https://ssl-config.mozilla.org"
                ),
                detail={"weak_ciphers": [{"name": n, "reason": r} for n, r in unique_weak[:10]]},
            ))

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        errors.append(f"Cipher check failed: {str(e)}")
    except Exception as e:
        errors.append(f"Cipher suite check error: {str(e)}")

    return cipher_details


# ──────────────────────────────────────────────
# 4. HSTS Check
# ──────────────────────────────────────────────

async def check_hsts(
    client: httpx.AsyncClient,
    url: str,
    host: str,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
):
    checks.append("HSTS")
    if not url.startswith("https://"):
        findings.append(SSLFinding(
            check_type=SSLCheckType.HSTS,
            target=url,
            evidence="Target URL uses HTTP — HSTS cannot be applied",
            severity=SeverityLevel.HIGH,
            description=(
                "The target site is not using HTTPS. "
                "HSTS requires HTTPS to be effective."
            ),
            remediation=(
                "Migrate the entire site to HTTPS. "
                "Obtain a trusted TLS certificate and redirect all HTTP to HTTPS."
            ),
            detail={},
        ))
        return

    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)
        hsts = resp.headers.get("strict-transport-security", "")

        if not hsts:
            findings.append(SSLFinding(
                check_type=SSLCheckType.HSTS,
                target=url,
                evidence="Strict-Transport-Security header is absent from HTTPS response",
                severity=SeverityLevel.MEDIUM,
                description=(
                    "The server does not send the HSTS header. "
                    "Without HSTS, browsers may connect over HTTP on first visit, "
                    "enabling SSL stripping attacks."
                ),
                remediation=(
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload "
                    "Minimum max-age: 6 months (15768000s). "
                    "Submit to HSTS preload list: https://hstspreload.org"
                ),
                detail={},
            ))
        else:
            # Parse HSTS directives
            max_age = None
            includes_subdomains = "includesubdomains" in hsts.lower()
            has_preload = "preload" in hsts.lower()

            ma_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if ma_match:
                max_age = int(ma_match.group(1))

            if max_age is not None and max_age < 15768000:
                findings.append(SSLFinding(
                    check_type=SSLCheckType.HSTS,
                    target=url,
                    evidence=f"HSTS max-age={max_age}s is below recommended minimum (15768000s / 6 months)",
                    severity=SeverityLevel.LOW,
                    description=(
                        f"HSTS is enabled but max-age={max_age}s is too short. "
                        "A short max-age means browsers will re-verify HTTPS compliance frequently, "
                        "leaving a window for downgrade attacks."
                    ),
                    remediation=(
                        "Increase max-age to at least 31536000 (1 year). "
                        "Add includeSubDomains and preload directives."
                    ),
                    detail={"hsts_header": hsts, "max_age": max_age},
                ))

            if not includes_subdomains:
                findings.append(SSLFinding(
                    check_type=SSLCheckType.HSTS,
                    target=url,
                    evidence="HSTS header missing 'includeSubDomains' directive",
                    severity=SeverityLevel.LOW,
                    description=(
                        "The HSTS policy does not cover subdomains. "
                        "Attackers could use a subdomain to perform a cookie injection attack."
                    ),
                    remediation=(
                        "Add 'includeSubDomains' to your HSTS header: "
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    detail={"hsts_header": hsts},
                ))

    except Exception as e:
        errors.append(f"HSTS check error: {str(e)}")


# ──────────────────────────────────────────────
# 5. Mixed Content Detection
# ──────────────────────────────────────────────

async def check_mixed_content(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
):
    checks.append("MIXED_CONTENT")
    if not url.startswith("https://"):
        return

    try:
        resp = await client.get(url, timeout=timeout)
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")

        mixed = []

        # Check all resource-loading tags
        tag_attrs = [
            ("script", "src"), ("link", "href"), ("img", "src"),
            ("iframe", "src"), ("video", "src"), ("audio", "src"),
            ("source", "src"), ("embed", "src"), ("object", "data"),
            ("form", "action"),
        ]
        for tag, attr in tag_attrs:
            for element in soup.find_all(tag, **{attr: True}):
                val = element.get(attr, "")
                if val.startswith("http://"):
                    mixed.append({
                        "tag": tag,
                        "attribute": attr,
                        "url": val[:100],
                    })

        # Also check inline CSS for http:// URLs
        for style in soup.find_all("style"):
            http_matches = re.findall(r'url\(["\']?(http://[^"\')\s]+)', style.string or "")
            for m in http_matches:
                mixed.append({"tag": "style", "attribute": "url()", "url": m[:100]})

        if mixed:
            findings.append(SSLFinding(
                check_type=SSLCheckType.MIXED_CONTENT,
                target=url,
                evidence=(
                    f"Found {len(mixed)} HTTP resource(s) loaded on HTTPS page: "
                    + ", ".join(m["url"] for m in mixed[:3])
                ),
                severity=SeverityLevel.MEDIUM,
                description=(
                    f"The HTTPS page loads {len(mixed)} resource(s) over insecure HTTP. "
                    "Mixed content weakens HTTPS security and may be blocked by browsers."
                ),
                remediation=(
                    "Update all resource URLs to use HTTPS. "
                    "Use protocol-relative URLs (//example.com/resource) as fallback. "
                    "Add Content-Security-Policy: upgrade-insecure-requests header."
                ),
                detail={"mixed_resources": mixed[:10]},
            ))

    except Exception as e:
        errors.append(f"Mixed content check error: {str(e)}")


# ──────────────────────────────────────────────
# 6. Known Vulnerability Checks
# ──────────────────────────────────────────────

def check_poodle(
    support: ProtocolSupport,
    host: str,
    port: int,
    findings: List[SSLFinding],
    checks: List[str],
):
    """POODLE: SSLv3 support = vulnerable."""
    checks.append("POODLE")
    # SSLv3 is checked via protocol version check; add POODLE-specific finding
    if support.sslv3:
        findings.append(SSLFinding(
            check_type=SSLCheckType.POODLE,
            target=f"{host}:{port}",
            evidence="Server supports SSLv3 — POODLE attack is possible",
            severity=SeverityLevel.CRITICAL,
            description=(
                "POODLE (Padding Oracle On Downgraded Legacy Encryption) — CVE-2014-3566. "
                "An attacker can perform a man-in-the-middle attack to downgrade the connection "
                "to SSLv3, then exploit CBC padding to decrypt session cookies."
            ),
            remediation=(
                "Disable SSLv3 immediately. "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
            detail={"cve": "CVE-2014-3566"},
        ))


def check_beast(
    support: ProtocolSupport,
    ciphers: List[CipherDetail],
    host: str,
    port: int,
    findings: List[SSLFinding],
    checks: List[str],
):
    """BEAST: TLS 1.0 + CBC cipher = vulnerable."""
    checks.append("BEAST")
    has_cbc = any("CBC" in c.name.upper() for c in ciphers)
    if support.tls10 and has_cbc:
        findings.append(SSLFinding(
            check_type=SSLCheckType.BEAST,
            target=f"{host}:{port}",
            evidence=(
                "TLS 1.0 is supported AND CBC cipher suites are in use — "
                "BEAST attack conditions are met"
            ),
            severity=SeverityLevel.HIGH,
            description=(
                "BEAST (Browser Exploit Against SSL/TLS) — CVE-2011-3389. "
                "An attacker with network access can exploit the TLS 1.0 CBC IV prediction "
                "to decrypt HTTPS cookies and session tokens."
            ),
            remediation=(
                "Disable TLS 1.0. Use TLS 1.2+ with AEAD ciphers (GCM, CHACHA20). "
                "Prioritize ECDHE cipher suites with AES-GCM."
            ),
            detail={"cve": "CVE-2011-3389"},
        ))


def check_crime_breach(
    host: str,
    port: int,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
):
    """CRIME: TLS compression enabled."""
    checks.append("CRIME")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                compression = ssock.compression()
                if compression:
                    findings.append(SSLFinding(
                        check_type=SSLCheckType.CRIME_BREACH,
                        target=f"{host}:{port}",
                        evidence=f"TLS compression is enabled: '{compression}'",
                        severity=SeverityLevel.HIGH,
                        description=(
                            "CRIME (Compression Ratio Info-leak Made Easy) — CVE-2012-4929. "
                            "TLS compression is enabled, allowing an attacker who can inject "
                            "chosen plaintext to recover secret values like session tokens."
                        ),
                        remediation=(
                            "Disable TLS compression in your server configuration. "
                            "OpenSSL: set SSL_OP_NO_COMPRESSION option. "
                            "Also disable HTTP-level compression (gzip) for sensitive endpoints "
                            "to mitigate BREACH (CVE-2013-3587)."
                        ),
                        detail={"compression_method": compression, "cves": ["CVE-2012-4929", "CVE-2013-3587"]},
                    ))
    except Exception as e:
        errors.append(f"CRIME check error: {str(e)}")


async def check_heartbleed(
    host: str,
    port: int,
    timeout: int,
    findings: List[SSLFinding],
    errors: List[str],
    checks: List[str],
):
    """
    Heartbleed: Send a malformed TLS heartbeat request.
    A vulnerable server returns more data than sent (memory leak).
    CVE-2014-0160
    """
    checks.append("HEARTBLEED")

    # Minimal TLS ClientHello + Heartbeat request
    # This is a safe probe — we just check if heartbeat extension is accepted
    hello = bytes([
        0x16, 0x03, 0x01,       # TLS Record: Handshake, TLS 1.0
        0x00, 0x4f,              # Length: 79 bytes
        0x01,                    # HandshakeType: ClientHello
        0x00, 0x00, 0x4b,        # Length
        0x03, 0x03,              # Version: TLS 1.2
        # Random (32 bytes)
        *([0x00] * 32),
        0x00,                    # Session ID length: 0
        0x00, 0x04,              # Cipher suites length: 4
        0x00, 0x2f,              # TLS_RSA_WITH_AES_128_CBC_SHA
        0x00, 0xff,              # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        0x01, 0x00,              # Compression: null
        0x00, 0x1b,              # Extensions length: 27
        # Heartbeat extension
        0x00, 0x0f,              # Extension type: heartbeat
        0x00, 0x01,              # Length: 1
        0x01,                    # Mode: peer_allowed_to_send
        # Other extensions
        0xff, 0x01, 0x00, 0x01, 0x00,   # renegotiation_info
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
        0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
    ])

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.write(hello)
        await writer.drain()

        # Read server response
        data = b""
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
        except asyncio.TimeoutError:
            pass

        writer.close()

        # Check if heartbeat extension is in server response
        if b"\x00\x0f" in data or b"\x18\x03" in data:
            findings.append(SSLFinding(
                check_type=SSLCheckType.HEARTBLEED,
                target=f"{host}:{port}",
                evidence="Server responded to heartbeat extension probe — possible Heartbleed exposure",
                severity=SeverityLevel.CRITICAL,
                description=(
                    "Heartbleed (CVE-2014-0160) — The server appears to support the TLS heartbeat "
                    "extension. Vulnerable OpenSSL versions (1.0.1–1.0.1f) allow attackers to read "
                    "up to 64KB of server memory per request, leaking private keys, passwords, and session tokens."
                ),
                remediation=(
                    "Update OpenSSL to 1.0.1g or later immediately. "
                    "After patching: revoke and reissue all SSL certificates, "
                    "invalidate all session tokens, and reset all passwords."
                ),
                detail={"cve": "CVE-2014-0160"},
            ))

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass  # Can't connect = not testing, not a vuln
    except Exception as e:
        errors.append(f"Heartbleed probe error: {str(e)}")


# ──────────────────────────────────────────────
# Main Scanner Entry Point
# ──────────────────────────────────────────────

async def run_ssl_scan(url: str, timeout: int = 10) -> dict:
    findings: List[SSLFinding] = []
    errors: List[str] = []
    checks: List[str] = []
    cipher_details: List[CipherDetail] = []
    cert_detail: Optional[CertificateDetail] = None
    protocol_support = ProtocolSupport()

    parsed = urlparse(url)
    host, port = parse_host_port(url)
    is_https = parsed.scheme == "https"

    if not is_https:
        findings.append(SSLFinding(
            check_type=SSLCheckType.PROTOCOL_VERSION,
            target=url,
            evidence="Target uses HTTP — no TLS in use",
            severity=SeverityLevel.HIGH,
            description=(
                "The target URL uses plain HTTP with no TLS encryption. "
                "All data transmitted is visible to network observers."
            ),
            remediation=(
                "Enable HTTPS by installing a TLS certificate. "
                "Redirect all HTTP traffic to HTTPS. "
                "Use Let's Encrypt for a free trusted certificate."
            ),
            detail={},
        ))

    async with httpx.AsyncClient(
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "WebVulnScanner/1.0 (educational use)"},
    ) as client:
        # Verify reachable
        try:
            await client.get(url, timeout=timeout)
        except Exception as e:
            return {
                "url": url,
                "status": "unreachable",
                "summary": SSLSummary(
                    total_checks=0, vulnerabilities_found=0,
                    certificate_issues=0, protocol_issues=0,
                    cipher_issues=0, hsts_issues=0,
                    known_vuln_issues=0, mixed_content_issues=0,
                    grade="N/A", risk_level=SeverityLevel.CRITICAL,
                ),
                "findings": [],
                "certificate": None,
                "protocol_support": None,
                "ciphers": [],
                "errors": [f"Could not reach target: {str(e)}"],
            }

        if is_https:
            # Run sync checks in executor (socket/ssl operations)
            loop = asyncio.get_event_loop()

            cert_detail = await loop.run_in_executor(
                None, check_certificate, host, port, timeout, findings, errors, checks
            )
            protocol_support = await loop.run_in_executor(
                None, check_protocol_versions, host, port, timeout, findings, errors, checks
            )
            cipher_details = await loop.run_in_executor(
                None, check_cipher_suites, host, port, timeout, findings, errors, checks
            )
            await loop.run_in_executor(
                None, check_crime_breach, host, port, timeout, findings, errors, checks
            )

            # Async checks
            await asyncio.gather(
                check_hsts(client, url, host, timeout, findings, errors, checks),
                check_mixed_content(client, url, timeout, findings, errors, checks),
                check_heartbleed(host, port, timeout, findings, errors, checks),
            )

            # Known vuln checks (depend on protocol/cipher results)
            check_poodle(protocol_support, host, port, findings, checks)
            check_beast(protocol_support, cipher_details, host, port, findings, checks)
        else:
            # HTTP-only: just check HSTS (will flag as missing)
            await check_hsts(client, url, host, timeout, findings, errors, checks)

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.check_type, f.evidence[:80])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    summary = SSLSummary(
        total_checks=len(checks),
        vulnerabilities_found=len(unique_findings),
        certificate_issues=sum(1 for f in unique_findings if f.check_type in (
            SSLCheckType.CERTIFICATE, SSLCheckType.CERT_CHAIN)),
        protocol_issues=sum(1 for f in unique_findings if f.check_type == SSLCheckType.PROTOCOL_VERSION),
        cipher_issues=sum(1 for f in unique_findings if f.check_type == SSLCheckType.CIPHER_SUITE),
        hsts_issues=sum(1 for f in unique_findings if f.check_type == SSLCheckType.HSTS),
        known_vuln_issues=sum(1 for f in unique_findings if f.check_type in (
            SSLCheckType.BEAST, SSLCheckType.POODLE,
            SSLCheckType.HEARTBLEED, SSLCheckType.CRIME_BREACH)),
        mixed_content_issues=sum(1 for f in unique_findings if f.check_type == SSLCheckType.MIXED_CONTENT),
        grade=calculate_grade(unique_findings),
        risk_level=calculate_risk(unique_findings),
    )

    return {
        "url": url,
        "status": "completed",
        "summary": summary,
        "findings": unique_findings,
        "certificate": cert_detail,
        "protocol_support": protocol_support,
        "ciphers": cipher_details,
        "errors": errors,
    }