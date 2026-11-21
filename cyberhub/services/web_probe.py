"""
Cyber Hub Backend - Website probe (Part 14)
Developed by Syed Muhammad Tayyab

The low-level, read-only network side of the Website / Developer Scanner:

* parse_target()  - "example.com", "https://site.pk/shop", "localhost:5173" -> a clean URL.
* resolve()       - DNS once, then every connection goes to that pinned IP (the Host header / TLS SNI still
                    carry the name), so a DNS answer can't change between the safety check and the request.
* scope_of()      - loopback | private | public; link-local / multicast / cloud-metadata addresses are refused.
* fetch()         - one HTTP(S) request with redirects (max 8), size cap (2 MB), gzip-bomb guard, timeouts,
                    never sends cookies or passwords, never runs scripts. A public site that redirects to a
                    local / private address is stopped there (no pivoting into the LAN).
* tls_info()      - certificate (parsed with `cryptography`), chain trust, hostname match, negotiated
                    protocol + cipher, and which TLS versions the server accepts (1.0 / 1.1 / 1.2 / 1.3).
* port_scan()     - TCP connect to a FIXED list of well-known ports + read the greeting some services send
                    (SSH / FTP / SMTP / MySQL / VNC). Nothing is ever sent to the service.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable

USER_AGENT = "Mozilla/5.0 (compatible; CyberHub-WebScanner/0.14; local security self-check)"
MAX_BODY = 2 * 1024 * 1024
MAX_REDIRECTS = 8
MAX_URL = 2048

LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
REFUSED_NETS = [ipaddress.ip_network(n) for n in (
    "169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "ff00::/8", "::/128")]

# Well-known ports checked by the port scan (fixed list - user-supplied ports are not accepted).
PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB file sharing", 465: "SMTP (TLS)", 587: "SMTP submission", 993: "IMAP (TLS)",
    995: "POP3 (TLS)", 1433: "SQL Server", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker API (no TLS)",
    2376: "Docker API", 3000: "Dev server (Node / React)", 3306: "MySQL / MariaDB", 3389: "Remote Desktop",
    5000: "Dev server (Flask / .NET)", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC remote control",
    5984: "CouchDB", 6379: "Redis", 8000: "Dev server (Django / PHP)", 8080: "HTTP (alternate)",
    8443: "HTTPS (alternate)", 8888: "Jupyter / dev server", 9200: "Elasticsearch", 9229: "Node.js debugger",
    10250: "Kubernetes kubelet", 11211: "Memcached", 27017: "MongoDB",
}
BANNER_PORTS = {21, 22, 25, 110, 143, 587, 3306, 5900}


class ProbeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


# ====================================================================== targets
def parse_target(raw: str, default_scheme: str = "https") -> dict:
    """{url, scheme, host, port, path, explicit_scheme, origin}. Raises ProbeError('bad_target', ...)."""
    s = (raw or "").strip()
    if not s or len(s) > MAX_URL or any(ord(ch) < 33 for ch in s):
        raise ProbeError("bad_target", "Enter a website address like example.com or https://example.com")
    explicit = "://" in s
    if not explicit:
        s = f"{default_scheme}://{s}"
    try:
        u = urllib.parse.urlsplit(s)
        port = u.port
    except ValueError:
        raise ProbeError("bad_target", "That address has an invalid port number")
    if u.scheme.lower() not in ("http", "https"):
        raise ProbeError("bad_target", "Only http:// and https:// addresses can be scanned")
    if u.username or u.password:
        raise ProbeError("bad_target", "Remove the user name / password from the address - Cyber Hub never sends "
                                       "credentials to a website")
    host = (u.hostname or "").rstrip(".")
    if not host:
        raise ProbeError("bad_target", "The address has no host name")
    try:
        ipaddress.ip_address(host)
        ascii_host = host
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9¡-￿_.-]{1,253}", host):
            raise ProbeError("bad_target", "That host name contains characters a website name can't have")
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ProbeError("bad_target", "That host name is not a valid internet name")
    scheme = u.scheme.lower()
    port = port or (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ProbeError("bad_target", "Port must be 1-65535")
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    origin = f"{scheme}://{netloc}" + ("" if default_port else f":{port}")
    return {"url": origin + path, "origin": origin, "scheme": scheme, "host": ascii_host, "port": port,
            "path": path, "explicit_scheme": explicit, "display": host}


def _public_override() -> set[str]:
    """Developer / test hook: host names treated as public internet sites (CYBERHUB_WEB_PUBLIC_HOSTS)."""
    return {h.strip().lower() for h in os.environ.get("CYBERHUB_WEB_PUBLIC_HOSTS", "").split(",") if h.strip()}


def ip_scope(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_loopback:
        return "loopback"
    if any(a in n for n in REFUSED_NETS) or a.is_multicast or a.is_unspecified:
        return "refused"
    if any(a in n for n in LOCAL_NETS):
        return "private"
    return "public"


def resolve(host: str, port: int, timeout: float = 5.0) -> list[str]:
    """IP addresses for a host (IPv4 first). getaddrinfo has no timeout, so it runs in a helper thread."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    box: dict[str, Any] = {}

    def work():
        try:
            box["r"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            box["e"] = e
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if "r" not in box:
        raise ProbeError("dns", f"Could not find {host} (DNS lookup failed)" if "e" in box else
                         f"DNS lookup for {host} timed out")
    ips: list[str] = []
    for fam, *_x, addr in box["r"]:
        ip = addr[0].split("%")[0]
        if ip not in ips:
            ips.append(ip)
    ips.sort(key=lambda i: ":" in i)                       # IPv4 first (works on more networks)
    return ips


def scope_of(host: str, ips: list[str]) -> tuple[str, str | None]:
    """(loopback | private | public, refusal reason or None). Any public address makes the target public."""
    if host.lower() in _public_override():
        return "public", None
    scopes = {ip_scope(i) for i in ips}
    if "refused" in scopes:
        return "refused", ("This address is link-local, multicast or a cloud metadata service - Cyber Hub does "
                           "not scan it")
    if "public" in scopes:
        return "public", None
    if "private" in scopes:
        return "private", None
    return "loopback", None


# ====================================================================== HTTP
class _Conn(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _TLSConn(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            ipaddress.ip_address(self.host)
            sni = None                                     # no SNI for a bare IP
        except ValueError:
            sni = self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=sni)


def _insecure_ctx() -> ssl.SSLContext:
    """For READING pages only - certificate problems are reported separately by tls_info()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ssl.SSLError, ValueError):                     # pragma: no cover
        pass
    return ctx


def _decode_body(raw: bytes, encoding: str | None, cap: int) -> bytes:
    enc = (encoding or "").lower().strip()
    if enc not in ("gzip", "deflate", "x-gzip"):
        return raw[:cap]
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS)
        out = d.decompress(raw, cap)                       # bomb guard: never more than cap bytes
        return out
    except zlib.error:
        try:
            return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, cap)
        except zlib.error:
            return raw[:cap]


def _ex_message(e: Exception) -> tuple[str, str]:
    if isinstance(e, ProbeError):
        return e.code, e.message
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timeout", "The site did not answer in time"
    if isinstance(e, ConnectionRefusedError):
        return "refused", "Connection refused - nothing is listening on that port"
    if isinstance(e, ssl.SSLError):
        return "tls", f"Secure connection failed: {getattr(e, 'reason', None) or e}"
    if isinstance(e, ConnectionResetError):
        return "reset", "The server closed the connection"
    if isinstance(e, http.client.HTTPException):
        return "protocol", f"The server's reply was not valid HTTP ({type(e).__name__})"
    if isinstance(e, OSError):
        return "network", f"Network error: {e.strerror or e}"
    return "error", str(e)


class Fetcher:
    """Makes the scanner's requests for one scan: pinned IPs, scope guard, request counter."""

    def __init__(self, timeout: float = 10.0, max_requests: int = 80, start_scope: str = "public",
                 cancel: Callable[[], None] | None = None):
        self.timeout = timeout
        self.max_requests = max_requests
        self.requests = 0
        self.start_scope = start_scope
        self.cancel = cancel or (lambda: None)
        self._ips: dict[str, list[str]] = {}

    def _pin(self, host: str, port: int) -> tuple[str, str]:
        if host not in self._ips:
            self._ips[host] = resolve(host, port, self.timeout)
        ips = self._ips[host]
        sc, why = scope_of(host, ips)
        if sc == "refused":
            raise ProbeError("refused_scope", why or "Address refused")
        if self.start_scope == "public" and sc in ("loopback", "private"):
            raise ProbeError("redirect_local", "The site pointed to an address on your own PC / network - Cyber Hub "
                                               "stopped there")
        return ips[0], sc

    def fetch(self, url: str, method: str = "GET", headers: dict | None = None, follow: bool = True,
              max_body: int = MAX_BODY, timeout: float | None = None) -> dict:
        """Response: {url, final_url, status, reason, headers[(k,v)], h{lower: [values]}, body, truncated,
        elapsed_ms, chain[{url, status, location}], ip, scope, version}. Raises ProbeError."""
        chain: list[dict] = []
        cur = url
        for _hop in range(MAX_REDIRECTS + 1):
            self.cancel()
            if self.requests >= self.max_requests:
                raise ProbeError("budget", "Request limit for one scan reached")
            t = parse_target(cur)
            ip, sc = self._pin(t["host"], t["port"])
            self.requests += 1
            started = time.monotonic()
            hdrs = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate", "Accept-Language": "en", "Connection": "close"}
            hdrs.update(headers or {})
            to = timeout or self.timeout
            conn = (_TLSConn(t["host"], t["port"], ip, to, _insecure_ctx()) if t["scheme"] == "https"
                    else _Conn(t["host"], t["port"], ip, to))
            try:
                conn.request(method, t["path"], headers=hdrs)
                r = conn.getresponse()
                raw = r.read(max_body + 1) if method != "HEAD" else b""
                hl = r.getheaders()
                status, reason, version = r.status, r.reason, r.version
            except Exception as e:
                code, msg = _ex_message(e)
                raise ProbeError(code, msg)
            finally:
                conn.close()
            truncated = len(raw) > max_body
            hmap: dict[str, list[str]] = {}
            for k, v in hl:
                hmap.setdefault(k.lower(), []).append(v)
            loc = (hmap.get("location") or [None])[0]
            chain.append({"url": t["url"], "status": status, "location": loc})
            if follow and status in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(t["url"], loc.strip())
                if urllib.parse.urlsplit(nxt).scheme.lower() not in ("http", "https"):
                    raise ProbeError("bad_redirect", "The site redirects to a non-web address")
                cur = nxt
                if method == "POST":
                    method = "GET"
                continue
            body = _decode_body(raw[:max_body + 1], (hmap.get("content-encoding") or [None])[0], max_body)
            return {"url": url, "final_url": t["url"], "status": status, "reason": reason, "headers": hl, "h": hmap,
                    "body": body[:max_body], "truncated": truncated or len(body) > max_body,
                    "elapsed_ms": int((time.monotonic() - started) * 1000), "chain": chain, "ip": ip, "scope": sc,
                    "version": "HTTP/1.1" if version == 11 else "HTTP/1.0"}
        raise ProbeError("redirects", f"More than {MAX_REDIRECTS} redirects")


# ====================================================================== TLS
TLS_VERSIONS = [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1"), ("TLS 1.2", "TLSv1_2"), ("TLS 1.3", "TLSv1_3")]
_LOCAL_TLS_FAIL = ("no protocols available", "no ciphers available", "unsupported protocol version",
                   "invalid ssl version", "ssl version not supported", "no cipher match")


def _tls_ctx(verify: bool, cafile: str | None = None) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
        if cafile and os.path.isfile(cafile):
            ctx.load_verify_locations(cafile)
        return ctx
    return _insecure_ctx()


def _handshake(ip: str, port: int, host: str, ctx: ssl.SSLContext, timeout: float) -> ssl.SSLSocket:
    sock = socket.create_connection((ip, port), timeout)
    try:
        try:
            ipaddress.ip_address(host)
            sni = None
        except ValueError:
            sni = host
        return ctx.wrap_socket(sock, server_hostname=sni)
    except Exception:
        sock.close()
        raise


def _supports(ip: str, port: int, host: str, version_name: str, timeout: float) -> bool | None:
    """True / False = the server accepts / refuses that TLS version; None = can't test from this PC."""
    import warnings
    with warnings.catch_warnings():                        # TLS 1.0 / 1.1 are deprecated - that's why we test them
        warnings.simplefilter("ignore", DeprecationWarning)
        ver = getattr(ssl.TLSVersion, version_name, None)
    if ver is None:
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        if version_name in ("TLSv1", "TLSv1_1"):
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        s = _handshake(ip, port, host, ctx, timeout)
        s.close()
        return True
    except ssl.SSLError as e:
        txt = str(e).lower()
        if any(x in txt for x in _LOCAL_TLS_FAIL) and "alert" not in txt:
            return None
        return False
    except (OSError, ValueError):
        return False


def parse_cert(der: bytes, now: datetime | None = None) -> dict:
    """Readable certificate facts from DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
    now = now or datetime.now(timezone.utc)
    c = x509.load_der_x509_certificate(der)

    def name(n) -> str:
        cn = n.get_attributes_for_oid(NameOID.COMMON_NAME)
        org = n.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return (cn[0].value if cn else "") or (org[0].value if org else "") or n.rfc4514_string()

    def org(n) -> str | None:
        o = n.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return o[0].value if o else None
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
    sans: list[str] = []
    try:
        ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [str(v) for v in ext.get_values_for_type(x509.DNSName)] + \
               [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key = ("RSA", pk.key_size)
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key = ("EC", pk.curve.key_size)
    elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key = ("EdDSA", 256 if isinstance(pk, ed25519.Ed25519PublicKey) else 456)
    elif isinstance(pk, dsa.DSAPublicKey):
        key = ("DSA", pk.key_size)
    else:                                                   # pragma: no cover
        key = (type(pk).__name__, 0)
    try:
        sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none"
    except Exception:                                       # pragma: no cover
        sig = "unknown"
    return {"subject": name(c.subject), "issuer": name(c.issuer), "issuer_org": org(c.issuer),
            "self_signed": c.issuer == c.subject, "sans": sans[:100], "san_count": len(sans),
            "not_before": nb.strftime("%Y-%m-%dT%H:%M:%SZ"), "not_after": na.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_left": int((na - now).total_seconds() // 86400), "not_yet_valid": nb > now,
            "validity_days": (na - nb).days, "serial": format(c.serial_number, "x"),
            "signature_hash": sig, "key_type": key[0], "key_bits": key[1],
            "wildcard": any(s.startswith("*.") for s in sans)}


def host_matches(host: str, sans: list[str], subject: str) -> bool:
    names = sans or [subject]
    h = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == h:
            return True
        if n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:] and h.count(".") >= n.count("."):
            return True
    return False


def tls_info(host: str, ip: str, port: int, timeout: float = 8.0, cafile: str | None = None,
             test_versions: bool = True) -> dict:
    """Everything about a site's HTTPS. Never raises for TLS problems - they are the findings."""
    out: dict[str, Any] = {"host": host, "port": port, "available": False, "trusted": None, "verify_error": None,
                           "verify_code": None, "hostname_ok": None, "protocol": None, "cipher": None,
                           "cipher_bits": None, "cert": None, "chain_length": None, "versions": {}}
    cafile = cafile or os.environ.get("CYBERHUB_WEB_CA_FILE") or None
    try:
        s = _handshake(ip, port, host, _tls_ctx(True, cafile), timeout)
        out.update(trusted=True, hostname_ok=True)
        s.close()
    except ssl.SSLCertVerificationError as e:
        out.update(trusted=False, verify_code=e.verify_code, verify_error=e.verify_message or str(e))
    except ssl.SSLError as e:
        out["verify_error"] = getattr(e, "reason", None) or str(e)
    except (OSError, ValueError) as e:
        code, msg = _ex_message(e)
        out["error"] = msg
        return out
    try:
        s = _handshake(ip, port, host, _tls_ctx(False), timeout)
    except Exception as e:
        _c, msg = _ex_message(e)
        out["error"] = msg
        return out
    try:
        out["available"] = True
        out["protocol"] = s.version()
        ci = s.cipher()
        if ci:
            out["cipher"], out["cipher_bits"] = ci[0], ci[2]
        der = s.getpeercert(binary_form=True)
        chain = getattr(s, "get_unverified_chain", None)
        if chain:
            try:
                out["chain_length"] = len(chain() or [])
            except Exception:                               # pragma: no cover
                pass
    finally:
        s.close()
    if der:
        try:
            out["cert"] = parse_cert(der)
            out["hostname_ok"] = host_matches(host, out["cert"]["sans"], out["cert"]["subject"])
        except Exception as e:                              # pragma: no cover - broken certificate
            out["cert_error"] = str(e)
    if test_versions:
        for label, name in TLS_VERSIONS:
            out["versions"][label] = _supports(ip, port, host, name, min(timeout, 5.0))
    return out


# ====================================================================== ports
def _banner(sock: socket.socket, port: int) -> str | None:
    try:
        sock.settimeout(1.2)
        data = sock.recv(256)
    except OSError:
        return None
    if not data:
        return None
    if port == 3306 and len(data) > 5:                     # MySQL greeting: 4-byte header, protocol, version\0
        v = data[5:].split(b"\0", 1)[0]
        txt = "MySQL " + v.decode("ascii", "replace")
    else:
        txt = data.decode("latin-1", "replace")
    txt = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in txt).strip()
    return re.sub(r"\s+", " ", txt)[:160] or None


def port_scan(ip: str, ports: list[int] | None = None, timeout: float = 1.5, workers: int = 16,
              cancel: Callable[[], None] | None = None) -> list[dict]:
    """[{port, service, state: open | closed | filtered, banner}] - connect only, nothing is sent."""
    ports = sorted(set(ports or PORTS))

    def one(p: int) -> dict:
        if cancel:
            try:
                cancel()
            except Exception:
                return {"port": p, "service": PORTS.get(p, ""), "state": "skipped", "banner": None}
        r = {"port": p, "service": PORTS.get(p, f"port {p}"), "state": "filtered", "banner": None}
        try:
            s = socket.create_connection((ip, p), timeout)
        except ConnectionRefusedError:
            r["state"] = "closed"
            return r
        except OSError:
            return r
        try:
            r["state"] = "open"
            if p in BANNER_PORTS:
                r["banner"] = _banner(s, p)
        finally:
            s.close()
        return r
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ports)))) as ex:
        res = list(ex.map(one, ports))
    if cancel:
        cancel()
    return res
