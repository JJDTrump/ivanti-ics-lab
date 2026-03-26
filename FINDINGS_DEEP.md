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

*Requires specific configuration (SAML/OIDC enabled)

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

No upper bound check exists. The field allows values up to 65535, resulting in `data_length = EAP_Length - 5 = 65530` bytes. When `EAP_Length` exceeds the actual HTTP POST body size, the subsequent `memmove()` reads beyond the allocated buffer:

```asm
; Address 0x000d33fe
memmove(DSStr_buffer, packet_data + 5, data_length)  ; data_length up to 65530
```

**Impact**: Pre-authentication information disclosure. Adjacent heap/stack memory is copied into the DSStr buffer and potentially returned or logged. This can leak:
- Heap metadata (useful for heap exploitation)
- Pointers (useful for ASLR bypass on 32-bit PIE binary)
- Session tokens or cryptographic material

**R2.8 Fix**: Added `cmp edi, 0x1000` (4096-byte upper limit) at `0x000dca10`, attribute length validation, and "invalid EAP Packet" error handling. Function grew from 2311 to 5160 bytes.

**Prerequisite**: EAP/RADIUS authentication must be configured.

---

## ZD-02: ObjectTag::rewrite sprintf Stack Buffer Overflow

### Affected: All versions (22.7R2.3, 22.7R2.8, 22.8R2.2)

**Vulnerable Function**: `ObjectTag::rewrite()` in `libdsplibs.so` at offset `0x156500` (10938 bytes)

**Root Cause**: The function uses `sprintf()` with `%s` format to write a user-controlled URL into a dynamically-sized stack buffer:

```
Format: "<param name='neoteris-doc-base' value='%s' />"
```

The stack buffer is allocated via `sub %edx, %esp` (dynamic stack allocation). If the URL exceeds the allocated buffer, `sprintf()` overwrites saved registers and the return address.

**Exploitation (22.8R2.2 saml-server)**:
- **NO Stack Canary**, **NO PIE** (fixed base: `0x08048000`)
- NX enabled (ROP required)

**Complete ROP Chain** (execve syscall, no libc needed):
```
pop ebx; ret        @ 0x080b3ac5  ->  0x0820d701 ("/bin/sh")
pop ecx; ret         @ 0x08173773  ->  0x00000000 (argv = NULL)
pop edx; ret         @ 0x0804db3f  ->  0x00000000 (envp = NULL)
mov eax, 0xb; ret    @ 0x0814c950  (SYS_execve = 11)
int 0x80             @ 0x0804b3e8  (trigger syscall)
```

**Limitation**: Requires authenticated VPN Web Proxy session. Not zero-auth.

---

## ZD-03: saml-endpoint.cgi Unsafe Taint-Washing Regex

### Affected: 22.7R2.3, 22.7R2.8 (Fixed in 22.8R2.2)

**File**: `/dana-na/auth/saml-endpoint.cgi` (PRE-AUTH endpoint)

```perl
my $cmd = "/bin/cat " . $file;
my ($command) = ($cmd =~ /([a-zA-Z0-9 \/.\-\_|]+)/);
my $o_fd = popen(*DUMP, $command, "r");
```

The character class includes pipe `|` (shell command separator). Mitigated by `DSSafe::popen()` internal metacharacter check, but represents a defense-in-depth failure.

**R2.2 Fix**: Complete rewrite with `File::Temp::tempfile()`, strict regex `^[a-zA-Z0-9_-]+$`, `MAX_PARAM_LEN => 32`, and `DSSafe::open()`.

---

## ZD-04: SAML Pre-Signature Data Processing

### Affected: 22.8R2.2

**Binary**: `saml-server` (NO Canary, NO PIE)

In `fcn.080fc220`, the SAML consumer handler performs memcpy, XMLString::transcode, XMLObjectBuilder operations on attacker-controlled XML **690 instructions before** signature verification at `0x080fd2e8`.

**Impact**: Heap-based exploitation via type confusion or vtable corruption. Combined with NO Canary + NO PIE = potentially exploitable.

**Prerequisite**: SAML authentication must be configured.

---

## ZD-05: Systemic Binary Hardening Deficiency

### Affected: 22.7R2.3

**ALL** network-facing binaries lack stack canaries and FORTIFY:

| Binary | Canary | PIE | RELRO | Dangerous Imports |
|--------|--------|-----|-------|------------------|
| web | NO | Yes | Partial | memcpy, DSStr::sprintf |
| saml-server | NO | NO | Partial | sprintf, strcpy, execv, popen |
| proxy-server | NO | NO | Partial | sprintf, strcpy, strcat |
| rewrite-server | NO | NO | Partial | sprintf, strcpy, strcat |
| browse-server | NO | NO | Partial | memcpy |
| filter-server | NO | NO | Partial | memcpy |
| cache_server | NO | NO | Partial | memcpy |

---

## ZD-06 through ZD-09: Additional Findings

- **ZD-06**: Hardcoded watchdog credentials (`neoteriswatchdogprocess`/`danastreet`) in login.cgi
- **ZD-07**: `generateRandomToken` uses only 32 bits of entropy from 128-bit urandom read
- **ZD-08**: X-Forwarded-For spoofing affects failed login recording and CSRF bypass
- **ZD-09**: OAuth consumer SSRF via direct `state` parameter concatenation to `localhost:7300`

---

## Analysis Methodology

### Attack Surfaces Exhaustively Analyzed

1. **web binary HTTP parser** - 7 memcpy, 2 strtol, 6 strncasecmp. All heap-targeted.
2. **IF-T/TLS protocol handler** - 6 memcpy with DSStr heap buffers and 0x800 assert limit.
3. **EAP-over-HTTP** - OOB read via missing length validation. Downstream RADIUS has 14 bounded memcpy.
4. **SAML consumer pipeline** - memcpy to MemoryManager heap, memmove with DSStr reserve.
5. **libdsplibs.so** - 40 system() + 8 popen() sites traced. All admin-only callers.
6. **CGI authentication architecture** - URL zone enforcement in C++ web binary.
7. **Content-Length parsing** - Digit-only validation with cmovs negative guard.
8. **Transfer-Encoding handling** - Server drops malformed CL.TE/TE.CL cleanly.

### Tools Used

- radare2, ROPgadget, checksec, curl, custom Python scripts
- QEMU lab: Ivanti ICS 22.7R2.8 at 127.0.0.1:20443

---

## Recommendations

1. Enable stack canaries and FORTIFY_SOURCE for ALL binaries
2. Enable PIE for saml-server (currently fixed base 0x08048000)
3. Add EAP packet length validation in R2.3 (or upgrade to R2.8+)
4. Verify SAML signature before any data processing
5. Increase token entropy in generateRandomToken
6. Remove hardcoded credentials from login.cgi
7. Sanitize X-Forwarded-For before using as client IP
