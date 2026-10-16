#!/usr/bin/env python3
"""Send yourself a real sign-in code and see exactly what happened.

    python scripts/check_otp_delivery.py --email you@gmail.com
    python scripts/check_otp_delivery.py --phone +919876543210

This is the "is it actually wired up?" command. It reports, without guessing:

* which gateway the deployment picked (and, if none, every variable it looked
  for — a misconfigured relay is the usual reason a code never arrives),
* whether the gateway accepted the message, its message id, and the provider's
  own error text when it refused,
* the code that was generated *only* when the deployment is outside production
  and the code was not really delivered (the labelled demo path).

Exit code is 0 only when a real gateway accepted the message.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services import otp  # noqa: E402


def _status_line(channel: str) -> str:
    status = otp.delivery_status(channel)
    if status["real"]:
        return f"{channel}: real gateway → {status['provider']}"
    if status["demo"]:
        return (f"{channel}: NO gateway configured — development demo only "
                f"(the code is shown in the response, nothing is sent)")
    return f"{channel}: NO gateway configured, and the demo is disabled → 503 in production"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--email", help="address to send a real code to")
    target.add_argument("--phone", help="E.164 number, e.g. +919876543210")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    channel = "email" if args.email else "phone"
    address = args.email or args.phone

    report = otp.delivery_report()
    if args.json:
        print(json.dumps({"channel": channel, "delivery": report}, indent=2))
    else:
        print("Configured delivery:")
        print("  " + _status_line("email"))
        print("  " + _status_line("phone"))
        print(f"  production={report['production']} demo_mode={report['demo_mode']} "
              f"ttl={report['ttl_s']}s resend={report['resend_cooldown_s']}s")
        print(f"\nSending a real {channel} code to {address} …")

    try:
        result = otp.request_code(channel, address, client_ip="127.0.0.1")
    except otp.OtpError as exc:
        print(f"\n✗ {exc.__class__.__name__} (HTTP {exc.status_code}): {exc}")
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"  via={result['via']} delivered={result['delivered']} demo={result['demo']}")
        if result.get("dev_code"):
            print(f"\n⚠️  DEMO — nothing was sent. The code is {result['dev_code']}\n"
                  "    Configure a gateway (see docs/deploy/DEPLOYMENT.md) and run"
                  " this again.")
        else:
            print("\n✓ The gateway accepted the message — check the device/mailbox"
                  " now. It expires in"
                  f" {result['ttl_s'] // 60} minutes.")

    if result["delivered"]:
        code = None
        for entry in otp.dev_inbox(address, limit=1):
            code = entry.get("code")
        suffix = f" (dev inbox code: {code})" if code else ""
        print(f"\nVerify it end to end with:\n  curl -s localhost:8000/api/auth/otp/verify"
              f" -H 'content-type: application/json' -d"
              f" '{{\"channel\":\"{channel}\",\"address\":\"{address}\",\"code\":\"<the code>\"}}'{suffix}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
