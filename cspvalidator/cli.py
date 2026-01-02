#!/usr/bin/env python3
import argparse
import sys
import requests
import random

# BANNERS
BANNERS = [
r"""
   _____  _____ _____   __      __   _ _     _       _             
  / ____|/ ____|  __ \  \ \    / /  | (_)   | |     | |            
 | |    | (___ | |__) |  \ \  / /_ _| |_  __| | __ _| |_ ___  _ __ 
 | |     \___ \|  ___/    \ \/ / _` | | |/ _` |/ _` | __/ _ \| '__|
 | |____ ____) | |         \  / (_| | | | (_| | (_| | || (_) | |   
  \_____|_____/|_|          \/ \__,_|_|_|\__,_|\__,_|\__\___/|_|   
                                                                   
""",
r"""
       (   (                                             
   (   )\ ))\ )              (     (           )         
   )\ (()/(()/(   (   (    ) )\(   )\ )   ) ( /(    (    
 (((_) /(_))(_))  )\  )\( /(((_)\ (()/(( /( )\())(  )(   
 )\___(_))(_))   ((_)((_)(_))_((_) ((_))(_)|_))/ )\(()\  
((/ __/ __| _ \  \ \ / ((_)_| |(_) _| ((_)_| |_ ((_)((_) 
 | (__\__ \  _/   \ V // _` | || / _` / _` |  _/ _ \ '_| 
  \___|___/_|      \_/ \__,_|_||_\__,_\__,_|\__\___/_|   
                                                                                                                            
""",
r"""
   ___________ ____     _    __      ___     __      __            
  / ____/ ___// __ \   | |  / /___ _/ (_)___/ /___ _/ /_____  _____
 / /    \__ \/ /_/ /   | | / / __ `/ / / __  / __ `/ __/ __ \/ ___/
/ /___ ___/ / ____/    | |/ / /_/ / / / /_/ / /_/ / /_/ /_/ / /    
\____//____/_/         |___/\__,_/_/_/\__,_/\__,_/\__/\____/_/     
                                                                                                                                      
""",
r"""
   ___ ___ ___  __   __    _ _    _      _           
  / __/ __| _ \ \ \ / /_ _| (_)__| |__ _| |_ ___ _ _ 
 | (__\__ \  _/  \ V / _` | | / _` / _` |  _/ _ \ '_|
  \___|___/_|     \_/\__,_|_|_\__,_\__,_|\__\___/_|  
                                                                                                                        
"""
]

def banner():
    print(random.choice(BANNERS))
    print("             by </th3.d1p4k>\n")

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

# Analyzer
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

# Harden CSP + diff
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
        suggestions.append("Removed insecure directives: " + ", ".join(removed))

    if added:
        suggestions.append("Added missing directives: " + ", ".join(added))

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
        print("\nHardened CSP:\n" + render(hardened))

        if not args.harden:
            print("\nSuggestions:")
            for i, s in enumerate(suggestions, 1):
                print(f"{i}. {s}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(render(hardened))

# SIMPLE HELP
def usage():
    print("""
Usage:

INPUT:
  -u <url>              Scan CSP from URL
  -f <file>             Scan URLs from file [HTTP probed]
  -s <csp|string|file>  Scan raw CSP or CSP file
  
OPTIONS:
  -vuln                 Show vulnerable directives + payloads
  -score                Show CSP score
  -harden               Show hardened CSP
  -o <file|path>        Save hardened CSP only

EXAMPLES:
  cspvalidator -u https://example.com -score -vuln
  cspvalidator -f urls.txt -vuln
  cspvalidator -s "default-src *; script-src 'unsafe-inline'"
""")
    sys.exit(0)

# ===============================
# CLI
# ===============================
def main():
    banner()
    if len(sys.argv) == 1 or any(x in sys.argv for x in ("-h", "--help")):
        usage()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-u", "--url")
    parser.add_argument("-f", "--file")
    parser.add_argument("-s", "--string")
    parser.add_argument("-o", "--output")
    parser.add_argument("-score", action="store_true")
    parser.add_argument("-vuln", action="store_true")
    parser.add_argument("-harden", action="store_true")
    args = parser.parse_args()
    
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
