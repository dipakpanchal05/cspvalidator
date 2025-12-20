# 🛡️ CSPValidator — Real CSP Exploit Detection & Hardening

CSPValidator is a **practical Content Security Policy (CSP) analysis tool** focused on real-world security impact.

It detects **exploitable CSP directives**, maps them to **real payloads**, generates a **hardened CSP**, and provides a **clear security score** — without noise or false positives.

---

## ✨ Features:

- 🔍 Detects **real CSP misconfigurations**
- 💥 Shows **exploitable directives with payloads**
- 🧱 Generates **OWASP-aligned hardened CSP**
- 📊 CSP **security score (0–100)**
- 🧠 **Diff-based suggestions**
- 💾 Save hardened CSP only (clean output)

---

## 📦 Installation:

```bash
pipx install git+https://github.com/dipakpanchal05/cspvalidator
cspvalidator --help
```

## 🚀 Usage:

### Analyze a domain
```bash
cspvalidator -u example.com
```

### Analyze multiple domains
```bash
cspvalidator -f domains.txt
```

### Analyze raw CSP
```bash
cspvalidator -s "default-src *; script-src 'unsafe-inline'"
```

### Analyze CSP from file
```bash
cspvalidator -s csp.txt
```

### Pipe input
```bash
echo "default-src *; script-src 'unsafe-inline'" | cspvalidator
echo "https://example.com" | cspvalidator
cat csp.txt | cspvalidator

```

---

## 🧪 Output Modes:

### Default (no flags)
Shows:
- Target
- Score
- Vulnerable directives + payloads
- Hardened CSP
- Suggestions

```bash
cspvalidator -u example.com
```

### Only vulnerabilities
```bash
cspvalidator -u example.com -vuln
```

### Only score
```bash
cspvalidator -u example.com -score
```

### Only hardened CSP
```bash
cspvalidator -u example.com -harden
```

### Combined flags
```bash
cspvalidator -u example.com -score -vuln
cspvalidator -u example.com -vuln -harden
```

---

## 💾 Save Hardened CSP:

```bash
cspvalidator -u example.com -o hardened_csp.txt
```

- Saves **only hardened CSP**
- Works on Windows & Linux
- Supports relative and absolute paths

---

## 📊 CSP Score:

- **100** → Strong CSP
- **0** → Broken CSP

Score penalties include:
- `default-src *`
- `script-src 'unsafe-inline'`
- Wildcards
- Missing `object-src`, `base-uri`, `frame-ancestors`

---

## 🧱 Hardened CSP Philosophy:

- Removes insecure values (`*`, `'unsafe-inline'`)
- Preserves domains but **warns**
- Enforces:
  - Nonce + `strict-dynamic`
  - Trusted Types
  - Object isolation
  - Mixed-content protection

Nothing is added unless missing.  
Nothing is suggested unless changed.

---

## 🧠 Suggestions Logic:

Suggestions are generated **only when actual changes occur**:

Example:
```
1. Removed insecure directives: default-src *, script-src 'unsafe-inline'
2. Added missing directives: object-src, base-uri, frame-ancestors
3. Preserved risky domain https://maps.googleapis.com (consider removal)
```

---

## 🔐 OWASP Coverage:

- OWASP CSP Cheat Sheet. [here](https://owasp.org/www-community/controls/Content_Security_Policy)
- DOM XSS mitigation.
- JSONP risk awareness.
- Modern browser enforcement.

---

## 🛠️ Ideal For:

- Pentesters
- Bug bounty hunters
- Security engineers
- CI/CD pipelines
- CSP audits

---

## 👤 Author:

**Made by** `</th3.d1p4k>`  
***Security-first. Real exploits only.***
