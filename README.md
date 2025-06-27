
# PayloadGen   
**A Universal Payload Generator for XSS, SQLi, and Command Injection Testing**  
Designed for penetration testers, CTF players, and security researchers.

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)

---

##  Features

-  Generate advanced payloads for:
  - **XSS** (reflected, stored, DOM-based)
  - **SQL Injection** (error-based, union-based, blind, time-based)
  - **Command Injection** (Linux/Windows)
-  Bypass filters using:
  - Comments (`/**/`)
  - Spacing tricks
  - Obfuscation (`java<!-- -->script`)
-  Encode payloads (Base64, Hex, URL, Unicode)
-  Export payloads to:
  - JSON file
  - CLI output
  - Clipboard
-  Send payloads directly to:
  - **Burp Suite** (file, clipboard, or REST API)
  - **OWASP ZAP** (via proxy + API key)

---

##  Setup

### Requirements

```bash
pip install -r requirements.txt
````

### Directory Structure

```
PayloadGen/
│
├── finalcode.py         # Main script
├── data/
│   ├── xss.json         # Encoded XSS payloads
│   ├── sqli.json        # Encoded SQLi payloads
│   └── cmd_payloads.py  # CMD payloads (Linux/Windows)
```

---

##  Usage

### General Syntax

```bash
python finalcode.py [--xss | --sqli | --cmd] --type=<type> --bypass=<technique> --encode=<method>
```

### Examples

####  Generate Blind SQLi Payloads (Encoded as Hex):

```bash
python finalcode.py --sqli --type=blind --bypass=all --encode=hex
```

####  Generate XSS Payloads (Obfuscated + Clipboard):

```bash
python finalcode.py --xss --obfuscate all --output=clipboard
```

#### Generate CMD Payloads for Linux and Export to JSON:

```bash
python finalcode.py --cmd --platform=linux --output=json
```

---

##  Integration Options

### Burp Suite

* `--burp file`: Save HTTP request for Burp (manual import)
* `--burp clipboard`: Copy request to clipboard
* `--burp api`: Send directly using Burp Suite Pro API

### OWASP ZAP

```bash
python finalcode.py --sqli --type=blind --zap --zap-api-key=your_key --target=http://example.com --param=input
```

---

##  Encoding & Obfuscation

* `--encode`: `base64`, `hex`, `url`, `unicode`
* `--obfuscate`: `comments`, `spacing`, `encoding`, `all`

---

## License

This project is licensed under the [MIT License](LICENSE).

---

##  Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md)

---
## Acknowledgements

* Inspired by: PayloadAllTheThings, SecLists, HackTricks  
* Thanks to: ITSOLERA Cyber Internship (2025) for guidance and mentorship  
* Special mention: Burp Suite and OWASP ZAP integrations for enabling automated testing  
* Built with: Python, Requests, Pyperclip, OWASP ZAP API, Burp Suite Pro API


##  Disclaimer

> This tool is for educational and authorized testing **only**.
> Unauthorized use against systems without consent is **illegal** and unethical.
