# Sentinel (Static Security Analyzer)

Sentinel is a command-line static analyzer that scans C, C++, and Python source files to identify vulnerability risks. Sentinel is best used for intaking these files before code reaches final production. The analyzer also matches each risk with its corresponding CWE (Common Weakness Enumeration) identifier.

This project was inspired by tools such as Bandit and Semgrep and is essentially a less sophisticated version of them. Nevertheless, Sentinel is designed to promote secure software development lifecycle (SDLC) as an automated first-pass security check.

---

## Features

- Scans C, C++, and Python source files for any vulnerabilities
- 30 rules across 4 severity levels: CRITICAL, HIGH, MEDIUM, LOW
- CWE mapping on all findings
- Three output formats: console, JSON, HTML
- Per-file breakdown with '--stats'
- False positive mitigation
- Tested against real-world vulnerable code

---

## Installation

No dependencies beyond Python 3. Simply clone the repo and run.
'''bash
git clone https://github.com/username/sentinel.git
cd sentinel
'''


---

## Usage

**Scan a single file:**
```bash
python sentinel.py target.py --format console
```

**Scan an entire directory:**
```bash
python sentinel.py ./my_project --format console
```

**Generate an HTML report:**
```bash
python sentinel.py ./my_project --format html --output report.html
```

**Generate a JSON report (for CI/CD integration):**
```bash
python sentinel.py ./my_project --format json --output report.json
```

**Filter by minimum severity:**
```bash
python sentinel.py ./my_project --severity HIGH
```

**Show per-file breakdown:**
```bash
python sentinel.py ./my_project --format console --stats
```


---

## Example Output
```
=======================================================
  SENTINEL — Static Security Analyzer
=======================================================
  Target : test_vulnerable.py
  Format : console
=======================================================

[CRITICAL] Hardcoded Password  (UNI001)
  File : test_vulnerable.py:10
  Code : password = "supersecret123"
  Info : A password appears to be hardcoded in source.
         Credentials should be loaded from environment
         variables or a secrets manager.
  CWE  : CWE-259

[CRITICAL] Use of eval()  (PY001)
  File : test_vulnerable.py:20
  Code : eval(data)
  Info : eval() executes arbitrary Python code. If any
         part of the input is user-controlled this is
         remote code execution.
  CWE  : CWE-95

=======================================================
  SUMMARY  —  10 finding(s)
=======================================================
  CRITICAL    4
  HIGH        4
  MEDIUM      2
=======================================================
```

---

## Rule Set

### Universal (all languages)

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| UNI001 | Hardcoded Password | CRITICAL | CWE-259 |
| UNI002 | Hardcoded API Key or Token | CRITICAL | CWE-798 |
| UNI003 | Hardcoded IP Address | LOW | CWE-547 |
| UNI004 | TODO/FIXME Security Note | LOW | — |
| UNI005 | Private Key Material | CRITICAL | CWE-321 |

### C / C++

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| CPP001 | Unsafe strcpy() | HIGH | CWE-120 |
| CPP002 | Unsafe gets() | CRITICAL | CWE-242 |
| CPP003 | Unsafe sprintf() | HIGH | CWE-120 |
| CPP004 | Unsafe strcat() | HIGH | CWE-120 |
| CPP005 | Format String Vulnerability | HIGH | CWE-134 |
| CPP006 | Unsafe scanf() | MEDIUM | CWE-120 |
| CPP007 | Weak Randomness via rand() | MEDIUM | CWE-338 |
| CPP008 | Unchecked malloc() Return | MEDIUM | CWE-476 |
| CPP009 | Command Injection via system() | HIGH | CWE-78 |
| CPP010 | memcpy() Integer Overflow Risk | MEDIUM | CWE-131 |
| CPP011 | Non-standard strcasecmp() | LOW | CWE-676 |
| CPP012 | Integer Overflow in malloc Size | HIGH | CWE-190 |
| CPP013 | Unsafe strtok() | MEDIUM | CWE-362 |
| CPP014 | Signed/Unsigned Comparison Risk | LOW | CWE-195 |
| CPP015 | atoi() Without Error Checking | MEDIUM | CWE-20 |

### Python

| ID | Title | Severity | CWE |
|----|-------|----------|-----|
| PY001 | Use of eval() | CRITICAL | CWE-95 |
| PY002 | Use of exec() | CRITICAL | CWE-95 |
| PY003 | Shell Injection via subprocess | HIGH | CWE-78 |
| PY004 | Use of os.system() | HIGH | CWE-78 |
| PY005 | Pickle Deserialization | HIGH | CWE-502 |
| PY006 | Weak Hashing (MD5/SHA1) | MEDIUM | CWE-327 |
| PY007 | SSL Verification Disabled | HIGH | CWE-295 |
| PY008 | Hardcoded DEBUG Mode | MEDIUM | CWE-94 |
| PY009 | assert for Security Checks | MEDIUM | CWE-617 |
| PY010 | SQL Query String Formatting | HIGH | CWE-89 |
| PY011 | raw_input() Usage | MEDIUM | CWE-95 |
| PY012 | yaml.load() Without Loader | HIGH | CWE-502 |
| PY013 | Hardcoded Secret in URL | HIGH | CWE-312 |
| PY014 | tempfile.mktemp() Race Condition | MEDIUM | CWE-377 |
| PY015 | Flask Debug Mode Enabled | HIGH | CWE-94 |

---

## Project Structure
```
sentinel/
├── sentinel.py              # Core scanner and CLI entry point
├── reporter.py              # Console, JSON, and HTML output
├── rules/
│   ├── universal_rules.py   # Language-agnostic patterns
│   ├── cpp_rules.py         # C and C++ vulnerability patterns
│   └── python_rules.py      # Python vulnerability patterns
└── tests/
    ├── test_vulnerable.py   # Python test cases
    └── test_vulnerable.cpp  # C++ test cases
```

---

## Why Sentinel

Most static analysis tools are either too heavyweight to set up quickly or too convoluted to learn from. The beauty of Sentinel is its simplicity; it was designed to be readable where every rule is a plain Python dictionary with an explanation and a CWE reference. Therefore expanding Sentinel is very straightforward, adding a new rule takes less than 10 lines.

It is intentionally designed to plug into a secure SDLC pipeline as a fast, dependency-free first pass before more comprehensive tools run.

---

## Author

Luke Deverian — Computer Science, UC San Diego