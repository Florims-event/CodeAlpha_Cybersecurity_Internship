# Task 3: Secure Coding Review

**CodeAlpha Cybersecurity Internship**

## 1. Overview

This task is a security review of the source code of a web application. I selected **Python** (Flask) and audited a deliberately vulnerable training application using two methods: **static analysis** with Bandit and **manual code inspection**. This report documents the vulnerabilities found, explains the risk of each, and gives remediation steps and secure coding best practices.

## 2. Scope and Target

| Item | Detail |
|---|---|
| Language | Python 3 |
| Framework | Flask |
| Application | VulnLab, an intentionally vulnerable Flask training application |
| Source | https://github.com/Maha1503/vulnlab |
| Version reviewed (commit) | `9b057fe9e5c3a5158885ff319fc209c0a9c78720` |
| Main file reviewed | `app.py` (269 lines, 201 lines of code as counted by Bandit) |
| Review type | White-box source code review. The application was **not run**. |

The target is a training application built to contain security flaws, so reviewing it is safe and lawful. The target's code is not copied into this repository. To reproduce the review, clone it from the link above and check out the commit listed.

![Downloading the target and recording the commit](screenshots/01-download-target.png)

## 3. Methodology

1. **Download and record the version.** The repository was cloned and the exact commit recorded.
2. **Static analysis.** Bandit scanned the code for known insecure patterns.
3. **Manual inspection.** Every flagged line was read in context, and the rest of `app.py` was read to find problems that a scanner cannot detect.
4. **Triage.** Each finding was rated by severity, mapped to a CWE (Common Weakness Enumeration) and given a fix.

### Tools

| Tool | Version |
|---|---|
| Kali Linux (VM) | 2026.2 |
| Python | 3.13.12 |
| Bandit | 1.9.4 |

![Bandit version](screenshots/02-bandit-version.png)

### Commands used

```bash
git clone https://github.com/Maha1503/vulnlab.git target
git -C target rev-parse HEAD
sudo apt install -y bandit
bandit -r target -x target/static/uploads -f txt  -o reports/bandit-report.txt
bandit -r target -x target/static/uploads -f json -o reports/bandit-report.json
cat -n target/app.py | sed -n '59,64p;129,131p'     # manual inspection
```

The folder `target/static/uploads` was excluded because it holds a sample file uploaded to the demo app, not application code.

## 4. Results Summary

Bandit reported **15 issues** in 201 lines of code.

| Severity | Count |
|---|---|
| High | 5 |
| Medium | 5 |
| Low | 5 |

By confidence: High 8, Medium 2, Low 5. Full output is in [`reports/bandit-report.txt`](reports/bandit-report.txt) and [`reports/bandit-report.json`](reports/bandit-report.json).

![Bandit scan summary](screenshots/03-bandit-scan-summary.png)

Manual inspection found weaknesses that Bandit did not report at all (F-03, F-08, F-09 and F-10) and important parts of three more findings that Bandit only partly caught (the file upload checks in F-04, the SSRF in F-05, and the API key and private key in F-06). This shows why static analysis and manual review should be used together.

## 5. Findings

| ID | Finding | Severity | CWE | Location in `app.py` | Found by |
|---|---|---|---|---|---|
| F-01 | SQL injection | High | CWE-89 | 62, 130 | Bandit (B608) and manual |
| F-02 | OS command injection | High | CWE-78 | 88, 93, 101 | Bandit (B605) and manual |
| F-03 | Incomplete input filter (blocklist) | Medium | CWE-184 | 98 | Manual |
| F-04 | Unsafe file upload and file handling | High | CWE-434, CWE-22, CWE-78 | 156 to 187 | Manual, Bandit (B605 at 185, 187) |
| F-05 | Server-side request forgery (SSRF) and missing timeouts | High | CWE-918, CWE-400 | 206 to 247 | Manual, Bandit (B113 at 228, 235, 244) |
| F-06 | Hardcoded credentials and keys | High | CWE-798 | 53, 259, 262 to 266 | Bandit (line 53), manual (others) |
| F-07 | Flask debug mode enabled | High | CWE-94 | 269 | Bandit (B201) |
| F-08 | Security headers deliberately removed | Medium | CWE-693 | 25 to 27 | Manual |
| F-09 | Missing authentication on admin page | High | CWE-306 | 34 to 36 | Manual |
| F-10 | Detailed error and query output | Low | CWE-209 | 132, 139 | Manual |

### How the 15 Bandit results map to the findings

| Line | Bandit test | Severity | Finding |
|---|---|---|---|
| 4 | B404 (subprocess import) | Low | Informational, see F-02 |
| 53 | B105 (hardcoded password) | Low | F-06 |
| 62 | B608 (SQL string building) | Medium | F-01 |
| 93 | B605 (shell process) | High | F-02 |
| 101 | B605 (shell process) | High | F-02, F-03 |
| 109 | B607 and B603 (subprocess) | Low | Reviewed, low risk (fixed arguments) |
| 114 | B603 (subprocess) | Low | Reviewed, lower risk (no shell) but host is unvalidated |
| 130 | B608 (SQL string building) | Medium | F-01 |
| 185 | B605 (shell process) | High | F-04 |
| 187 | B605 (shell process) | High | F-04 |
| 228, 235, 244 | B113 (no timeout) | Medium | F-05 |
| 269 | B201 (debug=True) | High | F-07 |

---

### F-01: SQL injection (High, CWE-89)

**Where:** line 62 (login) and line 130 (`/user` lookup).

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**Risk:** User input is pasted directly into the database query, so the database cannot tell the program's instructions from the user's data. An attacker can change the meaning of the query to bypass login or read data that should be private. Bandit rated this Medium with low confidence, but manual review confirms the input is fully attacker-controlled, so the real risk is High.

**Remediation:** use parameterized queries, and store password hashes instead of plain passwords.

```python
row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
if row and check_password_hash(row["password_hash"], password):
    ...  # login succeeds
```

![SQL and command injection code](screenshots/04-sql-and-command-injection-code.png)

### F-02: OS command injection (High, CWE-78)

**Where:** lines 88 and 93 (ping feature) and line 101.

```python
base_cmd = f"ping -c 1 {host}"
output = subprocess.getoutput(base_cmd)
```

**Risk:** `host` comes from the user and is placed into a command string that the system shell runs. An attacker can add extra commands after the host name and have the server run them.

**Remediation:** never build a command string. Validate the input, pass arguments as a list, do not use a shell, and set a timeout.

```python
import ipaddress, re, subprocess

HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

def valid_host(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME.fullmatch(value))

if not valid_host(host):
    error = "Invalid host"
else:
    result = subprocess.run(["ping", "-c", "1", host],
                            capture_output=True, text=True, timeout=5)
```

### F-03: Incomplete input filter (Medium, CWE-184)

**Where:** line 98.

```python
if ";" in host or "&&" in host or "|" in host:
```

**Risk:** The code tries to stop injection by blocking three characters. A blocklist like this always misses something, because the shell has many other ways to chain commands. The comment calls it "basic injection prevention", but it gives a false sense of safety. Bandit flags the shell call on line 101 but cannot judge the filter.

**Remediation:** replace the blocklist with an **allowlist** that accepts only valid host names and IP addresses (see the `valid_host` function in F-02).

### F-04: Unsafe file upload and file handling (High, CWE-434, CWE-22, CWE-78)

**Where:** lines 156 to 187.

```python
filename = file.filename
filepath = os.path.join(UPLOAD_FOLDER, filename)
...
if filename.endswith('.png') or filename.endswith('.jpg'):
...
if "os.system" in content:
    os.system(f"whoami > {output_path}")
```

**Risk:**
- The first upload mode accepts any file with no checks.
- The second mode checks only the ending of the file name, not the real content, so a file can be named like an image without being one.
- The user's own file name is used to build the save path without cleaning it, which can let a file be written outside the upload folder (path traversal).
- Files are saved in the `static` folder, which the web server publishes.
- The third mode reads an uploaded file and runs a shell command depending on what the file contains. In this demo the command text is fixed (`whoami`), so the attacker does not choose the command here, but running shell commands based on uploaded content is a dangerous design. Bandit rated lines 185 and 187 High for the shell call.

**Remediation:**

```python
from werkzeug.utils import secure_filename
import os

ALLOWED = {".png", ".jpg", ".jpeg"}
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024        # 2 MB limit
UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")  # outside static/

name = secure_filename(file.filename)
ext = os.path.splitext(name)[1].lower()
if not name or ext not in ALLOWED:
    abort(400)
file.save(os.path.join(UPLOAD_FOLDER, name))
```

Also delete the code that reads uploaded files and runs shell commands. Uploaded content should never be executed.

### F-05: Server-side request forgery and missing timeouts (High, CWE-918, CWE-400)

**Where:** lines 206 to 247, with `requests.get(url)` at lines 228, 235 and 244.

```python
r = requests.get(url)
...
if "169.254.169.254" in url:
    r = requests.get(url)
```

**Risk:**
- The server fetches any web address the user supplies. An attacker can make the server reach internal systems that outsiders cannot reach, such as `localhost` or the cloud metadata service at `169.254.169.254`, which can hold cloud credentials. The code even checks for those addresses and then allows them.
- Bandit found a smaller issue: no `timeout`, so a slow or silent server can make the app wait forever (B113, Medium). Bandit did not detect the SSRF itself.

**Remediation:** allow only approved sites, block private and internal addresses, add a timeout and do not follow redirects.

```python
import socket, ipaddress
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe_url(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or p.hostname not in ALLOWED_HOSTS:
        return False
    for info in socket.getaddrinfo(p.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True

if safe_url(url):
    r = requests.get(url, timeout=5, allow_redirects=False)
```

### F-06: Hardcoded credentials and keys (High, CWE-798)

**Where:** line 53, line 259 and lines 262 to 266.

```python
if username == 'admin' and password == 'admin123':
API_KEY = "SECRET-API-KEY-12345"
PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY----- ... '''
```

**Risk:** Anyone who can read the code, including anyone who finds it in a repository, gets the passwords and keys. Bandit flagged the password on line 53 (B105, Low). **It did not flag the API key or the private key**, which were found by manual inspection. The key in this demo is fake, but a real one would be a serious leak.

**Remediation:** keep secrets out of the code. Load them from environment variables or a secrets manager, and rotate any secret that has ever been committed.

```python
import os
API_KEY = os.environ["API_KEY"]
```

![Secrets, debug mode and SSRF code](screenshots/05-secrets-debug-and-ssrf-code.png)

### F-07: Flask debug mode enabled (High, CWE-94)

**Where:** line 269.

```python
app.run(debug=True)
```

**Risk:** The debug mode shows detailed errors and can provide an interactive console in the browser. If the app is reachable on a network, this can give an attacker a way to run code on the server.

**Remediation:** keep debug off by default and run production apps with a production server such as Gunicorn.

```python
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
```

### F-08: Security headers deliberately removed (Medium, CWE-693)

**Where:** lines 25 to 27.

```python
response.headers['Content-Security-Policy'] = ''
response.headers['X-Frame-Options'] = ''
response.headers['X-Content-Type-Options'] = ''
```

**Risk:** These headers tell the browser to block common attacks such as cross-site scripting, clickjacking and file-type confusion. Setting them to empty values turns that protection off. Bandit does not check this.

**Remediation:** set strict values, or remove the function.

```python
response.headers["Content-Security-Policy"] = "default-src 'self'"
response.headers["X-Frame-Options"] = "DENY"
response.headers["X-Content-Type-Options"] = "nosniff"
```

### F-09: Missing authentication on the admin page (High, CWE-306)

**Where:** lines 34 to 36, and the login labs at lines 46 to 49.

```python
@app.route('/admin')
def admin():
    return render_template('admin.html')
```

**Risk:** The admin page has no check that the visitor is logged in or allowed to see it. Anyone who knows the address can open it. Bandit cannot detect missing access checks.

**Remediation:** require a logged-in session with the right role before showing the page.

```python
from functools import wraps
from flask import session, abort

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")
```

### F-10: Detailed error and query output (Low, CWE-209)

**Where:** line 132 prints the full query to the console, and line 139 sends the raw database error to the user.

**Risk:** Error text can show attackers the database structure and help them refine an attack.

**Remediation:** log the detail on the server and show the user a short generic message.

```python
app.logger.exception("Database error")
return render_template("user.html", error="Something went wrong.")
```

## 6. Secure Coding Best Practices

1. **Never trust input.** Treat everything that comes from a user, a file, a URL or another system as untrusted.
2. **Use parameterized queries** for all database access. Never build queries with string formatting.
3. **Avoid the shell.** Call programs with argument lists and `shell=False`, and validate input with allowlists.
4. **Keep secrets out of source code.** Use environment variables or a secrets manager, and rotate leaked secrets.
5. **Hash passwords** with a modern algorithm such as the ones in `werkzeug.security`, never store them in plain text.
6. **Apply least privilege.** Check authentication and authorization on every sensitive route.
7. **Handle uploads safely.** Limit size and type, clean file names, store files outside the web root and never execute them.
8. **Defend against SSRF.** Allow only approved destinations, block internal addresses, add timeouts and limit redirects.
9. **Turn debug off in production** and show users generic error messages.
10. **Set security headers** such as Content-Security-Policy, X-Frame-Options and X-Content-Type-Options.
11. **Run static analysis in the development pipeline,** then add manual review and tests. Scanners find patterns, not design flaws.
12. **Keep dependencies updated** and set timeouts on every outgoing network call.

## 7. Remediation Priority

| Priority | Findings | Reason |
|---|---|---|
| 1 (fix first) | F-01, F-02, F-04, F-09 | Direct paths to data theft or code execution |
| 2 | F-05, F-06, F-07 | Internal access, leaked secrets and an exposed debugger |
| 3 | F-03, F-08, F-10 | Weak defenses and information leaks |

## 8. Limitations

- The review covered `app.py` and spot checks of the templates. It was a code review only. The application was not run and no exploits were tested.
- Bandit analyses Python only. It does not check the HTML templates, dependency versions or the database.
- Bandit confidence levels vary. Low-confidence results were checked by hand.
- The fixes in this report are recommended code changes. They were not applied to the target or re-scanned.

## 9. Ethical and Responsible Use

The target is an application built for security training and was reviewed on a private virtual machine. Code review techniques should only be used on software you own or have written permission to test.

## 10. Conclusion

The review found 15 Bandit issues and several more weaknesses through manual reading. The most serious are SQL injection, command injection, unsafe file upload, SSRF, hardcoded secrets, debug mode and a missing access check. Static analysis was fast and useful for finding dangerous patterns, but manual inspection found problems the scanner missed, including the leaked API key and private key, the SSRF, the removed security headers and the unprotected admin page. The recommended fixes use parameterized queries, input allowlists, safer process and file handling, secrets management and proper access control.

## 11. Repository Structure

```
Task-3-Secure-Coding-Review/
├── README.md
├── reports/
│   ├── bandit-report.txt
│   └── bandit-report.json
└── screenshots/
    ├── 01-download-target.png
    ├── 02-bandit-version.png
    ├── 03-bandit-scan-summary.png
    ├── 04-sql-and-command-injection-code.png
    └── 05-secrets-debug-and-ssrf-code.png
```
