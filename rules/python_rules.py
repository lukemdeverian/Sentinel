PYTHON_RULES = [
    {
        'id': 'PY001',
        'title': 'Use of eval()',
        'severity': 'CRITICAL',
        'pattern': r'\beval\s*\(',
        'description': 'eval() executes arbitrary Python code. If any part of the '
                       'input is user-controlled this is remote code execution. '
                       'Use ast.literal_eval() for safe expression parsing.',
        'cwe': 'CWE-95'
    },
    {
        'id': 'PY002',
        'title': 'Use of exec()',
        'severity': 'CRITICAL',
        'pattern': r'\bexec\s*\(',
        'description': 'exec() executes arbitrary Python code and should never '
                       'be used with user-supplied input.',
        'cwe': 'CWE-95'
    },
    {
        'id': 'PY003',
        'title': 'Shell Injection via subprocess',
        'severity': 'HIGH',
        'pattern': r'subprocess\.(call|run|Popen).{0,60}shell\s*=\s*True',
        'description': 'Running subprocess with shell=True and any user-controlled '
                       'data in the command is a command injection vulnerability. '
                       'Pass a list of arguments and use shell=False.',
        'cwe': 'CWE-78'
    },
    {
        'id': 'PY004',
        'title': 'Use of os.system()',
        'severity': 'HIGH',
        'pattern': r'\bos\.system\s*\(',
        'description': 'os.system() passes the command to the shell and is vulnerable '
                       'to injection. Use subprocess with a list of arguments instead.',
        'cwe': 'CWE-78'
    },
    {
        'id': 'PY005',
        'title': 'Pickle Deserialization',
        'severity': 'HIGH',
        'pattern': r'\bpickle\.(loads?|Unpickler)\s*\(',
        'description': 'Deserializing pickle data from an untrusted source allows '
                       'arbitrary code execution. Use JSON or another safe format.',
        'cwe': 'CWE-502'
    },
    {
        'id': 'PY006',
        'title': 'Weak Hashing Algorithm (MD5/SHA1)',
        'severity': 'MEDIUM',
        'pattern': r'hashlib\.(md5|sha1)\s*\(',
        'description': 'MD5 and SHA1 are cryptographically broken. '
                       'Use SHA-256 or stronger for any security-sensitive hashing.',
        'cwe': 'CWE-327'
    },
    {
        'id': 'PY007',
        'title': 'SSL Certificate Verification Disabled',
        'severity': 'HIGH',
        'pattern': r'verify\s*=\s*False',
        'description': 'Disabling SSL certificate verification exposes the connection '
                       'to man-in-the-middle attacks. Never disable in production.',
        'cwe': 'CWE-295'
    },
    {
        'id': 'PY008',
        'title': 'Hardcoded DEBUG Mode',
        'severity': 'MEDIUM',
        'pattern': r'\bDEBUG\s*=\s*True',
        'description': 'DEBUG=True in a web framework (Django, Flask) exposes stack '
                       'traces and config details to end users. Must be False in production.',
        'cwe': 'CWE-94'
    },
    {
        'id': 'PY009',
        'title': 'Use of assert for Security Checks',
        'severity': 'MEDIUM',
        'pattern': r'\bassert\b.{0,60}(auth|permission|admin|role|token|login)',
        'description': 'assert statements are stripped out when Python runs with '
                       'the -O flag. Never use assert for access control or security checks.',
        'cwe': 'CWE-617'
    },
    {
        'id': 'PY010',
        'title': 'SQL Query String Formatting',
        'severity': 'HIGH',
        'pattern': r'(execute|cursor)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE).{0,60}(%s|%d|\+|\.format|f["\'])',
        'description': 'Building SQL queries with string formatting or concatenation '
                       'is a SQL injection vulnerability. Always use parameterized queries.',
        'cwe': 'CWE-89'
    },
    {
        'id': 'PY011',
        'title': 'Use of input() in Python 2 Style',
        'severity': 'MEDIUM',
        'pattern': r'\braw_input\s*\(',
        'description': 'raw_input() is Python 2 only. In Python 2, input() evaluates '
                       'the input as code — equivalent to eval(). Ensure you are using '
                       'Python 3 where input() is safe.',
        'cwe': 'CWE-95'
    },
    {
        'id': 'PY012',
        'title': 'Yaml.load() Without Loader',
        'severity': 'HIGH',
        'pattern': r'yaml\.load\s*\([^,)]+\)',
        'description': 'yaml.load() without an explicit Loader argument can deserialize '
                       'arbitrary Python objects, leading to remote code execution. '
                       'Use yaml.safe_load() instead.',
        'cwe': 'CWE-502'
    },
    {
        'id': 'PY013',
        'title': 'Hardcoded Secret in URL',
        'severity': 'HIGH',
        'pattern': r'https?://[^"\']*:(password|secret|token|key|pass)=[^"\'&\s]{4,}',
        'description': 'A secret, password, or token appears to be embedded directly '
                       'in a URL. Credentials in URLs are logged by servers and proxies.',
        'cwe': 'CWE-312'
    },
    {
        'id': 'PY014',
        'title': 'Use of tempfile.mktemp()',
        'severity': 'MEDIUM',
        'pattern': r'\btempfile\.mktemp\s*\(',
        'description': 'mktemp() has a race condition between file creation and use, '
                       'allowing an attacker to substitute a malicious file. '
                       'Use tempfile.mkstemp() instead.',
        'cwe': 'CWE-377'
    },
    {
        'id': 'PY015',
        'title': 'Flask Debug Mode Enabled',
        'severity': 'HIGH',
        'pattern': r'app\.run\s*\([^)]*debug\s*=\s*True',
        'description': 'Running Flask with debug=True in production exposes an '
                       'interactive debugger that allows arbitrary code execution '
                       'by anyone who can reach the server.',
        'cwe': 'CWE-94'
    },
]