UNIVERSAL_RULES = [
    {
        'id': 'UNI001',
        'title': 'Hardcoded Password',
        'severity': 'CRITICAL',
        'pattern': r'(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
        'description': 'A password appears to be hardcoded in source. '
                       'Credentials should be loaded from environment variables or a secrets manager.',
        'cwe': 'CWE-259'
    },
    {
        'id': 'UNI002',
        'title': 'Hardcoded API Key or Token',
        'severity': 'CRITICAL',
        'pattern': r'(api_key|apikey|api_token|secret_key|auth_token)\s*=\s*["\'][^"\']{6,}["\']',
        'description': 'An API key or token appears hardcoded. '
                       'Secrets should never be stored in source code.',
        'cwe': 'CWE-798'
    },
    {
        'id': 'UNI003',
        'title': 'Hardcoded IP Address',
        'severity': 'LOW',
        'pattern': r'\b(\d{1,3}\.){3}\d{1,3}\b',
        'description': 'A hardcoded IP address was detected. '
                       'Network addresses should be configurable, not embedded in code.',
        'cwe': 'CWE-547'
    },
    {
        'id': 'UNI004',
        'title': 'TODO / FIXME Security Note',
        'severity': 'LOW',
        'pattern': r'(TODO|FIXME|HACK|XXX).{0,40}(auth|security|crypt|password|token|secret|vuln)',
        'description': 'A TODO or FIXME comment references a security-sensitive area. '
                       'These should be resolved before shipping.',
        'cwe': ''
    },
    {
        'id': 'UNI005',
        'title': 'Private Key Material',
        'severity': 'CRITICAL',
        'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'description': 'Private key material detected in source. '
                       'Keys must never be committed to a codebase.',
        'cwe': 'CWE-321'
    },
]