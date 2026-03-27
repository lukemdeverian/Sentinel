CPP_RULES = [
    {
        'id': 'CPP001',
        'title': 'Unsafe strcpy()',
        'severity': 'HIGH',
        'pattern': r'\bstrcpy\s*\(',
        'description': 'strcpy() performs no bounds checking and is a classic source of '
                       'buffer overflow vulnerabilities. Use strncpy() or strlcpy() instead.',
        'cwe': 'CWE-120'
    },
    {
        'id': 'CPP002',
        'title': 'Unsafe gets()',
        'severity': 'CRITICAL',
        'pattern': r'\bgets\s*\(',
        'description': 'gets() is so dangerous it was removed from C11. '
                       'It cannot limit input size and will always be a buffer overflow risk. '
                       'Use fgets() instead.',
        'cwe': 'CWE-242'
    },
    {
        'id': 'CPP003',
        'title': 'Unsafe sprintf()',
        'severity': 'HIGH',
        'pattern': r'\bsprintf\s*\(',
        'description': 'sprintf() does not check destination buffer size. '
                       'Use snprintf() with an explicit size limit.',
        'cwe': 'CWE-120'
    },
    {
        'id': 'CPP004',
        'title': 'Unsafe strcat()',
        'severity': 'HIGH',
        'pattern': r'\bstrcat\s*\(',
        'description': 'strcat() performs no bounds checking. '
                       'Use strncat() or std::string concatenation instead.',
        'cwe': 'CWE-120'
    },
    {
    'id': 'CPP005',
    'title': 'Format String Vulnerability',
    'severity': 'HIGH',
    'pattern': r'\b(printf|fprintf|sprintf|syslog)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
    'description': 'A user-controlled variable may be passed directly as a format string. '
                   'Always use an explicit format: printf("%s", input) not printf(input).',
    'cwe': 'CWE-134'
    },
    {
        'id': 'CPP006',
        'title': 'Unsafe scanf()',
        'severity': 'MEDIUM',
        'pattern': r'\bscanf\s*\(',
        'description': 'scanf() with %s can overflow if input exceeds buffer size. '
                       'Use field-width specifiers like %255s or prefer fgets().',
        'cwe': 'CWE-120'
    },
    {
        'id': 'CPP007',
        'title': 'Use of rand() for Security',
        'severity': 'MEDIUM',
        'pattern': r'\brand\s*\(\s*\)',
        'description': 'rand() is not cryptographically secure. '
                       'For security-sensitive randomness use a CSPRNG.',
        'cwe': 'CWE-338'
    },
    {
        'id': 'CPP008',
        'title': 'Null Pointer Dereference Risk',
        'severity': 'MEDIUM',
        'pattern': r'\bmalloc\s*\([^)]+\)\s*;',
        'description': 'Return value of malloc() is not immediately checked for NULL. '
                       'Dereferencing a NULL pointer causes undefined behavior.',
        'cwe': 'CWE-476'
    },
    {
        'id': 'CPP009',
        'title': 'Use of system()',
        'severity': 'HIGH',
        'pattern': r'\bsystem\s*\(',
        'description': 'system() passes a command to the shell and is vulnerable to '
                       'command injection if any part of the string is user-controlled. '
                       'Use execve() with explicit arguments instead.',
        'cwe': 'CWE-78'
    },
    {
        'id': 'CPP010',
        'title': 'Unsafe memcpy() — Possible Integer Overflow in Size',
        'severity': 'MEDIUM',
        'pattern': r'\bmemcpy\s*\(',
        'description': 'Verify that the size argument to memcpy() cannot overflow or '
                       'exceed the destination buffer. Integer overflow in size '
                       'calculations is a common heap corruption vector.',
        'cwe': 'CWE-131'
    },
    {
        'id': 'CPP011',
        'title': 'Use of strcasecmp() / stricmp()',
        'severity': 'LOW',
        'pattern': r'\b(strcasecmp|stricmp|strnicmp)\s*\(',
        'description': 'These functions are non-standard and behave inconsistently '
                       'across platforms. Use explicit case normalization instead.',
        'cwe': 'CWE-676'
    },
    {
        'id': 'CPP012',
        'title': 'Integer Overflow in Size Calculation',
        'severity': 'HIGH',
        'pattern': r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',
        'description': 'Multiplying two integers for use as a malloc size can overflow, '
                       'resulting in a much smaller allocation than intended. '
                       'Use calloc() or validate sizes before multiplying.',
        'cwe': 'CWE-190'
    },
    {
        'id': 'CPP013',
        'title': 'Unsafe strtok() Usage',
        'severity': 'MEDIUM',
        'pattern': r'\bstrtok\s*\(',
        'description': 'strtok() uses a static internal buffer making it non-reentrant '
                       'and unsafe in multi-threaded code. Use strtok_r() instead.',
        'cwe': 'CWE-362'
    },
    {
        'id': 'CPP014',
        'title': 'Signed/Unsigned Integer Comparison Risk',
        'severity': 'LOW',
        'pattern': r'\bsizeof\s*\([^)]+\)\s*[><=!]+\s*-\d',
        'description': 'Comparing sizeof() result (unsigned) with a negative value '
                       'always evaluates unexpectedly due to implicit conversion. '
                       'Ensure comparisons use consistent signedness.',
        'cwe': 'CWE-195'
    },
    {
        'id': 'CPP015',
        'title': 'Use of atoi() / atof() Without Error Checking',
        'severity': 'MEDIUM',
        'pattern': r'\b(atoi|atof|atol|atoll)\s*\(',
        'description': 'atoi() and related functions return 0 on invalid input with '
                       'no way to distinguish from a legitimate zero value. '
                       'Use strtol() with error checking instead.',
        'cwe': 'CWE-20'
    },
]