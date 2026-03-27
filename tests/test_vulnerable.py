# test_vulnerable.py
# This is a deliberately vulnerable file to verify Sentinel catches real issues

import os
import pickle
import hashlib
import subprocess

# Hardcoded credentials - should never be in source code
password = "supersecret123"
api_key = "sk-abc123xyz987"

# Command injection risk
def run_command(user_input):
    os.system(user_input)
    subprocess.run(user_input, shell=True)

# Arbitrary code execution
def process_input(data):
    eval(data)
    exec(data)

# Unsafe deserialization
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

# Weak hashing
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# SSL verification disabled
def fetch_data():
    import requests
    requests.get("https://example.com", verify=False)

# Debug mode on
DEBUG = True