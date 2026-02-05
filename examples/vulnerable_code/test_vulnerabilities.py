"""
Example file with intentional security vulnerabilities for testing SAST scanning.

DO NOT use this code in production!
This file is for testing and demonstration purposes only.
"""

import os
import subprocess
import pickle
from flask import Flask, request, make_response

app = Flask(__name__)

# ============================================================================
# VULNERABILITY 1: SQL Injection
# ============================================================================

def get_user_vulnerable(user_id):
    """
    VULNERABLE: SQL Injection via string concatenation
    CWE-89: Improper Neutralization of Special Elements used in an SQL Command
    """
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    return db.execute(query)


def get_user_safe(user_id):
    """
    SAFE: Using parameterized query
    """
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))


# ============================================================================
# VULNERABILITY 2: Command Injection
# ============================================================================

def ping_host_vulnerable(hostname):
    """
    VULNERABLE: Command injection via subprocess
    CWE-77: Improper Neutralization of Special Elements used in an OS Command
    """
    result = os.system(f"ping -c 4 {hostname}")  # VULNERABLE
    return result


def ping_host_safe(hostname):
    """
    SAFE: Using subprocess with list argument (no shell interpretation)
    """
    result = subprocess.run(['ping', '-c', '4', hostname], capture_output=True)
    return result


# ============================================================================
# VULNERABILITY 3: Hardcoded Secrets
# ============================================================================

# VULNERABLE: Hardcoded API key in source code
API_KEY = "test_api_key_replace_with_real_key_do_not_commit"  # VULNERABLE

# VULNERABLE: Hardcoded database credentials
DB_PASSWORD = "test_password_replace_with_real_password"  # VULNERABLE


def get_api_config_safe():
    """
    SAFE: Load secrets from environment variables
    """
    return {
        'api_key': os.environ.get('API_KEY'),
        'db_password': os.environ.get('DB_PASSWORD')
    }


# ============================================================================
# VULNERABILITY 4: Cross-Site Scripting (XSS)
# ============================================================================

@app.route('/greeting')
def greeting_vulnerable():
    """
    VULNERABLE: Reflected XSS via unsanitized user input
    CWE-79: Improper Neutralization of Input During Web Page Generation
    """
    username = request.args.get('username', '')
    html = f"<h1>Hello, {username}!</h1>"  # VULNERABLE
    return html


@app.route('/greeting-safe')
def greeting_safe():
    """
    SAFE: Using template with auto-escaping (Flask/Jinja2)
    """
    from flask import render_template_string
    username = request.args.get('username', '')
    return render_template_string("<h1>Hello, {{ username }}!</h1>", username=username)


# ============================================================================
# VULNERABILITY 5: Insecure Deserialization
# ============================================================================

@app.route('/load-data')
def load_data_vulnerable():
    """
    VULNERABLE: Unsafe deserialization of user-provided data
    CWE-502: Deserialization of Untrusted Data
    """
    pickled_data = request.args.get('data')
    data = pickle.loads(pickled_data)  # VULNERABLE
    return str(data)


# ============================================================================
# VULNERABILITY 6: Path Traversal
# ============================================================================

def read_file_vulnerable(filename):
    """
    VULNERABLE: Path traversal via unsanitized filename
    CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    """
    path = f"/var/app/files/{filename}"  # VULNERABLE
    with open(path, 'r') as f:
        return f.read()


def read_file_safe(filename):
    """
    SAFE: Validate filename and restrict to safe directory
    """
    # Ensure filename contains only safe characters
    if not filename.replace('_', '').replace('.', '').isalnum():
        raise ValueError("Invalid filename")

    # Ensure no path separators
    if '/' in filename or '\\' in filename:
        raise ValueError("Path separators not allowed")

    path = os.path.join("/var/app/files", filename)

    # Ensure result is within allowed directory
    if not os.path.abspath(path).startswith("/var/app/files/"):
        raise ValueError("Access denied")

    with open(path, 'r') as f:
        return f.read()


# ============================================================================
# VULNERABILITY 7: Weak Cryptography
# ============================================================================

import hashlib

def hash_password_vulnerable(password):
    """
    VULNERABLE: Using MD5 for password hashing (weak and broken)
    CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    """
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE


def hash_password_safe(password):
    """
    SAFE: Using strong password hashing with bcrypt or Argon2
    """
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


# ============================================================================
# VULNERABILITY 8: Information Disclosure via Error Messages
# ============================================================================

@app.route('/user/<user_id>')
def get_user_info_vulnerable(user_id):
    """
    VULNERABLE: Exposing internal details in error messages
    """
    try:
        user = db.get_user(user_id)
        return user.to_json()
    except Exception as e:
        # VULNERABLE: Returning raw error details to user
        return f"Error: {str(e)}", 500  # VULNERABLE


@app.route('/user-safe/<user_id>')
def get_user_info_safe(user_id):
    """
    SAFE: Generic error message, log details internally
    """
    try:
        user = db.get_user(user_id)
        return user.to_json()
    except Exception as e:
        # Log detailed error internally
        app.logger.error(f"Error fetching user {user_id}: {str(e)}")
        # Return generic message to user
        return "An error occurred. Please contact support.", 500


# ============================================================================
# VULNERABILITY 9: Insecure Random Number Generation
# ============================================================================

import random

def generate_token_vulnerable():
    """
    VULNERABLE: Using random module for security-sensitive tokens
    CWE-338: Use of Cryptographically Weak PRNG
    """
    return ''.join([random.choice('abcdef0123456789') for _ in range(32)])  # VULNERABLE


def generate_token_safe():
    """
    SAFE: Using secrets module for cryptographically secure random
    """
    import secrets
    return secrets.token_hex(32)


# ============================================================================
# VULNERABILITY 10: Insecure Direct Object Reference (IDOR)
# ============================================================================

@app.route('/orders/<order_id>')
def get_order_vulnerable(order_id):
    """
    VULNERABLE: No authorization check - any user can access any order
    CWE-639: Insecure Direct Object Reference
    """
    order = db.get_order(order_id)  # VULNERABLE - no authorization check
    return order.to_json()


@app.route('/orders-safe/<order_id>')
def get_order_safe(order_id):
    """
    SAFE: Check that user owns the order before returning it
    """
    order = db.get_order(order_id)
    if order.user_id != current_user.id:
        return "Access denied", 403
    return order.to_json()


if __name__ == '__main__':
    print("This file contains intentional vulnerabilities for testing SAST scanning")
    print("Do NOT use in production!")
