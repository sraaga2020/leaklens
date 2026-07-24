"""
LeakLens Comprehensive Vulnerability Showcase
==============================================
INTENTIONALLY INSECURE. For testing security scanners only.
ALL CREDENTIALS ARE FAKE AND RANDOMIZED FOR DEMO PURPOSES.
"""

import os
import sqlite3
import subprocess
import hashlib
import pickle
import random
import logging
import requests
import yaml
import json
import tempfile
from base64 import b64encode

# ============================================================================
# SECTION A: CLOUD CREDENTIALS & API KEYS
# ============================================================================

# AWS Credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_MFA_DEVICE = "arn:aws:iam::123456789012:mfa/user@example.com"

# Azure Credentials
AZURE_STORAGE_CONN = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=V2VsY29tZVRvQXp1cmVTdG9yYWdlQWNjb3VudA==;EndpointSuffix=core.windows.net"
AZURE_ACCOUNT_KEY = "V2VsY29tZVRvQXp1cmVTdG9yYWdlQWNjb3VudA=="
AZURE_AD_CLIENT_SECRET = "aBc1~2defGhiJKlMnOpQrsTuVwXyZ1234_aBcDeFg"

# GCP Service Account (inline JSON)
GCP_SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "my-project-123",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU7dIYabc+FpkW\nFakeKeyDataFakeKeyDataFakeKeyDataFakeKeyData\n-----END PRIVATE KEY-----\n"
}

# Firebase Config
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyD3TQj3WfeqWfVVVqVqVqVqVqVqVqVqVq",
    "authDomain": "myapp-123456.firebaseapp.com",
    "databaseURL": "https://myapp-123456.firebaseio.com",
    "projectId": "myapp-123456",
    "storageBucket": "myapp-123456.appspot.com"
}

# DigitalOcean Token
DIGITALOCEAN_TOKEN = "dop_v1_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7"

# Heroku API Key
HEROKU_API_KEY = "1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p"

# ============================================================================
# SECTION B: SERVICE TOKENS & MESSAGING PLATFORMS
# ============================================================================

# GitHub Token (multiple formats)
GITHUB_PAT = "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"
GITHUB_OAUTH = "gho_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"

# GitLab Token
GITLAB_TOKEN = "glpat-abcdefghij1234567890"

# Slack Token
SLACK_BOT_TOKEN = "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUv"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

# Discord Bot Token
DISCORD_TOKEN = "MTA5MDk5OTA5MDkwOTk5OTkwOQ.GaBcDe.FgHiJkLmNoPqRsTuVwXyZ1234"
DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz"

# Telegram Bot Token
TELEGRAM_BOT_TOKEN = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"

# Twitter API
TWITTER_API_KEY = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
TWITTER_API_SECRET = "1aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJk"
TWITTER_ACCESS_TOKEN = "1234567890-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBc"

# Facebook Access Token
FACEBOOK_ACCESS_TOKEN = "EAABsbCS1iHgBAOZAZBZC8WBZCNCZAZAZAZALZBZAZCNCZAZAZAZALZBZAZCNCZAZAZAZALZBZAZCNwZBZCNCZAZAZAZALZBZAZCN"

# ============================================================================
# SECTION C: PAYMENT & FINANCIAL CREDENTIALS
# ============================================================================

# Stripe Keys
STRIPE_SECRET_KEY = "sk_live_51A2b3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0"
STRIPE_RESTRICTED_KEY = "rk_test_51A2b3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0"

# PayPal Signature
PAYPAL_SIGNATURE = "AFcWxV21C7fd0v3bYYYRCpSSRl31A1234567890AbCdEf"

# Square API Keys
SQUARE_API_KEY = "sq_live_1A2b3C4d5E6f7G8h9i0J1k2L3m4N5o6P"
SQUARE_ACCESS_TOKEN = "sq0atp_1A2b3C4d5E6f7G8h9i0J1k2L3m4N5o6P"

# ============================================================================
# SECTION D: COMMUNICATION & DELIVERY SERVICES
# ============================================================================

# Twilio Credentials
TWILIO_ACCOUNT_SID = "AC1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
TWILIO_AUTH_TOKEN = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"

# SendGrid API Key
SENDGRID_API_KEY = "SG.1a2b3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R9s0T1u2V3w4X5y6Z7a8B9c0D1e2F"

# Mailgun Keys
MAILGUN_API_KEY = "key-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
MAILGUN_WEBHOOK_KEY = "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"

# Mapbox Token
MAPBOX_TOKEN = "pk.eyJ1IjoiZXhhbXBsZSIsImEiOiJjbGFiY2RlZiJ9.1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"

# NPM Token
NPM_TOKEN = "npm_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"

# PyPI Token
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc1CjE4MDU3MDAx"

# ============================================================================
# SECTION E: DATABASE CREDENTIALS & CONNECTION STRINGS
# ============================================================================

# PostgreSQL Connection
POSTGRES_URL = "postgresql://user:password123@db.example.com:5432/mydb"
POSTGRES_PASSWORD = "SuperSecret_Postgres_Pass_123"

# MySQL Connection
MYSQL_URL = "mysql://admin:Root1234!@mysql.internal.com:3306/prod_db"
MYSQL_PASSWORD = "CorrectHorseBatteryStaple"

# MongoDB Connection
MONGODB_URL = "mongodb+srv://admin:secretPassword123@cluster0.abc123.mongodb.net/database"

# Cassandra Configuration
CASSANDRA_CONTACT_POINTS = "cassandra-node-1.cluster.internal,cassandra-node-2.cluster.internal"
CASSANDRA_PASSWORD = "CassandraAdminPass!"

# Redis Configuration
REDIS_URL = "redis://:mySecurePass@redis.prod.internal:6379/0"

# JDBC Connection String
JDBC_CONNECTION = "jdbc:mysql://localhost:3306/mydb?user=admin&password=MyPassword123"

# ODBC Connection
ODBC_STRING = "Driver={SQL Server};Server=sql-server.internal;UID=admin;PWD=SecurePass123!"

# ============================================================================
# SECTION F: AUTHENTICATION & AUTHORIZATION
# ============================================================================

# HTTP Basic Auth (Base64)
BASIC_AUTH = "Basic " + str(b64encode(b"admin:Admin123!")).decode('utf-8')

# Bearer Token
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# JWT Secret (weak)
JWT_SECRET = "my_secret_key_123"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzIwMDAwMDAwfQ.fakeSignatureFakeSignatureFakeSignature"

# Default Credentials
DEFAULT_ADMIN = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"

DEFAULT_ROOT_PASSWORD = "root"

DATABASE_PASSWORD = "Password123"

# ============================================================================
# SECTION G: CRYPTOGRAPHY & WEAK ALGORITHMS
# ============================================================================

# MD5 Hash (weak - vulnerable to collisions)
def insecure_hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# SHA-1 Hash (weak - deprecated)
def insecure_hash_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# Hard-coded Encryption Key (critical)
ENCRYPTION_KEY = "SecureKey123!SecureKey123!SecureK"

# Hard-coded Salt (weak practice)
PASSWORD_SALT = "MySaltValue123!"

# Weak Random for Security
def generate_session_token():
    return str(random.randint(100000, 999999))

# ============================================================================
# SECTION H: PII & SENSITIVE DATA
# ============================================================================

# Social Security Number
USER_SSN = "123-45-6789"

# Credit Card Numbers
VISA_CARD = "4532015112830366"
MASTERCARD = "5425233010103442"
AMEX_CARD = "371449635398431"

# CVV Code
CVV = "123"

# Phone Numbers
US_PHONE = "555-123-4567"
INTL_PHONE = "+1-555-123-4567"

# Passport Number
PASSPORT_NUMBER = "N0012345"

# Driver's License
DRIVERS_LICENSE = "D1234567"

# Private IP Address (network scanning info)
INTERNAL_SERVER = "192.168.1.100"
PRIVATE_SUBNET = "10.0.0.0/8"

# Cryptocurrency Addresses
BITCOIN_ADDRESS = "1A1z7agoat5powLZW210kL1j14Z7z7zo5"
ETHEREUM_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc19e8f4C0e8Dd"

# ============================================================================
# SECTION I: CODE INJECTION VULNERABILITIES
# ============================================================================

# SQL Injection
def vulnerable_sql_query(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username='" + username + "' AND active=1"
    return conn.execute(query).fetchall()

# Command Injection
def vulnerable_command_execution(filename):
    subprocess.run("cat " + filename, shell=True)

# Command Injection via os.system
def dangerous_file_operation(path):
    os.system("rm -rf " + path)

# Path Traversal
def read_user_file(requested_file):
    with open("user_files/" + requested_file) as f:
        return f.read()

# ============================================================================
# SECTION J: INSECURE DESERIALIZATION
# ============================================================================

# Unsafe Pickle
def load_untrusted_pickle(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)  # Unsafe!

# Unsafe YAML
def load_untrusted_yaml(filename):
    with open(filename) as f:
        return yaml.load(f)  # Unsafe!

# ============================================================================
# SECTION K: INSECURE CONFIGURATIONS
# ============================================================================

# Debug Mode Enabled
DEBUG = True
VERBOSE_LOGGING = True

# CORS Misconfiguration
CORS_ALLOWED_ORIGINS = "*"

# SSL/TLS Verification Disabled
def fetch_without_ssl_verify():
    requests.get("https://api.example.com", verify=False)

# Certificate Validation Disabled
def insecure_request():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False

# HTTP Instead of HTTPS (sensitive endpoints)
API_ENDPOINT = "http://api.internal.com/authenticate"
PAYMENT_ENDPOINT = "http://payment.example.com/charge"
ADMIN_ENDPOINT = "http://admin.example.com/settings"

# Hard-coded Server URL
DATABASE_URL = "postgresql://localhost/prod_db"
API_SERVER = "http://10.0.0.50:8080"

# Hard-coded Admin Path
ADMIN_PANEL = "/admin"
MANAGEMENT_CONSOLE = "/wp-admin"

# ============================================================================
# SECTION L: CODE INJECTION & UNSAFE OPERATIONS
# ============================================================================

# Eval (critical)
def evaluate_expression(user_input):
    return eval(user_input)

# Exec (critical)
def execute_user_code(code_string):
    exec(code_string)

# ProcessBuilder / Runtime
def run_system_command(cmd):
    os.system(cmd)

# ============================================================================
# SECTION M: INFORMATION DISCLOSURE
# ============================================================================

# Logging Sensitive Data
def log_user_authentication(username, password):
    logging.info(f"User {username} logged in with password {password}")

def log_api_call(api_key, endpoint):
    logging.debug(f"Calling {endpoint} with API key: {api_key}")

# Exception with Stack Trace
def vulnerable_exception_handling():
    try:
        result = 1 / 0
    except Exception as e:
        logging.error(f"Error occurred: {e}", exc_info=True)

# ============================================================================
# SECTION N: ADDITIONAL RARE & IMPRESSIVE DETECTIONS
# ============================================================================

# Private Key (multiple formats)
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5
FakePrivateKeyFakePrivateKeyFakePrivateKeyFakePrivateKeyFakePrivateKey
-----END RSA PRIVATE KEY-----"""

EC_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGlVaYz7Yna+G2fMCaVVAM5S5SWpHNVq6aFo6BFgOIBoAoGCCqGSM49
FakeECPrivateKeyFakeECPrivateKeyFakeECPrivateKeyFakeECPrivateKeyFake
-----END EC PRIVATE KEY-----"""

PGP_PRIVATE_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG v1.62
hQEMA7lLK1234567890/+DADB1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0
FakePGPPrivateKeyFakePGPPrivateKeyFakePGPPrivateKeyFakePGPPrivateKey
-----END PGP PRIVATE KEY BLOCK-----"""

# High-Entropy Secret Assignment
SECRET_API_CONFIGURATION = "aBc1Def2GhIj3KlMn4OpQr5StUvWxYz6AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp"

# Multiple sensitive patterns in one location
CREDENTIALS_DICT = {
    "api_key": "sk_test_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
    "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "token": "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r",
    "password": "SuperSecretPassword123!"
}

# ============================================================================
# DEMONSTRATION ENTRY POINT
# ============================================================================

def demo():
    """This function intentionally demonstrates all detected vulnerabilities."""
    pass


if __name__ == "__main__":
    demo()

# ==========================================================

# TODO: Remove production password before release.


if __name__ == "__main__":

    debug()