from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "coverage", ".next"}
IGNORE_SUFFIXES = {".bak", ".pyc"}
MAX_FILE_SIZE = 1_500_000

@dataclass
class Finding:
    id: str
    file: str
    line: int
    match: str
    rule: str
    category: str
    severity: str
    confidence: str
    description: str
    blast_radius: str
    source: str = "working tree"
    commit: str | None = None
    remediable: bool = False

RULES = [
    # ===================== CLOUD & INFRASTRUCTURE CREDENTIALS =====================
    ("aws_access_key", "Cloud credential", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS access key ID"),
    ("aws_secret_key", "Cloud credential", "critical", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"), "AWS secret access key"),
    ("aws_mfa_serial", "Cloud credential", "high", re.compile(r"(?i)(?:mfa_serial|mfa.serial)\s*[:=]\s*['\"]?arn:aws:iam::\d{12}:mfa/[^\s'\"]+"), "AWS MFA device serial"),
    ("gcp_service_account", "Cloud credential", "critical", re.compile(r"(?i)service.?account.*?json|\"type\"\s*:\s*\"service_account\""), "GCP service account key"),
    ("gcp_private_key", "Cloud credential", "critical", re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----"), "GCP private key"),
    ("azure_connection_string", "Cloud credential", "critical", re.compile(r"DefaultEndpointsProtocol=https?;[^'\"\s]*AccountKey=[A-Za-z0-9+/=]+", re.I), "Azure storage connection string"),
    ("azure_account_key", "Cloud credential", "critical", re.compile(r"(?i)AccountKey\s*[:=]\s*['\"]([A-Za-z0-9+/=]{88})['\"]"), "Azure account key"),
    ("azure_ad_client_secret", "Cloud credential", "critical", re.compile(r"(?i)client[_-]?secret\s*[:=]\s*['\"]([A-Za-z0-9~_-]{34})['\"]"), "Azure AD client secret"),
    ("digitalocean_token", "Cloud credential", "critical", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "DigitalOcean personal access token"),
    ("digitalocean_spaces_key", "Cloud credential", "high", re.compile(r"(?i)digitalocean(?:_|-)spaces(?:_|-)(?:access|secret)[_-]key\s*[:=]\s*['\"]([A-Za-z0-9+/=]{20,})['\"]"), "DigitalOcean Spaces key"),
    ("heroku_api_key", "Cloud credential", "critical", re.compile(r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]([a-f0-9]{8}-[a-f0-9-]+)['\"]"), "Heroku API key"),
    ("firebase_config", "Cloud credential", "high", re.compile(r"(?i)firebase.*?(?:api[_-]?key|auth[_-]?domain|database[_-]?url)\s*[:=]"), "Firebase configuration"),
    ("firebase_private_key", "Cloud credential", "critical", re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----"), "Firebase private key"),
    
    # ===================== API KEYS & SERVICE TOKENS =====================
    ("github_token", "Source-control token", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,255}\b"), "GitHub access token"),
    ("github_app_token", "Source-control token", "critical", re.compile(r"\bghu_[A-Za-z0-9_]{36,255}\b"), "GitHub app token"),
    ("github_pat", "Source-control token", "critical", re.compile(r"(?i)github[_-]?token\s*[:=]\s*['\"]?ghp_[A-Za-z0-9]{36,}"), "GitHub personal access token"),
    ("gitlab_token", "Source-control token", "critical", re.compile(r"\bglpat-[A-Za-z0-9-]{20,}\b"), "GitLab personal access token"),
    ("gitlab_private_token", "Source-control token", "critical", re.compile(r"(?i)gitlab[_-]?(?:private[_-])?token\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]"), "GitLab private token"),
    ("bitbucket_token", "Source-control token", "high", re.compile(r"(?i)bitbucket[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]"), "Bitbucket token"),
    ("slack_token", "Messaging token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("slack_webhook", "Messaging token", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "Slack webhook URL"),
    ("discord_bot_token", "Messaging token", "critical", re.compile(r"\bMTA[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[ -~]+\b"), "Discord bot token"),
    ("discord_webhook", "Messaging token", "high", re.compile(r"https://discordapp\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"), "Discord webhook URL"),
    ("telegram_bot_token", "Messaging token", "high", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{25,}\b"), "Telegram bot token"),
    ("twitter_api_key", "API key", "high", re.compile(r"(?i)twitter[_-]?(?:consumer[_-])?(?:api[_-])?key\s*[:=]\s*['\"]([A-Za-z0-9]{25,})['\"]"), "Twitter API key"),
    ("twitter_api_secret", "API key", "high", re.compile(r"(?i)twitter[_-]?(?:consumer[_-])?secret\s*[:=]\s*['\"]([A-Za-z0-9]{50,})['\"]"), "Twitter API secret"),
    ("twitter_access_token", "API key", "high", re.compile(r"(?i)twitter[_-]?access[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9-]{40,})['\"]"), "Twitter access token"),
    ("facebook_access_token", "API key", "high", re.compile(r"(?i)facebook[_-]?(?:access[_-])?token\s*[:=]\s*['\"]([A-Za-z0-9]{100,})['\"]"), "Facebook access token"),
    ("facebook_app_secret", "API key", "high", re.compile(r"(?i)facebook[_-]?app[_-]?secret\s*[:=]\s*['\"]([a-f0-9]{32})['\"]"), "Facebook app secret"),
    ("google_api_key", "API key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    ("google_oauth_token", "API key", "high", re.compile(r"(?i)google[_-]?oauth[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]"), "Google OAuth token"),
    ("stripe_key", "Payment credential", "critical", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "Stripe secret key"),
    ("stripe_restricted_api_key", "Payment credential", "high", re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "Stripe restricted API key"),
    ("paypal_signature", "Payment credential", "high", re.compile(r"(?i)paypal[_-]?signature\s*[:=]\s*['\"]([A-Za-z0-9]{56})['\"]"), "PayPal signature"),
    ("square_api_key", "Payment credential", "high", re.compile(r"(?i)square[_-]?(?:api[_-])?key\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]"), "Square API key"),
    ("square_access_token", "Payment credential", "high", re.compile(r"sq0[atp]_[A-Za-z0-9_-]{20,}\b"), "Square access token"),
    ("twilio_account_sid", "API key", "high", re.compile(r"\bAC[a-z0-9]{32}\b"), "Twilio account SID"),
    ("twilio_auth_token", "API key", "high", re.compile(r"(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['\"]([a-z0-9]{32})['\"]"), "Twilio auth token"),
    ("sendgrid_api_key", "API key", "high", re.compile(r"\bSG\.[a-zA-Z0-9_-]{66}\b"), "SendGrid API key"),
    ("mailgun_api_key", "API key", "high", re.compile(r"(?i)mailgun[_-]?api[_-]?key\s*[:=]\s*['\"]?key-[a-zA-Z0-9]{32}"), "Mailgun API key"),
    ("mailgun_webhook_key", "API key", "high", re.compile(r"(?i)mailgun[_-]?webhook[_-]?key\s*[:=]\s*['\"]([a-zA-Z0-9_-]{32})['\"]"), "Mailgun webhook key"),
    ("mapbox_token", "API key", "high", re.compile(r"\bpk\.[a-zA-Z0-9_-]{60,}\b"), "Mapbox access token"),
    ("npm_token", "Package manager token", "high", re.compile(r"npm_[a-zA-Z0-9]{36}\b"), "NPM token"),
    ("pypi_token", "Package manager token", "high", re.compile(r"pypi-[A-Za-z0-9_-]{30,}\b"), "PyPI token"),
    
    # ===================== AUTHENTICATION & AUTHORIZATION =====================
    ("basic_auth_credentials", "Hard-coded credentials", "high", re.compile(r"(?i)Authorization\s*[:=]\s*['\"]Basic\s+([A-Za-z0-9+/=]{10,})['\"]"), "HTTP Basic authentication"),
    ("bearer_token", "Authentication token", "high", re.compile(r"(?i)(?:Bearer|Authorization)\s+[A-Za-z0-9._~+/-]{20,}"), "Bearer token"),
    ("jwt", "Authentication token", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "JWT token"),
    ("password_assignment", "Password", "high", re.compile(r"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"), "Hard-coded password"),
    ("default_admin_credentials", "Default credentials", "high", re.compile(r"(?i)(?:admin|root|operator)\s*[:=]\s*['\"](?:admin|root|password|12345|password123)['\"]"), "Default credentials"),
    ("default_db_password", "Default credentials", "high", re.compile(r"(?i)(?:database[_-]?)?password\s*[:=]\s*['\"](?:password|Password123|root|[0-9]{4})['\"]"), "Default database password"),
    ("api_key_assignment", "API key", "high", re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_./+=-]{16,})['\"]"), "Hard-coded API key"),
    
    # ===================== PRIVATE KEYS & CERTIFICATES =====================
    ("private_key", "Private key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----"), "Private key material"),
    ("pgp_private_key", "Private key", "critical", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "PGP private key"),
    ("ssl_certificate_key", "Private key", "critical", re.compile(r"-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----"), "SSL/TLS private key"),
    ("pem_private_key", "Private key", "critical", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "PEM private key"),
    ("dsa_private_key", "Private key", "critical", re.compile(r"-----BEGIN DSA PRIVATE KEY-----"), "DSA private key"),
    ("aws_pem_key", "Cloud credential", "critical", re.compile(r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----"), "AWS PEM key pair"),
    
    # ===================== DATABASE & CONNECTION STRINGS =====================
    ("connection_string", "Database credential", "critical", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|cassandra|oracle|sqlserver|mssql)://[^\s'\"`]+", re.I), "Database connection string"),
    ("jdbc_url", "Database credential", "high", re.compile(r"jdbc:(?:mysql|postgresql|oracle|sqlserver)://[^\s'\"`;]+(?:;[^\s'\"`;]+)*"), "JDBC connection string"),
    ("odbc_connection", "Database credential", "high", re.compile(r"(?i)Driver=\{?[A-Za-z0-9\s\-]+\}?;[^'\"]*(?:Server|UID|PWD)[^'\"]*"), "ODBC connection string"),
    ("mongodb_connection", "Database credential", "critical", re.compile(r"mongodb(?:\+srv)?://(?:[^:]+):(?:[^@]+)@[^\s/]+(?:/[^\s'\"`;]*)?"), "MongoDB connection string"),
    ("cassandra_connection", "Database credential", "high", re.compile(r"(?i)cassandra[_-]?(?:host|cluster|contact)[_-]?points?\s*[:=]\s*['\"]([^'\"]+)['\"]"), "Cassandra connection"),
    ("mysql_password", "Database credential", "high", re.compile(r"(?i)mysql[_-]?password\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), "MySQL password"),
    ("postgres_password", "Database credential", "high", re.compile(r"(?i)(?:postgres|postgresql)[_-]?password\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), "PostgreSQL password"),
    
    # ===================== CRYPTOGRAPHY & WEAK ALGORITHMS =====================
    ("md5_hash_usage", "Weak cryptography", "high", re.compile(r"(?i)(?:md5|hashlib\.md5|Crypto\.Hash\.MD5|MessageDigestAlgorithm\.MD5)"), "MD5 usage (weak)"),
    ("sha1_usage", "Weak cryptography", "high", re.compile(r"(?i)(?:sha1|SHA-1|hashlib\.sha1|Crypto\.Hash\.SHA1)"), "SHA-1 usage (weak)"),
    ("des_usage", "Weak cryptography", "high", re.compile(r"(?i)(?:DES|TripleDES|3DES|Crypto\.Cipher\.DES)"), "DES usage (very weak)"),
    ("hardcoded_encryption_key", "Weak cryptography", "critical", re.compile(r"(?i)(?:encryption[_-]?key|secret[_-]?key|cipher[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9+/=]{16,})['\"]"), "Hard-coded encryption key"),
    ("hardcoded_salt", "Weak cryptography", "high", re.compile(r"(?i)salt\s*[:=]\s*['\"]([A-Za-z0-9+/=]{8,})['\"]"), "Hard-coded salt value"),
    ("weak_random", "Weak cryptography", "high", re.compile(r"(?i)(?:random\.|Math\.random|rand\(\)|random\.random|uuid\.uuid4\(\))(?!.{0,30}(?:secrets|SystemRandom|secureRandom|SecureRandom|os\.urandom|cryptography))"), "Weak randomness"),
    ("no_random_seeding", "Weak cryptography", "medium", re.compile(r"(?i)(?:random\.seed\((?:time|os\.time|System\.currentTimeMillis)\(\)\)|srand\(time\(NULL\)\))"), "Time-based random seed"),
    
    # ===================== PERSONALLY IDENTIFIABLE INFORMATION (PII) =====================
    ("ssn_number", "PII", "high", re.compile(r"\b(?!000|666|9\d{2})\d{3}-?\d{2}-?\d{4}\b"), "Social Security Number (SSN)"),
    ("credit_card_visa", "PII", "high", re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"), "Visa credit card number"),
    ("credit_card_mastercard", "PII", "high", re.compile(r"\b5[1-5][0-9]{14}\b"), "Mastercard credit card number"),
    ("credit_card_amex", "PII", "high", re.compile(r"\b3[47][0-9]{13}\b"), "American Express card number"),
    ("credit_card_general", "PII", "high", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b"), "Credit card number"),
    ("cvv_code", "PII", "medium", re.compile(r"(?i)(?:cvv|cvc|csv|cid)[\"'\s]*[:=]\s*['\"]?\d{3,4}['\"]?"), "CVV/CVC code"),
    ("phone_number_us", "PII", "medium", re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"), "US phone number"),
    ("phone_number_intl", "PII", "medium", re.compile(r"\+\d{1,3}[-.\s]?\d{1,14}\b"), "International phone number"),
    ("passport_number", "PII", "high", re.compile(r"(?i)(?:passport|pasport)[\"'\s]*[:=]\s*['\"]?[A-Z0-9]{6,9}['\"]?"), "Passport number"),
    ("drivers_license", "PII", "high", re.compile(r"(?i)(?:driver.{0,5}license|dl)[\"'\s]*[:=]\s*['\"]?[A-Z0-9]{5,8}['\"]?"), "Driver's license number"),
    ("ipv4_address_private", "Infrastructure info", "medium", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "Private IPv4 address"),
    ("bitcoin_address", "Cryptocurrency", "medium", re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"), "Bitcoin address"),
    ("ethereum_address", "Cryptocurrency", "medium", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "Ethereum address"),
    
    # ===================== CODE INJECTION & INSECURE PATTERNS =====================
    ("sql_injection_pattern", "Code injection", "high", re.compile(r"(?i)(?:execute|query|sql)\s*\(['\"].*?[\+\s].*?['\"].*?\)"), "SQL query concatenation (SQL injection risk)"),
    ("command_injection_pattern", "Code injection", "high", re.compile(r"(?i)(?:exec|system|subprocess|os\.system|popen)\s*\(['\"].*?[\+\s].*?['\"]"), "Command execution with concatenation"),
    ("path_traversal_pattern", "Code injection", "high", re.compile(r"(?i)(?:open|read|write|file)['\"].*?\$['\"].*?['\"]"), "Path traversal pattern"),
    ("pickle_deserialization", "Insecure deserialization", "critical", re.compile(r"(?i)(?:pickle\.load|cPickle\.load|dill\.load)\s*\("), "Unsafe pickle deserialization"),
    ("yaml_deserialization", "Insecure deserialization", "high", re.compile(r"(?i)yaml\.(?:load|full_load|unsafe_load)\s*\((?!.*?Loader\s*=\s*yaml\.SafeLoader)"), "Unsafe YAML deserialization"),
    ("unserialize_usage", "Insecure deserialization", "high", re.compile(r"(?i)unserialize\s*\("), "PHP unserialize (unsafe)"),
    
    # ===================== INSECURE CONFIGURATIONS =====================
    ("debug_mode_enabled", "Configuration", "high", re.compile(r"(?i)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|ON)"), "Debug mode enabled"),
    ("cors_allow_all", "Configuration", "high", re.compile(r"(?i)Access-Control-Allow-Origin\s*[:=]\s*['\"\*'\"]"), "CORS allows all origins"),
    ("ssl_verify_disabled", "Configuration", "high", re.compile(r"(?i)(?:verify|ssl)[_-]?(?:verify|cert)\s*[:=]\s*(?:False|false|0|NO)"), "SSL/TLS verification disabled"),
    ("cert_validation_disabled", "Configuration", "high", re.compile(r"(?i)(?:insecure_skip_verify|verifySSLCerts|rejectUnauthorized)\s*[:=]\s*(?:True|true|false|no)"), "Certificate validation disabled"),
    ("http_instead_of_https", "Configuration", "medium", re.compile(r"(?i)http://(?:api|auth|login|admin|account|mail|payment)"), "HTTP instead of HTTPS for sensitive endpoint"),
    ("hardcoded_server_url", "Configuration", "medium", re.compile(r"(?i)(?:server|api|endpoint|base)[_-]?(?:url|uri)\s*[:=]\s*['\"](?:http|ws)://[^\s'\"]+['\"]"), "Hard-coded server URL"),
    ("hardcoded_admin_path", "Configuration", "medium", re.compile(r"(?i)(?:admin|management|console)\s*[:=]\s*['\"](?:/admin|/management|/wp-admin|/phpmyadmin)['\"]"), "Hard-coded admin path"),
    
    # ===================== LOGGING & ERROR HANDLING =====================
    ("log_sensitive_data", "Information disclosure", "high", re.compile(r"(?i)(?:print|log|console\.log|logger\.(?:info|debug|warn))\s*\(['\"].*?(?:password|token|secret|key|api|credential)['\"]"), "Logging sensitive data"),
    ("exception_with_stack_trace", "Information disclosure", "medium", re.compile(r"(?i)except|catch|rescue.*?(?:print|log|echo|raise).*?(?:traceback|stack|exception)"), "Exception info exposed in logs"),
    
    # ===================== PACKAGE & DEPENDENCY ISSUES =====================
    ("eval_usage", "Code injection", "critical", re.compile(r"(?i)(?:eval|exec|System\.eval|Runtime\.getRuntime|ProcessBuilder)\s*\("), "Use of eval/exec (code injection risk)"),
    
    # ===================== GENERIC SECRETS =====================
    ("generic_secret", "Generic secret", "medium", re.compile(r"(?i)(?:^|[^A-Za-z0-9])(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_./+=-]{16,})['\"]"), "Hard-coded secret assignment"),
    ("high_entropy_secret", "Generic secret", "medium", re.compile(r"(?i)\b(?:secret|token|key)\w*\s*[:=]\s*['\"]([A-Za-z0-9+/=_-]{24,})['\"]"), "High-entropy value assignment"),
]

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(c) / len(value)) * math.log2(value.count(c) / len(value)) for c in set(value))

def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 10:
        return "•" * len(value)
    return f"{value[:5]}{'•' * min(10, len(value) - 9)}{value[-4:]}"

def _blast(category: str, severity: str) -> str:
    messages = {
        "Cloud credential": "Someone could potentially access cloud resources, create costly services, or read protected storage under this identity.",
        "Database credential": "Someone could connect to the database, view or alter records, and potentially move through systems that trust it.",
        "Payment credential": "Someone could make API calls against your payment account. Rotate it immediately and review payment-provider logs.",
        "Private key": "Someone with this key may be able to impersonate a service or decrypt traffic protected by its matching public key.",
        "Source-control token": "Someone could access repositories or automation within the token’s granted permissions.",
        "Authentication token": "Someone may be able to act as the token’s owner until it expires or is revoked.",
        "Password": "Someone could sign in wherever this password is accepted, especially if it is reused elsewhere.",
    }
    return messages.get(category, "Someone could use this value to call the associated service or access data within its permissions.")

def _confidence(line: str, rule: str, value: str) -> str:
    lower = line.lower()
    if any(word in lower for word in ("example", "sample", "dummy", "fixture", "mock", "redacted", "changeme", "placeholder")):
        return "low"
    if rule in {"password_assignment", "generic_secret"} and _entropy(value) < 3.2:
        return "medium"
    return "high"

def _finding(path: str, line_no: int, line: str, rule: tuple, match: str, source: str, commit: str | None) -> Finding:
    name, category, severity, _, description = rule
    digest = hashlib.sha256(f"{source}|{commit}|{path}|{line_no}|{name}|{match}".encode()).hexdigest()[:16]
    confidence = _confidence(line, name, match)
    supported = Path(path).suffix.lower() in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
    # Most inline credentials can safely be replaced by an environment lookup.
    # Private-key blocks remain manual: their multiline storage format requires
    # provider-specific rotation and a deliberate key-management decision.
    return Finding(digest, path, line_no, _mask(match), name, category, severity, confidence, description, _blast(category, severity), source, commit, source == "working tree" and supported and name != "private_key")

def scan_text(path: str, text: str, source: str = "working tree", commit: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule in RULES:
            for found in rule[3].finditer(line):
                raw = found.group(1) if found.lastindex else found.group(0)
                findings.append(_finding(path, line_no, line, rule, raw, source, commit))
        # Catch only clearly random values assigned to a sensitive variable.
        assignment = re.search(r"(?i)\b(?:secret|token|key)\w*\s*[:=]\s*['\"]([A-Za-z0-9+/=_-]{24,})['\"]", line)
        if assignment and _entropy(assignment.group(1)) >= 4.1:
            rule = ("high_entropy_secret", "Generic secret", "medium", re.compile(""), "High-entropy secret assignment")
            findings.append(_finding(path, line_no, line, rule, assignment.group(1), source, commit))
    # Remove duplicate detection on the same line/value; prefer the strongest severity.
    seen: set[tuple[str, int, str]] = set()
    return [f for f in findings if not ((f.file, f.line, f.match) in seen or seen.add((f.file, f.line, f.match)))]

def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.parts) or path.suffix.lower() in IGNORE_SUFFIXES or not path.is_file():
            continue
        try:
            if path.stat().st_size <= MAX_FILE_SIZE:
                yield path
        except OSError:
            continue

def scan_worktree(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        try:
            raw = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(scan_text(str(path.relative_to(root)), raw))
    return findings

def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL, timeout=25)

def scan_history(root: Path, limit: int = 60) -> list[Finding]:
    try:
        commits = _git(root, "rev-list", f"--max-count={limit}", "HEAD").splitlines()
    except (subprocess.SubprocessError, OSError):
        return []
    findings: list[Finding] = []
    for commit in commits:
        try:
            files = _git(root, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines()
        except subprocess.SubprocessError:
            continue
        for file in files:
            if any(part in IGNORE_DIRS for part in Path(file).parts):
                continue
            try:
                content = _git(root, "show", f"{commit}:{file}")
            except subprocess.SubprocessError:
                continue
            findings.extend(scan_text(file, content, "git history", commit[:10]))
    return findings

def serialize(findings: list[Finding]) -> list[dict]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return [asdict(f) for f in sorted(findings, key=lambda item: (order[item.severity], item.file, item.line))]
