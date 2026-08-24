"""Regex-based scanner for secrets, credentials, and dangerous function calls.
"""

import re
import os

from .common import walk_files

SENSITIVE_PATTERNS = {
    "Private Key": {
        "Regex": r'(-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY(?: BLOCK)?-----)',
        "Severity": "Critical",
    },
    "AWS Secret Access Key": {
        "Regex": r'aws(?:.{0,20})?(?:secret|key|token).{0,20}?[\'"]([A-Za-z0-9/+=]{40})[\'"]',
        "Severity": "Critical",
    },
    "GitHub Token": {
        "Regex": r'\b(ghp_[0-9a-zA-Z]{36})\b',
        "Severity": "Critical",
    },
    "GitHub Fine-Grained Token": {
        "Regex": r'\b(github_pat_[0-9a-zA-Z_]{82})\b',
        "Severity": "Critical",
    },
    "Google OAuth Token": {
        "Regex": r'\b(ya29\.[0-9A-Za-z\-_]+)\b',
        "Severity": "Critical",
    },
    "Google (GCP) Service Account": {
        "Regex": r'("type":\s*"service_account")',
        "Severity": "Critical",
    },
    "Firebase Cloud Messaging Key": {
        "Regex": r'\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b',
        "Severity": "Critical",
    },
    "Password in URL": {
        "Regex": r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:([^/\s:@]{3,20})@.{1,100}["\'\s]',
        "Severity": "Critical",
    },
    "GitHub Token in URL": {
        "Regex": r'[a-zA-Z0-9_-]*:([a-zA-Z0-9_\-]+)@github\.com',
        "Severity": "Critical",
    },
    "Password": {
        "Regex": r'(?:password|pass|pwd|passwd)\b\s*[:=]\s*[\'"]?([^\s\'"/\\,;<>]{8,})[\'"]?',
        "Severity": "High",
    },
    "Generic API Key": {
        "Regex": r'(?:api_key|apikey|api-key|access_key|access-key|secret_key|secret-key)\b\s*[:=]\s*[\'"]?([a-zA-Z0-9-_.]{20,})[\'"]?',
        "Severity": "High",
    },
    "Dangerous Code Execution": {
        "Regex": r'\b(eval|exec)\s*\(',
        "Severity": "Critical",
    },
    "Dangerous OS Command": {
        "Regex": r'\bos\.(system|popen)\s*\(',
        "Severity": "Critical",
    },
    "Insecure Subprocess": {
        "Regex": r'\bsubprocess\.(?:run|Popen|call|check_output)\b.*shell\s*=\s*True',
        "Severity": "High",
    },
    "Dangerous Deserialization": {
        "Regex": r'\bpickle\.loads\s*\(',
        "Severity": "High",
    },
}


def build_combined_regex():
    name_map = {}
    all_patterns = []
    for i, (name, pattern_info) in enumerate(SENSITIVE_PATTERNS.items()):
        group_name = f'group{i}'
        all_patterns.append(f'(?P<{group_name}>{pattern_info["Regex"]})')
        name_map[group_name] = {"name": name, "severity": pattern_info["Severity"]}

    combined_regex = re.compile('|'.join(all_patterns), re.IGNORECASE)
    return combined_regex, name_map


_REGEX, _NAME_MAP = build_combined_regex()


def check_file(file_path):
    """Scan a single file and return a list of finding dicts."""
    matches = []

    if not os.path.isfile(file_path):
        return matches

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, 1):
                if len(line) > 10000:
                    continue

                for match in _REGEX.finditer(line):
                    group_name = match.lastgroup
                    if not group_name:
                        continue

                    full_match_text = match.group(group_name)
                    pattern_details = _NAME_MAP[group_name]

                    matches.append({
                        "file_path": file_path,
                        "line_number": line_number,
                        "secret": full_match_text.strip(),
                        "name": pattern_details["name"],
                        "severity": pattern_details["severity"],
                        "context": line.strip(),
                    })
    except Exception:
        pass  # 읽을 수 없는 파일은 건너뜀

    return matches


def scan(path, exclude=None):
    """Scan a file or directory tree and return all findings across all files."""
    exclude = exclude or set()
    all_matches = []
    for filepath in walk_files(path, exclude):
        all_matches.extend(check_file(filepath))
    return all_matches
