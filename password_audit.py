#!/usr/bin/env python3
"""
Offline password audit tool.

Audits plaintext password exports, unsalted password hash exports, and policy
exports. It never calls external services.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


BUILTIN_WEAK_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "welcome1",
    "letmein",
    "qwerty",
    "qwerty123",
    "abc123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "summer2024",
    "summer2025",
    "summer2026",
    "winter2024",
    "winter2025",
    "winter2026",
    "spring2024",
    "spring2025",
    "spring2026",
    "fall2024",
    "fall2025",
    "fall2026",
    "company123",
    "changeme",
    "default",
    "temp1234",
    "test123",
}

HASH_SPEED_GUESSES_PER_SECOND = {
    "ntlm": 120_000_000_000,
    "md5": 100_000_000_000,
    "sha1": 45_000_000_000,
    "sha256": 15_000_000_000,
    "sha512": 2_000_000_000,
    "bcrypt": 100_000,
    "unknown": 10_000_000_000,
    "plaintext": 10_000_000_000,
}

PASSWORD_FIELD_NAMES = {"password", "plaintext", "plain_text", "cleartext", "clear_text"}
HASH_FIELD_NAMES = {"hash", "password_hash", "pwd_hash", "nt_hash", "nthash", "md5", "sha1", "sha256", "sha512"}
USER_FIELD_NAMES = {"username", "user", "account", "samaccountname", "name", "email", "upn"}
ALGORITHM_FIELD_NAMES = {"algorithm", "alg", "hash_type", "type"}


@dataclass
class AccountRecord:
    username: str
    source: str
    password: str | None = None
    hash_value: str | None = None
    algorithm: str | None = None
    cracked_password: str | None = None
    cracked_by: str | None = None
    reasons: list[str] = field(default_factory=list)
    crack_time: str | None = None
    length: int | None = None


def md4(data: bytes) -> bytes:
    """Small MD4 implementation used for NTLM hashing."""
    mask = 0xFFFFFFFF

    def lrot(value: int, bits: int) -> int:
        value &= mask
        return ((value << bits) | (value >> (32 - bits))) & mask

    def f(x: int, y: int, z: int) -> int:
        return ((x & y) | (~x & z)) & mask

    def g(x: int, y: int, z: int) -> int:
        return ((x & y) | (x & z) | (y & z)) & mask

    def h(x: int, y: int, z: int) -> int:
        return (x ^ y ^ z) & mask

    message = bytearray(data)
    bit_len = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += bit_len.to_bytes(8, "little")

    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    for offset in range(0, len(message), 64):
        chunk = message[offset : offset + 64]
        x = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d

        s1 = [3, 7, 11, 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = lrot(a + f(b, c, d) + x[k], s1[i % 4])
            elif i % 4 == 1:
                d = lrot(d + f(a, b, c) + x[k], s1[i % 4])
            elif i % 4 == 2:
                c = lrot(c + f(d, a, b) + x[k], s1[i % 4])
            else:
                b = lrot(b + f(c, d, a) + x[k], s1[i % 4])

        s2 = [3, 5, 9, 13]
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, k in enumerate(order2):
            if i % 4 == 0:
                a = lrot(a + g(b, c, d) + x[k] + 0x5A827999, s2[i % 4])
            elif i % 4 == 1:
                d = lrot(d + g(a, b, c) + x[k] + 0x5A827999, s2[i % 4])
            elif i % 4 == 2:
                c = lrot(c + g(d, a, b) + x[k] + 0x5A827999, s2[i % 4])
            else:
                b = lrot(b + g(c, d, a) + x[k] + 0x5A827999, s2[i % 4])

        s3 = [3, 9, 11, 15]
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, k in enumerate(order3):
            if i % 4 == 0:
                a = lrot(a + h(b, c, d) + x[k] + 0x6ED9EBA1, s3[i % 4])
            elif i % 4 == 1:
                d = lrot(d + h(a, b, c) + x[k] + 0x6ED9EBA1, s3[i % 4])
            elif i % 4 == 2:
                c = lrot(c + h(d, a, b) + x[k] + 0x6ED9EBA1, s3[i % 4])
            else:
                b = lrot(b + h(c, d, a) + x[k] + 0x6ED9EBA1, s3[i % 4])

        a = (a + aa) & mask
        b = (b + bb) & mask
        c = (c + cc) & mask
        d = (d + dd) & mask

    return b"".join(part.to_bytes(4, "little") for part in (a, b, c, d))


def ntlm_hash(password: str) -> str:
    return md4(password.encode("utf-16le")).hex()


def normalize_hash(value: str) -> str:
    value = value.strip()
    if ":" in value and re.fullmatch(r"(?i)[a-f0-9]{32}:[a-f0-9]{32}", value):
        value = value.split(":", 1)[1]
    value = re.sub(r"^\{[A-Z0-9-]+\}", "", value, flags=re.I)
    return value.lower()


def detect_algorithm(hash_value: str) -> str:
    value = normalize_hash(hash_value)
    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        return "bcrypt"
    if re.fullmatch(r"[a-f0-9]{32}", value):
        return "md5_or_ntlm"
    if re.fullmatch(r"[a-f0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-f0-9]{64}", value):
        return "sha256"
    if re.fullmatch(r"[a-f0-9]{128}", value):
        return "sha512"
    return "unknown"


def hash_password(password: str, algorithm: str) -> str | None:
    algorithm = algorithm.lower()
    if algorithm == "ntlm":
        return ntlm_hash(password)
    if algorithm in {"md5", "sha1", "sha256", "sha512"}:
        return hashlib.new(algorithm, password.encode("utf-8")).hexdigest()
    return None


def candidate_algorithms(record: AccountRecord) -> list[str]:
    algorithm = (record.algorithm or "").lower().strip()
    if algorithm in {"ntlm", "md5", "sha1", "sha256", "sha512"}:
        return [algorithm]
    detected = detect_algorithm(record.hash_value or "")
    if detected == "md5_or_ntlm":
        return ["ntlm", "md5"]
    if detected in {"sha1", "sha256", "sha512"}:
        return [detected]
    return []


def normalize_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def first_present(row: dict[str, str], names: set[str]) -> str | None:
    normalized = {normalize_header(k): v for k, v in row.items()}
    for name in names:
        if name in normalized and str(normalized[name]).strip():
            return str(normalized[name]).strip()
    return None


def read_accounts(path: Path) -> list[AccountRecord]:
    records: list[AccountRecord] = []
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames:
            return records
        for idx, row in enumerate(reader, start=1):
            username = first_present(row, USER_FIELD_NAMES) or f"row_{idx}"
            password = first_present(row, PASSWORD_FIELD_NAMES)
            hash_value = first_present(row, HASH_FIELD_NAMES)
            algorithm = first_present(row, ALGORITHM_FIELD_NAMES)
            if password or hash_value:
                records.append(
                    AccountRecord(
                        username=username,
                        source=str(path),
                        password=password,
                        hash_value=normalize_hash(hash_value) if hash_value else None,
                        algorithm=algorithm.lower() if algorithm else None,
                    )
                )
        return records

    for idx, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        username = f"line_{idx}"
        hash_value = line
        algorithm = None
        colon_parts = line.split(":")
        if len(colon_parts) >= 4 and re.fullmatch(r"(?i)[a-f0-9]{32}", colon_parts[3]):
            username = colon_parts[0] or username
            hash_value = colon_parts[3]
            algorithm = "ntlm"
        elif len(colon_parts) == 2 and re.fullmatch(r"(?i)[a-f0-9]{32}", colon_parts[0]) and re.fullmatch(r"(?i)[a-f0-9]{32}", colon_parts[1]):
            hash_value = colon_parts[1]
            algorithm = "ntlm"
        if "," in line:
            parts = [part.strip() for part in line.split(",")]
            if len(parts) >= 2:
                username, hash_value = parts[0], parts[1]
                algorithm = parts[2].lower() if len(parts) > 2 and parts[2] else None
        elif algorithm is None and ":" in line and not re.fullmatch(r"(?i)[a-f0-9]{32}:[a-f0-9]{32}", line):
            username, hash_value = line.split(":", 1)
        records.append(
            AccountRecord(
                username=username,
                source=str(path),
                hash_value=normalize_hash(hash_value),
                algorithm=algorithm,
            )
        )
    return records


def load_wordlist(paths: list[Path]) -> dict[str, str]:
    words = {word: "built-in common list" for word in BUILTIN_WEAK_PASSWORDS}
    for path in paths:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            word = raw_line.strip()
            if word and not word.startswith("#"):
                words.setdefault(word, f"wordlist: {path.name}")
    return words


def crack_hashes(records: list[AccountRecord], words: dict[str, str]) -> None:
    lookup: dict[str, tuple[str, str]] = {}
    for password, origin in words.items():
        for algorithm in ("ntlm", "md5", "sha1", "sha256", "sha512"):
            digest = hash_password(password, algorithm)
            if digest:
                lookup.setdefault(f"{algorithm}:{digest}", (password, origin))

    for record in records:
        if record.password:
            record.cracked_password = record.password
            record.cracked_by = "plaintext export"
            continue
        if not record.hash_value:
            continue
        for algorithm in candidate_algorithms(record):
            key = f"{algorithm}:{normalize_hash(record.hash_value)}"
            if key in lookup:
                password, origin = lookup[key]
                record.cracked_password = password
                record.cracked_by = origin
                record.algorithm = algorithm
                break


def character_space(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return max(size, 1)


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return "instant"
    units = [
        ("year", 365 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value >= 100:
                return f"{value:,.0f} {name}s"
            if value >= 10:
                return f"{value:,.1f} {name}s"
            return f"{value:,.2f} {name}s"
    return "instant"


def estimate_crack_time(password: str, algorithm: str | None, override_speed: float | None) -> str:
    speed = override_speed or HASH_SPEED_GUESSES_PER_SECOND.get((algorithm or "unknown").lower(), HASH_SPEED_GUESSES_PER_SECOND["unknown"])
    guesses = character_space(password) ** len(password)
    average_seconds = (guesses / 2) / speed
    return human_duration(average_seconds)


def password_quality_reasons(password: str, weak_words: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    lower = password.lower()
    if lower in {word.lower() for word in weak_words}:
        reasons.append("known weak/common password")
    if len(password) < 12:
        reasons.append("shorter than 12 characters")
    if len(password) < 14:
        reasons.append("below recommended 14-character baseline")
    if re.fullmatch(r"[a-zA-Z]+", password):
        reasons.append("letters only")
    if re.fullmatch(r"[0-9]+", password):
        reasons.append("numbers only")
    if re.search(r"(.)\1\1", password):
        reasons.append("repeated character pattern")
    if re.search(r"(?:password|welcome|admin|qwerty|letmein|changeme)", lower):
        reasons.append("contains a common weak term")
    if re.search(r"(?:19|20)\d{2}$", password):
        reasons.append("ends with a year")
    return reasons


def add_account_findings(records: list[AccountRecord], weak_words: dict[str, str], speed: float | None) -> None:
    hash_groups: dict[str, list[AccountRecord]] = defaultdict(list)
    password_groups: dict[str, list[AccountRecord]] = defaultdict(list)

    for record in records:
        if record.hash_value:
            hash_groups[normalize_hash(record.hash_value)].append(record)
        if record.cracked_password is not None:
            record.length = len(record.cracked_password)
            record.crack_time = estimate_crack_time(record.cracked_password, record.algorithm or "plaintext", speed)
            record.reasons.extend(password_quality_reasons(record.cracked_password, weak_words))
            password_groups[record.cracked_password].append(record)
            if record.cracked_by and record.cracked_by != "plaintext export":
                record.reasons.append(f"matched {record.cracked_by}")

    for group in hash_groups.values():
        if len(group) > 1:
            for record in group:
                record.reasons.append(f"hash reused by {len(group)} accounts")

    for group in password_groups.values():
        if len(group) > 1:
            for record in group:
                record.reasons.append(f"password reused by {len(group)} accounts")

    for record in records:
        record.reasons = sorted(set(record.reasons))


def parse_policy_value(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if re.fullmatch(r"-?\d+", stripped):
            return int(stripped)
        if stripped.lower() in {"true", "false"}:
            return stripped.lower() == "true"
    return value


def flatten_policy(data: Any, prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            clean_key = normalize_header(str(key))
            joined = f"{prefix}_{clean_key}" if prefix else clean_key
            flat.update(flatten_policy(value, joined))
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            flat.update(flatten_policy(value, f"{prefix}_{idx}"))
    else:
        flat[prefix] = parse_policy_value(data)
    return flat


def read_policy(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".json":
        return flatten_policy(json.loads(text))
    if path.suffix.lower() == ".csv":
        rows = list(csv.reader(text.splitlines()))
        if not rows:
            return {}
        if len(rows[0]) >= 2 and normalize_header(rows[0][0]) in {"setting", "key", "name", "policy"}:
            return {normalize_header(row[0]): parse_policy_value(row[1]) for row in rows[1:] if len(row) >= 2}
        if len(rows) == 2:
            return {normalize_header(k): parse_policy_value(v) for k, v in zip(rows[0], rows[1])}
    policy: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
        else:
            continue
        policy[normalize_header(key)] = parse_policy_value(value)
    return policy


def find_policy_number(policy: dict[str, Any], patterns: Iterable[str]) -> int | None:
    compiled = [re.compile(pattern) for pattern in patterns]
    for key, value in policy.items():
        if any(pattern.search(key) for pattern in compiled) and isinstance(value, int):
            return value
    return None


def find_policy_bool(policy: dict[str, Any], patterns: Iterable[str]) -> bool | None:
    compiled = [re.compile(pattern) for pattern in patterns]
    for key, value in policy.items():
        if any(pattern.search(key) for pattern in compiled):
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {"enabled", "true", "yes"}:
                return True
            if isinstance(value, str) and value.lower() in {"disabled", "false", "no"}:
                return False
    return None


def analyze_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    min_length = find_policy_number(policy, [r"min.*length", r"minimum.*password.*length"])
    if min_length is not None and min_length < 14:
        findings.append(
            {
                "severity": "high" if min_length < 10 else "medium",
                "title": "Minimum password length is low",
                "detail": f"Minimum length appears to be {min_length}. Use at least 14 characters and allow passphrases.",
            }
        )

    history = find_policy_number(policy, [r"history", r"remembered"])
    if history is not None and history < 12:
        findings.append(
            {
                "severity": "medium",
                "title": "Password history is shallow",
                "detail": f"Password history appears to be {history}. Consider 12-24 previous passwords to reduce cycling.",
            }
        )

    lockout = find_policy_number(policy, [r"lockout.*threshold", r"bad.*password.*threshold"])
    if lockout is None or lockout == 0:
        findings.append(
            {
                "severity": "high",
                "title": "Account lockout threshold is missing or disabled",
                "detail": "Set a reasonable lockout or smart-lockout threshold to slow password spraying.",
            }
        )
    elif lockout > 10:
        findings.append(
            {
                "severity": "medium",
                "title": "Account lockout threshold is high",
                "detail": f"Threshold appears to be {lockout}. Consider 5-10 attempts with monitoring.",
            }
        )

    lockout_duration = find_policy_number(policy, [r"lockout.*duration"])
    if lockout_duration is not None and lockout_duration < 15:
        findings.append(
            {
                "severity": "medium",
                "title": "Lockout duration is short",
                "detail": f"Lockout duration appears to be {lockout_duration} minutes. Consider at least 15 minutes.",
            }
        )

    reversible = find_policy_bool(policy, [r"reversible.*encryption", r"store.*password.*reversible"])
    if reversible:
        findings.append(
            {
                "severity": "critical",
                "title": "Reversible password storage appears enabled",
                "detail": "Disable reversible password storage except for rare, tightly controlled compatibility needs.",
            }
        )

    complexity = find_policy_bool(policy, [r"complexity", r"password.*must.*meet"])
    if complexity is False:
        findings.append(
            {
                "severity": "low",
                "title": "Complexity rule appears disabled",
                "detail": "Length and breached-password screening matter more than symbol rules, but verify compensating controls exist.",
            }
        )

    return findings


def severity_for_record(record: AccountRecord) -> str:
    joined = " ".join(record.reasons).lower()
    if "known weak" in joined or "matched" in joined or "password reused" in joined:
        return "high"
    if "shorter than 12" in joined or "hash reused" in joined:
        return "medium"
    if record.reasons:
        return "low"
    return "info"


def summarize(records: list[AccountRecord], policy_findings: list[dict[str, str]]) -> dict[str, Any]:
    weak_records = [record for record in records if record.reasons]
    cracked = [record for record in records if record.cracked_password is not None]
    lengths = [record.length for record in cracked if record.length is not None]
    reused_hash_groups = [group for group in defaultdict(list, {}).values()]
    hash_counter = Counter(normalize_hash(record.hash_value) for record in records if record.hash_value)
    password_counter = Counter(record.cracked_password for record in records if record.cracked_password is not None)
    return {
        "accounts_analyzed": len(records),
        "accounts_with_findings": len(weak_records),
        "passwords_known_or_matched": len(cracked),
        "reused_hash_groups": sum(1 for _, count in hash_counter.items() if count > 1),
        "reused_password_groups": sum(1 for _, count in password_counter.items() if count > 1),
        "length_distribution": dict(sorted(Counter(lengths).items())),
        "policy_findings": len(policy_findings),
    }


def record_to_dict(record: AccountRecord, show_passwords: bool) -> dict[str, Any]:
    output = {
        "username": record.username,
        "source": record.source,
        "algorithm": record.algorithm or detect_algorithm(record.hash_value or "") if record.hash_value else record.algorithm,
        "length": record.length,
        "estimated_crack_time": record.crack_time,
        "severity": severity_for_record(record),
        "reasons": record.reasons,
        "matched": bool(record.cracked_password),
        "matched_by": record.cracked_by,
    }
    if record.hash_value:
        output["hash_prefix"] = f"{normalize_hash(record.hash_value)[:8]}..."
    if show_passwords and record.cracked_password is not None:
        output["password"] = record.cracked_password
    return output


def recommendations(summary: dict[str, Any], policy_findings: list[dict[str, str]]) -> list[str]:
    recs = []
    if summary["accounts_with_findings"]:
        recs.append("Reset accounts with weak, reused, or dictionary-matched passwords, starting with administrators and service accounts.")
    if summary["reused_hash_groups"] or summary["reused_password_groups"]:
        recs.append("Eliminate shared passwords; each human, admin, and service identity should have a unique secret.")
    if summary["passwords_known_or_matched"]:
        recs.append("Screen new passwords against breached/common-password lists before accepting them.")
    if policy_findings:
        recs.append("Tune password and lockout policy, then re-run this audit after the next password reset cycle.")
    recs.append("Prefer phishing-resistant MFA for privileged accounts and externally reachable identity flows.")
    recs.append("Store audit input and reports in a restricted location, then delete temporary plaintext exports after review.")
    return recs


def html_report(report: dict[str, Any]) -> str:
    rows = []
    for item in report["accounts"]:
        if not item["reasons"]:
            continue
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['username'])}</td>"
            f"<td>{html.escape(str(item.get('algorithm') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('length') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('estimated_crack_time') or 'unknown'))}</td>"
            f"<td>{html.escape('; '.join(item['reasons']))}</td>"
            "</tr>"
        )
    policy_rows = [
        "<tr>"
        f"<td>{html.escape(item['severity'])}</td>"
        f"<td>{html.escape(item['title'])}</td>"
        f"<td>{html.escape(item['detail'])}</td>"
        "</tr>"
        for item in report["policy_findings"]
    ]
    length_items = "".join(
        f"<li>{html.escape(str(length))} chars: {count}</li>"
        for length, count in report["summary"]["length_distribution"].items()
    )
    rec_items = "".join(f"<li>{html.escape(rec)}</li>" for rec in report["recommendations"])
    generated = html.escape(report["generated_at"])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Audit Report</title>
  <style>
    :root {{ color-scheme: light; --ink:#202124; --muted:#5f6368; --line:#dadce0; --bg:#f8fafd; --panel:#fff; --accent:#0b57d0; }}
    body {{ margin:0; font-family: Arial, Helvetica, sans-serif; color:var(--ink); background:var(--bg); }}
    main {{ max-width:1120px; margin:0 auto; padding:32px 20px 48px; }}
    h1 {{ margin:0 0 6px; font-size:32px; }}
    h2 {{ margin-top:30px; font-size:20px; }}
    .muted {{ color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:12px; margin:22px 0; }}
    .metric {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }}
    .metric b {{ display:block; font-size:26px; color:var(--accent); }}
    table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:14px; }}
    th {{ background:#eef3fb; }}
    ul {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px 22px; }}
  </style>
</head>
<body>
<main>
  <h1>Password Audit Report</h1>
  <div class="muted">Generated {generated}. Password values are hidden unless the tool was run with --show-passwords.</div>
  <section class="grid">
    <div class="metric"><span>Accounts analyzed</span><b>{report["summary"]["accounts_analyzed"]}</b></div>
    <div class="metric"><span>Accounts with findings</span><b>{report["summary"]["accounts_with_findings"]}</b></div>
    <div class="metric"><span>Known or matched passwords</span><b>{report["summary"]["passwords_known_or_matched"]}</b></div>
    <div class="metric"><span>Reused hash groups</span><b>{report["summary"]["reused_hash_groups"]}</b></div>
    <div class="metric"><span>Policy findings</span><b>{report["summary"]["policy_findings"]}</b></div>
  </section>
  <h2>Account Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Account</th><th>Algorithm</th><th>Length</th><th>Est. crack time</th><th>Reasons</th></tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="6">No account findings.</td></tr>'}</tbody>
  </table>
  <h2>Length Distribution</h2>
  <ul>{length_items if length_items else '<li>No plaintext or dictionary-matched passwords available for length analysis.</li>'}</ul>
  <h2>Policy Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead>
    <tbody>{''.join(policy_rows) if policy_rows else '<tr><td colspan="3">No policy findings.</td></tr>'}</tbody>
  </table>
  <h2>Recommendations</h2>
  <ul>{rec_items}</ul>
</main>
</body>
</html>
"""


def build_report(
    account_files: list[Path],
    policy_files: list[Path],
    wordlist_files: list[Path],
    show_passwords: bool,
    speed: float | None,
) -> dict[str, Any]:
    records: list[AccountRecord] = []
    for path in account_files:
        records.extend(read_accounts(path))

    weak_words = load_wordlist(wordlist_files)
    crack_hashes(records, weak_words)
    add_account_findings(records, weak_words, speed)

    policy_findings: list[dict[str, str]] = []
    policy_values: dict[str, Any] = {}
    for path in policy_files:
        policy = read_policy(path)
        policy_values[str(path)] = policy
        policy_findings.extend(analyze_policy(policy))

    summary = summarize(records, policy_findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "accounts": [record_to_dict(record, show_passwords) for record in records],
        "policy_findings": policy_findings,
        "policy_values": policy_values,
        "recommendations": recommendations(summary, policy_findings),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline password hash and policy audit tool.")
    parser.add_argument("--accounts", nargs="+", type=Path, required=True, help="CSV/TXT account export files with password or hash columns.")
    parser.add_argument("--policy", nargs="*", type=Path, default=[], help="Optional password policy exports in JSON, CSV, or key:value text.")
    parser.add_argument("--wordlist", nargs="*", type=Path, default=[], help="Optional weak password wordlist files.")
    parser.add_argument("--out", type=Path, default=Path("password_audit_report.html"), help="HTML report output path.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON report output path.")
    parser.add_argument("--show-passwords", action="store_true", help="Include matched plaintext passwords in JSON output.")
    parser.add_argument("--guesses-per-second", type=float, default=None, help="Override crack-time estimate speed.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    missing = [path for path in [*args.accounts, *args.policy, *args.wordlist] if not path.exists()]
    if missing:
        for path in missing:
            print(f"Missing file: {path}", file=sys.stderr)
        return 2

    report = build_report(args.accounts, args.policy, args.wordlist, args.show_passwords, args.guesses_per_second)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html_report(report), encoding="utf-8")
    json_out = args.json_out or args.out.with_suffix(".json")
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Analyzed {report['summary']['accounts_analyzed']} accounts.")
    print(f"Accounts with findings: {report['summary']['accounts_with_findings']}")
    print(f"HTML report: {args.out}")
    print(f"JSON report: {json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
