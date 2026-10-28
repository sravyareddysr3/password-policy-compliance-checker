#!/usr/bin/env python3
"""
Password Policy Compliance Checker
----------------------------------
A small defensive tool that audits SYNTHETIC account records against a
configurable password policy and reports which accounts violate which rules.

Defensive design choices:
  * Passwords are never printed or written to reports (only their length).
  * Policy is configurable (JSON) instead of hard-coded.
  * Weak-password check uses a small local denylist (no network calls).
  * Exit code is non-zero when violations are found, so it can run in CI.

Usage:
  python policy_checker.py data/synthetic_accounts.csv
  python policy_checker.py data/synthetic_accounts.csv --policy policy.json \
        --json output/report.json --csv output/report.csv
"""
import argparse
import csv
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import List, Optional

DEFAULT_POLICY = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
    "max_age_days": 365,          # flag stale passwords (0 disables)
    "max_repeat_run": 3,          # e.g. 'aaaa' is a run of 4 (0 disables)
    "forbid_username": True,
    "username_min_len": 3,        # shorter usernames are not substring-checked
    "forbid_common": True,
    "forbid_sequences": True,     # abcd, 1234, qwer ...
}

# Tiny illustrative denylist. In production use a large breached-password list.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "letmein", "welcome", "welcome1", "admin",
    "admin123", "iloveyou", "abc123", "monkey", "dragon", "football",
    "changeme", "passw0rd", "p@ssw0rd", "summer2024", "winter2025",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop",
             "asdfghjkl", "zxcvbnm"]

# Spaces count as symbols so that passphrases such as "correct horse 9 Staple"
# are not penalised.
SYMBOLS = set("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ")
DIGITS = "0123456789"          # ASCII only (str.isdigit() accepts e.g. '\u00b2')

# Common "leetspeak" substitutions, used to catch variants of denylisted words.
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                       "7": "t", "@": "a", "$": "s", "!": "i"})
_TRAILING = DIGITS + "".join(SYMBOLS)

# Keys whose values must be booleans / non-negative integers.
BOOL_KEYS = {"require_upper", "require_lower", "require_digit", "require_symbol",
             "forbid_username", "forbid_common", "forbid_sequences"}
INT_KEYS = {"min_length", "max_age_days", "max_repeat_run", "username_min_len"}


def _variants(pw: str) -> set:
    """Normalised forms of pw: lower-cased, de-leeted, and with trailing
    digits/symbols stripped (so 'Password123!' still matches 'password')."""
    forms = set()
    for base in (pw.lower(), pw.lower().translate(_LEET)):
        forms.add(base)
        stripped = base.rstrip(_TRAILING)
        if stripped:
            forms.add(stripped)
    return forms


COMMON_NORMALIZED = set()
for _p in COMMON_PASSWORDS:
    COMMON_NORMALIZED |= _variants(_p)


def is_common_password(pw: str) -> bool:
    """True if pw (or a trivially modified form of it) is on the denylist."""
    return bool(_variants(pw) & COMMON_NORMALIZED)


@dataclass
class Result:
    username: str
    compliant: bool
    violations: List[str] = field(default_factory=list)
    password_length: int = 0
    password_age_days: Optional[int] = None


def has_sequence(pw: str, length: int = 4) -> bool:
    """True if pw contains an ascending/descending run of `length` chars
    from a known sequence (case-insensitive)."""
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - length + 1):
                if s[i:i + length] in low:
                    return True
    return False


def max_repeat_run(pw: str) -> int:
    best = run = 1 if pw else 0
    for a, b in zip(pw, pw[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best


def parse_date(value: str) -> Optional[date]:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


def check_password(username: str, password: str, last_changed: Optional[str],
                   policy: dict, today: Optional[date] = None) -> Result:
    today = today or date.today()
    v: List[str] = []

    if len(password) < policy["min_length"]:
        v.append(f"Too short ({len(password)} < {policy['min_length']})")
    if policy["require_upper"] and not any(c.isupper() for c in password):
        v.append("Missing uppercase letter")
    if policy["require_lower"] and not any(c.islower() for c in password):
        v.append("Missing lowercase letter")
    if policy["require_digit"] and not any(c in DIGITS for c in password):
        v.append("Missing digit")
    if policy["require_symbol"] and not any(c in SYMBOLS for c in password):
        v.append("Missing symbol")
    if policy["forbid_username"] and username and \
            len(username) >= policy["username_min_len"] and \
            username.lower() in password.lower():
        v.append("Contains the username")
    if policy["forbid_common"] and is_common_password(password):
        v.append("Is a commonly used password")
    if policy["forbid_sequences"] and has_sequence(password):
        v.append("Contains a keyboard/alphabet/number sequence")
    if policy["max_repeat_run"] and \
            max_repeat_run(password) > policy["max_repeat_run"]:
        v.append(f"Repeats a character more than {policy['max_repeat_run']} times in a row")

    age = None
    if last_changed is None or not str(last_changed).strip():
        v.append("Missing last_changed date")
    else:
        d = parse_date(last_changed)
        if d is None:
            v.append("Invalid last_changed date (expected YYYY-MM-DD)")
        elif d > today:
            v.append(f"last_changed date is in the future ({d.isoformat()})")
        else:
            age = (today - d).days
            if policy["max_age_days"] and age > policy["max_age_days"]:
                v.append(f"Password is {age} days old (max {policy['max_age_days']})")

    return Result(username, not v, v, len(password), age)


def load_policy(path: Optional[str]) -> dict:
    policy = dict(DEFAULT_POLICY)
    if path:
        with open(path, encoding="utf-8-sig") as f:
            user = json.load(f)
        if not isinstance(user, dict):
            raise ValueError("Policy file must contain a JSON object")
        unknown = set(user) - set(DEFAULT_POLICY)
        if unknown:
            raise ValueError(f"Unknown policy keys: {sorted(unknown)}")
        policy.update(user)
    validate_policy(policy)
    return policy


def validate_policy(policy: dict) -> None:
    """Reject wrongly-typed values so a bad config fails loudly, not mid-run."""
    for key in BOOL_KEYS:
        if not isinstance(policy[key], bool):
            raise ValueError(f"Policy key '{key}' must be true or false")
    for key in INT_KEYS:
        val = policy[key]
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise ValueError(f"Policy key '{key}' must be a non-negative integer")


def audit_file(csv_path: str, policy: dict, today: Optional[date] = None) -> List[Result]:
    results = []
    # utf-8-sig transparently handles the BOM that Excel adds to CSV files.
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"username", "password", "last_changed"}
        fields = [(n or "").strip() for n in (reader.fieldnames or [])]
        if not required.issubset(fields):
            raise ValueError(f"CSV must have columns: {sorted(required)}")
        reader.fieldnames = fields
        for row in reader:
            if row["username"] is None or row["password"] is None:
                raise ValueError(
                    f"Malformed CSV row at line {reader.line_num}: "
                    "missing username or password field")
            # last_changed may be absent/blank: check_password flags that.
            results.append(check_password(row["username"], row["password"],
                                          row["last_changed"], policy, today))
    return results


def print_report(results: List[Result]) -> None:
    total = len(results)
    bad = [r for r in results if not r.compliant]
    print("=" * 64)
    print("PASSWORD POLICY COMPLIANCE REPORT (synthetic data)")
    print("=" * 64)
    for r in results:
        status = "PASS" if r.compliant else "FAIL"
        print(f"[{status}] {r.username:<12} (length={r.password_length})")
        for msg in r.violations:
            print(f"        - {msg}")
    print("-" * 64)
    rate = (100 * (total - len(bad)) / total) if total else 0
    print(f"Accounts checked : {total}")
    print(f"Compliant        : {total - len(bad)}")
    print(f"Non-compliant    : {len(bad)}")
    print(f"Compliance rate  : {rate:.1f}%")


def write_json(results: List[Result], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (cells starting = + - @)."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_csv(results: List[Result], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "compliant", "password_length",
                    "password_age_days", "violations"])
        for r in results:
            w.writerow([_csv_safe(r.username), r.compliant, r.password_length,
                        r.password_age_days,
                        _csv_safe("; ".join(r.violations))])


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Audit synthetic accounts against a password policy.")
    p.add_argument("input_csv")
    p.add_argument("--policy", help="JSON file overriding default policy")
    p.add_argument("--json", help="write JSON report to this path")
    p.add_argument("--csv", help="write CSV report to this path")
    p.add_argument("--today", help="override today's date (YYYY-MM-DD) for reproducible output")
    args = p.parse_args(argv)

    today = None
    if args.today:
        today = parse_date(args.today)
        if today is None:
            print(f"Error: invalid --today value {args.today!r} (expected YYYY-MM-DD)",
                  file=sys.stderr)
            return 2
    try:
        policy = load_policy(args.policy)
        results = audit_file(args.input_csv, policy, today)
    except (OSError, ValueError) as e:   # JSONDecodeError is a ValueError
        print(f"Error: {e}", file=sys.stderr)
        return 2

    print_report(results)
    if args.json:
        write_json(results, args.json)
    if args.csv:
        write_csv(results, args.csv)
    return 1 if any(not r.compliant for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
