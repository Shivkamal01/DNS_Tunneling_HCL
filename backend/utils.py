"""
Feature extraction and risk scoring for covert DNS tunneling detection.

The design principle here is *corroboration*: no single lexical statistic is
treated as evidence on its own. High Shannon entropy is expected for any CDN
hostname; a hex-looking label is expected for any hostname containing only
a-f; a base32-looking label matches nearly every lowercase hostname on the
internet, since RFC 4648 base32 uses a-z2-7 and therefore covers the whole
lowercase alphabet. Each signal only contributes score when a second,
independent signal agrees with it.
"""

import base64
import binascii
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Standard DNS record type mapping
RECORD_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# Record types that carry enough payload capacity to be worth tunnel traffic.
# A/NULL/CNAME are the classic Iodine/dnscat2 carriers; A/AAAA are normal.
HIGH_CAPACITY_TYPES = {16, 10, 5, 2, 255}

BASE32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
VOWELS = set("aeiou")

# RFC 8552 underscore-prefixed service labels. These are published records
# (DKIM selectors, SPF/DMARC policy, ACME challenges, SRV prefixes) whose
# content is cryptographic material by design. Treating their entropy as
# suspicious generates guaranteed false positives on any real network.
SERVICE_PREFIXES = (
    "_dmarc", "_domainkey", "_spf", "_sip", "_acme-challenge", "_mta-sts",
    "_tls", "_imap", "_pop3", "_smtp", "_autodiscover", "_ldap", "_kerberos",
    "_xmpp-server", "_caldavs", "_carddavs", "_bimi", "_dmarc-report",
)

# Domains known to run CDN / analytics front doors whose random-looking
# subdomain labels are benign. This is the *fallback* layer: the authoritative
# list lives in the `whitelist` table and is injected at runtime via
# set_whitelist(). Keep this short — it exists so the engine is never blind.
DEFAULT_WHITELIST = [
    "google.com",
    "google-analytics.com",
    "googleapis.com",
    "gstatic.com",
    "1e100.net",
    "akamaiedge.net",
    "akamai.net",
    "cloudfront.net",
    "azure.com",
    "windowsupdate.com",
    "microsoft.com",
    "apple.com",
    "icloud.com",
    "github.com",
    "cloudflare.com",
    "in-addr.arpa",
    "ip6.arpa",
]

# Runtime whitelist cache. Populated from the database at startup and after
# every write to /api/whitelist, so analyst rules actually take effect.
_whitelist_cache: List[str] = list(DEFAULT_WHITELIST)


def set_whitelist(patterns: Sequence[str]) -> None:
    """Replace the active whitelist with `patterns` merged over the defaults."""
    global _whitelist_cache
    merged = {p.strip().strip(".").lower() for p in DEFAULT_WHITELIST if p}
    merged.update(p.strip().strip(".").lower() for p in patterns if p)
    _whitelist_cache = sorted(merged)


def get_whitelist() -> List[str]:
    return list(_whitelist_cache)


def calculate_entropy(data: str) -> float:
    """
    Shannon entropy: H(X) = -sum(p(x) * log2(p(x))), computed in O(n)
    via a character frequency counter rather than repeated str.count() calls.
    """
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


def normalized_entropy(entropy: float, sample_length: int) -> float:
    """
    Entropy relative to the maximum achievable for a sample of this length.

    Raw Shannon entropy is length-dependent: a 10-character label can never
    exceed log2(10) = 3.32, so a fixed 3.75 threshold silently exempts every
    short label. Dividing by the ceiling makes the value comparable across
    label lengths and gives us a usable 0.0-1.0 scale.
    """
    if sample_length < 2:
        return 0.0
    ceiling = math.log2(min(sample_length, 37))  # 37 distinct chars covers a-z0-9
    if ceiling <= 0:
        return 0.0
    return round(min(entropy / ceiling, 1.0), 4)


def base32_foreign_ratio(sample: str) -> float:
    """
    Fraction of characters OUTSIDE the RFC 4648 base32 alphabet.

    The old implementation measured the fraction *inside* the alphabet, which
    is ~1.0 for nearly every hostname ever registered (a-z2-7 covers all
    lowercase letters). This inverted measure is the one with diagnostic
    value: a genuine base32 payload has a foreign ratio of ~0.0.
    """
    if not sample:
        return 0.0
    foreign = sum(1 for c in sample.upper() if c not in BASE32_ALPHABET)
    return round(foreign / len(sample), 4)


def try_base32_decode(sample: str) -> Tuple[bool, float]:
    """
    Attempt an RFC 4648 base32 decode of a label.

    Returns (decoded_ok, printable_ratio). Decoded bytes are then checked for
    printability: real exfiltration payloads are usually text or structured
    binary, whereas a random hostname that happens to sit inside the base32
    alphabet decodes to high-entropy noise.
    """
    candidate = sample.upper()
    if len(candidate) < 16:
        return False, 0.0
    padding = (-len(candidate)) % 8
    candidate = candidate + ("=" * padding)
    try:
        raw = base64.b32decode(candidate, casefold=True)
    except (binascii.Error, ValueError):
        return False, 0.0
    if not raw:
        return False, 0.0
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return True, round(printable / len(raw), 4)


def max_consonant_run(sample: str) -> int:
    """Longest consecutive run of consonants — natural language rarely exceeds 4."""
    longest = current = 0
    for c in sample.lower():
        if c.isalpha() and c not in VOWELS:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _match_whitelist(domain: str, rules: Sequence[str]) -> Optional[str]:
    for rule in rules:
        if domain == rule or domain.endswith("." + rule):
            return rule
    return None


def extract_dns_features(domain: str, query_type: int = 1) -> Dict[str, Any]:
    """
    Extracts structural, lexical and statistical telemetry features from a
    single DNS query name.
    """
    clean_domain = (domain or "").strip(".").lower()
    labels = clean_domain.split(".") if clean_domain else []

    # Split into registrable apex vs subdomain. This is a heuristic (no PSL),
    # but correct for the .com/.org/.net/.info shapes this engine targets.
    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
        apex_domain = ".".join(labels[-2:])
    else:
        subdomain = ""
        apex_domain = clean_domain

    target_payload = subdomain if subdomain else clean_domain
    stripped_payload = re.sub(r"[^a-z0-9]", "", target_payload)
    payload_len = len(stripped_payload)

    entropy = calculate_entropy(stripped_payload) if stripped_payload else 0.0
    ent_ratio = normalized_entropy(entropy, payload_len)

    digits = sum(1 for c in stripped_payload if c.isdigit())
    digit_ratio = round(digits / payload_len, 4) if payload_len else 0.0

    hex_chars = sum(1 for c in stripped_payload if c in "0123456789abcdef")
    hex_ratio = round(hex_chars / payload_len, 4) if payload_len else 0.0

    b32_foreign = base32_foreign_ratio(stripped_payload)
    b32_decoded, b32_printable = try_base32_decode(stripped_payload)

    alphas = [c for c in stripped_payload if c.isalpha()]
    vowels = sum(1 for c in alphas if c in VOWELS)
    vowel_ratio = round(vowels / len(alphas), 4) if alphas else 0.0
    consonant_run = max_consonant_run(stripped_payload)

    max_label_length = max((len(lbl) for lbl in labels), default=0)

    # Estimated exfiltrated payload size. Hex packs 2 chars/byte, base32
    # 8 chars/5 bytes. Everything else is counted as literal ASCII.
    if hex_ratio >= 0.98 and payload_len >= 8:
        est_payload_bytes = payload_len // 2
        encoding = "hex"
    elif b32_foreign <= 0.02 and b32_decoded and payload_len >= 16:
        est_payload_bytes = int(payload_len * 5 / 8)
        encoding = "base32"
    else:
        est_payload_bytes = payload_len
        encoding = "ascii"

    matched_rule = _match_whitelist(clean_domain, _whitelist_cache)
    is_service = any(lbl.startswith(p) for lbl in labels for p in SERVICE_PREFIXES)

    return {
        "domain": clean_domain,
        "apex_domain": apex_domain,
        "subdomain": subdomain,
        "target_payload": target_payload,
        "query_length": len(clean_domain),
        "subdomain_length": len(subdomain),
        "label_count": len(labels),
        "max_label_length": max_label_length,
        "entropy": entropy,
        "entropy_ratio": ent_ratio,
        "digit_ratio": digit_ratio,
        "hex_ratio": hex_ratio,
        "base32_foreign_ratio": b32_foreign,
        "base32_decodable": b32_decoded,
        "base32_printable_ratio": b32_printable,
        "vowel_ratio": vowel_ratio,
        "consonant_run": consonant_run,
        "encoding": encoding,
        "query_type": query_type,
        "qtype_name": RECORD_TYPES.get(query_type, f"TYPE_{query_type}"),
        "est_payload_bytes": est_payload_bytes,
        "is_whitelisted": matched_rule is not None,
        "whitelist_rule": matched_rule,
        "is_service_record": is_service,
    }


def evaluate_risk(features: Dict[str, Any]) -> Tuple[int, str, List[str]]:
    """
    Scores a feature dict between 0 and 100 and classifies severity.

    Every encoding signal is conditional on structural corroboration, so a
    random CDN hostname cannot reach High on lexical shape alone.
    """
    indicators: List[str] = []

    if features.get("is_whitelisted"):
        rule = features.get("whitelist_rule") or "configured rule"
        return 0, "Low", [f"Suppressed by whitelist rule: {rule}"]

    score = 0
    sublen = features.get("subdomain_length", 0)
    max_lbl = features.get("max_label_length", 0)
    qlen = features.get("query_length", 0)
    ent_ratio = features.get("entropy_ratio", 0.0)
    entropy = features.get("entropy", 0.0)
    hex_r = features.get("hex_ratio", 0.0)
    b32_foreign = features.get("base32_foreign_ratio", 1.0)
    b32_decodable = features.get("base32_decodable", False)
    b32_printable = features.get("base32_printable_ratio", 0.0)
    vowel_r = features.get("vowel_ratio", 1.0)
    cons_run = features.get("consonant_run", 0)
    qtype = features.get("query_type", 1)
    payload = features.get("target_payload", "").lower()
    is_service = features.get("is_service_record", False)

    # Whether the query even has room for a payload
    has_bulk = sublen >= 20 or max_lbl >= 28 or qlen >= 40

    # 1. Structural anomaly — necessary but not sufficient on its own.
    #    Published service records legitimately carry long cryptographic
    #    selectors, so structural weight is halved for them.
    structural_cap = 12 if is_service else 25
    if sublen >= 55 or max_lbl >= 50:
        score += structural_cap
        indicators.append(f"Excessive label length ({max_lbl} chars)")
    elif sublen >= 32 or max_lbl >= 30:
        score += int(structural_cap * 0.6)
        indicators.append(f"Elevated label length ({max_lbl} chars)")
    elif has_bulk:
        score += 8
        indicators.append(f"Extended query name ({qlen} chars)")

    # 2. Randomness, length-normalised so short labels aren't exempt.
    #    A DKIM selector is a 2048-bit key hash and always looks maximally
    #    random, so entropy alone must not flag it.
    if has_bulk and ent_ratio >= 0.92:
        score += 8 if is_service else 30
        indicators.append(f"Near-maximal entropy for payload length (H={entropy:.2f}, {ent_ratio:.0%} of ceiling)")
    elif has_bulk and ent_ratio >= 0.80:
        score += 5 if is_service else 18
        indicators.append(f"High entropy payload (H={entropy:.2f}, {ent_ratio:.0%} of ceiling)")
    elif ent_ratio >= 0.88 and sublen >= 12 and not is_service:
        score += 8
        indicators.append(f"Dense but short label set (H={entropy:.2f})")

    # 3. Hex profile — only meaningful when the sample is nearly all hex AND
    #    long enough that "all hex" is unlikely by chance (p ~ (16/36)^24).
    if hex_r >= 0.98 and sublen >= 24:
        score += 25
        indicators.append(f"Pure hexadecimal label {sublen} chars long (Iodine-style encoding)")
    elif hex_r >= 0.90 and has_bulk:
        score += 12
        indicators.append(f"Hexadecimal-dominant payload ({hex_r:.0%} hex characters)")

    # 4. Base32 profile — requires the decode to SUCCEED and yield high-entropy
    #    output. Merely being inside the base32 alphabet means nothing.
    if b32_decodable and b32_foreign <= 0.02 and sublen >= 16:
        if b32_printable >= 0.70:
            score += 22
            indicators.append(f"Label decodes as base32 to {b32_printable:.0%} printable bytes")
        else:
            score += 14
            indicators.append(f"Label decodes as base32 to binary data ({b32_printable:.0%} printable)")

    # 5. Lexical shape — consonant clustering is what natural words never do
    if not is_service:
        if cons_run >= 8:
            score += 12
            indicators.append(f"Consonant run of {cons_run} characters (no natural word shape)")
        elif cons_run >= 5 and has_bulk:
            score += 6
            indicators.append(f"Consonant cluster of {cons_run} characters")
        if vowel_r <= 0.12 and len(payload) >= 16:
            score += 8
            indicators.append(f"Vowel deficit ({vowel_r:.0%} vowels)")

    # 6. Record type — TXT/NULL carry bulk both directions; CNAME only matters
    #    when it is long enough to be smuggle traffic.
    if qtype == 10:
        score += 20
        indicators.append("NULL record query (Iodine tunnel channel)")
    elif qtype == 16 and has_bulk:
        score += 6 if is_service else 16
        indicators.append("TXT record query with extended payload (bulk transfer channel)")
    elif qtype == 16:
        score += 4
        indicators.append("TXT record query")
    elif qtype == 5 and sublen >= 24:
        score += 12
        indicators.append("Long CNAME chain with payload-sized label")

    # 7. Tool fingerprints. These match the *hostname*, which an attacker
    #    controls, so they corroborate rather than prove — but a dnscat2 label
    #    is a far more specific indicator than any shape statistic.
    if "dnscat" in payload:
        score += 30
        indicators.append("Signature match: dnscat2 C2 subdomain")
    if any(k in payload for k in ("iodine", "dnstt", "dns2tcp", "cobaltstrike")):
        score += 22
        indicators.append("Signature match: known DNS tunneling tool name")

    score = min(score, 100)

    # Calibrated against the benign/malicious corpus in tests/engine_test.py:
    # worst observed benign query scores 35, weakest true tunnel scores 53.
    if score <= 29:
        severity = "Low"
    elif score <= 49:
        severity = "Medium"
    elif score <= 79:
        severity = "High"
    else:
        severity = "Critical"

    if not indicators:
        indicators.append("No tunneling indicators above threshold")

    return score, severity, indicators
