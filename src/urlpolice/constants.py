"""Security constants for URL validation.

This module defines all constant values used across the urlpolice package,
including private IP ranges, cloud metadata endpoints, dangerous schemes,
and attack detection patterns.
"""

from ipaddress import IPv4Network, IPv6Network

# ---------------------------------------------------------------------------
# Private / reserved IPv4 ranges (RFC 1918, RFC 5737, RFC 6598, etc.)
# ---------------------------------------------------------------------------
PRIVATE_IPV4_RANGES: list[IPv4Network] = [
    IPv4Network("0.0.0.0/8"),
    IPv4Network("10.0.0.0/8"),
    IPv4Network("100.64.0.0/10"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.0.0.0/24"),
    IPv4Network("192.0.2.0/24"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("198.18.0.0/15"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
    IPv4Network("255.255.255.255/32"),
]

# ---------------------------------------------------------------------------
# Private / reserved IPv6 ranges
# ---------------------------------------------------------------------------
PRIVATE_IPV6_RANGES: list[IPv6Network] = [
    IPv6Network("::1/128"),
    IPv6Network("::/128"),
    IPv6Network("::ffff:0:0/96"),
    IPv6Network("::ffff:0:0:0/96"),
    IPv6Network("64:ff9b::/96"),
    IPv6Network("100::/64"),
    IPv6Network("2001::/32"),
    IPv6Network("2001:10::/28"),
    IPv6Network("2001:db8::/32"),
    IPv6Network("fc00::/7"),
    IPv6Network("fe80::/10"),
    IPv6Network("ff00::/8"),
]

# ---------------------------------------------------------------------------
# Cloud provider metadata endpoints (SSRF targets)
# ---------------------------------------------------------------------------
CLOUD_METADATA_ENDPOINTS: set[str] = {
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",
}

# ---------------------------------------------------------------------------
# URL scheme classification
# ---------------------------------------------------------------------------
DANGEROUS_SCHEMES: set[str] = {
    "file",
    "ftp",
    "ftps",
    "tftp",
    "gopher",
    "dict",
    "javascript",
    "data",
    "vbscript",
    "about",
    "jar",
    "mailto",
    "news",
    "nntp",
    "telnet",
    "ssh",
    "ldap",
    "ldaps",
    "smb",
    "nfs",
    "git",
    "svn",
}

SAFE_SCHEMES: set[str] = {
    "http",
    "https",
}

# ---------------------------------------------------------------------------
# Localhost detection variants
# ---------------------------------------------------------------------------
LOCALHOST_VARIANTS: set[str] = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    "0x7f.0.0.1",
    "0x7f000001",
    "2130706433",
    "017700000001",
    "0177.0.0.1",
    "0177.0.0.01",
    "0177.0.000.001",
}

# ---------------------------------------------------------------------------
# Dangerous port mapping
# ---------------------------------------------------------------------------
DANGEROUS_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "DB2",
}

# ---------------------------------------------------------------------------
# Open-redirect parameter names
# ---------------------------------------------------------------------------
REDIRECT_PARAMETERS: set[str] = {
    "redirect",
    "redir",
    "url",
    "next",
    "goto",
    "target",
    "destination",
    "dest",
    "return",
    "returnTo",
    "return_to",
    "continue",
    "out",
    "view",
    "forward",
    "to",
    "callback",
    "returnUrl",
    "ReturnUrl",
    "return_url",
}

# ---------------------------------------------------------------------------
# Attack-detection patterns
# ---------------------------------------------------------------------------
PATH_TRAVERSAL_PATTERNS: list[str] = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "%2e%2e/",
    "..%2f",
    "..%5c",
    "..../",
    "....\\",
    "%252e%252e%252f",
    "..%252f",
    "..%255c",
]

CRLF_PATTERNS: list[str] = [
    "\r",
    "\n",
    "%0d",
    "%0a",
    "%0D",
    "%0A",
    "\r\n",
    "%0d%0a",
]

OVERLONG_UTF8_PATTERNS: list[str] = [
    "%c0%af",
    "%c0%ae",
    "%e0%80%af",
    "%c0%2e",
    "%c0%2f",
]

# ---------------------------------------------------------------------------
# Homograph / confusable characters  (lookalike → ASCII equivalent)
# ---------------------------------------------------------------------------
HOMOGRAPH_CHARACTERS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # U+0430 -> a
    "\u0435": "e",  # U+0435 -> e
    "\u043e": "o",  # U+043E -> o
    "\u0440": "p",  # U+0440 -> p
    "\u0441": "c",  # U+0441 -> c
    "\u0443": "y",  # U+0443 -> y
    "\u0445": "x",  # U+0445 -> x
    # Greek
    "\u03bf": "o",  # U+03BF -> o
    "\u03bd": "v",  # U+03BD -> v
    "\u03c1": "p",  # U+03C1 -> p
}
