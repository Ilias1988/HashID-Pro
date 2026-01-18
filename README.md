# HashID-Pro

A powerful command-line hash identification tool that analyzes hash strings and identifies their possible algorithms. Supports multiple hash types including MD5, SHA-1, SHA-256, SHA-512, Bcrypt, NTLM, and MySQL5.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Multi-Algorithm Detection**: Identifies multiple possible hash types for ambiguous hashes (e.g., MD5 vs NTLM)
- **Confidence Scoring**: Provides confidence levels (HIGH/MEDIUM/LOW) based on pattern uniqueness
- **Rich CLI Output**: Beautiful, colored table output using the Rich library
- **Extensible**: Easy to add new hash patterns

## Supported Hash Types

| Algorithm | Length | Confidence |
|-----------|--------|------------|
| MD5 | 32 hex chars | Low (overlaps with NTLM) |
| NTLM | 32 hex chars | Low (overlaps with MD5) |
| SHA-1 | 40 hex chars | Medium |
| SHA-256 | 64 hex chars | Medium |
| SHA-384 | 96 hex chars | Medium |
| SHA-512 | 128 hex chars | Medium |
| Bcrypt | 60 chars ($2a$, $2b$, $2y$ prefix) | High |
| MySQL5 | 41 chars (* prefix) | High |
| MySQL323 | 16 hex chars | Medium |

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/HashID-Pro.git
cd HashID-Pro
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Navigate to the `hashid_pro` directory and run the tool:

```bash
cd hashid_pro
python main.py <hash>
```

### Examples

**Identify an MD5/NTLM hash:**
```bash
python main.py 5d41402abc4b2a76b9719d911017c592
```

**Identify a SHA-256 hash:**
```bash
python main.py 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

**Identify a Bcrypt hash:**
```bash
python main.py '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
```

**Identify a MySQL5 hash:**
```bash
python main.py '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
```

### Sample Output

```
+------------------------------------------+
| HashID-Pro - Hash Identification Tool    |
+------------------------------------------+

Input Hash: 5d41402abc4b2a76b9719d911017c592
Length: 32 characters

+------------------+------------------------------------------------+
| Algorithm        | Confidence/Note                                |
+------------------+------------------------------------------------+
| MD5              | Confidence: LOW                                |
|                  | MD5 Message-Digest Algorithm                   |
+------------------+------------------------------------------------+
| NTLM             | Confidence: LOW                                |
|                  | NTLM (NT LAN Manager) Hash                     |
|                  | Note: Same format as MD5, context needed       |
+------------------+------------------------------------------------+

Found 2 possible match(es).
```

## Project Structure

```
HashID-Pro/
├── hashid_pro/
│   ├── __init__.py
│   ├── hash_patterns.py   # Hash regex patterns and definitions
│   ├── analyzer.py        # HashAnalyzer class for hash identification
│   └── main.py            # CLI entry point
├── requirements.txt
├── .gitignore
└── README.md
```

## API Usage

You can also use HashID-Pro as a library in your Python projects:

```python
from hashid_pro.analyzer import HashAnalyzer

analyzer = HashAnalyzer()

# Analyze a single hash
results = analyzer.analyze('5d41402abc4b2a76b9719d911017c592')

for result in results:
    print(f"{result['type']}: {result['confidence']}")

# Check if a string is a valid hash
is_valid = analyzer.is_valid_hash('not_a_hash')  # False

# List all supported hash types
supported = analyzer.list_supported_types()
```

## Contributing

Contributions are welcome! To add support for new hash types:

1. Add the regex pattern to `hash_patterns.py` in the `PATTERNS` or `EXTENDED_PATTERNS` dictionary
2. Update the confidence calculation in `analyzer.py` if needed
3. Add test cases and update documentation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created for the security community.
