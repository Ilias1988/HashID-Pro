"""
HashID-Pro - Hash Patterns Module
Contains regex patterns for identifying various hash types.
"""

import re


class HashPatterns:
    """
    A class containing regex patterns for various cryptographic hash types.
    Each pattern is designed to match the specific format of that hash type.
    """
    
    # Hash pattern definitions with metadata
    PATTERNS = {
        'MD5': {
            'regex': re.compile(r'^[a-fA-F0-9]{32}$'),
            'description': 'MD5 Message-Digest Algorithm',
            'length': 32,
            'example': '5d41402abc4b2a76b9719d911017c592'
        },
        'SHA-1': {
            'regex': re.compile(r'^[a-fA-F0-9]{40}$'),
            'description': 'SHA-1 Secure Hash Algorithm',
            'length': 40,
            'example': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
        },
        'SHA-256': {
            'regex': re.compile(r'^[a-fA-F0-9]{64}$'),
            'description': 'SHA-256 Secure Hash Algorithm',
            'length': 64,
            'example': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        },
        'SHA-512': {
            'regex': re.compile(r'^[a-fA-F0-9]{128}$'),
            'description': 'SHA-512 Secure Hash Algorithm',
            'length': 128,
            'example': '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043'
        },
        'Bcrypt': {
            'regex': re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'),
            'description': 'Bcrypt password hashing function',
            'length': 60,
            'example': '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
        },
        'NTLM': {
            'regex': re.compile(r'^[a-fA-F0-9]{32}$'),
            'description': 'NTLM (NT LAN Manager) Hash - Note: Same format as MD5',
            'length': 32,
            'example': 'a4f49c406510bdcab6824ee7c30fd852',
            'note': 'NTLM hashes have the same format as MD5 (32 hex characters). Context is needed to differentiate.'
        },
        'MySQL5': {
            'regex': re.compile(r'^\*[A-F0-9]{40}$'),
            'description': 'MySQL 5.x password hash (SHA-1 based)',
            'length': 41,
            'example': '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
        }
    }
    
    # Additional patterns for extended hash types
    EXTENDED_PATTERNS = {
        'MySQL323': {
            'regex': re.compile(r'^[a-fA-F0-9]{16}$'),
            'description': 'MySQL 3.2.3 password hash (old format)',
            'length': 16,
            'example': '606717496665bcba'
        },
        'SHA-384': {
            'regex': re.compile(r'^[a-fA-F0-9]{96}$'),
            'description': 'SHA-384 Secure Hash Algorithm',
            'length': 96,
            'example': '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f'
        }
    }
    
    @classmethod
    def get_pattern(cls, hash_type: str) -> dict:
        """
        Get the pattern dictionary for a specific hash type.
        
        Args:
            hash_type: The name of the hash type (e.g., 'MD5', 'SHA-256')
            
        Returns:
            Dictionary containing regex, description, length, and example
        """
        # Check main patterns first
        if hash_type in cls.PATTERNS:
            return cls.PATTERNS[hash_type]
        # Check extended patterns
        if hash_type in cls.EXTENDED_PATTERNS:
            return cls.EXTENDED_PATTERNS[hash_type]
        return None
    
    @classmethod
    def get_all_patterns(cls) -> dict:
        """
        Get all available hash patterns (main + extended).
        
        Returns:
            Combined dictionary of all hash patterns
        """
        all_patterns = {}
        all_patterns.update(cls.PATTERNS)
        all_patterns.update(cls.EXTENDED_PATTERNS)
        return all_patterns
    
    @classmethod
    def match(cls, hash_string: str, hash_type: str) -> bool:
        """
        Check if a hash string matches a specific hash type pattern.
        
        Args:
            hash_string: The hash string to check
            hash_type: The hash type to match against
            
        Returns:
            True if the hash matches the pattern, False otherwise
        """
        pattern = cls.get_pattern(hash_type)
        if pattern:
            return bool(pattern['regex'].match(hash_string))
        return False
    
    @classmethod
    def identify(cls, hash_string: str) -> list:
        """
        Identify possible hash types for a given hash string.
        
        Args:
            hash_string: The hash string to identify
            
        Returns:
            List of possible hash type names that match the pattern
        """
        matches = []
        hash_string = hash_string.strip()
        
        for hash_type, pattern_info in cls.get_all_patterns().items():
            if pattern_info['regex'].match(hash_string):
                matches.append({
                    'type': hash_type,
                    'description': pattern_info['description'],
                    'note': pattern_info.get('note', None)
                })
        
        return matches


# Convenience dictionary for quick pattern access
HASH_REGEX = {
    'MD5': r'^[a-fA-F0-9]{32}$',
    'SHA-1': r'^[a-fA-F0-9]{40}$',
    'SHA-256': r'^[a-fA-F0-9]{64}$',
    'SHA-512': r'^[a-fA-F0-9]{128}$',
    'Bcrypt': r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$',
    'NTLM': r'^[a-fA-F0-9]{32}$',  # Same as MD5
    'MySQL5': r'^\*[A-F0-9]{40}$',
}


if __name__ == '__main__':
    # Test examples
    test_hashes = [
        '5d41402abc4b2a76b9719d911017c592',  # MD5/NTLM
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',  # SHA-1
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',  # SHA-256
        '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW',  # Bcrypt
        '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19',  # MySQL5
    ]
    
    print("HashID-Pro Pattern Testing")
    print("=" * 50)
    
    for test_hash in test_hashes:
        print(f"\nHash: {test_hash[:40]}{'...' if len(test_hash) > 40 else ''}")
        results = HashPatterns.identify(test_hash)
        if results:
            for result in results:
                print(f"  -> {result['type']}: {result['description']}")
                if result['note']:
                    print(f"     Note: {result['note']}")
        else:
            print("  -> Unknown hash type")
