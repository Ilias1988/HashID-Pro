"""
HashID-Pro - Hash Analyzer Module
Analyzes hash strings and identifies all possible hash types.
"""

from hash_patterns import HashPatterns, HASH_REGEX


class HashAnalyzer:
    """
    A class for analyzing and identifying hash strings.
    Returns all possible hash type matches since some hashes overlap
    (e.g., MD5 and NTLM both use 32 hex characters).
    """
    
    def __init__(self):
        """Initialize the HashAnalyzer with available patterns."""
        self.patterns = HashPatterns.get_all_patterns()
    
    def analyze(self, hash_string: str) -> list:
        """
        Analyze a hash string and return all possible hash type matches.
        
        Since different hash types can have the same format (e.g., MD5 and NTLM
        are both 32 hex characters), this method returns ALL matching types,
        not just the first one found.
        
        Args:
            hash_string: The hash string to analyze
            
        Returns:
            A list of dictionaries containing possible hash types with:
                - type: The hash type name (e.g., 'MD5', 'SHA-256')
                - description: A description of the hash algorithm
                - length: The expected character length
                - confidence: Confidence level ('high', 'medium', 'low')
                - note: Any additional notes about the hash type (optional)
        """
        matches = []
        hash_string = hash_string.strip()
        
        if not hash_string:
            return matches
        
        for hash_type, pattern_info in self.patterns.items():
            if pattern_info['regex'].match(hash_string):
                match_info = {
                    'type': hash_type,
                    'description': pattern_info['description'],
                    'length': pattern_info['length'],
                    'confidence': self._calculate_confidence(hash_type, hash_string),
                    'note': pattern_info.get('note', None)
                }
                matches.append(match_info)
        
        # Sort by confidence level (high first, then medium, then low)
        confidence_order = {'high': 0, 'medium': 1, 'low': 2}
        matches.sort(key=lambda x: confidence_order.get(x['confidence'], 3))
        
        return matches
    
    def _calculate_confidence(self, hash_type: str, hash_string: str) -> str:
        """
        Calculate confidence level for a hash type match.
        
        Some hash types have unique characteristics that increase confidence:
        - Bcrypt: Unique prefix makes it highly identifiable
        - MySQL5: Unique asterisk prefix makes it highly identifiable
        - MD5/NTLM: Same format, so lower confidence without context
        
        Args:
            hash_type: The detected hash type
            hash_string: The hash string being analyzed
            
        Returns:
            Confidence level: 'high', 'medium', or 'low'
        """
        # Hash types with unique prefixes have high confidence
        high_confidence_types = ['Bcrypt', 'MySQL5']
        
        # Hash types with unique lengths (no overlap) have medium-high confidence
        unique_length_types = ['SHA-1', 'SHA-256', 'SHA-512', 'SHA-384', 'MySQL323']
        
        # Hash types that overlap with others have lower confidence
        overlapping_types = ['MD5', 'NTLM']
        
        if hash_type in high_confidence_types:
            return 'high'
        elif hash_type in unique_length_types:
            return 'medium'
        elif hash_type in overlapping_types:
            return 'low'
        else:
            return 'medium'
    
    def analyze_multiple(self, hash_strings: list) -> dict:
        """
        Analyze multiple hash strings at once.
        
        Args:
            hash_strings: A list of hash strings to analyze
            
        Returns:
            A dictionary mapping each hash string to its analysis results
        """
        results = {}
        for hash_string in hash_strings:
            results[hash_string] = self.analyze(hash_string)
        return results
    
    def get_hash_info(self, hash_type: str) -> dict:
        """
        Get detailed information about a specific hash type.
        
        Args:
            hash_type: The name of the hash type (e.g., 'MD5', 'SHA-256')
            
        Returns:
            Dictionary with hash type information, or None if not found
        """
        return HashPatterns.get_pattern(hash_type)
    
    def list_supported_types(self) -> list:
        """
        List all supported hash types.
        
        Returns:
            A list of supported hash type names
        """
        return list(self.patterns.keys())
    
    def is_valid_hash(self, hash_string: str) -> bool:
        """
        Check if a string matches any known hash pattern.
        
        Args:
            hash_string: The string to check
            
        Returns:
            True if the string matches at least one hash pattern
        """
        return len(self.analyze(hash_string)) > 0


def analyze_hash(hash_string: str) -> list:
    """
    Convenience function to analyze a hash string without creating an instance.
    
    Args:
        hash_string: The hash string to analyze
        
    Returns:
        List of possible hash type matches
    """
    analyzer = HashAnalyzer()
    return analyzer.analyze(hash_string)


if __name__ == '__main__':
    # Test the analyzer
    analyzer = HashAnalyzer()
    
    print("HashID-Pro Hash Analyzer")
    print("=" * 60)
    
    # Test hashes demonstrating overlap detection
    test_hashes = [
        ('5d41402abc4b2a76b9719d911017c592', 'MD5/NTLM (overlapping)'),
        ('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'SHA-1'),
        ('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'SHA-256'),
        ('9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043', 'SHA-512'),
        ('$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW', 'Bcrypt'),
        ('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19', 'MySQL5'),
    ]
    
    for test_hash, expected_type in test_hashes:
        print(f"\nInput: {test_hash[:50]}{'...' if len(test_hash) > 50 else ''}")
        print(f"Expected: {expected_type}")
        print("Results:")
        
        results = analyzer.analyze(test_hash)
        
        if results:
            for result in results:
                note_text = f" ({result['note']})" if result['note'] else ""
                print(f"  [{result['confidence'].upper()}] {result['type']}: {result['description']}{note_text}")
        else:
            print("  No matches found")
    
    print("\n" + "=" * 60)
    print(f"Supported hash types: {', '.join(analyzer.list_supported_types())}")
