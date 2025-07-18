#!/usr/bin/env python3
"""
MongoDB Log Redaction Tool
Supports both on-premises (text format) and Atlas (JSON format) logs
Enhanced with international phone number detection
"""

import re
import json
import sys
from typing import Dict
from pathlib import Path

try:
    import phonenumbers
    from phonenumbers import NumberParseException

    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False
    print("⚠️  phonenumbers library not found. Install with: pip install phonenumbers")
    print("   Falling back to basic phone number patterns.")


class MongoLogRedactor:
    def __init__(self):
        self.redaction_patterns = {
            # CRITICAL - Phone numbers (International detection)
            'phone_numbers': {
                'pattern': r'"([+]?[\d\s\-\(\)\.]{7,20})"',
                'description': 'International phone numbers in quotes'
            },

            # HIGH PRIORITY
            'ip_addresses': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'description': 'IPv4 addresses'
            },

            'uuids': {
                'pattern': r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                'description': 'UUID identifiers'
            },

            'atlas_hostnames': {
                'pattern': r'atlas-[a-zA-Z0-9]+-shard-\d+-\d+\.[a-zA-Z0-9]+\.mongodb\.net',
                'description': 'Atlas cluster hostnames'
            },

            'git_commits': {
                'pattern': r'\b[0-9a-f]{40}\b',
                'description': 'Git commit hashes'
            },

            # MEDIUM PRIORITY
            'bot_ids': {
                'pattern': r'"([0-9a-f]{24})"',
                'description': 'MongoDB ObjectIds used as bot/app IDs'
            },

            'connection_ids': {
                'pattern': r'"connectionId":(\d+)',
                'description': 'Atlas connection IDs'
            },

            'operation_ids': {
                'pattern': r'"opId":(\d+)',
                'description': 'Atlas operation IDs'
            },

            'legacy_conn_ids': {
                'pattern': r'conn(\d+)',
                'description': 'On-premises connection IDs'
            },

            'email_addresses': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email addresses'
            }
        }

        # Statistics for redaction summary
        self.redaction_stats = {key: 0 for key in self.redaction_patterns.keys()}

        # Cache for phone validation (performance optimization)
        self.phone_cache = {'valid': set(), 'invalid': set()}

    def is_valid_phone_number(self, candidate: str) -> bool:
        """Validate if a string is a valid international phone number"""
        cleaned = re.sub(r'[\s\-\(\)\.]+', '', candidate)

        # Cache check
        if cleaned in self.phone_cache['valid']:
            return True
        if cleaned in self.phone_cache['invalid']:
            return False

        is_valid = False

        if PHONENUMBERS_AVAILABLE:
            # Use Google's phonenumbers library
            try:
                parsed = phonenumbers.parse(candidate, None)
                is_valid = phonenumbers.is_valid_number(parsed)
            except NumberParseException:
                # Try with common regions
                for region in ['US', 'GB', 'DE', 'MY', 'IN', 'SG', 'CN', 'JP']:
                    try:
                        parsed = phonenumbers.parse(candidate, region)
                        if phonenumbers.is_valid_number(parsed):
                            is_valid = True
                            break
                    except NumberParseException:
                        continue
        else:
            # Fallback validation
            is_valid = self._basic_phone_validation(cleaned)

        # Cache result
        cache_key = 'valid' if is_valid else 'invalid'
        self.phone_cache[cache_key].add(cleaned)

        return is_valid

    def _basic_phone_validation(self, cleaned: str) -> bool:
        """Basic phone validation fallback"""
        # Length check
        if len(cleaned) < 7 or len(cleaned) > 15:
            return False

        # Must be mostly digits
        if not re.match(r'^[+]?\d{7,15}$', cleaned):
            return False

        # Exclude obvious non-phone patterns
        exclusions = [r'^\d{4}$', r'^[01]+$', r'^\d{1,3}$', r'^1{5,}$', r'^0{4,}$']
        for pattern in exclusions:
            if re.match(pattern, cleaned):
                return False

        return True

    def redact_text(self, text: str, pattern_name: str) -> str:
        """Apply redaction pattern with X-masking"""
        pattern = self.redaction_patterns[pattern_name]['pattern']

        def replacement_func(match):
            original = match.group(0)

            # Special handling for phone numbers
            if pattern_name == 'phone_numbers':
                phone_candidate = match.group(1)  # Extract content inside quotes
                if not self.is_valid_phone_number(phone_candidate):
                    return original  # Don't redact if not a valid phone
                self.redaction_stats[pattern_name] += 1
                return f'"{"X" * len(phone_candidate)}"'

            # Special handling for other quoted patterns
            elif pattern_name == 'bot_ids':
                self.redaction_stats[pattern_name] += 1
                bot_id = match.group(1)
                return f'"{"X" * len(bot_id)}"'

            # Special handling for connection/operation IDs
            elif pattern_name == 'connection_ids':
                self.redaction_stats[pattern_name] += 1
                conn_id = match.group(1)
                return f'"connectionId":{"X" * len(conn_id)}'

            elif pattern_name == 'operation_ids':
                self.redaction_stats[pattern_name] += 1
                op_id = match.group(1)
                return f'"opId":{"X" * len(op_id)}'

            elif pattern_name == 'legacy_conn_ids':
                self.redaction_stats[pattern_name] += 1
                conn_id = match.group(1)
                return f'conn{"X" * len(conn_id)}'

            # Default: replace entire match with X's
            else:
                self.redaction_stats[pattern_name] += 1
                return "X" * len(original)

        return re.sub(pattern, replacement_func, text, flags=re.IGNORECASE)

    def detect_log_format(self, content: str) -> str:
        """Detect if log is Atlas JSON format or on-premises text format"""
        try:
            first_line = content.strip().split('\n')[0]
            json.loads(first_line)
            return 'atlas'
        except (json.JSONDecodeError, IndexError):
            return 'onprem'

    def redact_log_content(self, content: str, log_format: str) -> str:
        """Apply redaction patterns to log content"""
        print(f"Processing {log_format.upper()} log format...")

        # Apply patterns in priority order
        priority_patterns = [
            'phone_numbers',  # CRITICAL
            'ip_addresses', 'uuids', 'atlas_hostnames', 'git_commits', 'bot_ids',  # HIGH
            'connection_ids', 'operation_ids', 'legacy_conn_ids', 'email_addresses'  # MEDIUM
        ]

        redacted_content = content
        for pattern_name in priority_patterns:
            redacted_content = self.redact_text(redacted_content, pattern_name)

        return redacted_content

    def redact_log_file(self, input_file: str, output_file: str = None) -> Dict:
        """Main redaction function"""
        input_path = Path(input_file)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Read input file
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Detect format and apply redaction
        log_format = self.detect_log_format(content)
        redacted_content = self.redact_log_content(content, log_format)

        # Determine output file
        if output_file is None:
            output_file = str(input_path.with_suffix('.redacted' + input_path.suffix))

        # Write redacted content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(redacted_content)

        # Generate summary
        return {
            'input_file': input_file,
            'output_file': output_file,
            'log_format': log_format,
            'redaction_stats': {
                name: {'count': count, 'description': self.redaction_patterns[name]['description']}
                for name, count in self.redaction_stats.items() if count > 0
            }
        }

    def print_summary(self, summary: Dict):
        """Print redaction summary"""
        print(f"\n{'=' * 60}")
        print("REDACTION SUMMARY")
        print(f"{'=' * 60}")
        print(f"Input File: {summary['input_file']}")
        print(f"Output File: {summary['output_file']}")
        print(f"Log Format: {summary['log_format'].upper()}")

        if summary['redaction_stats']:
            print(f"\nRedaction Statistics:")
            for name, stats in summary['redaction_stats'].items():
                print(f"  {name}: {stats['count']} items - {stats['description']}")
        else:
            print("\nNo sensitive data found to redact.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python mongo_log_redactor.py <input_file> [output_file]")
        print("Example: python mongo_log_redactor.py mongo.log mongo_redacted.log")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        redactor = MongoLogRedactor()
        summary = redactor.redact_log_file(input_file, output_file)
        redactor.print_summary(summary)

        print(f"\n✅ Redaction completed successfully!")
        print(f"📁 Redacted log saved to: {summary['output_file']}")

        if PHONENUMBERS_AVAILABLE:
            print(f"🌍 Enhanced with international phone number detection")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()