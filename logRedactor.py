#!/usr/bin/env python3
"""
MongoDB Log Redaction Tool
Supports both on-premises (text format) and Atlas (JSON format) logs
"""

import re
import json
import sys
from typing import Dict, List, Pattern, Union
from pathlib import Path


class MongoLogRedactor:
    def __init__(self):
        self.redaction_patterns = {
            # CRITICAL - Phone numbers (Malaysian format in examples)
            'phone_numbers': {
                'pattern': r'"(60\d{8,10})"',
                'preserve_quotes': True,
                'description': 'Malaysian phone numbers in queries'
            },

            # HIGH PRIORITY
            'ip_addresses': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'preserve_quotes': False,
                'description': 'IPv4 addresses'
            },

            'uuids': {
                'pattern': r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                'preserve_quotes': False,
                'description': 'UUID identifiers'
            },

            'atlas_hostnames': {
                'pattern': r'atlas-[a-zA-Z0-9]+-shard-\d+-\d+\.[a-zA-Z0-9]+\.mongodb\.net',
                'preserve_quotes': False,
                'description': 'Atlas cluster hostnames'
            },

            'git_commits': {
                'pattern': r'\b[0-9a-f]{40}\b',
                'preserve_quotes': False,
                'description': 'Git commit hashes'
            },

            # MEDIUM PRIORITY
            'bot_ids': {
                'pattern': r'"([0-9a-f]{24})"',
                'preserve_quotes': True,
                'description': 'MongoDB ObjectIds used as bot/app IDs'
            },

            'connection_ids': {
                'pattern': r'"connectionId":(\d+)',
                'preserve_quotes': False,
                'preserve_prefix': '"connectionId":',
                'description': 'Atlas connection IDs'
            },

            'operation_ids': {
                'pattern': r'"opId":(\d+)',
                'preserve_quotes': False,
                'preserve_prefix': '"opId":',
                'description': 'Atlas operation IDs'
            },

            'legacy_conn_ids': {
                'pattern': r'conn(\d+)',
                'preserve_quotes': False,
                'preserve_prefix': 'conn',
                'description': 'On-premises connection IDs'
            },

            'tls_subjects': {
                'pattern': r'"peerSubject":"([^"]*)"',
                'preserve_quotes': True,
                'preserve_prefix': '"peerSubject":',
                'description': 'TLS certificate subjects'
            },

            'cipher_details': {
                'pattern': r'"cipher":"([^"]*)"',
                'preserve_quotes': True,
                'preserve_prefix': '"cipher":',
                'description': 'TLS cipher information'
            },

            # Additional patterns for comprehensive coverage
            'email_addresses': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'preserve_quotes': False,
                'description': 'Email addresses'
            },

            'session_lsid': {
                'pattern': r'"lsid":\s*{\s*"id":\s*UUID\("([^"]+)"\)',
                'preserve_quotes': False,
                'preserve_prefix': '"lsid": { "id": UUID("',
                'preserve_suffix': '")',
                'description': 'MongoDB session LSIDs'
            }
        }

        # Statistics for redaction summary
        self.redaction_stats = {key: 0 for key in self.redaction_patterns.keys()}

    def detect_log_format(self, content: str) -> str:
        """Detect if log is Atlas JSON format or on-premises text format"""
        try:
            # Try to parse first line as JSON
            first_line = content.strip().split('\n')[0]
            json.loads(first_line)
            return 'atlas'
        except (json.JSONDecodeError, IndexError):
            return 'onprem'

    def generate_x_mask(self, original: str, preserve_quotes: bool = False,
                        preserve_prefix: str = "", preserve_suffix: str = "") -> str:
        """Generate X mask matching the length of original content"""
        if preserve_quotes and original.startswith('"') and original.endswith('"'):
            # For quoted strings, preserve quotes and mask the content
            inner_content = original[1:-1]  # Remove quotes
            return f'"{preserve_prefix}{"X" * len(inner_content.replace(preserve_prefix, "").replace(preserve_suffix, ""))}{preserve_suffix}"'
        else:
            # For non-quoted content, generate X's for the specified part
            if preserve_prefix or preserve_suffix:
                # Find the part to mask (excluding prefixes/suffixes)
                content_to_mask = original
                if preserve_prefix:
                    content_to_mask = content_to_mask.replace(preserve_prefix, "", 1)
                if preserve_suffix:
                    content_to_mask = content_to_mask.replace(preserve_suffix, "")
                return f"{preserve_prefix}{'X' * len(content_to_mask)}{preserve_suffix}"
            else:
                return "X" * len(original)

    def redact_text(self, text: str, pattern_name: str) -> str:
        """Apply redaction pattern to text with length-preserving X masking"""
        pattern_config = self.redaction_patterns[pattern_name]
        pattern = pattern_config['pattern']

        def replacement_func(match):
            original_value = match.group(0)

            # Increment counter for statistics
            self.redaction_stats[pattern_name] += 1

            # Handle different pattern types
            if pattern_name == 'phone_numbers':
                # For phone numbers: "60124471286" -> "XXXXXXXXXXX"
                phone_number = match.group(1)  # Extract without quotes
                return f'"{"X" * len(phone_number)}"'

            elif pattern_name == 'bot_ids':
                # For bot IDs: "654b783feebc620014dd1faa" -> "XXXXXXXXXXXXXXXXXXXXXXXX"
                bot_id = match.group(1)  # Extract without quotes
                return f'"{"X" * len(bot_id)}"'

            elif pattern_name == 'connection_ids':
                # For connection IDs: "connectionId":15191 -> "connectionId":XXXXX
                conn_id = match.group(1)
                return f'"connectionId":{"X" * len(conn_id)}'

            elif pattern_name == 'operation_ids':
                # For operation IDs: "opId":24469505 -> "opId":XXXXXXXX
                op_id = match.group(1)
                return f'"opId":{"X" * len(op_id)}'

            elif pattern_name == 'legacy_conn_ids':
                # For legacy conn IDs: conn297396 -> connXXXXXX
                conn_id = match.group(1)
                return f'conn{"X" * len(conn_id)}'

            elif pattern_name == 'tls_subjects':
                # For TLS subjects: "peerSubject":"CN=*.wktu1.mongodb.net" -> "peerSubject":"XXXXXXXXXXXXXXXXXXXX"
                subject = match.group(1)
                return f'"peerSubject":"{"X" * len(subject)}"'

            elif pattern_name == 'cipher_details':
                # For cipher: "cipher":"ECDHE-RSA-AES256-GCM-SHA384" -> "cipher":"XXXXXXXXXXXXXXXXXXXXXXX"
                cipher = match.group(1)
                return f'"cipher":"{"X" * len(cipher)}"'

            elif pattern_name == 'session_lsid':
                # For LSID: "lsid": { "id": UUID("18dc6629-9262-4055-b3fa-6c00285da25b") -> "lsid": { "id": UUID("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                lsid = match.group(1)
                return f'"lsid": {{ "id": UUID("{"X" * len(lsid)}")'

            else:
                # For simple patterns (IPs, UUIDs, hostnames, emails, git commits)
                return "X" * len(original_value)

        return re.sub(pattern, replacement_func, text, flags=re.IGNORECASE)

    def redact_onprem_log(self, content: str) -> str:
        """Redact on-premises MongoDB log format"""
        print("Processing on-premises log format...")

        # Apply redaction patterns in priority order
        priority_order = [
            'phone_numbers',  # CRITICAL
            'ip_addresses', 'uuids', 'bot_ids', 'atlas_hostnames', 'git_commits',  # HIGH
            'legacy_conn_ids', 'connection_ids', 'operation_ids', 'tls_subjects', 'cipher_details',  # MEDIUM
            'email_addresses', 'session_lsid'  # ADDITIONAL
        ]

        redacted_content = content
        for pattern_name in priority_order:
            if pattern_name in self.redaction_patterns:
                redacted_content = self.redact_text(redacted_content, pattern_name)

        return redacted_content

    def redact_atlas_log(self, content: str) -> str:
        """Redact Atlas MongoDB log format (JSON lines)"""
        print("Processing Atlas log format...")

        lines = content.strip().split('\n')
        redacted_lines = []

        # Apply redaction patterns in priority order
        priority_order = [
            'ip_addresses', 'uuids', 'atlas_hostnames', 'git_commits',  # HIGH
            'connection_ids', 'operation_ids', 'tls_subjects', 'cipher_details',  # MEDIUM
            'email_addresses', 'session_lsid'  # ADDITIONAL
        ]

        for line in lines:
            if not line.strip():
                redacted_lines.append(line)
                continue

            redacted_line = line
            for pattern_name in priority_order:
                if pattern_name in self.redaction_patterns:
                    redacted_line = self.redact_text(redacted_line, pattern_name)

            redacted_lines.append(redacted_line)

        return '\n'.join(redacted_lines)

    def redact_log_file(self, input_file: str, output_file: str = None) -> Dict:
        """Main redaction function"""
        input_path = Path(input_file)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Read input file
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Detect format and apply appropriate redaction
        log_format = self.detect_log_format(content)

        if log_format == 'atlas':
            redacted_content = self.redact_atlas_log(content)
        else:
            redacted_content = self.redact_onprem_log(content)

        # Determine output file
        if output_file is None:
            output_file = str(input_path.with_suffix('.redacted' + input_path.suffix))

        # Write redacted content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(redacted_content)

        # Generate summary report
        summary = {
            'input_file': input_file,
            'output_file': output_file,
            'log_format': log_format,
            'redaction_stats': {}
        }

        for pattern_name, count in self.redaction_stats.items():
            if count > 0:
                summary['redaction_stats'][pattern_name] = {
                    'count': count,
                    'description': self.redaction_patterns[pattern_name]['description']
                }

        return summary

    def print_summary(self, summary: Dict):
        """Print redaction summary"""
        print(f"\n{'=' * 60}")
        print("REDACTION SUMMARY")
        print(f"{'=' * 60}")
        print(f"Input File: {summary['input_file']}")
        print(f"Output File: {summary['output_file']}")
        print(f"Log Format: {summary['log_format'].upper()}")
        print(f"\nRedaction Statistics:")

        if not summary['redaction_stats']:
            print("  No sensitive data found to redact.")
        else:
            for pattern_name, stats in summary['redaction_stats'].items():
                print(f"  {pattern_name}: {stats['count']} items - {stats['description']}")


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

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()