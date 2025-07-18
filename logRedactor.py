#!/usr/bin/env python3
"""
MongoDB Log Redaction Tool - Enhanced with Streaming Batch Processing and tqdm Progress Bar
Supports both on-premises (text format) and Atlas (JSON format) logs
Optimized for large files (GBs) with memory-efficient streaming processing
"""

import re
import json
import sys
import time
from typing import Dict, Iterator, TextIO
from pathlib import Path

try:
    from tqdm import tqdm

    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    print("⚠️  tqdm library not found. Install with: pip install tqdm")
    print("   Falling back to basic progress reporting.")

try:
    import phonenumbers
    from phonenumbers import NumberParseException

    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False
    print("⚠️  phonenumbers library not found. Install with: pip install phonenumbers")
    print("   Falling back to basic phone number patterns.")


class MongoLogRedactor:
    def __init__(self, batch_size: int = 5000):
        """
        Initialize the redactor with configurable batch processing

        Args:
            batch_size: Number of lines to process in each batch (default: 5000)
        """
        self.batch_size = batch_size
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

        # Progress tracking
        self.total_lines_processed = 0
        self.total_bytes_processed = 0

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

    def redact_batch(self, lines: list) -> list:
        """Apply redaction patterns to a batch of lines"""
        # Apply patterns in priority order
        priority_patterns = [
            'phone_numbers',  # CRITICAL
            'ip_addresses', 'uuids', 'atlas_hostnames', 'git_commits', 'bot_ids',  # HIGH
            'connection_ids', 'operation_ids', 'legacy_conn_ids', 'email_addresses'  # MEDIUM
        ]

        redacted_lines = []
        for line in lines:
            redacted_line = line
            for pattern_name in priority_patterns:
                redacted_line = self.redact_text(redacted_line, pattern_name)
            redacted_lines.append(redacted_line)

        return redacted_lines

    def detect_log_format(self, file_path: str) -> str:
        """Detect log format by reading first few lines"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for _ in range(5):  # Check first 5 lines
                    line = f.readline().strip()
                    if line:
                        try:
                            json.loads(line)
                            return 'atlas'  # Found valid JSON
                        except json.JSONDecodeError:
                            continue
                return 'onprem'  # No valid JSON found
        except Exception:
            return 'onprem'  # Default to on-prem format

    def read_lines_batch(self, file_handle: TextIO, batch_size: int) -> Iterator[list]:
        """Generator that yields batches of lines from file"""
        batch = []
        for line in file_handle:
            batch.append(line.rstrip('\n\r'))
            if len(batch) >= batch_size:
                yield batch
                batch = []

        # Yield remaining lines
        if batch:
            yield batch

    def get_file_size(self, file_path: str) -> int:
        """Get file size in bytes"""
        return Path(file_path).stat().st_size

    def format_bytes(self, bytes_size: int) -> str:
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"

    def format_time(self, seconds: float) -> str:
        """Format seconds into human readable time"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            return f"{seconds / 3600:.1f}h"

    def redact_log_file_streaming(self, input_file: str, output_file: str = None) -> Dict:
        """Main redaction function with streaming batch processing and tqdm progress bar"""
        input_path = Path(input_file)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Get file info
        file_size = self.get_file_size(input_file)
        log_format = self.detect_log_format(input_file)

        # Determine output file
        if output_file is None:
            output_file = str(input_path.with_suffix('.redacted' + input_path.suffix))

        print(f"📁 Processing {log_format.upper()} log: {input_file}")
        print(f"📊 File size: {self.format_bytes(file_size)}")
        print(f"🔄 Batch size: {self.batch_size} lines")
        print(f"💾 Output: {output_file}")
        print(f"🚀 Starting streaming redaction...\n")

        start_time = time.time()
        batch_count = 0

        # Initialize progress bar
        if TQDM_AVAILABLE:
            # Use tqdm with bytes-based progress
            progress_bar = tqdm(
                total=file_size,
                unit='B',
                unit_scale=True,
                unit_divisor=1024,
                desc="🔒 Redacting",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
                colour='green'
            )
        else:
            progress_bar = None

        try:
            # Process file in streaming batches
            with open(input_file, 'r', encoding='utf-8') as input_f, \
                    open(output_file, 'w', encoding='utf-8') as output_f:

                for batch_lines in self.read_lines_batch(input_f, self.batch_size):
                    batch_count += 1
                    batch_start = time.time()

                    # Redact the batch
                    redacted_lines = self.redact_batch(batch_lines)

                    # Write redacted batch to output
                    for line in redacted_lines:
                        output_f.write(line + '\n')

                    # Update progress
                    lines_in_batch = len(batch_lines)
                    bytes_in_batch = sum(len(line.encode('utf-8')) for line in batch_lines)

                    self.total_lines_processed += lines_in_batch
                    self.total_bytes_processed += bytes_in_batch

                    # Update progress bar
                    if TQDM_AVAILABLE and progress_bar:
                        # Calculate dynamic stats
                        batch_time = time.time() - batch_start
                        total_time = time.time() - start_time
                        total_redactions = sum(self.redaction_stats.values())

                        # Update progress bar with current batch size
                        progress_bar.update(bytes_in_batch)

                        # Update postfix with detailed stats
                        progress_bar.set_postfix({
                            'Batch': f'{batch_count}',
                            'Lines': f'{self.total_lines_processed:,}',
                            'Redactions': f'{total_redactions:,}',
                            'Batch/s': f'{batch_time:.2f}s'
                        })
                    else:
                        # Fallback to original progress reporting
                        batch_time = time.time() - batch_start
                        total_time = time.time() - start_time
                        progress_pct = (self.total_bytes_processed / file_size) * 100

                        print(f"📦 Batch {batch_count:4d}: {lines_in_batch:6d} lines, "
                              f"{self.format_bytes(bytes_in_batch):8s}, "
                              f"{batch_time:.2f}s | "
                              f"Progress: {progress_pct:.1f}% | "
                              f"Total: {self.format_time(total_time)}")

                    # Flush output periodically for large files
                    if batch_count % 10 == 0:
                        output_f.flush()

        finally:
            # Close progress bar
            if TQDM_AVAILABLE and progress_bar:
                progress_bar.close()

        total_time = time.time() - start_time
        throughput = self.total_bytes_processed / total_time if total_time > 0 else 0

        print(f"\n✅ Streaming redaction completed!")
        print(f"⏱️  Total time: {self.format_time(total_time)}")
        print(f"📈 Throughput: {self.format_bytes(throughput)}/s")
        print(f"📊 Processed: {self.total_lines_processed:,} lines, {self.format_bytes(self.total_bytes_processed)}")

        # Generate summary
        return {
            'input_file': input_file,
            'output_file': output_file,
            'log_format': log_format,
            'file_size': file_size,
            'lines_processed': self.total_lines_processed,
            'bytes_processed': self.total_bytes_processed,
            'processing_time': total_time,
            'throughput_bps': throughput,
            'batches_processed': batch_count,
            'redaction_stats': {
                name: {'count': count, 'description': self.redaction_patterns[name]['description']}
                for name, count in self.redaction_stats.items() if count > 0
            }
        }

    def print_summary(self, summary: Dict):
        """Print comprehensive redaction summary"""
        print(f"\n{'=' * 70}")
        print("REDACTION SUMMARY")
        print(f"{'=' * 70}")
        print(f"Input File: {summary['input_file']}")
        print(f"Output File: {summary['output_file']}")
        print(f"Log Format: {summary['log_format'].upper()}")
        print(f"File Size: {self.format_bytes(summary['file_size'])}")
        print(f"Lines Processed: {summary['lines_processed']:,}")
        print(f"Processing Time: {self.format_time(summary['processing_time'])}")
        print(f"Throughput: {self.format_bytes(summary['throughput_bps'])}/s")
        print(f"Batches: {summary['batches_processed']}")

        if summary['redaction_stats']:
            print(f"\nRedaction Statistics:")
            total_redactions = sum(stats['count'] for stats in summary['redaction_stats'].values())
            print(f"Total items redacted: {total_redactions:,}")
            print("-" * 50)
            for name, stats in summary['redaction_stats'].items():
                print(f"  {name}: {stats['count']:,} items - {stats['description']}")
        else:
            print("\nNo sensitive data found to redact.")

        print(f"\n🔒 Sensitive data successfully redacted while preserving log structure!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python logRedactor.py <input_file> [output_file] [batch_size]")
        print("Example: python logRedactor.py mongo.log mongo_redacted.log 5000")
        print("  batch_size: Number of lines per batch (default: 5000, recommended: 1000-10000)")
        print("\nRequired dependencies:")
        print("  pip install tqdm phonenumbers")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    batch_size = int(sys.argv[3]) if len(sys.argv) > 3 else 5000

    # Validate batch size
    if batch_size < 100:
        print("⚠️  Warning: Very small batch size may impact performance")
    elif batch_size > 50000:
        print("⚠️  Warning: Very large batch size may cause memory issues")

    try:
        print("🔒 MongoDB Log Redaction Tool - Streaming Edition with Progress Bar")
        print("=" * 70)

        redactor = MongoLogRedactor(batch_size=batch_size)
        summary = redactor.redact_log_file_streaming(input_file, output_file)
        redactor.print_summary(summary)

        feature_status = []
        if TQDM_AVAILABLE:
            feature_status.append("📊 Enhanced with visual progress bar")
        if PHONENUMBERS_AVAILABLE:
            feature_status.append("🌍 Enhanced with international phone number detection")

        if feature_status:
            print("\n" + " | ".join(feature_status))

    except KeyboardInterrupt:
        print("\n⚠️  Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()