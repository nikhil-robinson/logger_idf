#!/usr/bin/env python3
"""
Blackbox Log Decoder - Decrypts and parses encrypted blackbox log files

This script decodes .blackbox binary log files created by the ESP-IDF
blackbox logger library. It supports both encrypted (AES-256-CTR) and
unencrypted log files.

Usage:
    python blackbox_decoder.py <logfile.blackbox> [options]

Examples:
    # Decode an encrypted file (will prompt for key)
    python blackbox_decoder.py secure001.blackbox

    # Decode with key provided as hex string
    python blackbox_decoder.py secure001.blackbox --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F

    # Decode with key from file
    python blackbox_decoder.py secure001.blackbox --key-file my_key.bin

    # Output to CSV format
    python blackbox_decoder.py secure001.blackbox --format csv --output logs.csv

    # Filter by log level
    python blackbox_decoder.py secure001.blackbox --level ERROR

Author: Nikhil Robinson
Version: 1.0.0
"""

import argparse
import struct
import sys
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, BinaryIO, Iterator
from dataclasses import dataclass
from enum import IntEnum
import json
import csv

# Check for cryptography library
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Warning: 'cryptography' library not installed. Encrypted files cannot be decoded.")
    print("Install with: pip install cryptography")


# ==============================================================================
# Constants (must match blackbox.h)
# ==============================================================================

MAGIC_BYTES = bytes([0x42, 0x4C, 0x42, 0x4F])  # "BLBO" (Blackbox)
BLACKBOX_VERSION = 1
MAX_MESSAGE_SIZE = 256

# File header size (packed structure)
FILE_HEADER_SIZE = 4 + 1 + 1 + 2 + 8 + 32  # 48 bytes

# Packet header size (packed structure)
PACKET_HEADER_SIZE = 4 + 1 + 1 + 1 + 1 + 8 + 4 + 4 + 2 + 2  # 28 bytes

# IV size for AES encryption
IV_SIZE = 16


class LogLevel(IntEnum):
    """Log severity levels"""
    NONE = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    VERBOSE = 5

    @classmethod
    def from_string(cls, name: str) -> 'LogLevel':
        """Convert string to LogLevel"""
        name = name.upper()
        if name in cls.__members__:
            return cls[name]
        raise ValueError(f"Unknown log level: {name}")

    def to_string(self) -> str:
        """Convert LogLevel to string"""
        return self.name


class MsgType(IntEnum):
    """Message types"""
    LOG = 0x01
    INFO = 0x02
    MULTI = 0x03
    PARAM = 0x04
    DATA = 0x05
    DROPOUT = 0x06
    SYNC = 0x07
    PANIC = 0x10
    BACKTRACE = 0x11
    COREDUMP = 0x12


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class FileHeader:
    """Blackbox file header"""
    magic: bytes
    version: int
    flags: int
    header_size: int
    timestamp_us: int
    device_id: str
    encrypted: bool

    @property
    def creation_time(self) -> datetime:
        """Get creation time as datetime (assuming boot time as epoch)"""
        # Note: timestamp_us is microseconds since boot, not Unix timestamp
        return datetime.now() - timedelta(microseconds=self.timestamp_us)


@dataclass
class LogPacket:
    """Decoded log packet"""
    magic: bytes
    version: int
    msg_type: MsgType
    level: LogLevel
    timestamp_us: int
    tag_hash: int
    file_hash: int
    line: int
    payload: str

    @property
    def timestamp_sec(self) -> float:
        """Timestamp in seconds"""
        return self.timestamp_us / 1_000_000.0

    @property
    def timestamp_str(self) -> str:
        """Formatted timestamp string"""
        secs = self.timestamp_us // 1_000_000
        usecs = self.timestamp_us % 1_000_000
        hours = secs // 3600
        mins = (secs % 3600) // 60
        secs = secs % 60
        return f"{hours:02d}:{mins:02d}:{secs:02d}.{usecs:06d}"


# ==============================================================================
# Decoder Class
# ==============================================================================

class BlackboxDecoder:
    """Decoder for blackbox log files"""

    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initialize decoder.

        Args:
            encryption_key: 32-byte AES-256 key for encrypted files
        """
        self.encryption_key = encryption_key
        self.file_header: Optional[FileHeader] = None
        self.iv: Optional[bytes] = None
        self.cipher = None
        self.decryptor = None

    def _parse_file_header(self, data: bytes) -> FileHeader:
        """Parse file header from bytes"""
        if len(data) < FILE_HEADER_SIZE:
            raise ValueError(f"File header too short: {len(data)} < {FILE_HEADER_SIZE}")

        # Unpack: magic(4) + version(1) + flags(1) + header_size(2) + timestamp(8) + device_id(32)
        magic = data[0:4]
        version = data[4]
        flags = data[5]
        header_size = struct.unpack('<H', data[6:8])[0]
        timestamp_us = struct.unpack('<Q', data[8:16])[0]
        device_id = data[16:48].rstrip(b'\x00').decode('utf-8', errors='replace')

        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid magic bytes: {magic.hex()} (expected {MAGIC_BYTES.hex()})")

        encrypted = bool(flags & 0x01)

        return FileHeader(
            magic=magic,
            version=version,
            flags=flags,
            header_size=header_size,
            timestamp_us=timestamp_us,
            device_id=device_id,
            encrypted=encrypted
        )

    def _setup_decryption(self, iv: bytes):
        """Setup AES-256-CTR decryption"""
        if not HAS_CRYPTO:
            raise RuntimeError("Cryptography library not installed")
        
        if self.encryption_key is None:
            raise ValueError("Encryption key required for encrypted file")

        if len(self.encryption_key) != 32:
            raise ValueError(f"Encryption key must be 32 bytes, got {len(self.encryption_key)}")

        self.iv = iv
        self.cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CTR(iv),
            backend=default_backend()
        )
        self.decryptor = self.cipher.decryptor()

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-256-CTR"""
        if self.decryptor is None:
            raise RuntimeError("Decryption not initialized")
        return self.decryptor.update(data)

    def _parse_packet(self, data: bytes) -> Optional[LogPacket]:
        """Parse a single log packet from bytes"""
        if len(data) < PACKET_HEADER_SIZE:
            return None

        # Unpack header
        magic = data[0:4]
        version = data[4]
        msg_type = data[5]
        level = data[6]
        reserved = data[7]
        timestamp_us = struct.unpack('<Q', data[8:16])[0]
        tag_hash = struct.unpack('<I', data[16:20])[0]
        file_hash = struct.unpack('<I', data[20:24])[0]
        line = struct.unpack('<H', data[24:26])[0]
        payload_length = struct.unpack('<H', data[26:28])[0]

        # Validate magic
        if magic != MAGIC_BYTES:
            return None

        # Extract payload
        payload_start = PACKET_HEADER_SIZE
        payload_end = payload_start + payload_length
        
        if len(data) < payload_end:
            return None

        payload = data[payload_start:payload_end].decode('utf-8', errors='replace')

        try:
            msg_type_enum = MsgType(msg_type)
        except ValueError:
            msg_type_enum = MsgType.LOG

        try:
            level_enum = LogLevel(level)
        except ValueError:
            level_enum = LogLevel.INFO

        return LogPacket(
            magic=magic,
            version=version,
            msg_type=msg_type_enum,
            level=level_enum,
            timestamp_us=timestamp_us,
            tag_hash=tag_hash,
            file_hash=file_hash,
            line=line,
            payload=payload
        )

    def decode_file(self, filepath: str) -> Iterator[LogPacket]:
        """
        Decode a blackbox log file.

        Args:
            filepath: Path to .blackbox file

        Yields:
            LogPacket objects
        """
        with open(filepath, 'rb') as f:
            # Read file header
            header_data = f.read(FILE_HEADER_SIZE)
            self.file_header = self._parse_file_header(header_data)

            print(f"File Header:")
            print(f"  Version: {self.file_header.version}")
            print(f"  Device ID: {self.file_header.device_id}")
            print(f"  Encrypted: {self.file_header.encrypted}")
            print(f"  Timestamp: {self.file_header.timestamp_us} µs")
            print()

            # Read IV if encrypted
            if self.file_header.encrypted:
                iv = f.read(IV_SIZE)
                if len(iv) != IV_SIZE:
                    raise ValueError("Failed to read IV")
                self._setup_decryption(iv)
                print(f"  IV: {iv.hex()}")
                print()

            # Read and decode packets
            buffer = b''
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break

                # Decrypt if needed
                if self.file_header.encrypted:
                    chunk = self._decrypt(chunk)

                buffer += chunk

                # Process complete packets in buffer
                while len(buffer) >= PACKET_HEADER_SIZE:
                    # Try to find magic bytes
                    magic_pos = buffer.find(MAGIC_BYTES)
                    if magic_pos == -1:
                        # No magic found, keep last 3 bytes (in case magic is split)
                        buffer = buffer[-3:] if len(buffer) > 3 else buffer
                        break

                    if magic_pos > 0:
                        # Skip bytes before magic
                        buffer = buffer[magic_pos:]

                    # Check if we have enough for header
                    if len(buffer) < PACKET_HEADER_SIZE:
                        break

                    # Get payload length from header
                    payload_length = struct.unpack('<H', buffer[26:28])[0]
                    total_size = PACKET_HEADER_SIZE + payload_length

                    # Check if we have complete packet
                    if len(buffer) < total_size:
                        break

                    # Parse packet
                    packet_data = buffer[:total_size]
                    packet = self._parse_packet(packet_data)

                    if packet:
                        yield packet

                    # Remove processed packet from buffer
                    buffer = buffer[total_size:]


# ==============================================================================
# Output Formatters
# ==============================================================================

def format_text(packet: LogPacket) -> str:
    """Format packet as human-readable text"""
    level_colors = {
        LogLevel.ERROR: '\033[91m',    # Red
        LogLevel.WARN: '\033[93m',     # Yellow
        LogLevel.INFO: '\033[92m',     # Green
        LogLevel.DEBUG: '\033[94m',    # Blue
        LogLevel.VERBOSE: '\033[90m',  # Gray
    }
    reset = '\033[0m'
    bold = '\033[1m'
    
    color = level_colors.get(packet.level, '')
    level_str = f"[{packet.level.to_string():7s}]"
    
    # Special formatting for panic-related messages
    if packet.msg_type == MsgType.PANIC:
        return f"{packet.timestamp_str} {bold}\033[91m[PANIC  ]{reset} {bold}{packet.payload}{reset}"
    elif packet.msg_type == MsgType.BACKTRACE:
        return f"{packet.timestamp_str} {bold}\033[95m[BKTRACE]{reset} {packet.payload}"
    elif packet.msg_type == MsgType.COREDUMP:
        return f"{packet.timestamp_str} {bold}\033[96m[COREDMP]{reset} {packet.payload}"
    
    return f"{packet.timestamp_str} {color}{level_str}{reset} (tag:0x{packet.tag_hash:08X}, line:{packet.line}) {packet.payload}"


def format_json(packet: LogPacket) -> str:
    """Format packet as JSON"""
    return json.dumps({
        'timestamp_us': packet.timestamp_us,
        'timestamp': packet.timestamp_str,
        'level': packet.level.to_string(),
        'msg_type': packet.msg_type.name,
        'tag_hash': f"0x{packet.tag_hash:08X}",
        'file_hash': f"0x{packet.file_hash:08X}",
        'line': packet.line,
        'message': packet.payload
    })


def format_csv_row(packet: LogPacket) -> List[str]:
    """Format packet as CSV row"""
    return [
        str(packet.timestamp_us),
        packet.timestamp_str,
        packet.level.to_string(),
        packet.msg_type.name,
        f"0x{packet.tag_hash:08X}",
        f"0x{packet.file_hash:08X}",
        str(packet.line),
        packet.payload
    ]


# ==============================================================================
# Main
# ==============================================================================

def parse_hex_key(hex_string: str) -> bytes:
    """Parse hex string to bytes"""
    # Remove any spaces or common separators
    hex_string = hex_string.replace(' ', '').replace('-', '').replace(':', '')
    return bytes.fromhex(hex_string)


def main():
    parser = argparse.ArgumentParser(
        description='Decode blackbox log files (with optional AES-256 decryption)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s logfile.blackbox
  %(prog)s secure.blackbox --key 0001020304...1E1F
  %(prog)s secure.blackbox --key-file key.bin
  %(prog)s logfile.blackbox --format csv --output logs.csv
  %(prog)s logfile.blackbox --level ERROR
        """
    )

    parser.add_argument('logfile', help='Path to .blackbox log file')
    parser.add_argument('--key', '-k', help='AES-256 encryption key as hex string (64 hex chars)')
    parser.add_argument('--key-file', '-K', help='File containing raw 32-byte encryption key')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'csv'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--level', '-l', choices=['ERROR', 'WARN', 'INFO', 'DEBUG', 'VERBOSE'],
                        help='Filter by minimum log level')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics at end')

    args = parser.parse_args()

    # Check file exists
    if not os.path.exists(args.logfile):
        print(f"Error: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    # Get encryption key
    encryption_key = None
    if args.key:
        try:
            encryption_key = parse_hex_key(args.key)
            if len(encryption_key) != 32:
                print(f"Error: Key must be 32 bytes (64 hex chars), got {len(encryption_key)}", file=sys.stderr)
                sys.exit(1)
        except ValueError as e:
            print(f"Error: Invalid hex key: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.key_file:
        try:
            with open(args.key_file, 'rb') as f:
                encryption_key = f.read()
            if len(encryption_key) != 32:
                print(f"Error: Key file must contain exactly 32 bytes, got {len(encryption_key)}", file=sys.stderr)
                sys.exit(1)
        except IOError as e:
            print(f"Error: Cannot read key file: {e}", file=sys.stderr)
            sys.exit(1)

    # Parse level filter
    level_filter = None
    if args.level:
        level_filter = LogLevel.from_string(args.level)

    # Disable colors if requested or not a TTY
    if args.no_color or args.output or not sys.stdout.isatty():
        # Override format_text to not use colors
        global format_text
        original_format_text = format_text
        def format_text(packet: LogPacket) -> str:
            level_str = f"[{packet.level.to_string():7s}]"
            return f"{packet.timestamp_str} {level_str} (tag:0x{packet.tag_hash:08X}, line:{packet.line}) {packet.payload}"

    # Create decoder
    decoder = BlackboxDecoder(encryption_key=encryption_key)

    # Statistics
    stats = {level: 0 for level in LogLevel}
    msg_type_stats = {msg_type: 0 for msg_type in MsgType}
    total_packets = 0
    panic_count = 0

    # Open output file
    output_file = open(args.output, 'w', newline='') if args.output else sys.stdout
    csv_writer = None

    try:
        # Write CSV header if needed
        if args.format == 'csv':
            csv_writer = csv.writer(output_file)
            csv_writer.writerow(['timestamp_us', 'timestamp', 'level', 'msg_type', 
                                'tag_hash', 'file_hash', 'line', 'message'])

        # Decode and output
        for packet in decoder.decode_file(args.logfile):
            # Update stats
            stats[packet.level] += 1
            msg_type_stats[packet.msg_type] += 1
            total_packets += 1
            
            # Track panic events
            if packet.msg_type in (MsgType.PANIC, MsgType.BACKTRACE, MsgType.COREDUMP):
                panic_count += 1

            # Apply level filter
            if level_filter and packet.level > level_filter:
                continue

            # Format and output
            if args.format == 'text':
                print(format_text(packet), file=output_file)
            elif args.format == 'json':
                print(format_json(packet), file=output_file)
            elif args.format == 'csv':
                csv_writer.writerow(format_csv_row(packet))

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
    finally:
        if args.output:
            output_file.close()

    # Print statistics
    if args.stats:
        print("\n" + "=" * 50, file=sys.stderr)
        print("Statistics:", file=sys.stderr)
        print(f"  Total packets: {total_packets}", file=sys.stderr)
        for level in LogLevel:
            if level != LogLevel.NONE and stats[level] > 0:
                print(f"  {level.to_string():8s}: {stats[level]}", file=sys.stderr)
        
        # Print panic-related stats if any
        if panic_count > 0:
            print(f"\n  Panic/Crash Data:", file=sys.stderr)
            for msg_type in (MsgType.PANIC, MsgType.BACKTRACE, MsgType.COREDUMP):
                if msg_type_stats[msg_type] > 0:
                    print(f"    {msg_type.name:10s}: {msg_type_stats[msg_type]}", file=sys.stderr)
        
        if decoder.file_header:
            print(f"\n  Device ID: {decoder.file_header.device_id}", file=sys.stderr)
            print(f"  Encrypted: {decoder.file_header.encrypted}", file=sys.stderr)


if __name__ == '__main__':
    main()
