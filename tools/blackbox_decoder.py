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
Version: 2.0.0
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

# Packet header size (packed structure) - includes CRC16
PACKET_HEADER_SIZE = 4 + 1 + 1 + 1 + 1 + 8 + 4 + 4 + 2 + 2 + 2  # 30 bytes

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
    
    # Structured message types (v2.0)
    STRUCT_IMU = 0x10
    STRUCT_IMU_RAW = 0x11
    STRUCT_MAG = 0x12
    STRUCT_BARO = 0x13
    STRUCT_GPS = 0x20
    STRUCT_GPS_VEL = 0x21
    STRUCT_ATTITUDE = 0x30
    STRUCT_PID_ROLL = 0x40
    STRUCT_PID_PITCH = 0x41
    STRUCT_PID_YAW = 0x42
    STRUCT_PID_ALT = 0x43
    STRUCT_RC_INPUT = 0x50
    STRUCT_RC_OUTPUT = 0x51
    STRUCT_MOTOR = 0xA0
    STRUCT_ESC = 0xA1
    STRUCT_BATTERY = 0xB0
    STRUCT_STATUS = 0x07

    @classmethod
    def is_struct_type(cls, msg_type: int) -> bool:
        """Check if message type is a structured message"""
        return msg_type in (
            cls.STRUCT_IMU, cls.STRUCT_IMU_RAW, cls.STRUCT_MAG, cls.STRUCT_BARO,
            cls.STRUCT_GPS, cls.STRUCT_GPS_VEL, cls.STRUCT_ATTITUDE,
            cls.STRUCT_PID_ROLL, cls.STRUCT_PID_PITCH, cls.STRUCT_PID_YAW, cls.STRUCT_PID_ALT,
            cls.STRUCT_RC_INPUT, cls.STRUCT_RC_OUTPUT, cls.STRUCT_MOTOR,
            cls.STRUCT_ESC, cls.STRUCT_BATTERY, cls.STRUCT_STATUS
        )


# Struct message magic bytes ("STRK")
STRUCT_MAGIC_BYTES = bytes([0x53, 0x54, 0x52, 0x4B])
STRUCT_PACKET_HEADER_SIZE = 20  # 4 + 1 + 1 + 1 + 1 + 8 + 2 + 2


# ==============================================================================
# Structured Message Data Classes
# ==============================================================================

@dataclass
class StructIMU:
    """IMU sensor data"""
    timestamp_us: int
    gyro_x: float
    gyro_y: float
    gyro_z: float
    accel_x: float
    accel_y: float
    accel_z: float
    temp: float

    @classmethod
    def unpack(cls, data: bytes) -> 'StructIMU':
        if len(data) < 36:
            raise ValueError(f"IMU data too short: {len(data)}")
        values = struct.unpack('<Qfffffff', data[:36])
        return cls(*values)

    def __str__(self) -> str:
        return f"IMU: gyro=({self.gyro_x:.3f},{self.gyro_y:.3f},{self.gyro_z:.3f}) accel=({self.accel_x:.2f},{self.accel_y:.2f},{self.accel_z:.2f}) temp={self.temp:.1f}°C"


@dataclass
class StructGPS:
    """GPS position data"""
    timestamp_us: int
    lat: int  # degrees * 1e7
    lon: int  # degrees * 1e7
    alt_mm: int
    vel_n: int  # mm/s
    vel_e: int  # mm/s
    vel_d: int  # mm/s
    hdop: int
    vdop: int
    satellites: int
    fix_type: int
    flags: int

    @classmethod
    def unpack(cls, data: bytes) -> 'StructGPS':
        if len(data) < 36:
            raise ValueError(f"GPS data too short: {len(data)}")
        values = struct.unpack('<QiiiiiiHHBBB', data[:36])
        return cls(*values)

    def __str__(self) -> str:
        lat_deg = self.lat / 1e7
        lon_deg = self.lon / 1e7
        alt_m = self.alt_mm / 1000.0
        return f"GPS: lat={lat_deg:.6f} lon={lon_deg:.6f} alt={alt_m:.1f}m sats={self.satellites} fix={self.fix_type}"


@dataclass
class StructAttitude:
    """Attitude (orientation) data"""
    timestamp_us: int
    roll: float
    pitch: float
    yaw: float
    roll_rate: float
    pitch_rate: float
    yaw_rate: float

    @classmethod
    def unpack(cls, data: bytes) -> 'StructAttitude':
        if len(data) < 32:
            raise ValueError(f"Attitude data too short: {len(data)}")
        values = struct.unpack('<Qffffff', data[:32])
        return cls(*values)

    def __str__(self) -> str:
        import math
        roll_deg = math.degrees(self.roll)
        pitch_deg = math.degrees(self.pitch)
        yaw_deg = math.degrees(self.yaw)
        return f"ATT: roll={roll_deg:.1f}° pitch={pitch_deg:.1f}° yaw={yaw_deg:.1f}°"


@dataclass
class StructPID:
    """PID controller state"""
    timestamp_us: int
    axis: int
    setpoint: float
    measured: float
    error: float
    p_term: float
    i_term: float
    d_term: float
    ff_term: float
    output: float

    @classmethod
    def unpack(cls, data: bytes) -> 'StructPID':
        if len(data) < 40:
            raise ValueError(f"PID data too short: {len(data)}")
        values = struct.unpack('<QBffffffff', data[:40])
        return cls(*values)

    def __str__(self) -> str:
        axis_names = {0: 'ROLL', 1: 'PITCH', 2: 'YAW', 3: 'ALT'}
        axis_name = axis_names.get(self.axis, f'AXIS{self.axis}')
        return f"PID[{axis_name}]: sp={self.setpoint:.3f} err={self.error:.3f} P={self.p_term:.2f} I={self.i_term:.2f} D={self.d_term:.2f} out={self.output:.2f}"


@dataclass
class StructMotor:
    """Motor outputs"""
    timestamp_us: int
    motors: List[int]  # 8 motor values (PWM 1000-2000)

    @classmethod
    def unpack(cls, data: bytes) -> 'StructMotor':
        if len(data) < 24:
            raise ValueError(f"Motor data too short: {len(data)}")
        values = struct.unpack('<QHHHHHHHH', data[:24])
        return cls(timestamp_us=values[0], motors=list(values[1:]))

    def __str__(self) -> str:
        motor_strs = [f"M{i+1}:{v}" for i, v in enumerate(self.motors) if v > 0]
        return f"MOT: {' '.join(motor_strs)}"


@dataclass
class StructBattery:
    """Battery status"""
    timestamp_us: int
    voltage_mv: int
    current_ma: int
    capacity_mah: int
    remaining_pct: int
    cell_count: int
    temperature: int  # centidegrees

    @classmethod
    def unpack(cls, data: bytes) -> 'StructBattery':
        if len(data) < 22:
            raise ValueError(f"Battery data too short: {len(data)}")
        values = struct.unpack('<QIiIBBh', data[:22])
        return cls(*values)

    def __str__(self) -> str:
        v = self.voltage_mv / 1000.0
        a = self.current_ma / 1000.0
        t = self.temperature / 100.0
        return f"BAT: {v:.2f}V {a:.1f}A {self.remaining_pct}% {self.capacity_mah}mAh {t:.1f}°C"


# Struct message parsers by type
STRUCT_PARSERS = {
    MsgType.STRUCT_IMU: StructIMU.unpack,
    MsgType.STRUCT_GPS: StructGPS.unpack,
    MsgType.STRUCT_ATTITUDE: StructAttitude.unpack,
    MsgType.STRUCT_PID_ROLL: StructPID.unpack,
    MsgType.STRUCT_PID_PITCH: StructPID.unpack,
    MsgType.STRUCT_PID_YAW: StructPID.unpack,
    MsgType.STRUCT_PID_ALT: StructPID.unpack,
    MsgType.STRUCT_MOTOR: StructMotor.unpack,
    MsgType.STRUCT_BATTERY: StructBattery.unpack,
}


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
    crc16: int = 0
    crc_valid: bool = True

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


@dataclass
class StructPacket:
    """Decoded structured message packet"""
    magic: bytes
    version: int
    msg_type: MsgType
    timestamp_us: int
    data_size: int
    crc16: int
    crc_valid: bool
    data: object  # Parsed struct (StructIMU, StructGPS, etc.)

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

    @staticmethod
    def _calculate_crc16(data: bytes) -> int:
        """Calculate CRC-16 checksum (CCITT polynomial 0x1021)"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return crc

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
        crc16 = struct.unpack('<H', data[28:30])[0]

        # Validate magic
        if magic != MAGIC_BYTES:
            return None

        # Extract payload
        payload_start = PACKET_HEADER_SIZE
        payload_end = payload_start + payload_length
        
        if len(data) < payload_end:
            return None

        payload = data[payload_start:payload_end].decode('utf-8', errors='replace')

        # Validate CRC (calculated over header excluding CRC field + payload)
        crc_data = data[0:28] + data[payload_start:payload_end]
        calculated_crc = self._calculate_crc16(crc_data)
        crc_valid = (calculated_crc == crc16)

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
            payload=payload,
            crc16=crc16,
            crc_valid=crc_valid
        )

    def _parse_struct_packet(self, data: bytes) -> Optional[StructPacket]:
        """Parse a structured message packet from bytes"""
        if len(data) < STRUCT_PACKET_HEADER_SIZE:
            return None

        # Struct header: magic(4) + version(1) + msg_type(1) + format(1) + reserved(1) + timestamp(8) + data_size(2) + crc16(2)
        magic = data[0:4]
        version = data[4]
        msg_type = data[5]
        format_type = data[6]
        reserved = data[7]
        timestamp_us = struct.unpack('<Q', data[8:16])[0]
        data_size = struct.unpack('<H', data[16:18])[0]
        crc16 = struct.unpack('<H', data[18:20])[0]

        # Validate magic
        if magic != STRUCT_MAGIC_BYTES:
            return None

        # Extract data
        data_start = STRUCT_PACKET_HEADER_SIZE
        data_end = data_start + data_size

        if len(data) < data_end:
            return None

        payload_data = data[data_start:data_end]

        # Validate CRC (header excluding CRC + data)
        crc_data = data[0:18] + payload_data
        calculated_crc = self._calculate_crc16(crc_data)
        crc_valid = (calculated_crc == crc16)

        try:
            msg_type_enum = MsgType(msg_type)
        except ValueError:
            msg_type_enum = MsgType.LOG

        # Parse structured data
        parsed_data = None
        if msg_type_enum in STRUCT_PARSERS:
            try:
                parsed_data = STRUCT_PARSERS[msg_type_enum](payload_data)
            except (ValueError, struct.error) as e:
                print(f"Warning: Failed to parse struct {msg_type_enum.name}: {e}")
                parsed_data = payload_data  # Return raw bytes on parse failure

        return StructPacket(
            magic=magic,
            version=version,
            msg_type=msg_type_enum,
            timestamp_us=timestamp_us,
            data_size=data_size,
            crc16=crc16,
            crc_valid=crc_valid,
            data=parsed_data
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

    def decode_struct_file(self, filepath: str) -> Iterator[StructPacket]:
        """
        Decode a blackbox structured data log file.

        Args:
            filepath: Path to .blackbox file with struct data

        Yields:
            StructPacket objects
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
                while len(buffer) >= STRUCT_PACKET_HEADER_SIZE:
                    # Try to find struct magic bytes first, then log magic
                    struct_pos = buffer.find(STRUCT_MAGIC_BYTES)
                    log_pos = buffer.find(MAGIC_BYTES)

                    # Determine which comes first
                    if struct_pos == -1 and log_pos == -1:
                        buffer = buffer[-3:] if len(buffer) > 3 else buffer
                        break

                    # Process struct packet if it comes first
                    if struct_pos != -1 and (log_pos == -1 or struct_pos <= log_pos):
                        if struct_pos > 0:
                            buffer = buffer[struct_pos:]

                        if len(buffer) < STRUCT_PACKET_HEADER_SIZE:
                            break

                        # Get data size from header
                        data_size = struct.unpack('<H', buffer[16:18])[0]
                        total_size = STRUCT_PACKET_HEADER_SIZE + data_size

                        if len(buffer) < total_size:
                            break

                        # Parse struct packet
                        packet_data = buffer[:total_size]
                        packet = self._parse_struct_packet(packet_data)

                        if packet:
                            yield packet

                        buffer = buffer[total_size:]
                    else:
                        # Skip log packet
                        if log_pos > 0:
                            buffer = buffer[log_pos:]

                        if len(buffer) < PACKET_HEADER_SIZE:
                            break

                        payload_length = struct.unpack('<H', buffer[26:28])[0]
                        total_size = PACKET_HEADER_SIZE + payload_length

                        if len(buffer) < total_size:
                            break

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
    
    # CRC validation indicator
    crc_indicator = '' if packet.crc_valid else f' {bold}\033[91m[CRC ERR]{reset}'
    
    # Special formatting for panic-related messages
    if packet.msg_type == MsgType.PANIC:
        return f"{packet.timestamp_str} {bold}\033[91m[PANIC  ]{reset} {bold}{packet.payload}{reset}{crc_indicator}"
    elif packet.msg_type == MsgType.BACKTRACE:
        return f"{packet.timestamp_str} {bold}\033[95m[BKTRACE]{reset} {packet.payload}{crc_indicator}"
    elif packet.msg_type == MsgType.COREDUMP:
        return f"{packet.timestamp_str} {bold}\033[96m[COREDMP]{reset} {packet.payload}{crc_indicator}"
    
    return f"{packet.timestamp_str} {color}{level_str}{reset} (tag:0x{packet.tag_hash:08X}, line:{packet.line}) {packet.payload}{crc_indicator}"


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
        'message': packet.payload,
        'crc16': f"0x{packet.crc16:04X}",
        'crc_valid': packet.crc_valid
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


def format_struct_text(packet: StructPacket) -> str:
    """Format struct packet as human-readable text"""
    crc_indicator = '' if packet.crc_valid else ' \033[91m[CRC ERR]\033[0m'
    
    if packet.data is not None and hasattr(packet.data, '__str__'):
        return f"{packet.timestamp_str} \033[96m[{packet.msg_type.name:10s}]\033[0m {packet.data}{crc_indicator}"
    else:
        return f"{packet.timestamp_str} \033[96m[{packet.msg_type.name:10s}]\033[0m <{packet.data_size} bytes>{crc_indicator}"


def format_struct_json(packet: StructPacket) -> str:
    """Format struct packet as JSON"""
    data_dict = {}
    if packet.data is not None and hasattr(packet.data, '__dict__'):
        data_dict = {k: v for k, v in packet.data.__dict__.items() if not k.startswith('_')}
    
    return json.dumps({
        'timestamp_us': packet.timestamp_us,
        'timestamp': packet.timestamp_str,
        'msg_type': packet.msg_type.name,
        'data_size': packet.data_size,
        'crc16': f"0x{packet.crc16:04X}",
        'crc_valid': packet.crc_valid,
        'data': data_dict
    })


def format_struct_csv_row(packet: StructPacket) -> List[str]:
    """Format struct packet as CSV row"""
    data_str = str(packet.data) if packet.data else ''
    return [
        str(packet.timestamp_us),
        packet.timestamp_str,
        packet.msg_type.name,
        str(packet.data_size),
        data_str
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
  %(prog)s flight.blackbox --struct    # Decode structured flight data
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
    parser.add_argument('--struct', action='store_true', 
                        help='Decode structured flight data (IMU, GPS, PID, Motor, etc.)')

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
            if args.struct:
                csv_writer.writerow(['timestamp_us', 'timestamp', 'msg_type', 'data_size', 'data'])
            else:
                csv_writer.writerow(['timestamp_us', 'timestamp', 'level', 'msg_type', 
                                    'tag_hash', 'file_hash', 'line', 'message'])

        # Decode based on mode (struct vs text logs)
        if args.struct:
            # Structured data mode
            struct_stats = {}
            for packet in decoder.decode_struct_file(args.logfile):
                # Update stats
                msg_name = packet.msg_type.name
                struct_stats[msg_name] = struct_stats.get(msg_name, 0) + 1
                total_packets += 1

                # Format and output
                if args.format == 'text':
                    print(format_struct_text(packet), file=output_file)
                elif args.format == 'json':
                    print(format_struct_json(packet), file=output_file)
                elif args.format == 'csv':
                    csv_writer.writerow(format_struct_csv_row(packet))

            # Print struct stats
            if args.stats:
                print("\n" + "=" * 50, file=sys.stderr)
                print("Structured Data Statistics:", file=sys.stderr)
                print(f"  Total messages: {total_packets}", file=sys.stderr)
                for msg_type, count in sorted(struct_stats.items()):
                    print(f"  {msg_type:15s}: {count}", file=sys.stderr)

        else:
            # Traditional log mode
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

    # Print statistics (only for non-struct mode, struct mode handles its own)
    if args.stats and not args.struct:
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
