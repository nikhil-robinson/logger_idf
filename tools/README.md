# Blackbox Logger Tools

This folder contains utility tools for working with blackbox log files.

## Tools

### blackbox_decoder.py

A Python script to decode and decrypt `.blackbox` binary log files, including structured flight data.

#### Features

- Decodes both encrypted and unencrypted log files
- AES-256-CTR decryption support
- **Structured flight data decoding** (IMU, GPS, PID, Motor, Battery, etc.)
- Multiple output formats: text, JSON, CSV
- Log level filtering
- Colored terminal output
- Statistics reporting

#### Installation

```bash
cd tools
pip install -r requirements.txt
```

#### Usage

```bash
# Basic usage (unencrypted file)
python blackbox_decoder.py logfile.blackbox

# Decode structured flight data
python blackbox_decoder.py flight.blackbox --struct

# Decode structured data to CSV
python blackbox_decoder.py flight.blackbox --struct --format csv --output flight_data.csv

# Decrypt an encrypted file with hex key
python blackbox_decoder.py secure001.blackbox --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F

# Decrypt with key from binary file
python blackbox_decoder.py secure001.blackbox --key-file encryption_key.bin

# Output to CSV format
python blackbox_decoder.py secure001.blackbox --key YOUR_KEY --format csv --output logs.csv

# Output to JSON format
python blackbox_decoder.py secure001.blackbox --format json

# Filter by log level (show only ERROR and above)
python blackbox_decoder.py logfile.blackbox --level ERROR

# Show statistics at end
python blackbox_decoder.py logfile.blackbox --stats

# Disable colored output
python blackbox_decoder.py logfile.blackbox --no-color
```

#### Command Line Options

| Option | Description |
|--------|-------------|
| `logfile` | Path to the .blackbox log file (required) |
| `--struct` | Decode structured flight data (IMU, GPS, PID, Motor, etc.) |
| `--key`, `-k` | AES-256 encryption key as hex string (64 hex characters) |
| `--key-file`, `-K` | File containing raw 32-byte encryption key |
| `--format`, `-f` | Output format: `text`, `json`, or `csv` (default: text) |
| `--output`, `-o` | Output file path (default: stdout) |
| `--level`, `-l` | Filter by minimum log level: ERROR, WARN, INFO, DEBUG, VERBOSE |
| `--no-color` | Disable colored terminal output |
| `--stats`, `-s` | Show statistics summary at end |

#### Output Formats

**Text (default)**
```
00:01:23.456789 [INFO   ] (tag:0x12345678, line:42) Sensor reading: temp=25.5°C
00:01:24.123456 [WARN   ] (tag:0x12345678, line:55) High temperature warning: 32.1°C
00:01:25.789012 [ERROR  ] (tag:0x12345678, line:60) Critical temperature exceeded!
```

**Structured Data (--struct mode)**
```
00:00:01.234567 [STRUCT_IMU ] IMU: gyro=(0.012,-0.005,0.003) accel=(0.10,0.05,-9.81) temp=25.5°C
00:00:01.334567 [STRUCT_GPS ] GPS: lat=37.774900 lon=-122.419400 alt=50.0m sats=12 fix=3
00:00:01.434567 [STRUCT_ATT ] ATT: roll=1.2° pitch=-0.5° yaw=45.3°
```

**JSON**
```json
{"timestamp_us": 83456789, "timestamp": "00:01:23.456789", "level": "INFO", "msg_type": "LOG", "tag_hash": "0x12345678", "file_hash": "0xABCDEF01", "line": 42, "message": "Sensor reading: temp=25.5°C"}
```

**CSV**
```csv
timestamp_us,timestamp,level,msg_type,tag_hash,file_hash,line,message
83456789,00:01:23.456789,INFO,LOG,0x12345678,0xABCDEF01,42,"Sensor reading: temp=25.5°C"
```

#### Example: Decrypting Logs from the Encryption Example

If you used the encryption example with the default key:

```python
# Default key from encryption_example/main/main.c
KEY = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
```

Decode with:
```bash
python blackbox_decoder.py /path/to/secure001.blackbox \
    --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F \
    --stats
```

#### Binary Log Format

The decoder understands the blackbox binary format:

**File Header (48 bytes)**
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic bytes: "ULog" (0x55 0x4C 0x6F 0x67) |
| 4 | 1 | Version |
| 5 | 1 | Flags (bit 0: encrypted) |
| 6 | 2 | Header size |
| 8 | 8 | Timestamp (µs since boot) |
| 16 | 32 | Device ID |

**IV (16 bytes, only if encrypted)**
| Offset | Size | Field |
|--------|------|-------|
| 48 | 16 | AES IV/Nonce |

**Log Packet Header (28 bytes)**
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic bytes |
| 4 | 1 | Version |
| 5 | 1 | Message type |
| 6 | 1 | Log level |
| 7 | 1 | Reserved |
| 8 | 8 | Timestamp (µs) |
| 16 | 4 | Tag hash (FNV-1a) |
| 20 | 4 | File hash (FNV-1a) |
| 24 | 2 | Line number |
| 26 | 2 | Payload length |

**Payload (variable)**
| Offset | Size | Field |
|--------|------|-------|
| 28 | N | UTF-8 message (N = payload_length) |

## License

See the main project LICENSE file.
