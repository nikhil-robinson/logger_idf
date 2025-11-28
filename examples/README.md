# Blackbox Logger Examples

This folder contains three example applications demonstrating different use cases of the blackbox logger library.

## Examples Overview

| Example | Storage | Encryption | Use Case |
|---------|---------|------------|----------|
| [spiffs_example](spiffs_example/) | SPIFFS | No | Internal flash logging, small logs |
| [sdcard_example](sdcard_example/) | SD Card | No | High-throughput flight data logging |
| [encryption_example](encryption_example/) | SD Card | AES-256 | Secure sensitive data logging |

---

## 1. SPIFFS Example

**Location:** `examples/spiffs_example/`

Demonstrates logging to SPIFFS (SPI Flash File System) internal storage.

### Features
- Uses internal flash storage (no external hardware needed)
- Automatic SPIFFS formatting if mount fails
- Simulated sensor readings with temperature/humidity data
- Monitors SPIFFS space usage

### Best For
- Small to medium log files
- Applications without SD card hardware
- Quick prototyping

### Configuration
```c
config.root_path = "/spiffs/logs";
config.file_size_limit = 64 * 1024;  // 64KB (smaller for flash)
config.buffer_size = 16 * 1024;       // 16KB minimum
```

### Requirements
- SPIFFS partition in partition table (usually `storage` partition)
- ESP-IDF SPIFFS component enabled

---

## 2. SD Card Example

**Location:** `examples/sdcard_example/`

Demonstrates high-throughput logging to an SD card via SPI interface.

### Features
- SD card storage for large log files
- High-frequency data logging (50Hz flight data simulation)
- Multiple logging tasks (flight data + GPS)
- Message rate statistics
- Automatic log file listing

### Best For
- Flight controllers / drones
- Long-duration data acquisition
- High-speed sensor logging
- Easy log retrieval (remove SD card)

### Configuration
```c
config.root_path = "/sdcard/logs";
config.file_size_limit = 512 * 1024;  // 512KB per file
config.buffer_size = 32 * 1024;        // 32KB buffer
config.flush_interval_ms = 100;        // Fast flush for high-rate data
```

### Hardware Requirements
- SD card module connected via SPI
- Default pins (configurable):
  - MOSI: GPIO 23
  - MISO: GPIO 19
  - CLK: GPIO 18
  - CS: GPIO 5

---

## 3. Encryption Example

**Location:** `examples/encryption_example/`

Demonstrates AES-256 encrypted logging for secure data storage.

### Features
- AES-256-CTR encryption
- Secure storage of sensitive data
- Console shows plaintext (for debugging)
- File contents are encrypted

### Best For
- Protecting proprietary data
- Storing user/personal information
- Compliance with data protection requirements
- Audit logs that must not be tampered with

### Configuration
```c
config.encrypt = true;
memcpy(config.encryption_key, your_256_bit_key, 32);
```

### Security Notes
⚠️ **Important Security Considerations:**
- Never hardcode keys in production code
- Use secure key storage (encrypted NVS, HSM)
- Keep encryption keys separate from firmware
- Consider secure provisioning during manufacturing

---

## Building an Example

1. Navigate to the example directory:
   ```bash
   cd examples/spiffs_example
   ```

2. Set up ESP-IDF environment:
   ```bash
   . $IDF_PATH/export.sh
   ```

3. Configure the project (optional):
   ```bash
   idf.py menuconfig
   ```

4. Build:
   ```bash
   idf.py build
   ```

5. Flash and monitor:
   ```bash
   idf.py -p /dev/ttyUSB0 flash monitor
   ```

---

## Adding the Blackbox Component

Each example expects the blackbox component to be available. You can:

### Option 1: Component in project
Create a `components` folder and symlink/copy the blackbox library:
```bash
mkdir -p components
ln -s ../../../ components/blackbox
```

### Option 2: Extra component dirs
In the example's `CMakeLists.txt`, add:
```cmake
set(EXTRA_COMPONENT_DIRS "../..")
```

### Option 3: IDF Component Manager
Add to `idf_component.yml`:
```yaml
dependencies:
  blackbox:
    path: "../.."
```

---

## Log File Format

All examples produce `.blackbox` binary log files with:
- 4-byte magic header: `ULog` (0x55 0x4C 0x6F 0x67)
- File header with device ID and creation timestamp
- Binary log packets with timestamps, levels, and messages
- Optional AES-256-CTR encryption

---

## Troubleshooting

### SPIFFS mount fails
- Ensure SPIFFS partition exists in partition table
- Try `idf.py erase_flash` and re-flash

### SD card not detected
- Check SPI pin connections
- Verify SD card is FAT32 formatted
- Try a different SD card

### Messages being dropped
- Increase `buffer_size`
- Decrease `flush_interval_ms`
- Reduce logging frequency

### Encryption issues
- Verify key is exactly 32 bytes
- Check mbedTLS is enabled in ESP-IDF

---

## License

See the main project LICENSE file.
