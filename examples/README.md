# Blackbox Logger Examples

This folder contains example applications demonstrating different use cases of the blackbox logger library.

## Examples Overview

| Example | Storage | Format | Use Case |
|---------|---------|--------|----------|
| [flight_data_example](flight_data_example/) | SPIFFS | BBOX | Structured IMU/GPS/PID/Motor logging |
| [px4_spiffs_example](px4_spiffs_example/) | SPIFFS | **PX4 ULog** | QGroundControl/FlightPlot compatible logs |
| [ardupilot_spiffs_example](ardupilot_spiffs_example/) | SPIFFS | **ArduPilot** | Mission Planner compatible logs |
| [spiffs_example](spiffs_example/) | SPIFFS | BBOX | Internal flash logging, small logs |
| [sdcard_example](sdcard_example/) | SD Card | BBOX | High-throughput flight data logging |
| [encryption_example](encryption_example/) | SD Card | BBOX+AES | Secure sensitive data logging |
| [panic_example](panic_example/) | SD Card | BBOX | Crash/coredump logging demonstration |

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

## 4. Flight Data Example (NEW in v2.0)

**Location:** `examples/flight_data_example/`

Demonstrates structured flight data logging with IMU, GPS, PID, and motor telemetry.

### Features
- High-frequency IMU logging (100 Hz)
- GPS, Attitude, Motor, Battery logging (10 Hz)  
- PID controller state logging (50 Hz)
- Multiple log format support (BBOX, PX4 ULog, ArduPilot DataFlash)

### Best For
- Drone/quadcopter flight data recording
- Robotics sensor fusion debugging
- Vehicle telemetry logging
- Integration with PX4/ArduPilot analysis tools

### Configuration
```c
#include "blackbox.h"
#include "blackbox_messages.h"

blackbox_config_t config;
blackbox_get_default_config(&config);
config.log_format = BLACKBOX_FORMAT_PX4_ULOG;  // or _ARDUPILOT, _BBOX
blackbox_init(&config);

// Log IMU data
bbox_msg_imu_t imu;
imu.timestamp_us = esp_timer_get_time();
imu.gyro_x = mpu_get_gyro_x();
// ... fill other fields
blackbox_log_imu(&imu);
```

### Log Format Compatibility

| Format | Extension | Compatible Tools |
|--------|-----------|------------------|
| PX4 ULog | `.ulg` | QGroundControl, FlightPlot, PlotJuggler |
| ArduPilot | `.bin` | Mission Planner, MAVExplorer |
| BBOX Native | `.blackbox` | `blackbox_decoder.py --struct` |

### Hardware Requirements
- Any ESP32 board with SPIFFS or SD card

---

## 5. Panic Example

**Location:** `examples/panic_example/`

Demonstrates the automatic panic/coredump logging feature.

### Features
- Library automatically handles all crash logging internally
- No callbacks or complex setup required
- Just enable via `panic_flags` and call `blackbox_init()`

### Best For
- Debugging field crashes
- Post-mortem analysis
- Crash reporting systems

### Configuration
```c
blackbox_config_t config;
blackbox_get_default_config(&config);
config.panic_flags = BLACKBOX_PANIC_FLAGS_ALL;  // Enable panic logging
blackbox_init(&config);  // That's it!
```

### What Gets Captured Automatically
- Crash reason (LoadProhibited, assertion, etc.)
- Stack backtrace
- CPU register dump
- Memory dump (optional)

### Hardware Requirements
- SD card module (same as sdcard_example)
- ESP32 development board

---

## 6. PX4 ULog SPIFFS Example

**Location:** `examples/px4_spiffs_example/`

Demonstrates PX4 ULog format logging to SPIFFS internal flash.

### Features
- **PX4 ULog format** (`.ulg` files)
- Compatible with QGroundControl, FlightPlot, PlotJuggler
- Simulated PX4-style flight data
- Flight mode simulation (ARM → POSCTL → LOITER → RTL → LAND)
- ESC telemetry logging

### Best For
- PX4 ecosystem integration
- QGroundControl log analysis
- pyulog scripting and automation
- Research data in standard format

### Configuration
```c
blackbox_config_t config;
blackbox_get_default_config(&config);
config.root_path = "/spiffs/logs";
config.file_prefix = "px4_";
config.log_format = BLACKBOX_FORMAT_PX4_ULOG;
blackbox_init(&config);
```

### Analysis with pyulog
```bash
pip install pyulog
ulog_info your_log.ulg
ulog2csv -m sensor_combined your_log.ulg
```

---

## 7. ArduPilot DataFlash SPIFFS Example

**Location:** `examples/ardupilot_spiffs_example/`

Demonstrates ArduPilot DataFlash format logging to SPIFFS internal flash.

### Features
- **ArduPilot DataFlash format** (`.bin` files)
- Compatible with Mission Planner, MAVExplorer
- Simulated ArduCopter-style flight data
- RC input and motor output logging
- Barometer and magnetometer data

### Best For
- ArduPilot ecosystem integration
- Mission Planner log review
- Existing ArduPilot analysis workflows
- Comparison with actual flight logs

### Configuration
```c
blackbox_config_t config;
blackbox_get_default_config(&config);
config.root_path = "/spiffs/logs";
config.file_prefix = "ardu";
config.log_format = BLACKBOX_FORMAT_ARDUPILOT;
blackbox_init(&config);
```

### Analysis with MAVExplorer
```bash
pip install pymavlink
mavlogdump.py --types IMU,GPS,ATT your_log.bin
mavgraph.py your_log.bin "IMU.AccX" "IMU.AccY"
```

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

## Log File Formats

Examples produce different formats based on `config.log_format`:

| Format | Extension | Description |
|--------|-----------|-------------|
| `BLACKBOX_FORMAT_BBOX` | `.blackbox` | Native format with optional AES-256 encryption |
| `BLACKBOX_FORMAT_PX4_ULOG` | `.ulg` | PX4 ULog for QGroundControl, FlightPlot |
| `BLACKBOX_FORMAT_ARDUPILOT` | `.bin` | ArduPilot DataFlash for Mission Planner |

### Native BBOX Format
- 4-byte magic header: `BBOX` (0x42 0x42 0x4F 0x58)
- File header with device ID and creation timestamp
- Binary log packets with timestamps, levels, and messages
- Optional AES-256-CTR encryption (only in BBOX format)

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
