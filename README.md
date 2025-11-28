# ULog Logger Library for ESP-IDF

A Blackbox logging library for ESP-IDF with binary format support.

## Features


- ✅ **Non-blocking API** - Lock-free ring buffer ensures zero latency in tight loops
- ✅ **Dual output** - Simultaneous console (ESP_LOG) and file output
- ✅ **Optional AES-256 encryption** - Secure your  logs
- ✅ **Automatic file rotation** - Configurable file size limits
- ✅ **Component tags** - Track logs by subsystem (IMU, MOTOR, CTRL_LOOP, etc.)
- ✅ **File, line, timestamp** - Full context for every log entry
- ✅ **Filesystem agnostic** - Works with SD card, SPIFFS, LittleFS, or any mounted FS

## Installation

### Using ESP-IDF Component Manager

Add to your project's `idf_component.yml`:

```yaml
dependencies:
  nikhil-robinson/blackbox: "*"
```

### Manual Installation

Clone into your project's `components` directory:

```bash
cd your_project/components
git clone https://github.com/nikhil-robinson/blackbox.git
```

## Quick Start

```c
#include "blackbox.h"

// Mount your filesystem first (SD card, SPIFFS, etc.)
// The logger never mounts filesystems - you must do that

void app_main(void)
{
    // Mount SD card (your code)
    mount_sd_card();
    
    // Configure the logger
    blackbox_config_t cfg = {
        .root_path = "/sdcard/logs",
        .file_prefix = "flight",
        .encrypt = false,
        .file_size_limit = 512 * 1024,  // 512 KB per file
        .buffer_size = 32 * 1024,        // 32 KB ring buffer
        .flush_interval_ms = 200,
        .min_level = BLACKBOX_LOG_LEVEL_INFO,
        .console_output = true,
        .file_output = true,
    };
    
    // Initialize logger
    ESP_ERROR_CHECK(blackbox_init(&cfg));
    
    // Use the logging macros
    BLACKBOX_LOG_INFO("MAIN", "System initialized");
    BLACKBOX_LOG_WARN("IMU", "Calibration drift detected");
    BLACKBOX_LOG_ERROR("MOTOR", "ESC communication timeout");
    
    // Your main loop
    while (1) {
        float accel_x = 1.23f;
        float gyro_z = 4.56f;
        
        BLACKBOX_LOG_INFO("IMU", "Accel=%.2f Gyro=%.2f", accel_x, gyro_z);
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
```

## API Reference

### Initialization

```c
// Get default configuration
blackbox_config_t cfg;
blackbox_get_default_config(&cfg);

// Initialize with configuration
esp_err_t blackbox_init(const blackbox_config_t* config);

// Cleanup (flushes remaining data)
esp_err_t blackbox_deinit(void);

// Check if initialized
bool blackbox_is_initialized(void);
```

### Logging Macros (Primary API)

```c
BLACKBOX_LOG_ERROR(tag, fmt, ...)   // Error level
BLACKBOX_LOG_WARN(tag, fmt, ...)    // Warning level
BLACKBOX_LOG_INFO(tag, fmt, ...)    // Info level
BLACKBOX_LOG_DEBUG(tag, fmt, ...)   // Debug level
BLACKBOX_LOG_VERBOSE(tag, fmt, ...) // Verbose level

// Shorthand versions
BLACKBOX_LOG_E(tag, fmt, ...)
BLACKBOX_LOG_W(tag, fmt, ...)
BLACKBOX_LOG_I(tag, fmt, ...)
BLACKBOX_LOG_D(tag, fmt, ...)
BLACKBOX_LOG_V(tag, fmt, ...)
```

### Runtime Control

```c
// Force flush buffer to file
esp_err_t blackbox_flush(void);

// Rotate to new log file immediately
esp_err_t blackbox_rotate_file(void);

// Set minimum log level
esp_err_t blackbox_set_level(blackbox_level_t level);
blackbox_level_t blackbox_get_level(void);

// Enable/disable outputs
esp_err_t blackbox_set_console_output(bool enable);
esp_err_t blackbox_set_file_output(bool enable);
```

### Statistics

```c
blackbox_stats_t stats;
blackbox_get_stats(&stats);

printf("Messages logged: %llu\n", stats.messages_logged);
printf("Messages dropped: %llu\n", stats.messages_dropped);
printf("Bytes written: %llu\n", stats.bytes_written);
printf("Files created: %u\n", stats.files_created);
printf("Buffer high water: %u\n", stats.buffer_high_water);
printf("Write errors: %u\n", stats.write_errors);

// Reset statistics
blackbox_reset_stats();
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `root_path` | `const char*` | Required | Root path for log files (e.g., "/sdcard/logs") |
| `file_prefix` | `const char*` | "flight" | Log file name prefix |
| `encrypt` | `bool` | false | Enable AES-256 encryption |
| `encryption_key` | `uint8_t[32]` | - | AES-256 key (required if encrypt=true) |
| `file_size_limit` | `size_t` | 512 KB | File rotation size limit |
| `buffer_size` | `size_t` | 32 KB | Ring buffer size (min 16 KB) |
| `flush_interval_ms` | `uint32_t` | 200 ms | Periodic flush interval |
| `min_level` | `blackbox_level_t` | INFO | Minimum log level to record |
| `console_output` | `bool` | true | Enable ESP_LOG console output |
| `file_output` | `bool` | true | Enable file output |

## Log Levels

| Level | Value | Description |
|-------|-------|-------------|
| `BLACKBOX_LOG_LEVEL_NONE` | 0 | No logging |
| `BLACKBOX_LOG_LEVEL_ERROR` | 1 | Errors only |
| `BLACKBOX_LOG_LEVEL_WARN` | 2 | Warnings and above |
| `BLACKBOX_LOG_LEVEL_INFO` | 3 | Info and above (default) |
| `BLACKBOX_LOG_LEVEL_DEBUG` | 4 | Debug and above |
| `BLACKBOX_LOG_LEVEL_VERBOSE` | 5 | All messages |

## Encryption

To enable encrypted logs:

```c
blackbox_config_t cfg;
blackbox_get_default_config(&cfg);

cfg.encrypt = true;

// Set your 256-bit encryption key
const uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
memcpy(cfg.encryption_key, key, 32);

blackbox_init(&cfg);
```

Encrypted files have the encryption flag set in the file header and include the IV after the header.

## ULog File Format

Each log file starts with a header:

```
+----------------+
| Magic (4 bytes)| "ULog"
| Version (1)    |
| Flags (1)      | bit 0 = encrypted
| Header Size (2)|
| Timestamp (8)  | File creation time (µs)
| Device ID (32) | MAC address
+----------------+
| [IV (16)]      | Only if encrypted
+----------------+
| Log Packets... |
+----------------+
```

Each log packet:

```
+-------------------+
| Magic (4)         | "ULog"
| Version (1)       |
| Msg Type (1)      |
| Level (1)         |
| Reserved (1)      |
| Timestamp (8)     | µs since boot
| Tag Hash (4)      | FNV-1a hash
| File Hash (4)     | FNV-1a hash
| Line (2)          |
| Payload Len (2)   |
+-------------------+
| Payload (UTF-8)   |
+-------------------+
```

## Architecture

```
┌──────────────────────────┐
│   USER APPLICATION       │
│  BLACKBOX_LOG_INFO / WARN / ERR  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│     FRONTEND API         │
│ formats ULog packet      │
│ writes to ring buffer    │
│ mirrors to ESP_LOG       │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    RING BUFFER           │
│ lock-free, non-blocking  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   LOG WRITER TASK        │
│ reads packets            │
│ optional encryption      │
│ writes to file           │
│ file rotation            │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│      FILESYSTEM          │
│ SD / SPIFFS / LittleFS   │
└──────────────────────────┘
```

## Memory Usage

- **Ring Buffer**: 16-64 KB (configurable)
- **Writer Task Stack**: 4 KB
- **Per-packet overhead**: ~28 bytes header + payload

## Performance

- **Frontend API**: ~5-10 µs per log call (non-blocking)
- **Zero blocking**: Logging calls never wait for file I/O
- **Drop oldest**: On buffer overflow, oldest messages are dropped

## Example: Drone Flight Controller

```c
#include "blackbox.h"

#define TAG_IMU     "IMU"
#define TAG_MOTOR   "MOTOR"
#define TAG_CTRL    "CTRL"
#define TAG_GPS     "GPS"
#define TAG_BATT    "BATT"

void imu_task(void* arg)
{
    while (1) {
        float ax, ay, az, gx, gy, gz;
        read_imu(&ax, &ay, &az, &gx, &gy, &gz);
        
        BLACKBOX_LOG_DEBUG(TAG_IMU, "A:[%.2f,%.2f,%.2f] G:[%.2f,%.2f,%.2f]",
                   ax, ay, az, gx, gy, gz);
        
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void motor_task(void* arg)
{
    while (1) {
        uint16_t rpm[4];
        read_motor_rpm(rpm);
        
        BLACKBOX_LOG_INFO(TAG_MOTOR, "RPM:[%u,%u,%u,%u]",
                  rpm[0], rpm[1], rpm[2], rpm[3]);
        
        if (rpm[0] < 1000) {
            BLACKBOX_LOG_WARN(TAG_MOTOR, "Motor 0 low RPM!");
        }
        
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

void battery_monitor(void* arg)
{
    while (1) {
        float voltage = read_battery_voltage();
        
        if (voltage < 10.5f) {
            BLACKBOX_LOG_ERROR(TAG_BATT, "CRITICAL: Voltage=%.2fV", voltage);
        } else if (voltage < 11.0f) {
            BLACKBOX_LOG_WARN(TAG_BATT, "Low battery: %.2fV", voltage);
        }
        
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

## License

MIT License

## Author

Nikhil Robinson

## Contributing

Pull requests are welcome! Please ensure your code follows the existing style and includes appropriate documentation.
