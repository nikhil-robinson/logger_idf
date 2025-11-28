<p align="center">
  <img src="https://img.shields.io/badge/ESP--IDF-V5.2%2B-blue?&logo=espressif" alt="ESP-IDF">
  <img src="https://img.shields.io/badge/License-MIT-green?" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange?" alt="Version">
</p>

<h1 align="center">🛫 Blackbox Logger for ESP-IDF</h1>

<p align="center">
  <strong>A high-performance, non-blocking binary logging library for ESP32xx family</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-examples">Examples</a> •
  <a href="#-api-reference">API</a> •
  <a href="#-tools">Tools</a>
</p>

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Examples](#-examples)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Binary Log Format](#-binary-log-format)
- [Tools](#-tools)
- [Architecture](#-architecture)
- [Performance](#-performance)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🚀 **Non-blocking API** | Lock-free ring buffer ensures zero latency in tight control loops |
| 📺 **Dual Output** | Simultaneous console (ESP_LOG) and binary file output |
| 🔐 **AES-256 Encryption** | Optional encryption for secure, tamper-proof logs |
| 🔄 **Auto File Rotation** | Automatic file rotation based on configurable size limits |
| 🏷️ **Component Tags** | Organize logs by subsystem (IMU, MOTOR, GPS, etc.) |
| 📍 **Full Context** | Every log includes file name, line number, and microsecond timestamp |
| 💾 **Filesystem Agnostic** | Works with SD card, SPIFFS, LittleFS, or any mounted filesystem |
| ⚡ **Thread-Safe** | Safe to call from multiple tasks and cores simultaneously |
| 📊 **Statistics** | Track messages logged, dropped, bytes written, and more |
| 💥 **Panic Logging** | Capture crash information, backtraces, and register dumps to file |

---

## 📦 Installation

### Using ESP-IDF Component Manager (Recommended)

Add to your project's `idf_component.yml`:

```yaml
dependencies:
  nikhil-robinson/blackbox:
    git: https://github.com/nikhil-robinson/blackbox.git
```

Then run:
```bash
idf.py reconfigure
```

### Manual Installation

Clone into your project's `components` directory:

```bash
cd your_project/components
git clone https://github.com/nikhil-robinson/blackbox.git blackbox
```

### Dependencies

- ESP-IDF V5.2 or later
- mbedTLS (included in ESP-IDF, required for encryption)

---

## 🚀 Quick Start

```c
#include "blackbox.h"

void app_main(void)
{
    // 1. Mount your filesystem first (SD card, SPIFFS, etc.)
    //    The logger never mounts filesystems - you must do that
    init_sdcard();  // Your code
    
    // 2. Configure the logger
    blackbox_config_t config;
    blackbox_get_default_config(&config);
    config.root_path = "/sdcard/logs";
    config.file_prefix = "sensor";
    config.min_level = BLACKBOX_LOG_LEVEL_INFO;
    
    // 3. Initialize
    ESP_ERROR_CHECK(blackbox_init(&config));
    
    // 4. Start logging!
    BLACKBOX_LOG_INFO("MAIN", "System initialized, firmware v1.0.0");
    BLACKBOX_LOG_WARN("IMU", "Calibration drift: %.2f degrees", 0.5f);
    BLACKBOX_LOG_ERROR("MOTOR", "ESC #2 communication timeout!");
    
    // 5. Your application loop
    while (1) {
        float altitude = get_altitude();
        BLACKBOX_LOG_DEBUG("NAV", "Altitude: %.2f m", altitude);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // 6. Cleanup (optional, flushes remaining data)
    blackbox_deinit();
}
```

---

## 📚 Examples

Complete working examples are provided in the [`examples/`](examples/) directory:

| Example | Storage | Encryption | Description |
|---------|---------|------------|-------------|
| [**spiffs_example**](examples/spiffs_example/) | SPIFFS | ❌ | Internal flash logging for simple applications |
| [**sdcard_example**](examples/sdcard_example/) | SD Card | ❌ | High-throughput logging for sensor controllers |
| [**encryption_example**](examples/encryption_example/) | SD Card | ✅ | Secure logging with AES-256 encryption |
| [**panic_example**](examples/panic_example/) | SD Card | ❌ | Crash/coredump logging with panic handler |

### Running an Example

```bash
cd examples/sdcard_example
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## ⚙️ Configuration

### Configuration Structure

```c
typedef struct {
    const char* root_path;          // Log directory path
    const char* file_prefix;        // File name prefix
    bool encrypt;                   // Enable AES-256 encryption
    uint8_t encryption_key[32];     // 256-bit encryption key
    size_t file_size_limit;         // File rotation size
    size_t buffer_size;             // Ring buffer size
    uint32_t flush_interval_ms;     // Flush interval
    blackbox_level_t min_level;     // Minimum log level
    bool console_output;            // Enable console output
    bool file_output;               // Enable file output
    
    // Panic handler configuration (32-bit flag bitmask)
    uint32_t panic_flags;           // BLACKBOX_PANIC_FLAG_* bitmask
} blackbox_config_t;
```

### Panic Handler Flags

| Flag | Value | Description |
|------|-------|-------------|
| `BLACKBOX_PANIC_FLAG_NONE` | `0x00000000` | No panic features enabled |
| `BLACKBOX_PANIC_FLAG_ENABLED` | `0x00000001` | Enable panic handler |
| `BLACKBOX_PANIC_FLAG_BACKTRACE` | `0x00000002` | Include stack backtrace |
| `BLACKBOX_PANIC_FLAG_REGISTERS` | `0x00000004` | Include CPU register dump |
| `BLACKBOX_PANIC_FLAG_MEMORY_DUMP` | `0x00000008` | Include memory dump around SP |
| `BLACKBOX_PANIC_FLAG_TASK_INFO` | `0x00000010` | Include current task info |
| `BLACKBOX_PANIC_FLAG_HEAP_INFO` | `0x00000020` | Include heap statistics |
| `BLACKBOX_PANIC_FLAGS_DEFAULT` | `0x00000007` | Enabled + backtrace + registers |
| `BLACKBOX_PANIC_FLAGS_ALL` | `0x0000003F` | All features enabled |

### Example Panic Configuration

```c
blackbox_config_t config;
blackbox_get_default_config(&config);

// Default: panic enabled with backtrace and registers
// config.panic_flags == BLACKBOX_PANIC_FLAGS_DEFAULT

// Enable all panic features
config.panic_flags = BLACKBOX_PANIC_FLAGS_ALL;

// Custom: only backtrace, no memory dump
config.panic_flags = BLACKBOX_PANIC_FLAG_ENABLED | 
                     BLACKBOX_PANIC_FLAG_BACKTRACE;

// Disable panic handler entirely
config.panic_flags = BLACKBOX_PANIC_FLAG_NONE;
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `root_path` | `const char*` | **Required** | Root path for log files (e.g., "/sdcard/logs") |
| `file_prefix` | `const char*` | `"flight"` | Log file name prefix |
| `encrypt` | `bool` | `false` | Enable AES-256-CTR encryption |
| `encryption_key` | `uint8_t[32]` | - | 256-bit AES key (required if `encrypt=true`) |
| `file_size_limit` | `size_t` | `512 KB` | File rotation size limit |
| `buffer_size` | `size_t` | `32 KB` | Ring buffer size (minimum 16 KB) |
| `flush_interval_ms` | `uint32_t` | `200 ms` | Periodic flush interval |
| `min_level` | `blackbox_level_t` | `INFO` | Minimum log level to record |
| `console_output` | `bool` | `true` | Mirror logs to ESP_LOG console |
| `file_output` | `bool` | `true` | Write logs to binary file |
| `panic_flags` | `uint32_t` | `0x07` | Panic handler flags (see table above) |

### Kconfig Options (Compile-Time Constants)

The following options can be configured via `idf.py menuconfig` under **Blackbox Logger Configuration**:

#### Buffer and Memory Settings
| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_BLACKBOX_DEFAULT_BUFFER_SIZE` | `32` KB | Default ring buffer size |
| `CONFIG_BLACKBOX_MIN_BUFFER_SIZE` | `16` KB | Minimum allowed buffer size |
| `CONFIG_BLACKBOX_MAX_MESSAGE_SIZE` | `256` bytes | Maximum message payload size |

#### File Settings
| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_BLACKBOX_DEFAULT_FILE_SIZE_LIMIT` | `512` KB | Default file rotation size |
| `CONFIG_BLACKBOX_MAX_PATH_LENGTH` | `128` bytes | Maximum file path length |
| `CONFIG_BLACKBOX_DEFAULT_FLUSH_INTERVAL` | `200` ms | Default flush interval |

#### Task Settings
| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_BLACKBOX_WRITER_TASK_STACK_SIZE` | `4096` bytes | Writer task stack size |
| `CONFIG_BLACKBOX_WRITER_TASK_PRIORITY` | `2` | Writer task FreeRTOS priority |

#### Panic Handler Settings
| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_BLACKBOX_PANIC_MEMORY_DUMP_SIZE` | `256` bytes | Size of memory dump (64-1024) |

### Log Levels

| Level | Value | Macro | Use Case |
|-------|-------|-------|----------|
| `NONE` | 0 | - | Disable logging |
| `ERROR` | 1 | `BLACKBOX_LOG_E` | Critical failures |
| `WARN` | 2 | `BLACKBOX_LOG_W` | Warnings, degraded operation |
| `INFO` | 3 | `BLACKBOX_LOG_I` | Normal operation events |
| `DEBUG` | 4 | `BLACKBOX_LOG_D` | Debugging information |
| `VERBOSE` | 5 | `BLACKBOX_LOG_V` | Detailed tracing |

---

## 📖 API Reference

### Initialization

```c
// Get default configuration
void blackbox_get_default_config(blackbox_config_t* config);

// Initialize the logger
esp_err_t blackbox_init(const blackbox_config_t* config);

// Deinitialize (flushes remaining data)
esp_err_t blackbox_deinit(void);

// Check if initialized
bool blackbox_is_initialized(void);
```

### Logging Macros

```c
// Primary logging macros
BLACKBOX_LOG_ERROR(tag, fmt, ...)   // Error level
BLACKBOX_LOG_WARN(tag, fmt, ...)    // Warning level
BLACKBOX_LOG_INFO(tag, fmt, ...)    // Info level
BLACKBOX_LOG_DEBUG(tag, fmt, ...)   // Debug level
BLACKBOX_LOG_VERBOSE(tag, fmt, ...) // Verbose level

// Shorthand aliases
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

// Set/get minimum log level
esp_err_t blackbox_set_level(blackbox_level_t level);
blackbox_level_t blackbox_get_level(void);

// Enable/disable outputs at runtime
esp_err_t blackbox_set_console_output(bool enable);
esp_err_t blackbox_set_file_output(bool enable);
```

### Panic Handler (Optional)

```c
// Set panic flags at runtime (use BLACKBOX_PANIC_FLAG_* macros)
esp_err_t blackbox_set_panic_flags(uint32_t flags);

// Get current panic flags
uint32_t blackbox_get_panic_flags(void);

// Enable/disable panic handler (convenience wrapper)
esp_err_t blackbox_set_panic_handler(bool enable);

// Check if panic handler is enabled
bool blackbox_is_panic_handler_enabled(void);

// Log a test panic entry (for testing decoder)
esp_err_t blackbox_log_test_panic(const char* reason);
```

#### Runtime Panic Configuration Example

```c
// Enable all panic features at runtime
blackbox_set_panic_flags(BLACKBOX_PANIC_FLAGS_ALL);

// Disable only memory dump
uint32_t flags = blackbox_get_panic_flags();
flags &= ~BLACKBOX_PANIC_FLAG_MEMORY_DUMP;
blackbox_set_panic_flags(flags);

// Simple enable/disable
blackbox_set_panic_handler(false);  // Disable
blackbox_set_panic_handler(true);   // Re-enable (preserves other flags)
```

### Statistics

```c
typedef struct {
    uint64_t messages_logged;    // Total messages logged
    uint64_t messages_dropped;   // Messages dropped (buffer full)
    uint64_t bytes_written;      // Total bytes written to file
    uint32_t files_created;      // Number of log files created
    uint32_t buffer_high_water;  // Buffer high water mark
    uint32_t write_errors;       // File write errors
} blackbox_stats_t;

// Get statistics
esp_err_t blackbox_get_stats(blackbox_stats_t* stats);

// Reset statistics
esp_err_t blackbox_reset_stats(void);
```

---

## 📄 Binary Log Format

### File Structure

```
┌────────────────────────────────────────┐
│         FILE HEADER (48 bytes)         │
├────────────────────────────────────────┤
│      IV (16 bytes) - if encrypted      │
├────────────────────────────────────────┤
│                                        │
│            LOG PACKETS                 │
│         (variable size each)           │
│                                        │
└────────────────────────────────────────┘
```

### File Header

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic | (0x42 0x4C 0x42 0x4F) |
| 4 | 1 | Version | Format version (currently 1) |
| 5 | 1 | Flags | Bit 0: encrypted |
| 6 | 2 | Header Size | Size of this header |
| 8 | 8 | Timestamp | File creation time (µs since boot) |
| 16 | 32 | Device ID | Device MAC address |

### Log Packet Header

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic | `"BLBO"` |
| 4 | 1 | Version | Format version |
| 5 | 1 | Msg Type | Message type (0x01 = LOG) |
| 6 | 1 | Level | Log level (1-5) |
| 7 | 1 | Reserved | Alignment padding |
| 8 | 8 | Timestamp | Microseconds since boot |
| 16 | 4 | Tag Hash | FNV-1a hash of tag string |
| 20 | 4 | File Hash | FNV-1a hash of source file |
| 24 | 2 | Line | Source line number |
| 26 | 2 | Payload Len | Length of message payload |
| 28 | N | Payload | UTF-8 message string |

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| `LOG` | 0x01 | Standard log message |
| `INFO` | 0x02 | Information message |
| `MULTI` | 0x03 | Multi-part message |
| `PARAM` | 0x04 | Parameter message |
| `DATA` | 0x05 | Data message |
| `DROPOUT` | 0x06 | Dropout marker |
| `SYNC` | 0x07 | Sync message |
| `PANIC` | 0x10 | Panic/crash information |
| `BACKTRACE` | 0x11 | Backtrace data |
| `COREDUMP` | 0x12 | Core dump marker |

### Panic Log Data

When panic logging is enabled, the following information is captured on crash:

- **Panic Reason**: The cause of the crash (e.g., "LoadProhibited", "StoreProhibited", "InstrFetchProhibited")
- **Core ID**: Which CPU core crashed
- **Crash Address**: The memory address that caused the fault
- **Backtrace**: Stack trace showing the call chain that led to the crash
- **CPU Registers**: All general-purpose registers at crash time (PC, SP, A0-A15 for Xtensa; MEPC, RA, SP, etc. for RISC-V)
- **Memory Dump** (optional): Memory contents around the stack pointer

---

## 🔧 Tools

### Python Log Decoder

A Python tool is provided to decode and decrypt blackbox log files:

```bash
cd tools
pip install -r requirements.txt

# Decode unencrypted file
python blackbox_decoder.py sensor001.blackbox

# Decode encrypted file
python blackbox_decoder.py secure001.blackbox \
    --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F

# Export to CSV
python blackbox_decoder.py flight001.blackbox --format csv --output logs.csv

# Filter by level
python blackbox_decoder.py flight001.blackbox --level ERROR --stats
```

See [`tools/README.md`](tools/README.md) for full documentation.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER APPLICATION                         │
│         BLACKBOX_LOG_INFO() / WARN() / ERROR()              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     FRONTEND API                            │
│  • Formats binary BLBO packet                               │
│  • Writes to lock-free ring buffer (non-blocking)           │
│  • Mirrors to ESP_LOG console                               │
│  • Atomic statistics updates                                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    RING BUFFER                              │
│  • Lock-free, thread-safe                                   │
│  • Configurable size (16-64 KB typical)                     │
│  • Automatic overflow handling                              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               LOG WRITER TASK (Background)                  │
│  • Reads packets from ring buffer                           │
│  • Optional AES-256-CTR encryption                          │
│  • Writes to filesystem                                     │
│  • Handles file rotation                                    │
│  • Periodic flush                                           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     FILESYSTEM                              │
│            SD Card / SPIFFS / LittleFS                      │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Performance

### Benchmarks (ESP32 @ 240 MHz)

| Metric | Value |
|--------|-------|
| Log call latency | 5-10 µs (non-blocking) |
| Maximum throughput | 50,000+ messages/sec |
| Minimum buffer size | 16 KB |
| Writer task stack | 4 KB |
| Per-packet overhead | 28 bytes header |

### Design Principles

- **Zero blocking**: Log calls never wait for file I/O
- **Lock-free**: No mutexes in the hot path
- **Graceful degradation**: On buffer overflow, oldest messages are dropped (not newest)
- **Atomic counters**: Statistics updated without locks

---

## 🐛 Troubleshooting

### Messages Being Dropped

```c
blackbox_stats_t stats;
blackbox_get_stats(&stats);
if (stats.messages_dropped > 0) {
    // Increase buffer size or reduce log frequency
    // config.buffer_size = 64 * 1024;
}
```

**Solutions:**
- Increase `buffer_size`
- Decrease `flush_interval_ms`
- Reduce logging frequency
- Disable `console_output` for higher throughput

### File Not Created

- Ensure filesystem is mounted before calling `blackbox_init()`
- Check that `root_path` directory exists or can be created
- Verify sufficient storage space

### Encryption Errors

- Ensure `encryption_key` is exactly 32 bytes
- Verify mbedTLS AES is enabled in sdkconfig:
  ```
  CONFIG_MBEDTLS_AES_C=y
  CONFIG_MBEDTLS_CIPHER_MODE_CTR=y
  ```

### High CPU Usage

- Increase `flush_interval_ms`
- Reduce log level (`min_level`)
- Disable `console_output`

---

## 📁 Project Structure

```
blackbox/
├── blackbox.c              # Library implementation
├── blackbox.h              # Public API header
├── CMakeLists.txt          # Component build configuration
├── idf_component.yml       # Component manager manifest
├── README.md               # This file
│
├── examples/
│   ├── README.md           # Examples overview
│   ├── spiffs_example/     # SPIFFS storage example
│   ├── sdcard_example/     # SD card example
│   └── encryption_example/ # AES encryption example
│
└── tools/
    ├── README.md           # Tools documentation
    ├── requirements.txt    # Python dependencies
    └── blackbox_decoder.py # Log decoder script
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow existing code formatting
- Add documentation for new functions
- Include example usage where appropriate
- Update README for significant changes

---

## 📄 License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Nikhil Robinson**

- GitHub: [@nikhil-robinson](https://github.com/nikhil-robinson)

---

<p align="center">
  Made with ❤️ for the ESP32 community
</p>
