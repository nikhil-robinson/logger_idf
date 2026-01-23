# Blackbox Flight Data Logger

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/nikhil/blackbox)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A portable, high-performance flight data logging library with Hardware Abstraction Layer (HAL) architecture.

## Features

- **🔌 Platform Independent**: HAL architecture enables easy porting to any platform
- **📊 Multiple Formats**: BBOX (native), PX4 ULog (.ulg), ArduPilot DataFlash (.bin)
- **⚡ High Performance**: Lock-free ring buffer, background writing
- **🔒 Optional Encryption**: AES-256-CTR for sensitive data (platform dependent)
- **📝 Structured Logging**: Built-in support for IMU, GPS, PID, Motor, Battery, etc.
- **📄 Text Logging**: Printf-style logging with tags and levels
- **🖥️ Desktop Testing**: Test on Linux/macOS before deploying to hardware

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                         │
├─────────────────────────────────────────────────────────────┤
│                      blackbox.h (API)                        │
├─────────────────────────────────────────────────────────────┤
│   core/blackbox_core.c     │     core/blackbox_encoder.h    │
│   (Platform Independent)    │     (Format Encoders)          │
├─────────────────────────────────────────────────────────────┤
│                     hal/blackbox_hal.h                       │
│                    (HAL Interface)                           │
├──────────────────┬──────────────────┬───────────────────────┤
│  hal_esp.c       │  hal_posix.c     │  hal_yourplatform.c   │
│  (ESP-IDF)       │  (Linux/macOS)   │  (Your Port)          │
└──────────────────┴──────────────────┴───────────────────────┘
```

## Quick Start

### ESP-IDF (ESP32)

```c
#include "blackbox.h"
#include "hal/blackbox_hal_esp.h"

void app_main(void)
{
    // Get the ESP-IDF HAL
    const bbox_hal_t *hal = bbox_hal_esp_get();

    // Configure
    bbox_config_t config;
    bbox_get_default_config(&config);
    config.root_path = "/spiffs/logs";
    config.log_format = BBOX_FORMAT_PX4_ULOG;

    // Initialize
    bbox_init(&config, hal);

    // Log text messages
    BBOX_LOG_I("MAIN", "System initialized");

    // Log structured data
    bbox_msg_imu_t imu = {
        .timestamp_us = hal->get_time_us(),
        .accel_x = 0.1f, .accel_y = 0.2f, .accel_z = -9.81f,
        .gyro_x = 0.01f, .gyro_y = 0.02f, .gyro_z = 0.0f,
        .temperature = 25.0f,
        .imu_id = 0
    };
    bbox_log_imu(&imu);

    // Cleanup
    bbox_deinit();
}
```

### Desktop (Linux/macOS)

```c
#include "blackbox.h"
#include "hal/blackbox_hal_posix.h"

int main(void)
{
    const bbox_hal_t *hal = bbox_hal_posix_get();

    bbox_config_t config;
    bbox_get_default_config(&config);
    config.root_path = "/tmp/logs";
    config.encrypt = false;  // No encryption on POSIX

    bbox_init(&config, hal);
    BBOX_LOG_I("MAIN", "Hello from desktop!");
    bbox_deinit();

    return 0;
}
```

## Project Structure

```
blackbox/
├── include/
│   └── blackbox.h          # Public API header
├── core/
│   ├── blackbox_core.c     # Core implementation (platform independent)
│   ├── blackbox_types.h    # Type definitions and enums
│   ├── blackbox_messages.h # Structured message definitions
│   ├── blackbox_encoder.h  # Format encoders
│   └── blackbox_ringbuf.h  # Lock-free ring buffer
├── hal/
│   ├── blackbox_hal.h      # HAL interface definition
│   ├── blackbox_hal_esp.c  # ESP-IDF implementation
│   ├── blackbox_hal_esp.h
│   ├── blackbox_hal_posix.c # Linux/macOS implementation
│   ├── blackbox_hal_posix.h
│   └── blackbox_hal_template.c # Template for new ports
├── examples/
│   ├── hal_example/        # ESP-IDF HAL example
│   ├── posix_test/         # Desktop test program
│   └── ...
├── tools/
│   ├── blackbox_decoder.py # Python log decoder
│   └── README.md
└── README.md
```

## HAL Interface

The HAL provides an abstraction layer between the core library and platform-specific code:

### Required Functions (Must Implement)

| Function | Purpose |
|----------|---------|
| `file_open` | Open file for writing |
| `file_write` | Write data to file |
| `file_sync` | Sync file to storage |
| `file_close` | Close file |
| `file_size` | Get current file size |
| `get_time_us` | Get timestamp in microseconds |

### Optional Functions (NULL if not available)

| Function | Purpose |
|----------|---------|
| `mutex_*` | Thread-safe access |
| `task_*` | Background writer task |
| `sem_*` | Task synchronization |
| `aes_*` | Encryption support |
| `log_output` | Console debug output |
| `malloc/free` | Custom allocator |
| `get_device_id` | Unique device ID |

## Operating Modes

### Background Task Mode (Default)

```c
config.single_threaded = false;
```

A background task drains the ring buffer and writes to file. Best for real-time systems.

### Polling Mode

```c
config.single_threaded = true;

// In your main loop:
while (1) {
    bbox_log_imu(&imu);
    bbox_process();  // Call periodically to write data
}
```

No RTOS required. Good for bare-metal systems.

## Log Formats

| Format | Extension | Compatible With |
|--------|-----------|-----------------|
| BBOX | `.blackbox` | Python decoder |
| PX4 ULog | `.ulg` | QGroundControl, FlightPlot, pyulog |
| ArduPilot | `.bin` | Mission Planner, MAVExplorer |

## Porting to New Platforms

1. Copy `hal/blackbox_hal_template.c` to `hal/blackbox_hal_yourplatform.c`
2. Implement required functions (file I/O, timestamp)
3. Optionally implement threading and encryption
4. Create your HAL getter function

Example minimal HAL:

```c
static bbox_file_t my_file_open(const char *path, bool append) {
    return (bbox_file_t)fopen(path, append ? "ab" : "wb");
}

static uint64_t my_get_time_us(void) {
    return my_timer_read_us();  // Your timer function
}

static const bbox_hal_t s_my_hal = {
    .file_open = my_file_open,
    .file_write = my_file_write,
    .file_sync = my_file_sync,
    .file_close = my_file_close,
    .file_size = my_file_size,
    .get_time_us = my_get_time_us,
    // Set remaining to NULL
};

const bbox_hal_t *my_hal_get(void) {
    return &s_my_hal;
}
```

## API Reference

### Initialization

```c
bbox_err_t bbox_init(const bbox_config_t *config, const bbox_hal_t *hal);
bbox_err_t bbox_deinit(void);
bool bbox_is_initialized(void);
void bbox_get_default_config(bbox_config_t *config);
```

### Text Logging

```c
// Macros (recommended)
BBOX_LOG_E(tag, fmt, ...);  // Error
BBOX_LOG_W(tag, fmt, ...);  // Warning
BBOX_LOG_I(tag, fmt, ...);  // Info
BBOX_LOG_D(tag, fmt, ...);  // Debug
BBOX_LOG_V(tag, fmt, ...);  // Verbose

// Direct function
void bbox_log(bbox_log_level_t level, const char *tag, 
              const char *file, uint32_t line, const char *fmt, ...);
```

### Structured Logging

```c
bbox_err_t bbox_log_imu(const bbox_msg_imu_t *imu);
bbox_err_t bbox_log_gps(const bbox_msg_gps_t *gps);
bbox_err_t bbox_log_attitude(const bbox_msg_attitude_t *att);
bbox_err_t bbox_log_pid(bbox_msg_id_t axis, const bbox_msg_pid_t *pid);
bbox_err_t bbox_log_motor(const bbox_msg_motor_t *motor);
bbox_err_t bbox_log_battery(const bbox_msg_battery_t *battery);
bbox_err_t bbox_log_rc_input(const bbox_msg_rc_input_t *rc);
bbox_err_t bbox_log_status(const bbox_msg_status_t *status);
bbox_err_t bbox_log_baro(const bbox_msg_baro_t *baro);
bbox_err_t bbox_log_mag(const bbox_msg_mag_t *mag);
bbox_err_t bbox_log_esc(const bbox_msg_esc_t *esc);

// Generic struct logging
bbox_err_t bbox_log_struct(bbox_msg_id_t msg_id, const void *data, size_t size);
```

### Control

```c
bbox_err_t bbox_flush(void);                     // Force flush to file
bbox_err_t bbox_process(void);                   // Process ring buffer (polling mode)
bbox_err_t bbox_rotate_file(void);               // Start new log file
bbox_err_t bbox_set_level(bbox_log_level_t level);
bbox_err_t bbox_set_console_output(bool enable);
bbox_err_t bbox_set_file_output(bool enable);
bbox_err_t bbox_get_stats(bbox_stats_t *stats);
```

## Decoding Logs

Use the Python decoder to analyze log files:

```bash
# Basic decode
python3 tools/blackbox_decoder.py flight_000001.blackbox

# Structured data as JSON
python3 tools/blackbox_decoder.py flight_000001.blackbox --struct --json

# Decrypt
python3 tools/blackbox_decoder.py flight_000001.blackbox --key your_hex_key
```

For PX4 ULog files, use standard tools:

```bash
# pyulog
ulog_info flight.ulg
ulog2csv flight.ulg

# QGroundControl
# File → Analyze Log
```

## Migration from v2.0

See [MIGRATION.md](MIGRATION.md) for upgrading from the v2.0 ESP-IDF-only API.

## License

MIT License - see [LICENSE](LICENSE)

## Author

Nikhil Robinson
