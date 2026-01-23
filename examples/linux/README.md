# Linux Examples

These examples demonstrate the Blackbox logger library on Linux/macOS without any embedded hardware.

## Prerequisites

- GCC or Clang compiler
- POSIX-compatible system (Linux, macOS, WSL)
- pthreads library (usually included)

## Building

```bash
cd examples/linux

# Build all examples
make all

# Build specific example
make flight_data

# Clean build artifacts and logs
make clean
```

## Examples

### basic_logging

Basic text logging example - equivalent to the ESP-IDF `spiffs_example`.

```bash
./basic_logging
```

Demonstrates:
- Logger initialization with POSIX HAL
- Text logging with different levels (INFO, WARN, ERROR, DEBUG)
- Statistics reporting
- Graceful shutdown with Ctrl+C

### flight_data

Structured flight data logging with simulated IMU, GPS, attitude, PID, motors, and battery data.

```bash
# Default BBOX format
./flight_data

# PX4 ULog format (compatible with QGroundControl)
./flight_data --format ulog

# ArduPilot DataFlash format
./flight_data --format ardupilot

# Run for 30 seconds at 200Hz
./flight_data --duration 30 --rate 200

# Use polling mode (no background thread)
./flight_data --single-threaded
```

### single_threaded

Demonstrates polling mode without background threads.

```bash
./single_threaded
```

Key points:
- Set `config.single_threaded = true`
- Call `bbox_process()` regularly in your main loop
- Good for bare-metal systems or when you need full control

### multi_format

Creates log files in all three formats for comparison.

```bash
./multi_format
```

Creates files in:
- `/tmp/blackbox_formats/bbox/` - BBOX native format
- `/tmp/blackbox_formats/ulog/` - PX4 ULog format
- `/tmp/blackbox_formats/ardupilot/` - ArduPilot DataFlash format

### ardupilot_pid

PID controller logging in ArduPilot DataFlash format for viewing with MAVExplorer.

```bash
# Run for 10 seconds at 400Hz
./ardupilot_pid --duration 10

# View with MAVExplorer
pip install MAVProxy
mavexplorer.py /tmp/blackbox_ardupilot/flight000001.bin
```

Logs Roll/Pitch/Yaw PID data including:
- Setpoint (target) and measured values
- P, I, D, FF terms
- Total output

In MAVExplorer: Graph menu → PIDR/PIDP/PIDY → Select fields to plot.

## Log Output

By default, logs are written to `/tmp/blackbox_*`. Use the Python decoder to analyze:

```bash
# Decode BBOX format
python3 ../../tools/blackbox_decoder.py /tmp/blackbox_logs/*.blackbox

# For ULog format, use pyulog
pip install pyulog
ulog_info /tmp/blackbox_flight/*.ulg
ulog2csv /tmp/blackbox_flight/*.ulg
```

## Code Structure

All examples follow this pattern:

```c
#include "include/blackbox.h"
#include "hal/blackbox_hal_posix.h"

int main() {
    // 1. Get the POSIX HAL
    const bbox_hal_t *hal = bbox_hal_posix_get();
    
    // 2. Configure
    bbox_config_t config;
    bbox_get_default_config(&config);
    config.root_path = "/tmp/logs";
    config.log_format = BBOX_FORMAT_PX4_ULOG;
    
    // 3. Initialize
    bbox_init(&config, hal);
    
    // 4. Log data
    BBOX_LOG_I("TAG", "Hello!");
    bbox_log_imu(&imu_data);
    
    // 5. Cleanup
    bbox_deinit();
    
    return 0;
}
```

## Porting to Other Platforms

These examples use `blackbox_hal_posix.c`, which provides:
- File I/O via stdio
- Timestamps via `gettimeofday()`
- Threading via pthreads
- No encryption (POSIX HAL doesn't implement AES)

To port to a new platform, implement the HAL interface in `hal/blackbox_hal.h`.
See `hal/blackbox_hal_template.c` for a starting point.
