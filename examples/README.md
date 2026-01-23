# Blackbox Examples

## ESP-IDF (ESP32)

### hal_example

Full-featured ESP-IDF example demonstrating the HAL-based API.

```bash
cd hal_example
idf.py build
idf.py flash monitor
```

Features:
- IMU, GPS, attitude, motor, battery logging
- PX4 ULog format output
- Background writer task
- SPIFFS storage

## Linux/macOS

### linux

Five portable examples for desktop development and testing.

```bash
cd linux
make all

# Basic text logging
./basic_logging

# Structured flight data
./flight_data --format ulog --duration 10

# Polling mode (no background thread)
./single_threaded

# Compare all three formats
./multi_format

# ArduPilot PID logging (view with MAVExplorer)
./ardupilot_pid --duration 10
mavexplorer.py /tmp/blackbox_ardupilot/flight000001.bin
```

See [linux/README.md](linux/README.md) for detailed documentation.
