# PX4 ULog Format Example (SPIFFS)

This example demonstrates structured flight data logging using the **PX4 ULog** format stored on SPIFFS internal flash storage.

## Features

- **PX4 ULog Format**: Generates `.ulg` files compatible with PX4 ecosystem tools
- **SPIFFS Storage**: Uses internal SPI flash for log storage (no SD card required)
- **Simulated PX4 Flight Data**: IMU, GPS, Baro, Mag, Attitude, PID, Motors, Battery, RC, ESC
- **100Hz IMU Logging**: High-frequency sensor data capture
- **Self-Describing Format**: Message format definitions embedded in file

## PX4 ULog Format

The ULog format is PX4's official binary logging format:

```
[Header (16 bytes)]
  Magic "ULogXXXX" + version + timestamp

[Definitions Section]
  - FLAG_BITS: Appended data flags
  - INFO: Key-value metadata
  - FORMAT: Message type definitions

[Data Section]
  - DATA: Actual sensor/state messages
  - LOGGING: Text log messages
```

### Message Types Logged

| Message | Rate | Description |
|---------|------|-------------|
| sensor_combined | 100Hz | IMU (gyro + accel) |
| vehicle_attitude | 100Hz | Roll, pitch, yaw |
| rate_ctrl_status | 50Hz | PID outputs per axis |
| actuator_outputs | 50Hz | Motor PWM values |
| vehicle_gps_position | 10Hz | GPS fix data |
| sensor_baro | 10Hz | Barometric altitude |
| sensor_mag | 10Hz | Magnetometer |
| input_rc | 10Hz | RC receiver |
| esc_status | 10Hz | ESC telemetry |
| battery_status | 2Hz | Battery state |

## Compatible Analysis Tools

### QGroundControl (Cross-platform)
1. Open QGroundControl
2. Go to **Analyze** → **Log Download** (or load local file)
3. Use built-in log analyzer for automatic analysis
4. View flight path, sensor data, and system events

### FlightPlot (Java)
```bash
# Download FlightPlot
wget https://github.com/PX4/FlightPlot/releases/download/v0.8.2/flightplot.jar

# Run
java -jar flightplot.jar

# Load .ulg file and plot data
```

### PlotJuggler (with PX4 plugin)
```bash
# Install PlotJuggler
sudo apt install plotjuggler

# Install PX4 plugin
# Or use AppImage with built-in support

# Load .ulg file directly
plotjuggler your_log.ulg
```

### pyulog (Python)
```bash
# Install
pip install pyulog

# Get log info
ulog_info your_log.ulg

# Convert to CSV
ulog2csv your_log.ulg

# List topics
ulog_messages your_log.ulg

# Extract specific topic
ulog2csv -m sensor_combined your_log.ulg
```

### Python Scripting
```python
from pyulog import ULog

# Load log
ulog = ULog("your_log.ulg")

# List available messages
for msg in ulog.data_list:
    print(f"{msg.name}: {len(msg.data['timestamp'])} samples")

# Access IMU data
imu = ulog.get_dataset("sensor_combined")
timestamps = imu.data["timestamp"]
accel_x = imu.data["accelerometer_m_s2[0]"]
gyro_z = imu.data["gyro_rad[2]"]
```

## Building and Flashing

```bash
cd examples/px4_spiffs_example

# Set target (ESP32, ESP32-S3, etc.)
idf.py set-target esp32s3

# Build
idf.py build

# Flash and monitor
idf.py -p /dev/ttyUSB0 flash monitor
```

## Configuration

### Kconfig Options

In `menuconfig`, navigate to **Component config** → **Blackbox Logger**:

- **Log Format**: Set to "PX4 ULog"
- **Enable Structured Logging**: Must be enabled

### Runtime Configuration

```c
blackbox_config_t config;
blackbox_get_default_config(&config);

config.root_path = "/spiffs/logs";
config.file_prefix = "px4_";
config.log_format = BLACKBOX_FORMAT_PX4_ULOG;
config.file_size_limit = 128 * 1024;  // 128KB per file
```

## SPIFFS Partition

The partition table (`partitions.csv`) allocates 512KB for SPIFFS:

```csv
spiffs,   data, spiffs,  ,  512K,
```

## Example Output

```
I (xxx) PX4_ULOG_EXAMPLE: ========================================
I (xxx) PX4_ULOG_EXAMPLE:     Blackbox PX4 ULog Format Example
I (xxx) PX4_ULOG_EXAMPLE: ========================================
I (xxx) PX4_ULOG_EXAMPLE: SPIFFS mounted: total=458752 bytes, used=0 bytes
I (xxx) PX4_ULOG_EXAMPLE: Logger initialized - PX4 ULog format
I (xxx) PX4_ULOG_EXAMPLE: Log files: /spiffs/logs/px4_*.ulg

I (xxx) PX4_ULOG_EXAMPLE: === PX4 ULog Stats ===
I (xxx) PX4_ULOG_EXAMPLE: Messages: 8234 logged, 0 dropped
I (xxx) PX4_ULOG_EXAMPLE: Bytes written: 156789, Files: 1
I (xxx) PX4_ULOG_EXAMPLE: State: arm=1, mode=POSCTL, alt=52.3m
```

## Flight Simulation Sequence

The example simulates a complete flight:

1. **0-15s**: Disarmed, pre-flight checks
2. **15s**: ARM command
3. **30s**: Switch to POSCTL mode
4. **45s**: Switch to AUTO_LOITER
5. **60s**: RTL (Return to Launch)
6. **75s**: LAND and DISARM
7. **Repeat**

## Extracting Logs

### Via esptool
```bash
# Read SPIFFS partition
esptool.py read_flash 0x110000 0x80000 spiffs.bin

# Use mkspiffs or Python to extract
```

### Via Application
Add HTTP or serial file transfer to your app:
```c
// Example: HTTP server endpoint
// GET /logs/px4_000001.ulg
```

## Comparison: ULog vs DataFlash

| Feature | PX4 ULog | ArduPilot DataFlash |
|---------|----------|---------------------|
| File Extension | .ulg | .bin |
| Self-describing | Yes | Yes |
| Nested Types | Yes | No |
| Logging Messages | Yes | Yes |
| Append Support | Yes | No |
| Primary Tools | QGC, FlightPlot | Mission Planner |

## Troubleshooting

### "Failed to create log file"
- Check SPIFFS space: `esp_spiffs_info()`
- Reduce `file_size_limit`

### "pyulog can't read file"
- Ensure complete file write (call `blackbox_flush()`)
- Check file header integrity

### "QGroundControl shows no data"
- Verify FORMAT messages are written
- Check timestamp continuity

## License

MIT License - See main project LICENSE file.
