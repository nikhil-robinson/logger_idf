# ArduPilot DataFlash Format Example (SPIFFS)

This example demonstrates structured flight data logging using the **ArduPilot DataFlash** format stored on SPIFFS internal flash storage.

## Features

- **ArduPilot DataFlash Format**: Generates `.bin` files compatible with ArduPilot analysis tools
- **SPIFFS Storage**: Uses internal SPI flash for log storage (no SD card required)
- **Simulated Flight Data**: IMU, GPS, Baro, Mag, Attitude, Motors, Battery, RC Input
- **100Hz IMU Logging**: High-frequency sensor data capture
- **Self-Describing Format**: FMT messages define data structures

## ArduPilot DataFlash Format

The DataFlash format is ArduPilot's native binary logging format:

```
[FMT][FMT][FMT]...[DATA][DATA][DATA]...

FMT Message: Defines message structure (type, length, format, labels)
DATA Message: Actual sensor/state data
```

### Message Types Logged

| Message | Rate | Description |
|---------|------|-------------|
| IMU | 100Hz | Gyroscope and accelerometer data |
| GPS | 10Hz | Position, velocity, fix status |
| BARO | 10Hz | Barometric pressure and altitude |
| MAG | 10Hz | Magnetometer readings |
| ATT | 10Hz | Attitude (roll, pitch, yaw) |
| RCIN | 10Hz | RC receiver channels |
| RCOU | 10Hz | Motor/servo outputs |
| BAT | 10Hz | Battery voltage, current, capacity |

## Compatible Analysis Tools

### Mission Planner (Windows)
1. Open Mission Planner
2. Go to **DataFlash Logs** tab
3. Click **Review a Log**
4. Select the `.bin` file from SPIFFS
5. Use **Log Browser** or **Graph This** for analysis

### MAVExplorer (Cross-platform)
```bash
# Install pymavlink
pip install pymavlink

# Analyze log file
mavlogdump.py --types IMU,GPS,ATT your_log.bin

# Plot data
mavgraph.py your_log.bin "IMU.AccX" "IMU.AccY"
```

### APM Planner 2.0
1. Open APM Planner
2. Go to **Flight Data** → **DataFlash Logs**
3. Load and analyze the `.bin` file

## Building and Flashing

```bash
cd examples/ardupilot_spiffs_example

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

- **Log Format**: Set to "ArduPilot DataFlash"
- **Enable Structured Logging**: Must be enabled

### Runtime Configuration

```c
blackbox_config_t config;
blackbox_get_default_config(&config);

config.root_path = "/spiffs/logs";
config.file_prefix = "ardu";
config.log_format = BLACKBOX_FORMAT_ARDUPILOT;
config.file_size_limit = 128 * 1024;  // 128KB per file
```

## SPIFFS Partition

The partition table (`partitions.csv`) allocates 512KB for SPIFFS:

```csv
spiffs,   data, spiffs,  ,  512K,
```

With 128KB file size limit, you can store ~4 log files before rotation overwrites old files.

## Example Output

```
I (xxx) ARDUPILOT_EXAMPLE: ========================================
I (xxx) ARDUPILOT_EXAMPLE:   Blackbox ArduPilot DataFlash Example
I (xxx) ARDUPILOT_EXAMPLE: ========================================
I (xxx) ARDUPILOT_EXAMPLE: SPIFFS mounted: total=458752 bytes, used=0 bytes
I (xxx) ARDUPILOT_EXAMPLE: Logger initialized - ArduPilot DataFlash format
I (xxx) ARDUPILOT_EXAMPLE: Log files: /spiffs/logs/ardu*.bin

I (xxx) ARDUPILOT_EXAMPLE: === ArduPilot Log Stats ===
I (xxx) ARDUPILOT_EXAMPLE: Messages: 5432 logged, 0 dropped
I (xxx) ARDUPILOT_EXAMPLE: Bytes written: 87654, Files: 1
I (xxx) ARDUPILOT_EXAMPLE: Vehicle: armed=1, alt=100.5m, hdg=45.2°
```

## Extracting Logs from SPIFFS

### Method 1: Using esptool
```bash
# Read SPIFFS partition
esptool.py read_flash 0x110000 0x80000 spiffs.bin

# Mount and extract (Linux)
mkdir /tmp/spiffs
mount -o loop spiffs.bin /tmp/spiffs
cp /tmp/spiffs/logs/*.bin ./
```

### Method 2: Serial/WiFi Transfer
Implement file transfer in your application using:
- ESP HTTP Server
- ESP WebSocket
- Custom serial protocol

## Memory Considerations

- **Ring Buffer**: 8KB (adjustable via `buffer_size`)
- **Stack Size**: 4KB per task
- **SPIFFS Overhead**: ~4KB for metadata
- **File Limit**: 128KB per file to prevent fragmentation

## Troubleshooting

### "SPIFFS partition not found"
Ensure `partitions.csv` is correct and flash with:
```bash
idf.py -p /dev/ttyUSB0 erase_flash flash
```

### "Failed to create log file"
- Check SPIFFS is not full: `esp_spiffs_info()`
- Ensure `/spiffs/logs` directory exists (created automatically)

### "Messages dropped"
- Increase `buffer_size` in config
- Reduce logging frequency
- Increase `flush_interval_ms` (tradeoff: more data loss on crash)

## License

MIT License - See main project LICENSE file.
