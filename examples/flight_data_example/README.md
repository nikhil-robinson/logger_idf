# Blackbox Structured Flight Data Logging Example

This example demonstrates structured data logging for drone/robotics applications with support for multiple industry-standard log formats.

## Features

- **High-frequency IMU logging** (100 Hz)
- **GPS, Attitude, Motor, Battery logging** (10 Hz)
- **PID controller state logging** (50 Hz)
- **Multiple log format support:**
  - BBOX Native (.blackbox) - Custom format with optional encryption
  - PX4 ULog (.ulg) - Compatible with PX4 ecosystem tools
  - ArduPilot DataFlash (.bin) - Compatible with ArduPilot tools

## Log Format Compatibility

### PX4 ULog Format (.ulg)
- [QGroundControl](https://qgroundcontrol.com/) - Log viewer
- [FlightPlot](https://github.com/PX4/FlightPlot) - Java-based log plotter
- [PlotJuggler](https://www.plotjuggler.io/) - Real-time data visualization
- [pyulog](https://github.com/PX4/pyulog) - Python ULog parser

### ArduPilot DataFlash Format (.bin)
- [Mission Planner](https://ardupilot.org/planner/) - Log Review
- [MAVExplorer](https://ardupilot.org/dev/docs/using-mavexplorer-for-log-analysis.html)
- [UAV Log Viewer](https://plot.ardupilot.org/)

## Hardware Requirements

- ESP32 or ESP32-S3 development board
- SPIFFS partition for log storage (this example uses internal flash)
- For production use: SD card recommended for larger storage

## Building and Flashing

```bash
# Set target (ESP32 or ESP32-S3)
idf.py set-target esp32s3

# Build the project
idf.py build

# Flash and monitor
idf.py -p /dev/ttyUSB0 flash monitor
```

## Configuration

You can change the log format in `main.c`:

```c
// Select format:
config.log_format = BLACKBOX_FORMAT_BBOX;       // Native format
config.log_format = BLACKBOX_FORMAT_PX4_ULOG;   // PX4 ULog
config.log_format = BLACKBOX_FORMAT_ARDUPILOT;  // ArduPilot DataFlash
```

Or use menuconfig:

```bash
idf.py menuconfig
# Navigate to: Component config → Blackbox Logger → Log Format Settings
```

## Message Types

The example logs the following message types:

| Message | Rate | Description |
|---------|------|-------------|
| IMU | 100 Hz | Gyroscope, accelerometer, temperature |
| GPS | 10 Hz | Position, altitude, satellites, fix type |
| Attitude | 10 Hz | Roll, pitch, yaw (Euler angles) |
| Motor | 10 Hz | Motor PWM outputs (8 channels) |
| Battery | 10 Hz | Voltage, current, capacity, temperature |
| PID | 50 Hz | PID state for roll/pitch/yaw axes |

## Analyzing Logs

### PX4 ULog Format

```bash
# Install pyulog
pip install pyulog

# Convert to CSV
ulog2csv flight000001.ulg

# Show info
ulog_info flight000001.ulg
```

### BBOX Native Format

Use the included decoder tool:

```bash
cd tools/
python blackbox_decoder.py /path/to/flight000001.blackbox --output csv
```

## Memory Usage

Typical memory usage at full logging rate:
- Ring buffer: 32 KB
- Task stacks: ~12 KB (3 logging tasks)
- Total: ~50 KB RAM

## Data Rates

At full logging rates:
- IMU: 100 Hz × ~40 bytes = 4 KB/s
- Sensors: 10 Hz × ~200 bytes = 2 KB/s
- PID: 50 Hz × 3 axes × ~36 bytes = 5.4 KB/s
- **Total: ~11.4 KB/s** (~41 MB/hour)

## Integration with Flight Controllers

This logging library is designed to integrate with custom flight controller firmware. Replace the simulated sensor functions with your actual sensor drivers:

```c
// Instead of simulate_imu(), use your actual IMU driver:
void read_imu_task(void *arg)
{
    bbox_msg_imu_t imu;
    while (1) {
        // Read from actual IMU hardware
        mpu6050_read(&imu.accel_x, &imu.accel_y, &imu.accel_z,
                     &imu.gyro_x, &imu.gyro_y, &imu.gyro_z);
        imu.timestamp_us = esp_timer_get_time();
        
        blackbox_log_imu(&imu);
        vTaskDelay(pdMS_TO_TICKS(10));  // 100 Hz
    }
}
```
