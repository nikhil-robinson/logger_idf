# Migration Guide: v2.0 to v3.0

This guide helps you migrate from the ESP-IDF-specific v2.0 API to the
HAL-based v3.0 API.

## Overview of Changes

| Aspect | v2.0 | v3.0 |
|--------|------|------|
| Platform | ESP-IDF only | Any platform via HAL |
| Header | `blackbox.h` | `blackbox.h` + `hal/blackbox_hal_*.h` |
| Init | `blackbox_init(&config)` | `bbox_init(&config, hal)` |
| Return type | `esp_err_t` | `bbox_err_t` |
| Prefix | `blackbox_` / `BLACKBOX_` | `bbox_` / `BBOX_` |
| Log levels | `BLACKBOX_LOG_LEVEL_*` | `BBOX_LOG_LEVEL_*` |

## Step-by-Step Migration

### 1. Update Includes

```c
// v2.0
#include "blackbox.h"

// v3.0
#include "blackbox.h"
#include "hal/blackbox_hal_esp.h"  // For ESP-IDF
```

### 2. Update Initialization

```c
// v2.0
blackbox_config_t config;
blackbox_get_default_config(&config);
config.root_path = "/spiffs/logs";
esp_err_t ret = blackbox_init(&config);

// v3.0
const bbox_hal_t *hal = bbox_hal_esp_get();

bbox_config_t config;
bbox_get_default_config(&config);
config.root_path = "/spiffs/logs";
bbox_err_t ret = bbox_init(&config, hal);
```

### 3. Update Function Calls

| v2.0 Function | v3.0 Function |
|---------------|---------------|
| `blackbox_init()` | `bbox_init()` |
| `blackbox_deinit()` | `bbox_deinit()` |
| `blackbox_log()` | `bbox_log()` |
| `blackbox_flush()` | `bbox_flush()` |
| `blackbox_get_stats()` | `bbox_get_stats()` |
| `blackbox_set_level()` | `bbox_set_level()` |
| `blackbox_log_imu()` | `bbox_log_imu()` |
| `blackbox_log_gps()` | `bbox_log_gps()` |
| `blackbox_is_initialized()` | `bbox_is_initialized()` |

### 4. Update Logging Macros

```c
// v2.0
BLACKBOX_LOG_INFO(TAG, "Hello %d", 42);
BLACKBOX_LOG_ERROR(TAG, "Error!");
BLACKBOX_LOG_I(TAG, "Shorthand");

// v3.0
BBOX_LOG_INFO(TAG, "Hello %d", 42);
BBOX_LOG_ERROR(TAG, "Error!");
BBOX_LOG_I(TAG, "Shorthand");
```

### 5. Update Return Type Checks

```c
// v2.0
if (blackbox_init(&config) != ESP_OK) {
    ESP_LOGE(TAG, "Init failed");
}

// v3.0
if (bbox_init(&config, hal) != BBOX_OK) {
    // Handle error
}
```

### 6. Update Log Level Enum

```c
// v2.0
config.min_level = BLACKBOX_LOG_LEVEL_DEBUG;

// v3.0
config.min_level = BBOX_LOG_LEVEL_DEBUG;
```

### 7. Update Log Format Enum

```c
// v2.0
config.log_format = BLACKBOX_FORMAT_PX4_ULOG;

// v3.0
config.log_format = BBOX_FORMAT_PX4_ULOG;
```

### 8. Update Stats Structure

```c
// v2.0
blackbox_stats_t stats;
blackbox_get_stats(&stats);

// v3.0
bbox_stats_t stats;
bbox_get_stats(&stats);
// Note: struct_messages field added in v3.0
```

### 9. Update Timestamp Macros

```c
// v2.0 (used esp_timer directly)
bbox_msg_imu_t imu = {
    .timestamp_us = esp_timer_get_time(),
    // ...
};

// v3.0 (use HAL)
const bbox_hal_t *hal = bbox_hal_esp_get();
bbox_msg_imu_t imu = {
    .timestamp_us = hal->get_time_us(),
    // ...
};

// Or use macros that take HAL pointer
BBOX_LOG_IMU(hal, ax, ay, az, gx, gy, gz, temp, id);
```

### 10. New Feature: Single-Threaded Mode

v3.0 adds polling mode for bare-metal systems:

```c
config.single_threaded = true;

// In main loop:
while (1) {
    // Log data...
    bbox_process();  // NEW: Process ring buffer
}
```

## Compatibility Shim (Optional)

If you have a large codebase and want to migrate gradually, create a shim:

```c
// blackbox_compat.h
#ifndef BLACKBOX_COMPAT_H
#define BLACKBOX_COMPAT_H

#include "blackbox.h"
#include "hal/blackbox_hal_esp.h"

/* Type aliases */
typedef bbox_config_t blackbox_config_t;
typedef bbox_stats_t blackbox_stats_t;
typedef bbox_log_level_t blackbox_level_t;

/* Enum aliases */
#define BLACKBOX_LOG_LEVEL_ERROR   BBOX_LOG_LEVEL_ERROR
#define BLACKBOX_LOG_LEVEL_WARN    BBOX_LOG_LEVEL_WARN
#define BLACKBOX_LOG_LEVEL_INFO    BBOX_LOG_LEVEL_INFO
#define BLACKBOX_LOG_LEVEL_DEBUG   BBOX_LOG_LEVEL_DEBUG
#define BLACKBOX_FORMAT_BBOX       BBOX_FORMAT_BBOX
#define BLACKBOX_FORMAT_PX4_ULOG   BBOX_FORMAT_PX4_ULOG
#define BLACKBOX_FORMAT_ARDUPILOT  BBOX_FORMAT_ARDUPILOT

/* Function wrappers */
static inline esp_err_t blackbox_init(const blackbox_config_t *cfg) {
    bbox_err_t err = bbox_init(cfg, bbox_hal_esp_get());
    return (err == BBOX_OK) ? ESP_OK : ESP_FAIL;
}

#define blackbox_deinit()      bbox_deinit()
#define blackbox_flush()       bbox_flush()
#define blackbox_log_imu(x)    bbox_log_imu(x)
#define blackbox_log_gps(x)    bbox_log_gps(x)
// ... add more as needed

/* Macro aliases */
#define BLACKBOX_LOG_E  BBOX_LOG_E
#define BLACKBOX_LOG_W  BBOX_LOG_W
#define BLACKBOX_LOG_I  BBOX_LOG_I
#define BLACKBOX_LOG_D  BBOX_LOG_D

#endif
```

## Removed Features

The following v2.0 features are removed in v3.0:

1. **Panic Handler**: The ESP-IDF specific panic handler is not part of core.
   Implement platform-specific panic handling in your application if needed.

2. **Kconfig Integration**: Configuration is now done at runtime via `bbox_config_t`.
   You can still use Kconfig to populate the config struct in your application.

## New Features in v3.0

1. **HAL Architecture**: Port to any platform
2. **Single-Threaded Mode**: No RTOS required
3. **Desktop Testing**: Test on Linux/macOS
4. **`bbox_process()`**: Manual ring buffer processing
5. **`struct_messages` stat**: Track structured message count
6. **Template HAL**: Easy starting point for new ports

## Build System Changes

### ESP-IDF Component

The CMakeLists.txt is updated but the component structure is the same:

```cmake
# The component auto-includes ESP HAL
idf_component_register(
    SRCS
        "core/blackbox_core.c"
        "hal/blackbox_hal_esp.c"
    INCLUDE_DIRS
        "."
        "include"
        "core"
        "hal"
    REQUIRES
        mbedtls
)
```

### Desktop Build

New: You can build for desktop:

```bash
gcc -o test test.c core/blackbox_core.c hal/blackbox_hal_posix.c \
    -I. -lpthread -lm
```

## Testing Your Migration

1. Build your project and fix any compile errors
2. Run on hardware and verify logs are written correctly
3. Decode logs with Python decoder to verify format
4. Check statistics to ensure no messages dropped

If you encounter issues, please open a GitHub issue with your migration scenario.
