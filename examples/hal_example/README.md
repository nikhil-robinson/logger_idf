# Blackbox HAL Example

This example demonstrates the new HAL-based Blackbox API with ESP-IDF.

## Overview

The Blackbox library v3.0 uses a Hardware Abstraction Layer (HAL) architecture
that separates platform-specific code from core logging logic. This enables:

- **Portability**: Same API works on ESP32, STM32, Linux, etc.
- **Testability**: Run and test on desktop before deploying to hardware
- **Maintainability**: Platform bugs fixed in one place (the HAL)

## Key Changes from v2.0

```c
// Old API (v2.0) - ESP-IDF specific
#include "blackbox.h"
blackbox_config_t config;
blackbox_get_default_config(&config);
esp_err_t ret = blackbox_init(&config);

// New API (v3.0) - HAL-based
#include "blackbox.h"
#include "hal/blackbox_hal_esp.h"

const bbox_hal_t *hal = bbox_hal_esp_get();  // Get platform HAL
bbox_config_t config;
bbox_get_default_config(&config);
bbox_err_t ret = bbox_init(&config, hal);    // Pass HAL to init
```

## Single-Threaded Mode

For bare-metal or resource-constrained systems, you can use polling mode:

```c
config.single_threaded = true;  // No background task

// In your main loop:
while (1) {
    // Your sensor reading code...
    bbox_log_imu(&imu);
    
    // Periodically process the buffer
    bbox_process();  // Writes pending data to file
}
```

## Building

```bash
cd examples/hal_example
idf.py set-target esp32
idf.py build flash monitor
```

## HAL Implementations

| HAL Backend | File | Features |
|-------------|------|----------|
| ESP-IDF | `hal/blackbox_hal_esp.c` | Full: FreeRTOS, mbedTLS, SPIFFS/FATFS |
| POSIX | `hal/blackbox_hal_posix.c` | Threading via pthreads, no encryption |
| Template | `hal/blackbox_hal_template.c` | Starting point for new ports |

## Porting to New Platforms

1. Copy `hal/blackbox_hal_template.c` to `hal/blackbox_hal_yourplatform.c`
2. Implement required functions (file I/O, timestamp)
3. Optionally implement threading and encryption
4. Call `bbox_init()` with your HAL

See `hal/blackbox_hal.h` for the complete interface documentation.
