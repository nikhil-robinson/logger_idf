/**
 * @file blackbox_hal_esp.h
 * @brief ESP-IDF HAL backend for Blackbox logger
 *
 * This file provides the ESP-IDF implementation of the HAL interface.
 * It wraps FreeRTOS, ESP-IDF file I/O, mbedTLS, and other ESP-specific APIs.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_HAL_ESP_H
#define BLACKBOX_HAL_ESP_H

#include "../hal/blackbox_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the ESP-IDF HAL implementation
 *
 * Returns a pointer to a statically allocated HAL structure
 * with all ESP-IDF function implementations.
 *
 * @return Pointer to ESP-IDF HAL interface
 */
const bbox_hal_t *bbox_hal_esp_get(void);

/**
 * @brief Initialize ESP-IDF specific resources
 *
 * Call this before using the HAL. This is optional - the HAL
 * functions will work without it, but this allows for any
 * platform-specific setup.
 *
 * @return BBOX_OK on success
 */
bbox_err_t bbox_hal_esp_init(void);

/**
 * @brief Cleanup ESP-IDF specific resources
 *
 * Call this when done using the HAL to free any allocated resources.
 *
 * @return BBOX_OK on success
 */
bbox_err_t bbox_hal_esp_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_HAL_ESP_H */
