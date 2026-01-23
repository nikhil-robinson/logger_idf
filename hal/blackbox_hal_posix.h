/**
 * @file blackbox_hal_posix.h
 * @brief POSIX HAL backend for Blackbox logger (Linux/macOS)
 *
 * This file provides a POSIX-compatible implementation of the HAL interface.
 * Useful for desktop testing, simulation, and development.
 *
 * Features:
 * - File I/O via stdio
 * - Threading via pthreads
 * - Time via gettimeofday
 * - No encryption (set encrypt=false in config)
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_HAL_POSIX_H
#define BLACKBOX_HAL_POSIX_H

#include "../hal/blackbox_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the POSIX HAL implementation
 *
 * Returns a pointer to a statically allocated HAL structure
 * with POSIX function implementations.
 *
 * @return Pointer to POSIX HAL interface
 */
const bbox_hal_t *bbox_hal_posix_get(void);

/**
 * @brief Get a single-threaded (polling) POSIX HAL
 *
 * This variant has no threading support - use with single_threaded=true
 * in the config and call bbox_process() in your main loop.
 *
 * @return Pointer to single-threaded POSIX HAL interface
 */
const bbox_hal_t *bbox_hal_posix_single_threaded_get(void);

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_HAL_POSIX_H */
