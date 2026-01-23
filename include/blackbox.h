/**
 * @file blackbox.h
 * @brief Blackbox Flight Data Logger - Public API
 *
 * A portable, high-performance flight data logging library with:
 * - Multiple format support: BBOX, PX4 ULog, ArduPilot DataFlash
 * - Structured message logging (IMU, GPS, PID, Motor, etc.)
 * - Optional AES-256 encryption
 * - Platform-independent via HAL
 * - Single-threaded or background task modes
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_H
#define BLACKBOX_H

#include "core/blackbox_types.h"
#include "core/blackbox_messages.h"
#include "hal/blackbox_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Initialization and Control
 ******************************************************************************/

/**
 * @brief Initialize the blackbox logger
 *
 * @param config Logger configuration
 * @param hal Hardware abstraction layer interface
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_init(const bbox_config_t *config, const bbox_hal_t *hal);

/**
 * @brief Deinitialize the logger
 *
 * Flushes remaining data and cleans up resources.
 *
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_deinit(void);

/**
 * @brief Check if logger is initialized
 *
 * @return true if initialized
 */
bool bbox_is_initialized(void);

/**
 * @brief Get default configuration
 *
 * @param config Configuration structure to fill with defaults
 */
void bbox_get_default_config(bbox_config_t *config);

/*******************************************************************************
 * Text Logging API
 ******************************************************************************/

/**
 * @brief Log a formatted text message
 *
 * @param level Log level
 * @param tag Component tag
 * @param file Source file name (__FILE__)
 * @param line Source line number (__LINE__)
 * @param fmt Printf-style format string
 * @param ... Format arguments
 */
void bbox_log(bbox_log_level_t level, const char *tag, const char *file,
              uint32_t line, const char *fmt, ...);

/**
 * @brief Log a formatted text message (va_list version)
 */
void bbox_log_va(bbox_log_level_t level, const char *tag, const char *file,
                 uint32_t line, const char *fmt, va_list args);

/*******************************************************************************
 * Structured Message Logging API
 ******************************************************************************/

/**
 * @brief Log a structured message
 *
 * @param msg_id Message type ID
 * @param data Pointer to message struct
 * @param size Size of message struct in bytes
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_log_struct(bbox_msg_id_t msg_id, const void *data, size_t size);

/**
 * @brief Log IMU sensor data
 */
bbox_err_t bbox_log_imu(const bbox_msg_imu_t *imu);

/**
 * @brief Log GPS position data
 */
bbox_err_t bbox_log_gps(const bbox_msg_gps_t *gps);

/**
 * @brief Log attitude data
 */
bbox_err_t bbox_log_attitude(const bbox_msg_attitude_t *att);

/**
 * @brief Log PID controller state
 */
bbox_err_t bbox_log_pid(bbox_msg_id_t axis, const bbox_msg_pid_t *pid);

/**
 * @brief Log motor outputs
 */
bbox_err_t bbox_log_motor(const bbox_msg_motor_t *motor);

/**
 * @brief Log battery status
 */
bbox_err_t bbox_log_battery(const bbox_msg_battery_t *battery);

/**
 * @brief Log RC input channels
 */
bbox_err_t bbox_log_rc_input(const bbox_msg_rc_input_t *rc);

/**
 * @brief Log system status
 */
bbox_err_t bbox_log_status(const bbox_msg_status_t *status);

/**
 * @brief Log barometer data
 */
bbox_err_t bbox_log_baro(const bbox_msg_baro_t *baro);

/**
 * @brief Log magnetometer data
 */
bbox_err_t bbox_log_mag(const bbox_msg_mag_t *mag);

/**
 * @brief Log ESC telemetry data
 */
bbox_err_t bbox_log_esc(const bbox_msg_esc_t *esc);

/*******************************************************************************
 * Control Functions
 ******************************************************************************/

/**
 * @brief Force flush buffered data to file
 *
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_flush(void);

/**
 * @brief Process pending writes (for single-threaded mode)
 *
 * Call this periodically in your main loop when using single_threaded=true.
 * This drains the ring buffer and writes data to file.
 *
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_process(void);

/**
 * @brief Rotate to a new log file immediately
 *
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_rotate_file(void);

/**
 * @brief Set minimum log level at runtime
 *
 * @param level New minimum log level
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_set_level(bbox_log_level_t level);

/**
 * @brief Get current minimum log level
 *
 * @return Current minimum log level
 */
bbox_log_level_t bbox_get_level(void);

/**
 * @brief Enable or disable console output at runtime
 *
 * @param enable true to enable, false to disable
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_set_console_output(bool enable);

/**
 * @brief Enable or disable file output at runtime
 *
 * @param enable true to enable, false to disable
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_set_file_output(bool enable);

/**
 * @brief Get logger statistics
 *
 * @param stats Pointer to stats structure to fill
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_get_stats(bbox_stats_t *stats);

/**
 * @brief Reset logger statistics
 *
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_reset_stats(void);

/**
 * @brief Get current log format
 *
 * @return Current log format
 */
bbox_format_t bbox_get_format(void);

/**
 * @brief Get current log file path
 *
 * @param buf Buffer to write path to
 * @param buf_len Buffer length
 * @return bbox_err_t BBOX_OK on success
 */
bbox_err_t bbox_get_current_file(char *buf, size_t buf_len);

/*******************************************************************************
 * Convenience Macros
 ******************************************************************************/

/** Log error message */
#define BBOX_LOG_E(tag, fmt, ...) \
    bbox_log(BBOX_LOG_LEVEL_ERROR, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/** Log warning message */
#define BBOX_LOG_W(tag, fmt, ...) \
    bbox_log(BBOX_LOG_LEVEL_WARN, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/** Log info message */
#define BBOX_LOG_I(tag, fmt, ...) \
    bbox_log(BBOX_LOG_LEVEL_INFO, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/** Log debug message */
#define BBOX_LOG_D(tag, fmt, ...) \
    bbox_log(BBOX_LOG_LEVEL_DEBUG, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/** Log verbose message */
#define BBOX_LOG_V(tag, fmt, ...) \
    bbox_log(BBOX_LOG_LEVEL_VERBOSE, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* Full name aliases */
#define BBOX_LOG_ERROR(tag, fmt, ...) BBOX_LOG_E(tag, fmt, ##__VA_ARGS__)
#define BBOX_LOG_WARN(tag, fmt, ...)  BBOX_LOG_W(tag, fmt, ##__VA_ARGS__)
#define BBOX_LOG_INFO(tag, fmt, ...)  BBOX_LOG_I(tag, fmt, ##__VA_ARGS__)
#define BBOX_LOG_DEBUG(tag, fmt, ...) BBOX_LOG_D(tag, fmt, ##__VA_ARGS__)
#define BBOX_LOG_VERBOSE(tag, fmt, ...) BBOX_LOG_V(tag, fmt, ##__VA_ARGS__)

/*******************************************************************************
 * Struct Logging Convenience Macros
 ******************************************************************************/

/**
 * @brief Log IMU data with automatic timestamp
 * @note Requires HAL get_time_us function
 */
#define BBOX_LOG_IMU(hal, ax, ay, az, gx, gy, gz, temp, id) do { \
    bbox_msg_imu_t _imu = { \
        .timestamp_us = (hal)->get_time_us(), \
        .accel_x = (ax), .accel_y = (ay), .accel_z = (az), \
        .gyro_x = (gx), .gyro_y = (gy), .gyro_z = (gz), \
        .temperature = (temp), .imu_id = (id) \
    }; \
    bbox_log_imu(&_imu); \
} while(0)

/**
 * @brief Log attitude data with automatic timestamp
 */
#define BBOX_LOG_ATTITUDE(hal, r, p, y, rr, pr, yr) do { \
    bbox_msg_attitude_t _att = { \
        .timestamp_us = (hal)->get_time_us(), \
        .roll = (r), .pitch = (p), .yaw = (y), \
        .rollspeed = (rr), .pitchspeed = (pr), .yawspeed = (yr) \
    }; \
    bbox_log_attitude(&_att); \
} while(0)

/**
 * @brief Log motor outputs with automatic timestamp
 */
#define BBOX_LOG_MOTOR(hal, m1, m2, m3, m4, count, armed) do { \
    bbox_msg_motor_t _mot = { \
        .timestamp_us = (hal)->get_time_us(), \
        .motor = {(m1), (m2), (m3), (m4), 0, 0, 0, 0}, \
        .motor_count = (count), .armed = (armed) \
    }; \
    bbox_log_motor(&_mot); \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_H */
