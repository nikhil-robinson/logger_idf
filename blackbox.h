/**
 * @file blackbox.h
 * @brief Flight Data Logger Library for ESP-IDF
 *
 * A high-performance logging library with:
 * - Multiple format support: BBOX, PX4 ULog, ArduPilot DataFlash
 * - Structured message logging (IMU, GPS, PID, Motor, etc.)
 * - Console (ESP_LOG) + file output
 * - Lock-free ring buffer for non-blocking writes
 * - Optional AES encryption (BBOX format)
 * - Automatic file rotation
 * - Component tags, file, line, timestamp
 *
 * @author Nikhil Robinson
 * @version 2.0.0
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include "esp_err.h"
#include "blackbox_messages.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*******************************************************************************
 * Constants and Macros
 ******************************************************************************/

/** ULog magic bytes */
#define BLACKBOX_LOG_MAGIC_BYTE0 0x42 // 'B'
#define BLACKBOX_LOG_MAGIC_BYTE1 0x4C // 'L'
#define BLACKBOX_LOG_MAGIC_BYTE2 0x42 // 'B'
#define BLACKBOX_LOG_MAGIC_BYTE3 0x4F // 'O'

/** ULog version */
#define BLACKBOX_LOG_VERSION 1

/** Default ring buffer size - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_DEFAULT_BUFFER_SIZE
#define BLACKBOX_LOG_DEFAULT_BUFFER_SIZE (CONFIG_BLACKBOX_DEFAULT_BUFFER_SIZE * 1024)
#else
#define BLACKBOX_LOG_DEFAULT_BUFFER_SIZE (32 * 1024)
#endif

/** Minimum ring buffer size - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_MIN_BUFFER_SIZE
#define BLACKBOX_LOG_MIN_BUFFER_SIZE (CONFIG_BLACKBOX_MIN_BUFFER_SIZE * 1024)
#else
#define BLACKBOX_LOG_MIN_BUFFER_SIZE (16 * 1024)
#endif

/** Maximum message payload size - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_MAX_MESSAGE_SIZE
#define BLACKBOX_LOG_MAX_MESSAGE_SIZE CONFIG_BLACKBOX_MAX_MESSAGE_SIZE
#else
#define BLACKBOX_LOG_MAX_MESSAGE_SIZE 256
#endif

/** Default file size limit for rotation - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_DEFAULT_FILE_SIZE_LIMIT
#define BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT (CONFIG_BLACKBOX_DEFAULT_FILE_SIZE_LIMIT * 1024)
#else
#define BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT (512 * 1024)
#endif

/** Default flush interval in ms - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_DEFAULT_FLUSH_INTERVAL
#define BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS CONFIG_BLACKBOX_DEFAULT_FLUSH_INTERVAL
#else
#define BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS 200
#endif

/** Writer task stack size - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_WRITER_TASK_STACK_SIZE
#define BLACKBOX_LOG_WRITER_TASK_STACK_SIZE CONFIG_BLACKBOX_WRITER_TASK_STACK_SIZE
#else
#define BLACKBOX_LOG_WRITER_TASK_STACK_SIZE 4096
#endif

/** Writer task priority - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_WRITER_TASK_PRIORITY
#define BLACKBOX_LOG_WRITER_TASK_PRIORITY CONFIG_BLACKBOX_WRITER_TASK_PRIORITY
#else
#define BLACKBOX_LOG_WRITER_TASK_PRIORITY 2
#endif

/** Maximum path length - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_MAX_PATH_LENGTH
#define BLACKBOX_LOG_MAX_PATH_LENGTH CONFIG_BLACKBOX_MAX_PATH_LENGTH
#else
#define BLACKBOX_LOG_MAX_PATH_LENGTH 128
#endif

/** Maximum tag length - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_MAX_TAG_LENGTH
#define BLACKBOX_LOG_MAX_TAG_LENGTH CONFIG_BLACKBOX_MAX_TAG_LENGTH
#else
#define BLACKBOX_LOG_MAX_TAG_LENGTH 32
#endif

/** Panic memory dump size - configurable via Kconfig */
#ifdef CONFIG_BLACKBOX_PANIC_MEMORY_DUMP_SIZE
#define BLACKBOX_LOG_PANIC_MEMORY_DUMP_SIZE CONFIG_BLACKBOX_PANIC_MEMORY_DUMP_SIZE
#else
#define BLACKBOX_LOG_PANIC_MEMORY_DUMP_SIZE 256
#endif

/** Panic handler flags (32-bit bitmask) */
#define BLACKBOX_PANIC_FLAG_NONE          0         /**< No panic features enabled */
#define BLACKBOX_PANIC_FLAG_ENABLED       (1 << 0)  /**< Enable panic handler */
#define BLACKBOX_PANIC_FLAG_BACKTRACE     (1 << 1)  /**< Include stack backtrace */
#define BLACKBOX_PANIC_FLAG_REGISTERS     (1 << 2)  /**< Include CPU register dump */
#define BLACKBOX_PANIC_FLAG_MEMORY_DUMP   (1 << 3)  /**< Include memory dump around SP */
#define BLACKBOX_PANIC_FLAG_TASK_INFO     (1 << 4)  /**< Include current task info */
#define BLACKBOX_PANIC_FLAG_HEAP_INFO     (1 << 5)  /**< Include heap statistics */
/* Bits 6-31 reserved for future use */

/** Default panic flags: enabled with backtrace and registers */
#define BLACKBOX_PANIC_FLAGS_DEFAULT (BLACKBOX_PANIC_FLAG_ENABLED | \
                                      BLACKBOX_PANIC_FLAG_BACKTRACE | \
                                      BLACKBOX_PANIC_FLAG_REGISTERS)

/** All panic flags enabled */
#define BLACKBOX_PANIC_FLAGS_ALL (BLACKBOX_PANIC_FLAG_ENABLED | \
                                  BLACKBOX_PANIC_FLAG_BACKTRACE | \
                                  BLACKBOX_PANIC_FLAG_REGISTERS | \
                                  BLACKBOX_PANIC_FLAG_MEMORY_DUMP | \
                                  BLACKBOX_PANIC_FLAG_TASK_INFO | \
                                  BLACKBOX_PANIC_FLAG_HEAP_INFO)

    /*******************************************************************************
     * ULog Message Types
     ******************************************************************************/

    /**
     * @brief ULog message types
     */
    typedef enum
    {
        BLACKBOX_LOG_MSG_TYPE_LOG = 0x01,       /**< Standard log message */
        BLACKBOX_LOG_MSG_TYPE_INFO = 0x02,      /**< Information message */
        BLACKBOX_LOG_MSG_TYPE_MULTI = 0x03,     /**< Multi-part message */
        BLACKBOX_LOG_MSG_TYPE_PARAM = 0x04,     /**< Parameter message */
        BLACKBOX_LOG_MSG_TYPE_DATA = 0x05,      /**< Data message */
        BLACKBOX_LOG_MSG_TYPE_DROPOUT = 0x06,   /**< Dropout marker */
        BLACKBOX_LOG_MSG_TYPE_SYNC = 0x07,      /**< Sync message */
        BLACKBOX_LOG_MSG_TYPE_PANIC = 0x10,     /**< Panic/crash information */
        BLACKBOX_LOG_MSG_TYPE_BACKTRACE = 0x11, /**< Backtrace data */
        BLACKBOX_LOG_MSG_TYPE_COREDUMP = 0x12,  /**< Core dump marker */
    } blackbox_msg_type_t;

    /*******************************************************************************
     * Log Levels
     ******************************************************************************/

    /**
     * @brief Log severity levels
     */
    typedef enum
    {
        BLACKBOX_LOG_LEVEL_NONE = 0,    /**< No logging */
        BLACKBOX_LOG_LEVEL_ERROR = 1,   /**< Error level */
        BLACKBOX_LOG_LEVEL_WARN = 2,    /**< Warning level */
        BLACKBOX_LOG_LEVEL_INFO = 3,    /**< Info level */
        BLACKBOX_LOG_LEVEL_DEBUG = 4,   /**< Debug level */
        BLACKBOX_LOG_LEVEL_VERBOSE = 5, /**< Verbose level */
    } blackbox_level_t;

    /*******************************************************************************
     * Log Format Selection
     ******************************************************************************/

    /**
     * @brief Supported log file formats
     */
    typedef enum {
        BLACKBOX_FORMAT_BBOX = 0,      /**< Native BBOX binary format (.blackbox) */
        BLACKBOX_FORMAT_PX4_ULOG = 1,  /**< PX4 ULog format (.ulg) */
        BLACKBOX_FORMAT_ARDUPILOT = 2, /**< ArduPilot DataFlash format (.bin) */
    } blackbox_log_format_t;

    /*******************************************************************************
     * Configuration Structure
     ******************************************************************************/

    /**
     * @brief ULog configuration structure
     *
     * User provides this to initialize the logger.
     * The library never mounts filesystems - user must do that before init.
     */
    typedef struct
    {
        const char *root_path;      /**< Root path for log files (e.g., "/sdcard/logs" or "/spiffs/logs") */
        const char *file_prefix;    /**< Log file prefix (default: "flight") */
        bool encrypt;               /**< Enable AES encryption (BBOX format only) */
        uint8_t encryption_key[32]; /**< AES-256 encryption key (if encrypt=true) */
        size_t file_size_limit;     /**< File size limit for rotation (bytes) */
        size_t buffer_size;         /**< Ring buffer size (bytes, min 16KB) */
        uint32_t flush_interval_ms; /**< Flush interval in milliseconds */
        blackbox_level_t min_level; /**< Minimum log level to record */
        bool console_output;        /**< Enable console output via ESP_LOG */
        bool file_output;           /**< Enable file output */

        /**
         * @brief Log file format
         * 
         * Select the output format:
         * - BLACKBOX_FORMAT_BBOX: Native binary format (default)
         * - BLACKBOX_FORMAT_PX4_ULOG: PX4-compatible ULog format
         * - BLACKBOX_FORMAT_ARDUPILOT: ArduPilot DataFlash format
         */
        blackbox_log_format_t log_format;

        /**
         * @brief Panic handler flags (32-bit bitmask)
         *
         * Use BLACKBOX_PANIC_FLAG_* macros to configure:
         * - BLACKBOX_PANIC_FLAG_ENABLED: Enable panic handler
         * - BLACKBOX_PANIC_FLAG_BACKTRACE: Include stack backtrace
         * - BLACKBOX_PANIC_FLAG_REGISTERS: Include CPU register dump
         * - BLACKBOX_PANIC_FLAG_MEMORY_DUMP: Include memory dump around SP
         * - BLACKBOX_PANIC_FLAG_TASK_INFO: Include current task info
         * - BLACKBOX_PANIC_FLAG_HEAP_INFO: Include heap statistics
         *
         * Default: BLACKBOX_PANIC_FLAGS_DEFAULT
         */
        uint32_t panic_flags;
    } blackbox_config_t;

    /*******************************************************************************
     * ULog Packet Header Structure (Binary Format)
     ******************************************************************************/

    /**
     * @brief ULog packet header (packed for binary storage)
     */
    typedef struct __attribute__((packed))
    {
        uint8_t magic[4];        /**< Magic bytes: "ULog" */
        uint8_t version;         /**< ULog version */
        uint8_t msg_type;        /**< Message type */
        uint8_t level;           /**< Log level */
        uint8_t reserved;        /**< Reserved for alignment */
        uint64_t timestamp_us;   /**< Timestamp in microseconds */
        uint32_t tag_hash;       /**< Component tag hash (FNV-1a) */
        uint32_t file_hash;      /**< Source file name hash */
        uint16_t line;           /**< Source line number */
        uint16_t payload_length; /**< Payload length */
        uint16_t crc16;          /**< CRC-16 checksum of header + payload */
    } blackbox_header_t;

    /**
     * @brief Complete ULog packet (header + payload)
     */
    typedef struct __attribute__((packed))
    {
        blackbox_header_t header;                    /**< Packet header */
        char payload[BLACKBOX_LOG_MAX_MESSAGE_SIZE]; /**< Message payload (UTF-8) */
    } blackbox_packet_t;

    /*******************************************************************************
     * ULog File Header Structure
     ******************************************************************************/

    /**
     * @brief ULog file header (written at the start of each log file)
     */
    typedef struct __attribute__((packed))
    {
        uint8_t magic[4];      /**< Magic bytes: "ULog" */
        uint8_t version;       /**< ULog version */
        uint8_t flags;         /**< Flags (bit 0: encrypted) */
        uint16_t header_size;  /**< Size of this header */
        uint64_t timestamp_us; /**< File creation timestamp */
        char device_id[32];    /**< Device identifier */
    } blackbox_file_header_t;

    /*******************************************************************************
     * Statistics Structure
     ******************************************************************************/

    /**
     * @brief ULog statistics
     */
    typedef struct
    {
        uint64_t messages_logged;   /**< Total messages logged */
        uint64_t messages_dropped;  /**< Messages dropped (buffer overflow) */
        uint64_t bytes_written;     /**< Total bytes written to file */
        uint32_t files_created;     /**< Number of log files created */
        uint32_t buffer_high_water; /**< Buffer high water mark (bytes used) */
        uint32_t write_errors;      /**< File write errors */
    } blackbox_stats_t;

    /*******************************************************************************
     * Public API Functions
     ******************************************************************************/

    /**
     * @brief Initialize the ULog logger
     *
     * @param config Pointer to configuration structure
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_init(const blackbox_config_t *config);

    /**
     * @brief Deinitialize the ULog logger
     *
     * Flushes remaining data and cleans up resources.
     *
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_deinit(void);

    /**
     * @brief Log a message
     *
     * This is the core logging function. Use the BLACKBOX_LOG_* macros instead of calling directly.
     *
     * @param level Log level
     * @param tag Component tag
     * @param file Source file name
     * @param line Source line number
     * @param fmt Printf-style format string
     * @param ... Format arguments
     */
    void blackbox_log(blackbox_level_t level, const char *tag, const char *file,
                      uint32_t line, const char *fmt, ...);

    /**
     * @brief Log a message (va_list version)
     *
     * @param level Log level
     * @param tag Component tag
     * @param file Source file name
     * @param line Source line number
     * @param fmt Printf-style format string
     * @param args Format arguments as va_list
     */
    void blackbox_log_va(blackbox_level_t level, const char *tag, const char *file,
                         uint32_t line, const char *fmt, va_list args);

    /**
     * @brief Force flush the ring buffer to file
     *
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_flush(void);

    /**
     * @brief Get logger statistics
     *
     * @param stats Pointer to stats structure to fill
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_get_stats(blackbox_stats_t *stats);

    /**
     * @brief Reset logger statistics
     *
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_reset_stats(void);

    /**
     * @brief Set minimum log level at runtime
     *
     * @param level New minimum log level
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_set_level(blackbox_level_t level);

    /**
     * @brief Get current minimum log level
     *
     * @return blackbox_level_t Current minimum log level
     */
    blackbox_level_t blackbox_get_level(void);

    /**
     * @brief Enable or disable console output at runtime
     *
     * @param enable true to enable, false to disable
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_set_console_output(bool enable);

    /**
     * @brief Enable or disable file output at runtime
     *
     * @param enable true to enable, false to disable
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_set_file_output(bool enable);

    /**
     * @brief Rotate to a new log file immediately
     *
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_rotate_file(void);

    /**
     * @brief Check if logger is initialized
     *
     * @return bool true if initialized
     */
    bool blackbox_is_initialized(void);

    /**
     * @brief Get default configuration
     *
     * @param config Pointer to config structure to fill with defaults
     */
    void blackbox_get_default_config(blackbox_config_t *config);

    /**
     * @brief Set panic handler flags at runtime
     *
     * Use BLACKBOX_PANIC_FLAG_* macros to configure panic behavior.
     * Changes take effect immediately.
     *
     * @param flags Bitmask of BLACKBOX_PANIC_FLAG_* values
     * @return esp_err_t ESP_OK on success
     *
     * @example
     * // Enable panic with backtrace only
     * blackbox_set_panic_flags(BLACKBOX_PANIC_FLAG_ENABLED | BLACKBOX_PANIC_FLAG_BACKTRACE);
     *
     * // Enable all panic features
     * blackbox_set_panic_flags(BLACKBOX_PANIC_FLAGS_ALL);
     *
     * // Disable panic handler
     * blackbox_set_panic_flags(BLACKBOX_PANIC_FLAG_NONE);
     */
    esp_err_t blackbox_set_panic_flags(uint32_t flags);

    /**
     * @brief Get current panic handler flags
     *
     * @return uint32_t Current panic flags bitmask
     */
    uint32_t blackbox_get_panic_flags(void);

    /**
     * @brief Enable or disable panic handler at runtime
     *
     * This is a convenience wrapper that sets/clears the BLACKBOX_PANIC_FLAG_ENABLED
     * bit while preserving other flags.
     *
     * @param enable true to enable panic logging, false to disable
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_set_panic_handler(bool enable);

    /**
     * @brief Check if panic handler is enabled
     *
     * @return bool true if panic handler is enabled and active
     */
    bool blackbox_is_panic_handler_enabled(void);

    /**
     * @brief Manually trigger a panic log entry (for testing)
     *
     * This function writes a test panic entry to the log file without
     * actually causing a panic. Useful for testing the decoder.
     *
     * @param reason Simulated panic reason string
     * @return esp_err_t ESP_OK on success
     */
    esp_err_t blackbox_log_test_panic(const char *reason);

/*******************************************************************************
 * Structured Message Logging API
 ******************************************************************************/

/**
 * @brief Log a structured message
 * 
 * Logs a binary struct with automatic format encoding based on the
 * configured log format (BBOX, PX4 ULog, or ArduPilot DataFlash).
 *
 * @param msg_id Message type ID (from bbox_msg_id_t)
 * @param data Pointer to the message struct
 * @param size Size of the message struct in bytes
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_struct(bbox_msg_id_t msg_id, const void *data, size_t size);

/**
 * @brief Log IMU sensor data
 * 
 * @param imu Pointer to IMU data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_imu(const bbox_msg_imu_t *imu);

/**
 * @brief Log GPS position data
 * 
 * @param gps Pointer to GPS data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_gps(const bbox_msg_gps_t *gps);

/**
 * @brief Log attitude data
 * 
 * @param att Pointer to attitude data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_attitude(const bbox_msg_attitude_t *att);

/**
 * @brief Log PID controller state
 * 
 * @param axis PID axis (BBOX_MSG_PID_ROLL, BBOX_MSG_PID_PITCH, BBOX_MSG_PID_YAW, BBOX_MSG_PID_ALT)
 * @param pid Pointer to PID data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_pid(bbox_msg_id_t axis, const bbox_msg_pid_t *pid);

/**
 * @brief Log motor outputs
 * 
 * @param motor Pointer to motor data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_motor(const bbox_msg_motor_t *motor);

/**
 * @brief Log battery status
 * 
 * @param battery Pointer to battery data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_battery(const bbox_msg_battery_t *battery);

/**
 * @brief Log RC input channels
 * 
 * @param rc Pointer to RC input data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_rc_input(const bbox_msg_rc_input_t *rc);

/**
 * @brief Log system status
 * 
 * @param status Pointer to status data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_status(const bbox_msg_status_t *status);

/**
 * @brief Log barometer data
 * 
 * @param baro Pointer to barometer data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_baro(const bbox_msg_baro_t *baro);

/**
 * @brief Log magnetometer data
 * 
 * @param mag Pointer to magnetometer data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_mag(const bbox_msg_mag_t *mag);

/**
 * @brief Log ESC telemetry data
 * 
 * @param esc Pointer to ESC data struct
 * @return esp_err_t ESP_OK on success
 */
esp_err_t blackbox_log_esc(const bbox_msg_esc_t *esc);

/**
 * @brief Get current log format
 * 
 * @return blackbox_log_format_t Current log format
 */
blackbox_log_format_t blackbox_get_log_format(void);

/*******************************************************************************
 * Convenience Macros for Struct Logging
 ******************************************************************************/

/**
 * @brief Log IMU data with automatic timestamp
 */
#define BLACKBOX_LOG_IMU(ax, ay, az, gx, gy, gz, temp, id) do { \
    bbox_msg_imu_t _imu = { \
        .timestamp_us = esp_timer_get_time(), \
        .accel_x = (ax), .accel_y = (ay), .accel_z = (az), \
        .gyro_x = (gx), .gyro_y = (gy), .gyro_z = (gz), \
        .temperature = (temp), .imu_id = (id) \
    }; \
    blackbox_log_imu(&_imu); \
} while(0)

/**
 * @brief Log attitude data with automatic timestamp
 */
#define BLACKBOX_LOG_ATTITUDE(r, p, y, rr, pr, yr) do { \
    bbox_msg_attitude_t _att = { \
        .timestamp_us = esp_timer_get_time(), \
        .roll = (r), .pitch = (p), .yaw = (y), \
        .rollspeed = (rr), .pitchspeed = (pr), .yawspeed = (yr) \
    }; \
    blackbox_log_attitude(&_att); \
} while(0)

/**
 * @brief Log PID state with automatic timestamp
 */
#define BLACKBOX_LOG_PID(axis_id, sp, meas, err, p, i, d, ff, out) do { \
    bbox_msg_pid_t _pid = { \
        .timestamp_us = esp_timer_get_time(), \
        .setpoint = (sp), .measured = (meas), .error = (err), \
        .p_term = (p), .i_term = (i), .d_term = (d), \
        .ff_term = (ff), .output = (out), .axis = (axis_id) \
    }; \
    blackbox_log_pid(BBOX_MSG_PID_ROLL + (axis_id), &_pid); \
} while(0)

/**
 * @brief Log motor outputs with automatic timestamp
 */
#define BLACKBOX_LOG_MOTOR(m1, m2, m3, m4, count, armed_flag) do { \
    bbox_msg_motor_t _mot = { \
        .timestamp_us = esp_timer_get_time(), \
        .motor = {(m1), (m2), (m3), (m4), 0, 0, 0, 0}, \
        .motor_count = (count), .armed = (armed_flag) \
    }; \
    blackbox_log_motor(&_mot); \
} while(0)

/*******************************************************************************
 * Text Logging Macros (Primary API)
 ******************************************************************************/

/**
 * @brief Log an error message
 */
#define BLACKBOX_LOG_ERROR(tag, fmt, ...) \
    blackbox_log(BLACKBOX_LOG_LEVEL_ERROR, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Log a warning message
 */
#define BLACKBOX_LOG_WARN(tag, fmt, ...) \
    blackbox_log(BLACKBOX_LOG_LEVEL_WARN, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Log an info message
 */
#define BLACKBOX_LOG_INFO(tag, fmt, ...) \
    blackbox_log(BLACKBOX_LOG_LEVEL_INFO, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Log a debug message
 */
#define BLACKBOX_LOG_DEBUG(tag, fmt, ...) \
    blackbox_log(BLACKBOX_LOG_LEVEL_DEBUG, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Log a verbose message
 */
#define BLACKBOX_LOG_VERBOSE(tag, fmt, ...) \
    blackbox_log(BLACKBOX_LOG_LEVEL_VERBOSE, tag, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Shorthand aliases
 */
#define BLACKBOX_LOG_E(tag, fmt, ...) BLACKBOX_LOG_ERROR(tag, fmt, ##__VA_ARGS__)
#define BLACKBOX_LOG_W(tag, fmt, ...) BLACKBOX_LOG_WARN(tag, fmt, ##__VA_ARGS__)
#define BLACKBOX_LOG_I(tag, fmt, ...) BLACKBOX_LOG_INFO(tag, fmt, ##__VA_ARGS__)
#define BLACKBOX_LOG_D(tag, fmt, ...) BLACKBOX_LOG_DEBUG(tag, fmt, ##__VA_ARGS__)
#define BLACKBOX_LOG_V(tag, fmt, ...) BLACKBOX_LOG_VERBOSE(tag, fmt, ##__VA_ARGS__)

    /*******************************************************************************
     * Utility Functions
     ******************************************************************************/

    /**
     * @brief Compute FNV-1a hash of a string
     *
     * @param str String to hash
     * @return uint32_t Hash value
     */
    uint32_t blackbox_hash_string(const char *str);

    /**
     * @brief Get log level name as string
     *
     * @param level Log level
     * @return const char* Level name
     */
    const char *blackbox_level_to_string(blackbox_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
