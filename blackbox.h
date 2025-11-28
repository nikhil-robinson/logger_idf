/**
 * @file blackbox.h
 * @brief ULog Logger Library for ESP-IDF
 * 
 * A logging library with:
 * - Blackbox binary format
 * - Console (ESP_LOG) + file output
 * - Lock-free ring buffer for non-blocking writes
 * - Optional AES encryption
 * - Automatic file rotation
 * - Component tags, file, line, timestamp
 * 
 * @author Nikhil Robinson
 * @version 1.0.0
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Constants and Macros
 ******************************************************************************/

/** ULog magic bytes */
#define BLACKBOX_LOG_MAGIC_BYTE0    0x55  // 'U'
#define BLACKBOX_LOG_MAGIC_BYTE1    0x4C  // 'L'
#define BLACKBOX_LOG_MAGIC_BYTE2    0x6F  // 'o'
#define BLACKBOX_LOG_MAGIC_BYTE3    0x67  // 'g'

/** ULog version */
#define BLACKBOX_LOG_VERSION        1

/** Default ring buffer size (32 KB) */
#define BLACKBOX_LOG_DEFAULT_BUFFER_SIZE    (32 * 1024)

/** Minimum ring buffer size (16 KB) */
#define BLACKBOX_LOG_MIN_BUFFER_SIZE        (16 * 1024)

/** Maximum message payload size */
#define BLACKBOX_LOG_MAX_MESSAGE_SIZE       256

/** Default file size limit for rotation (512 KB) */
#define BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT (512 * 1024)

/** Default flush interval in ms */
#define BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS  200

/** Writer task stack size */
#define BLACKBOX_LOG_WRITER_TASK_STACK_SIZE     4096

/** Writer task priority (low priority) */
#define BLACKBOX_LOG_WRITER_TASK_PRIORITY       2

/** Maximum path length */
#define BLACKBOX_LOG_MAX_PATH_LENGTH            128

/** Maximum tag length */
#define BLACKBOX_LOG_MAX_TAG_LENGTH             32

/*******************************************************************************
 * ULog Message Types
 ******************************************************************************/

/**
 * @brief ULog message types
 */
typedef enum {
    BLACKBOX_LOG_MSG_TYPE_LOG       = 0x01,  /**< Standard log message */
    BLACKBOX_LOG_MSG_TYPE_INFO      = 0x02,  /**< Information message */
    BLACKBOX_LOG_MSG_TYPE_MULTI     = 0x03,  /**< Multi-part message */
    BLACKBOX_LOG_MSG_TYPE_PARAM     = 0x04,  /**< Parameter message */
    BLACKBOX_LOG_MSG_TYPE_DATA      = 0x05,  /**< Data message */
    BLACKBOX_LOG_MSG_TYPE_DROPOUT   = 0x06,  /**< Dropout marker */
    BLACKBOX_LOG_MSG_TYPE_SYNC      = 0x07,  /**< Sync message */
} blackbox_msg_type_t;

/*******************************************************************************
 * Log Levels
 ******************************************************************************/

/**
 * @brief Log severity levels
 */
typedef enum {
    BLACKBOX_LOG_LEVEL_NONE     = 0,  /**< No logging */
    BLACKBOX_LOG_LEVEL_ERROR    = 1,  /**< Error level */
    BLACKBOX_LOG_LEVEL_WARN     = 2,  /**< Warning level */
    BLACKBOX_LOG_LEVEL_INFO     = 3,  /**< Info level */
    BLACKBOX_LOG_LEVEL_DEBUG    = 4,  /**< Debug level */
    BLACKBOX_LOG_LEVEL_VERBOSE  = 5,  /**< Verbose level */
} blackbox_level_t;

/*******************************************************************************
 * Configuration Structure
 ******************************************************************************/

/**
 * @brief ULog configuration structure
 * 
 * User provides this to initialize the logger.
 * The library never mounts filesystems - user must do that before init.
 */
typedef struct {
    const char* root_path;          /**< Root path for log files (e.g., "/sdcard/logs" or "/spiffs/logs") */
    const char* file_prefix;        /**< Log file prefix (default: "flight") */
    bool encrypt;                   /**< Enable AES encryption */
    uint8_t encryption_key[32];     /**< AES-256 encryption key (if encrypt=true) */
    size_t file_size_limit;         /**< File size limit for rotation (bytes) */
    size_t buffer_size;             /**< Ring buffer size (bytes, min 16KB) */
    uint32_t flush_interval_ms;     /**< Flush interval in milliseconds */
    blackbox_level_t min_level;         /**< Minimum log level to record */
    bool console_output;            /**< Enable console output via ESP_LOG */
    bool file_output;               /**< Enable file output */
} blackbox_config_t;

/*******************************************************************************
 * ULog Packet Header Structure (Binary Format)
 ******************************************************************************/

/**
 * @brief ULog packet header (packed for binary storage)
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[4];               /**< Magic bytes: "ULog" */
    uint8_t version;                /**< ULog version */
    uint8_t msg_type;               /**< Message type */
    uint8_t level;                  /**< Log level */
    uint8_t reserved;               /**< Reserved for alignment */
    uint64_t timestamp_us;          /**< Timestamp in microseconds */
    uint32_t tag_hash;              /**< Component tag hash (FNV-1a) */
    uint32_t file_hash;             /**< Source file name hash */
    uint16_t line;                  /**< Source line number */
    uint16_t payload_length;        /**< Payload length */
} blackbox_header_t;

/**
 * @brief Complete ULog packet (header + payload)
 */
typedef struct __attribute__((packed)) {
    blackbox_header_t header;           /**< Packet header */
    char payload[BLACKBOX_LOG_MAX_MESSAGE_SIZE]; /**< Message payload (UTF-8) */
} blackbox_packet_t;

/*******************************************************************************
 * ULog File Header Structure
 ******************************************************************************/

/**
 * @brief ULog file header (written at the start of each log file)
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[4];               /**< Magic bytes: "ULog" */
    uint8_t version;                /**< ULog version */
    uint8_t flags;                  /**< Flags (bit 0: encrypted) */
    uint16_t header_size;           /**< Size of this header */
    uint64_t timestamp_us;          /**< File creation timestamp */
    char device_id[32];             /**< Device identifier */
} blackbox_file_header_t;

/*******************************************************************************
 * Statistics Structure
 ******************************************************************************/

/**
 * @brief ULog statistics
 */
typedef struct {
    uint64_t messages_logged;       /**< Total messages logged */
    uint64_t messages_dropped;      /**< Messages dropped (buffer overflow) */
    uint64_t bytes_written;         /**< Total bytes written to file */
    uint32_t files_created;         /**< Number of log files created */
    uint32_t buffer_high_water;     /**< Buffer high water mark (bytes used) */
    uint32_t write_errors;          /**< File write errors */
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
esp_err_t blackbox_init(const blackbox_config_t* config);

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
void blackbox_log(blackbox_level_t level, const char* tag, const char* file, 
              uint32_t line, const char* fmt, ...);

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
void blackbox_log_va(blackbox_level_t level, const char* tag, const char* file,
                 uint32_t line, const char* fmt, va_list args);

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
esp_err_t blackbox_get_stats(blackbox_stats_t* stats);

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
void blackbox_get_default_config(blackbox_config_t* config);

/*******************************************************************************
 * Logging Macros (Primary API)
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
uint32_t blackbox_hash_string(const char* str);

/**
 * @brief Get log level name as string
 * 
 * @param level Log level
 * @return const char* Level name
 */
const char* blackbox_level_to_string(blackbox_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
