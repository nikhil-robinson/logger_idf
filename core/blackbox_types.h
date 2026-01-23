/**
 * @file blackbox_types.h
 * @brief Core type definitions for the Blackbox flight data logger
 *
 * This file contains all portable type definitions, enums, and constants
 * used throughout the blackbox library. It has no platform dependencies.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_TYPES_H
#define BLACKBOX_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Version Information
 ******************************************************************************/

#define BLACKBOX_VERSION_MAJOR 3
#define BLACKBOX_VERSION_MINOR 0
#define BLACKBOX_VERSION_PATCH 0
#define BLACKBOX_VERSION_STRING "3.0.0"

/*******************************************************************************
 * Return Codes (Platform Independent)
 ******************************************************************************/

typedef enum {
    BBOX_OK = 0,                    /**< Success */
    BBOX_ERR_INVALID_ARG = -1,      /**< Invalid argument */
    BBOX_ERR_NO_MEM = -2,           /**< Out of memory */
    BBOX_ERR_INVALID_STATE = -3,    /**< Invalid state */
    BBOX_ERR_IO = -4,               /**< I/O error */
    BBOX_ERR_NOT_SUPPORTED = -5,    /**< Operation not supported */
    BBOX_ERR_TIMEOUT = -6,          /**< Operation timed out */
    BBOX_ERR_BUFFER_FULL = -7,      /**< Ring buffer full */
    BBOX_ERR_HAL = -8,              /**< HAL function failed */
    BBOX_ERR_CRYPTO = -9,           /**< Encryption/decryption error */
} bbox_err_t;

/*******************************************************************************
 * Constants and Limits
 ******************************************************************************/

/** ULog magic bytes */
#define BLACKBOX_LOG_MAGIC_BYTE0 0x42 /* 'B' */
#define BLACKBOX_LOG_MAGIC_BYTE1 0x4C /* 'L' */
#define BLACKBOX_LOG_MAGIC_BYTE2 0x42 /* 'B' */
#define BLACKBOX_LOG_MAGIC_BYTE3 0x4F /* 'O' */

/** Log file format version */
#define BLACKBOX_LOG_VERSION 1

/** Default sizes (can be overridden in config) */
#define BLACKBOX_DEFAULT_BUFFER_SIZE      (32 * 1024)
#define BLACKBOX_MIN_BUFFER_SIZE          (4 * 1024)
#define BLACKBOX_MAX_MESSAGE_SIZE         256
#define BLACKBOX_DEFAULT_FILE_SIZE_LIMIT  (512 * 1024)
#define BLACKBOX_DEFAULT_FLUSH_INTERVAL   200  /* ms */
#define BLACKBOX_MAX_PATH_LENGTH          128
#define BLACKBOX_MAX_TAG_LENGTH           32

/*******************************************************************************
 * Log Levels
 ******************************************************************************/

/**
 * @brief Log severity levels
 */
typedef enum {
    BBOX_LOG_LEVEL_NONE = 0,    /**< No logging */
    BBOX_LOG_LEVEL_ERROR = 1,   /**< Error level */
    BBOX_LOG_LEVEL_WARN = 2,    /**< Warning level */
    BBOX_LOG_LEVEL_INFO = 3,    /**< Info level */
    BBOX_LOG_LEVEL_DEBUG = 4,   /**< Debug level */
    BBOX_LOG_LEVEL_VERBOSE = 5, /**< Verbose level */
} bbox_log_level_t;

/*******************************************************************************
 * Log Format Selection
 ******************************************************************************/

/**
 * @brief Supported log file formats
 */
typedef enum {
    BBOX_FORMAT_BBOX = 0,       /**< Native BBOX binary format (.blackbox) */
    BBOX_FORMAT_PX4_ULOG = 1,   /**< PX4 ULog format (.ulg) */
    BBOX_FORMAT_ARDUPILOT = 2,  /**< ArduPilot DataFlash format (.bin) */
} bbox_format_t;

/*******************************************************************************
 * Message Types
 ******************************************************************************/

/**
 * @brief Internal message types for log packets
 */
typedef enum {
    BBOX_MSG_TYPE_LOG = 0x01,       /**< Standard log message */
    BBOX_MSG_TYPE_INFO = 0x02,      /**< Information message */
    BBOX_MSG_TYPE_MULTI = 0x03,     /**< Multi-part message */
    BBOX_MSG_TYPE_PARAM = 0x04,     /**< Parameter message */
    BBOX_MSG_TYPE_DATA = 0x05,      /**< Data message */
    BBOX_MSG_TYPE_DROPOUT = 0x06,   /**< Dropout marker */
    BBOX_MSG_TYPE_SYNC = 0x07,      /**< Sync message */
    BBOX_MSG_TYPE_STRUCT = 0x08,    /**< Structured data message */
} bbox_msg_type_t;

/*******************************************************************************
 * Packet Structures (Binary Format)
 ******************************************************************************/

/**
 * @brief Log packet header (packed for binary storage)
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[4];        /**< Magic bytes: "BLBO" */
    uint8_t version;         /**< Format version */
    uint8_t msg_type;        /**< Message type */
    uint8_t level;           /**< Log level */
    uint8_t reserved;        /**< Reserved for alignment */
    uint64_t timestamp_us;   /**< Timestamp in microseconds */
    uint32_t tag_hash;       /**< Component tag hash (FNV-1a) */
    uint32_t file_hash;      /**< Source file name hash */
    uint16_t line;           /**< Source line number */
    uint16_t payload_length; /**< Payload length */
    uint16_t crc16;          /**< CRC-16 checksum of header + payload */
} bbox_packet_header_t;

/**
 * @brief Complete log packet (header + payload)
 */
typedef struct __attribute__((packed)) {
    bbox_packet_header_t header;              /**< Packet header */
    char payload[BLACKBOX_MAX_MESSAGE_SIZE];  /**< Message payload */
} bbox_packet_t;

/**
 * @brief File header (written at start of each log file)
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[4];      /**< Magic bytes: "BLBO" */
    uint8_t version;       /**< Format version */
    uint8_t flags;         /**< Flags (bit 0: encrypted) */
    uint16_t header_size;  /**< Size of this header */
    uint64_t timestamp_us; /**< File creation timestamp */
    char device_id[32];    /**< Device identifier */
} bbox_file_header_t;

/*******************************************************************************
 * Statistics
 ******************************************************************************/

/**
 * @brief Logger statistics
 */
typedef struct {
    uint64_t messages_logged;   /**< Total messages logged */
    uint64_t messages_dropped;  /**< Messages dropped (buffer overflow) */
    uint64_t bytes_written;     /**< Total bytes written to file */
    uint32_t files_created;     /**< Number of log files created */
    uint32_t buffer_high_water; /**< Buffer high water mark (bytes used) */
    uint32_t write_errors;      /**< File write errors */
    uint64_t struct_messages;   /**< Structured messages logged */
} bbox_stats_t;

/*******************************************************************************
 * Configuration
 ******************************************************************************/

/**
 * @brief Logger configuration structure
 */
typedef struct {
    const char *root_path;      /**< Root path for log files */
    const char *file_prefix;    /**< Log file prefix (default: "flight") */
    
    /* Format and encryption */
    bbox_format_t log_format;   /**< Output format (BBOX, ULog, DataFlash) */
    bool encrypt;               /**< Enable AES-256 encryption (BBOX only) */
    uint8_t encryption_key[32]; /**< AES-256 encryption key */
    
    /* Buffer and timing */
    size_t buffer_size;         /**< Ring buffer size (bytes, min 4KB) */
    size_t file_size_limit;     /**< File size limit for rotation (bytes) */
    uint32_t flush_interval_ms; /**< Flush interval in milliseconds */
    
    /* Output control */
    bbox_log_level_t min_level; /**< Minimum log level to record */
    bool console_output;        /**< Enable console output */
    bool file_output;           /**< Enable file output */
    
    /* Threading mode */
    bool single_threaded;       /**< True = polling mode, false = background task */
} bbox_config_t;

/*******************************************************************************
 * Utility Functions (Inline, Platform Independent)
 ******************************************************************************/

/**
 * @brief Compute FNV-1a hash of a string
 */
static inline uint32_t bbox_hash_fnv1a(const char *str)
{
    if (str == NULL) {
        return 0;
    }
    uint32_t hash = 2166136261u;
    const uint8_t *p = (const uint8_t *)str;
    while (*p) {
        hash = (hash ^ *p++) * 16777619u;
    }
    return hash;
}

/**
 * @brief Calculate CRC-16 checksum (CCITT polynomial 0x1021)
 */
static inline uint16_t bbox_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/**
 * @brief Get log level name as string
 */
static inline const char *bbox_level_to_string(bbox_log_level_t level)
{
    switch (level) {
        case BBOX_LOG_LEVEL_ERROR:   return "ERROR";
        case BBOX_LOG_LEVEL_WARN:    return "WARN";
        case BBOX_LOG_LEVEL_INFO:    return "INFO";
        case BBOX_LOG_LEVEL_DEBUG:   return "DEBUG";
        case BBOX_LOG_LEVEL_VERBOSE: return "VERBOSE";
        default:                     return "UNKNOWN";
    }
}

/**
 * @brief Get format file extension
 */
static inline const char *bbox_format_extension(bbox_format_t format)
{
    switch (format) {
        case BBOX_FORMAT_BBOX:      return "blackbox";
        case BBOX_FORMAT_PX4_ULOG:  return "ulg";
        case BBOX_FORMAT_ARDUPILOT: return "bin";
        default:                    return "log";
    }
}

/**
 * @brief Get format name
 */
static inline const char *bbox_format_name(bbox_format_t format)
{
    switch (format) {
        case BBOX_FORMAT_BBOX:      return "BBOX";
        case BBOX_FORMAT_PX4_ULOG:  return "PX4 ULog";
        case BBOX_FORMAT_ARDUPILOT: return "ArduPilot DataFlash";
        default:                    return "Unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_TYPES_H */
