/**
 * @file blackbox_formats.h
 * @brief Log format encoders for PX4 ULog, ArduPilot DataFlash, and BBOX
 *
 * Provides format-specific encoding for flight data logging.
 * Supports:
 * - BBOX: Native binary format (compact, simple)
 * - PX4 ULog: Compatible with PX4 flight stack and analysis tools
 * - ArduPilot DataFlash: Compatible with ArduPilot/Mission Planner
 *
 * @author Nikhil Robinson
 * @version 2.0.0
 */

#ifndef BLACKBOX_FORMATS_H
#define BLACKBOX_FORMATS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "blackbox_messages.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Log Format Selection
 ******************************************************************************/

/**
 * @brief Supported log file formats
 */
typedef enum {
    BBOX_FORMAT_BBOX = 0,      /**< Native BBOX binary format */
    BBOX_FORMAT_PX4_ULOG = 1,  /**< PX4 ULog format (.ulg) */
    BBOX_FORMAT_ARDUPILOT = 2, /**< ArduPilot DataFlash format (.bin) */
} bbox_log_format_t;

/**
 * @brief Get file extension for format
 */
static inline const char* bbox_format_get_extension(bbox_log_format_t format)
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
static inline const char* bbox_format_get_name(bbox_log_format_t format)
{
    switch (format) {
        case BBOX_FORMAT_BBOX:      return "BBOX";
        case BBOX_FORMAT_PX4_ULOG:  return "PX4 ULog";
        case BBOX_FORMAT_ARDUPILOT: return "ArduPilot DataFlash";
        default:                    return "Unknown";
    }
}

/*******************************************************************************
 * PX4 ULog Format Definitions
 * Reference: https://docs.px4.io/main/en/dev_log/ulog_file_format.html
 ******************************************************************************/

#define ULOG_MAGIC                  {0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35}
#define ULOG_MAGIC_SIZE             7
#define ULOG_VERSION                1

/* ULog message types */
typedef enum {
    ULOG_MSG_FORMAT         = 'F',  /**< Format definition */
    ULOG_MSG_DATA           = 'D',  /**< Data message */
    ULOG_MSG_INFO           = 'I',  /**< Information message */
    ULOG_MSG_INFO_MULTIPLE  = 'M',  /**< Multi information message */
    ULOG_MSG_PARAMETER      = 'P',  /**< Parameter message */
    ULOG_MSG_ADD_LOGGED_MSG = 'A',  /**< Add logged message */
    ULOG_MSG_REMOVE_LOGGED_MSG = 'R', /**< Remove logged message */
    ULOG_MSG_SYNC           = 'S',  /**< Sync message */
    ULOG_MSG_DROPOUT        = 'O',  /**< Dropout message */
    ULOG_MSG_LOGGING        = 'L',  /**< Logged string message */
    ULOG_MSG_LOGGING_TAGGED = 'C',  /**< Tagged logged string */
    ULOG_MSG_FLAG_BITS      = 'B',  /**< Flag bits message */
} ulog_msg_type_t;

/**
 * @brief ULog message header
 */
typedef struct __attribute__((packed)) {
    uint16_t msg_size;        /**< Size of message (excluding header) */
    uint8_t msg_type;         /**< Message type */
} ulog_msg_header_t;

/**
 * @brief ULog file header
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[ULOG_MAGIC_SIZE];
    uint8_t version;
    uint64_t timestamp_us;    /**< Timestamp of log start */
} ulog_file_header_t;

/**
 * @brief ULog format definition message
 */
typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    char format[256];         /**< Format string: "name:field1;field2;..." */
} ulog_format_msg_t;

/**
 * @brief ULog add logged message
 */
typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    uint8_t multi_id;         /**< Multi instance ID */
    uint16_t msg_id;          /**< Message ID for data messages */
    char message_name[64];    /**< Message name (must match format) */
} ulog_add_logged_msg_t;

/**
 * @brief ULog data message header
 */
typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    uint16_t msg_id;          /**< Message ID (from add logged msg) */
} ulog_data_header_t;

/**
 * @brief ULog info message
 */
typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    uint8_t key_len;
    char key_value[];         /**< Key (key_len bytes) followed by value */
} ulog_info_msg_t;

/**
 * @brief ULog logging message (text log)
 */
typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    uint8_t log_level;        /**< Log level (0-7) */
    uint64_t timestamp;       /**< Timestamp */
    char message[];           /**< Log message text */
} ulog_logging_msg_t;

/*******************************************************************************
 * ArduPilot DataFlash Format Definitions
 * Reference: https://ardupilot.org/dev/docs/code-overview-adding-a-new-log-message.html
 ******************************************************************************/

#define DATAFLASH_HEAD_BYTE1        0xA3
#define DATAFLASH_HEAD_BYTE2        0x95

/* DataFlash message IDs */
typedef enum {
    DF_MSG_FORMAT   = 0x80,   /**< Format definition */
    DF_MSG_PARM     = 0x00,   /**< Parameter */
    DF_MSG_GPS      = 0x01,   /**< GPS */
    DF_MSG_IMU      = 0x02,   /**< IMU */
    DF_MSG_MSG      = 0x03,   /**< Text message */
    DF_MSG_RCIN     = 0x04,   /**< RC input */
    DF_MSG_RCOUT    = 0x05,   /**< RC output */
    DF_MSG_BARO     = 0x06,   /**< Barometer */
    DF_MSG_CURR     = 0x07,   /**< Current sensor */
    DF_MSG_ATT      = 0x08,   /**< Attitude */
    DF_MSG_MAG      = 0x09,   /**< Magnetometer */
    DF_MSG_MODE     = 0x0A,   /**< Mode change */
    DF_MSG_PID      = 0x0B,   /**< PID tuning */
    DF_MSG_MOT      = 0x0C,   /**< Motor output */
    DF_MSG_ESC      = 0x0D,   /**< ESC telemetry */
    DF_MSG_BAT      = 0x0E,   /**< Battery */
    DF_MSG_STAT     = 0x0F,   /**< Status */
    /* User-defined messages start at 0x40 */
} dataflash_msg_id_t;

/**
 * @brief DataFlash message header
 */
typedef struct __attribute__((packed)) {
    uint8_t head1;            /**< Header byte 1 (0xA3) */
    uint8_t head2;            /**< Header byte 2 (0x95) */
    uint8_t msg_id;           /**< Message ID */
} dataflash_msg_header_t;

/**
 * @brief DataFlash format definition message (FMT)
 * 
 * Defines the structure of a message type.
 * Format characters:
 *   a   : int16_t[32]
 *   b   : int8_t
 *   B   : uint8_t
 *   h   : int16_t
 *   H   : uint16_t
 *   i   : int32_t
 *   I   : uint32_t
 *   f   : float
 *   d   : double
 *   n   : char[4]
 *   N   : char[16]
 *   Z   : char[64]
 *   c   : int16_t * 100
 *   C   : uint16_t * 100
 *   e   : int32_t * 100
 *   E   : uint32_t * 100
 *   L   : int32_t (latitude/longitude)
 *   M   : uint8_t (flight mode)
 *   q   : int64_t
 *   Q   : uint64_t
 */
typedef struct __attribute__((packed)) {
    dataflash_msg_header_t header;
    uint8_t type;             /**< Message type ID */
    uint8_t length;           /**< Message length including header */
    char name[4];             /**< Message name (4 chars) */
    char format[16];          /**< Format string */
    char labels[64];          /**< Comma-separated field labels */
} dataflash_fmt_msg_t;

/*******************************************************************************
 * Format Encoder Context
 ******************************************************************************/

/**
 * @brief Format encoder state
 */
typedef struct {
    bbox_log_format_t format;
    uint16_t next_msg_id;     /**< Next available message ID (ULog) */
    bool format_written[256]; /**< Track which formats have been written */
    uint64_t start_time_us;   /**< Log start timestamp */
} bbox_format_ctx_t;

/**
 * @brief Initialize format encoder context
 */
static inline void bbox_format_ctx_init(bbox_format_ctx_t *ctx, bbox_log_format_t format)
{
    ctx->format = format;
    ctx->next_msg_id = 0;
    ctx->start_time_us = 0;
    for (int i = 0; i < 256; i++) {
        ctx->format_written[i] = false;
    }
}

/*******************************************************************************
 * Format String Generators (for ULog and DataFlash)
 ******************************************************************************/

/**
 * @brief Get ULog format string for a message type
 */
static inline const char* bbox_get_ulog_format(bbox_msg_id_t msg_id)
{
    switch (msg_id) {
        case BBOX_MSG_IMU:
            return "sensor_accel:uint64_t timestamp;float x;float y;float z;"
                   "float gyro_x;float gyro_y;float gyro_z;float temperature;uint8_t id";
        case BBOX_MSG_GPS:
            return "vehicle_gps_position:uint64_t timestamp;int32_t lat;int32_t lon;"
                   "int32_t alt;int32_t alt_ellipsoid;uint16_t hdop;uint16_t vdop;"
                   "uint16_t vel;int16_t cog;uint8_t fix;uint8_t satellites;"
                   "uint16_t hacc;uint16_t vacc";
        case BBOX_MSG_ATTITUDE:
            return "vehicle_attitude:uint64_t timestamp;float roll;float pitch;"
                   "float yaw;float rollspeed;float pitchspeed;float yawspeed";
        case BBOX_MSG_PID_ROLL:
        case BBOX_MSG_PID_PITCH:
        case BBOX_MSG_PID_YAW:
        case BBOX_MSG_PID_ALT:
            return "rate_ctrl_status:uint64_t timestamp;float setpoint;float measured;"
                   "float error;float p;float i;float d;float ff;float output;uint8_t axis";
        case BBOX_MSG_MOTOR:
            return "actuator_outputs:uint64_t timestamp;uint16_t output[8];"
                   "uint8_t noutputs;uint8_t armed";
        case BBOX_MSG_BATTERY:
            return "battery_status:uint64_t timestamp;uint16_t voltage;int32_t current;"
                   "int32_t discharged;uint8_t remaining;uint8_t cells;"
                   "uint16_t cell_v[6];int8_t temp;uint8_t id";
        case BBOX_MSG_RC_INPUT:
            return "input_rc:uint64_t timestamp;uint16_t values[16];uint8_t count;"
                   "uint8_t rssi;uint8_t failsafe";
        case BBOX_MSG_STATUS:
            return "vehicle_status:uint64_t timestamp;uint8_t mode;uint8_t armed;"
                   "uint8_t failsafe;uint8_t gps_ok;uint8_t imu_ok;uint8_t baro_ok;"
                   "uint8_t mag_ok;uint8_t rc_ok;uint16_t cpu;uint32_t heap;uint16_t rate";
        default:
            return NULL;
    }
}

/**
 * @brief Get DataFlash format info for a message type
 * @param msg_id BBOX message ID
 * @param name Output: 4-char message name
 * @param format Output: Format string
 * @param labels Output: Comma-separated labels
 */
static inline void bbox_get_dataflash_format(bbox_msg_id_t msg_id, 
                                              char name[5], 
                                              char format[17], 
                                              char labels[65])
{
    switch (msg_id) {
        case BBOX_MSG_IMU:
            strcpy(name, "IMU");
            strcpy(format, "QffffffBf");
            strcpy(labels, "TimeUS,AccX,AccY,AccZ,GyrX,GyrY,GyrZ,I,T");
            break;
        case BBOX_MSG_GPS:
            strcpy(name, "GPS");
            strcpy(format, "QBBiiiiHHHhBHH");
            strcpy(labels, "TimeUS,Fix,NSats,Lat,Lng,Alt,AGL,HDop,VDop,Spd,Crs,HAcc,VAcc");
            break;
        case BBOX_MSG_ATTITUDE:
            strcpy(name, "ATT");
            strcpy(format, "Qffffff");
            strcpy(labels, "TimeUS,Roll,Pitch,Yaw,RollR,PitchR,YawR");
            break;
        case BBOX_MSG_PID_ROLL:
            strcpy(name, "PIDR");
            strcpy(format, "QffffffffB");
            strcpy(labels, "TimeUS,Tar,Act,Err,P,I,D,FF,Out,Ax");
            break;
        case BBOX_MSG_PID_PITCH:
            strcpy(name, "PIDP");
            strcpy(format, "QffffffffB");
            strcpy(labels, "TimeUS,Tar,Act,Err,P,I,D,FF,Out,Ax");
            break;
        case BBOX_MSG_PID_YAW:
            strcpy(name, "PIDY");
            strcpy(format, "QffffffffB");
            strcpy(labels, "TimeUS,Tar,Act,Err,P,I,D,FF,Out,Ax");
            break;
        case BBOX_MSG_PID_ALT:
            strcpy(name, "PIDA");
            strcpy(format, "QffffffffB");
            strcpy(labels, "TimeUS,Tar,Act,Err,P,I,D,FF,Out,Ax");
            break;
        case BBOX_MSG_MOTOR:
            strcpy(name, "MOT");
            strcpy(format, "QHHHHHHHHBB");
            strcpy(labels, "TimeUS,M1,M2,M3,M4,M5,M6,M7,M8,Cnt,Arm");
            break;
        case BBOX_MSG_BATTERY:
            strcpy(name, "BAT");
            strcpy(format, "QHiiBBHHHHHHbB");
            strcpy(labels, "TimeUS,Volt,Curr,CurrTot,Rem,Cells,C1,C2,C3,C4,C5,C6,T,I");
            break;
        case BBOX_MSG_RC_INPUT:
            strcpy(name, "RCIN");
            strcpy(format, "QHHHHHHHHHHHHHHHHbBB");
            strcpy(labels, "TimeUS,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11,C12,C13,C14,C15,C16,Cnt,RSSI,FS");
            break;
        case BBOX_MSG_BARO:
            strcpy(name, "BARO");
            strcpy(format, "QfffB");
            strcpy(labels, "TimeUS,Press,Alt,Temp,I");
            break;
        case BBOX_MSG_MAG:
            strcpy(name, "MAG");
            strcpy(format, "QffffB");
            strcpy(labels, "TimeUS,MagX,MagY,MagZ,Temp,I");
            break;
        case BBOX_MSG_STATUS:
            strcpy(name, "STAT");
            strcpy(format, "QBBBBBBBBHIH");
            strcpy(labels, "TimeUS,Mode,Arm,FS,GPS,IMU,Bar,Mag,RC,CPU,Heap,Rate");
            break;
        default:
            strcpy(name, "UNK");
            strcpy(format, "Q");
            strcpy(labels, "TimeUS");
            break;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_FORMATS_H */
