/**
 * @file blackbox_encoder.h
 * @brief Format encoders for BBOX, PX4 ULog, and ArduPilot DataFlash
 *
 * Platform-independent encoding logic for different log formats.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_ENCODER_H
#define BLACKBOX_ENCODER_H

#include "blackbox_types.h"
#include "blackbox_messages.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * PX4 ULog Format Definitions
 ******************************************************************************/

#define ULOG_MAGIC_SIZE 7
static const uint8_t ULOG_MAGIC[ULOG_MAGIC_SIZE] = {0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35};

typedef enum {
    ULOG_MSG_FORMAT         = 'F',
    ULOG_MSG_DATA           = 'D',
    ULOG_MSG_INFO           = 'I',
    ULOG_MSG_INFO_MULTIPLE  = 'M',
    ULOG_MSG_PARAMETER      = 'P',
    ULOG_MSG_ADD_LOGGED_MSG = 'A',
    ULOG_MSG_REMOVE_LOGGED_MSG = 'R',
    ULOG_MSG_SYNC           = 'S',
    ULOG_MSG_DROPOUT        = 'O',
    ULOG_MSG_LOGGING        = 'L',
    ULOG_MSG_LOGGING_TAGGED = 'C',
    ULOG_MSG_FLAG_BITS      = 'B',
} ulog_msg_type_t;

typedef struct __attribute__((packed)) {
    uint16_t msg_size;
    uint8_t msg_type;
} ulog_msg_header_t;

typedef struct __attribute__((packed)) {
    uint8_t magic[ULOG_MAGIC_SIZE];
    uint8_t version;
    uint64_t timestamp_us;
} ulog_file_header_t;

typedef struct __attribute__((packed)) {
    ulog_msg_header_t header;
    uint16_t msg_id;
} ulog_data_header_t;

/*******************************************************************************
 * ArduPilot DataFlash Format Definitions
 ******************************************************************************/

#define DATAFLASH_HEAD_BYTE1 0xA3
#define DATAFLASH_HEAD_BYTE2 0x95

typedef enum {
    DF_MSG_FORMAT   = 0x80,  /* Must be 128 */
    DF_MSG_PARM     = 0x20,  /* Parameters */
    DF_MSG_GPS      = 0x21,
    DF_MSG_IMU      = 0x22,
    DF_MSG_MSG      = 0x23,  /* Text messages */
    DF_MSG_RCIN     = 0x24,
    DF_MSG_RCOU     = 0x25,  /* RC output */
    DF_MSG_BARO     = 0x26,
    DF_MSG_CURR     = 0x27,
    DF_MSG_ATT      = 0x28,  /* Attitude */
    DF_MSG_MAG      = 0x29,
    DF_MSG_MODE     = 0x2A,
    DF_MSG_PIDR     = 0x2B,  /* PID Roll */
    DF_MSG_PIDP     = 0x2C,  /* PID Pitch */
    DF_MSG_PIDY     = 0x2D,  /* PID Yaw */
    DF_MSG_PIDA     = 0x2E,  /* PID Altitude */
    DF_MSG_MOT      = 0x2F,
    DF_MSG_ESC      = 0x30,
    DF_MSG_BAT      = 0x31,
    DF_MSG_STAT     = 0x32,
} dataflash_msg_id_t;

typedef struct __attribute__((packed)) {
    uint8_t head1;
    uint8_t head2;
    uint8_t msg_id;
} dataflash_msg_header_t;

typedef struct __attribute__((packed)) {
    dataflash_msg_header_t header;
    uint8_t type;
    uint8_t length;
    char name[4];
    char format[16];
    char labels[64];
} dataflash_fmt_msg_t;

/**
 * @brief ArduPilot PID message structure (matches ArduPilot log_PID)
 */
typedef struct __attribute__((packed)) {
    dataflash_msg_header_t header;
    uint64_t timestamp_us;
    float target;
    float actual;
    float error;
    float P;
    float I;
    float D;
    float FF;
    float DFF;
    float Dmod;
    float SRate;
    uint8_t flags;
} dataflash_pid_msg_t;

/**
 * @brief ArduPilot ATT message structure
 */
typedef struct __attribute__((packed)) {
    dataflash_msg_header_t header;
    uint64_t timestamp_us;
    int16_t roll_cd;      /* centi-degrees */
    int16_t pitch_cd;
    uint16_t yaw_cd;
    int16_t roll_err_cd;
    int16_t pitch_err_cd;
    int16_t yaw_err_cd;
} dataflash_att_msg_t;

/**
 * @brief ArduPilot IMU message structure
 */
typedef struct __attribute__((packed)) {
    dataflash_msg_header_t header;
    uint64_t timestamp_us;
    float gyro_x;
    float gyro_y;
    float gyro_z;
    float accel_x;
    float accel_y;
    float accel_z;
    uint8_t instance;
    float temperature;
} dataflash_imu_msg_t;

/*******************************************************************************
 * Encoder Context
 ******************************************************************************/

/**
 * @brief Encoder state for format tracking
 */
typedef struct {
    bbox_format_t format;
    uint16_t next_msg_id;       /**< Next available message ID (ULog) */
    uint16_t msg_id_map[256];   /**< Map bbox_msg_id to format-specific ID */
    bool format_written[256];   /**< Track which formats have been written */
    uint64_t start_time_us;
} bbox_encoder_ctx_t;

/**
 * @brief Initialize encoder context
 */
static inline void bbox_encoder_init(bbox_encoder_ctx_t *ctx, bbox_format_t format)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->format = format;
    ctx->next_msg_id = 0;
}

/*******************************************************************************
 * BBOX Native Format Encoding
 ******************************************************************************/

/**
 * @brief Build a BBOX text log packet
 * 
 * @param packet Output packet buffer
 * @param level Log level
 * @param timestamp_us Timestamp in microseconds
 * @param tag Component tag
 * @param file Source file name
 * @param line Source line number
 * @param message Formatted message
 * @return Size of packet in bytes
 */
static inline size_t bbox_encode_text_packet(
    bbox_packet_t *packet,
    bbox_log_level_t level,
    uint64_t timestamp_us,
    const char *tag,
    const char *file,
    uint32_t line,
    const char *message)
{
    static const uint8_t magic[4] = {
        BLACKBOX_LOG_MAGIC_BYTE0, BLACKBOX_LOG_MAGIC_BYTE1,
        BLACKBOX_LOG_MAGIC_BYTE2, BLACKBOX_LOG_MAGIC_BYTE3
    };
    
    memcpy(packet->header.magic, magic, 4);
    packet->header.version = BLACKBOX_LOG_VERSION;
    packet->header.msg_type = BBOX_MSG_TYPE_LOG;
    packet->header.level = (uint8_t)level;
    packet->header.reserved = 0;
    packet->header.timestamp_us = timestamp_us;
    packet->header.tag_hash = bbox_hash_fnv1a(tag);
    packet->header.file_hash = bbox_hash_fnv1a(file);
    packet->header.line = (uint16_t)line;
    
    /* Copy message payload */
    size_t msg_len = strlen(message);
    if (msg_len >= BLACKBOX_MAX_MESSAGE_SIZE) {
        msg_len = BLACKBOX_MAX_MESSAGE_SIZE - 1;
    }
    memcpy(packet->payload, message, msg_len);
    packet->payload[msg_len] = '\0';
    packet->header.payload_length = (uint16_t)msg_len;
    
    /* Calculate total packet size */
    size_t packet_size = sizeof(bbox_packet_header_t) + msg_len;
    
    /* Calculate CRC-16 over header (excluding crc16 field) and payload */
    size_t crc_data_len = sizeof(bbox_packet_header_t) - sizeof(uint16_t) + msg_len;
    packet->header.crc16 = bbox_crc16((const uint8_t *)packet, crc_data_len);
    
    return packet_size;
}

/**
 * @brief Build a BBOX struct packet
 */
static inline size_t bbox_encode_struct_packet(
    uint8_t *buffer,
    size_t buffer_size,
    bbox_msg_id_t msg_id,
    uint64_t timestamp_us,
    const void *data,
    size_t data_size)
{
    /* Struct packet format:
     * [1 byte: msg_type (0x08)]
     * [1 byte: msg_id]
     * [2 bytes: data_size]
     * [8 bytes: timestamp]
     * [N bytes: data]
     */
    size_t total_size = 1 + 1 + 2 + 8 + data_size;
    if (total_size > buffer_size) {
        return 0;
    }
    
    size_t offset = 0;
    buffer[offset++] = BBOX_MSG_TYPE_STRUCT;
    buffer[offset++] = (uint8_t)msg_id;
    buffer[offset++] = (uint8_t)(data_size & 0xFF);
    buffer[offset++] = (uint8_t)((data_size >> 8) & 0xFF);
    memcpy(buffer + offset, &timestamp_us, 8);
    offset += 8;
    memcpy(buffer + offset, data, data_size);
    
    return total_size;
}

/*******************************************************************************
 * PX4 ULog Format Encoding
 ******************************************************************************/

/**
 * @brief Write ULog file header
 */
static inline size_t bbox_encode_ulog_file_header(uint8_t *buffer, uint64_t timestamp_us)
{
    ulog_file_header_t *header = (ulog_file_header_t *)buffer;
    memcpy(header->magic, ULOG_MAGIC, ULOG_MAGIC_SIZE);
    header->version = 1;
    header->timestamp_us = timestamp_us;
    return sizeof(ulog_file_header_t);
}

/**
 * @brief Encode ULog data message
 */
static inline size_t bbox_encode_ulog_data(
    uint8_t *buffer,
    size_t buffer_size,
    uint16_t msg_id,
    const void *data,
    size_t data_size)
{
    size_t total_size = sizeof(ulog_data_header_t) + data_size;
    if (total_size > buffer_size) {
        return 0;
    }
    
    ulog_data_header_t *header = (ulog_data_header_t *)buffer;
    header->header.msg_size = (uint16_t)(sizeof(uint16_t) + data_size);
    header->header.msg_type = ULOG_MSG_DATA;
    header->msg_id = msg_id;
    
    memcpy(buffer + sizeof(ulog_data_header_t), data, data_size);
    
    return total_size;
}

/*******************************************************************************
 * ArduPilot DataFlash Format Encoding
 ******************************************************************************/

/**
 * @brief Write DataFlash FMT message (format definition)
 */
static inline size_t bbox_encode_dataflash_fmt(
    uint8_t *buffer,
    uint8_t msg_type,
    uint8_t msg_length,
    const char *name,
    const char *format,
    const char *labels)
{
    dataflash_fmt_msg_t *fmt = (dataflash_fmt_msg_t *)buffer;
    
    fmt->header.head1 = DATAFLASH_HEAD_BYTE1;
    fmt->header.head2 = DATAFLASH_HEAD_BYTE2;
    fmt->header.msg_id = DF_MSG_FORMAT;
    fmt->type = msg_type;
    fmt->length = msg_length;
    
    memset(fmt->name, 0, sizeof(fmt->name));
    memset(fmt->format, 0, sizeof(fmt->format));
    memset(fmt->labels, 0, sizeof(fmt->labels));
    
    /* Copy name - use full 4 bytes (ArduPilot format doesn't null-terminate) */
    size_t name_len = strlen(name);
    if (name_len > sizeof(fmt->name)) name_len = sizeof(fmt->name);
    memcpy(fmt->name, name, name_len);
    
    strncpy(fmt->format, format, sizeof(fmt->format) - 1);
    strncpy(fmt->labels, labels, sizeof(fmt->labels) - 1);
    
    return sizeof(dataflash_fmt_msg_t);
}

/**
 * @brief Write DataFlash message header
 */
static inline void bbox_encode_dataflash_header(uint8_t *buffer, uint8_t msg_id)
{
    dataflash_msg_header_t *header = (dataflash_msg_header_t *)buffer;
    header->head1 = DATAFLASH_HEAD_BYTE1;
    header->head2 = DATAFLASH_HEAD_BYTE2;
    header->msg_id = msg_id;
}

/**
 * @brief Encode a DataFlash PID message (PIDR, PIDP, PIDY, PIDA)
 */
static inline size_t bbox_encode_dataflash_pid(
    uint8_t *buffer,
    size_t buffer_size,
    uint8_t msg_type,
    uint64_t timestamp_us,
    float target,
    float actual,
    float error,
    float P,
    float I,
    float D,
    float FF,
    float output,
    uint8_t axis)
{
    if (buffer_size < sizeof(dataflash_pid_msg_t)) {
        return 0;
    }
    
    dataflash_pid_msg_t *msg = (dataflash_pid_msg_t *)buffer;
    msg->header.head1 = DATAFLASH_HEAD_BYTE1;
    msg->header.head2 = DATAFLASH_HEAD_BYTE2;
    msg->header.msg_id = msg_type;
    msg->timestamp_us = timestamp_us;
    msg->target = target;
    msg->actual = actual;
    msg->error = error;
    msg->P = P;
    msg->I = I;
    msg->D = D;
    msg->FF = FF;
    msg->DFF = 0.0f;  /* Derivative feed-forward, not used */
    msg->Dmod = 1.0f; /* D modifier, default 1.0 */
    msg->SRate = 0.0f; /* Slew rate */
    msg->flags = axis; /* Use flags to store axis for compat */
    
    return sizeof(dataflash_pid_msg_t);
}

/**
 * @brief Encode a DataFlash ATT message
 */
static inline size_t bbox_encode_dataflash_att(
    uint8_t *buffer,
    size_t buffer_size,
    uint64_t timestamp_us,
    float roll_rad,
    float pitch_rad,
    float yaw_rad,
    float rollspeed,
    float pitchspeed,
    float yawspeed)
{
    if (buffer_size < sizeof(dataflash_att_msg_t)) {
        return 0;
    }
    
    dataflash_att_msg_t *msg = (dataflash_att_msg_t *)buffer;
    msg->header.head1 = DATAFLASH_HEAD_BYTE1;
    msg->header.head2 = DATAFLASH_HEAD_BYTE2;
    msg->header.msg_id = DF_MSG_ATT;
    msg->timestamp_us = timestamp_us;
    
    /* Convert radians to centi-degrees */
    msg->roll_cd = (int16_t)(roll_rad * 5729.578f);  /* rad to cdeg */
    msg->pitch_cd = (int16_t)(pitch_rad * 5729.578f);
    msg->yaw_cd = (uint16_t)((yaw_rad < 0 ? yaw_rad + 6.283185f : yaw_rad) * 5729.578f);
    
    /* Error terms as rates for now */
    msg->roll_err_cd = (int16_t)(rollspeed * 5729.578f);
    msg->pitch_err_cd = (int16_t)(pitchspeed * 5729.578f);
    msg->yaw_err_cd = (int16_t)(yawspeed * 5729.578f);
    
    return sizeof(dataflash_att_msg_t);
}

/**
 * @brief Encode a DataFlash IMU message
 */
static inline size_t bbox_encode_dataflash_imu(
    uint8_t *buffer,
    size_t buffer_size,
    uint64_t timestamp_us,
    float accel_x, float accel_y, float accel_z,
    float gyro_x, float gyro_y, float gyro_z,
    float temperature,
    uint8_t instance)
{
    if (buffer_size < sizeof(dataflash_imu_msg_t)) {
        return 0;
    }
    
    dataflash_imu_msg_t *msg = (dataflash_imu_msg_t *)buffer;
    msg->header.head1 = DATAFLASH_HEAD_BYTE1;
    msg->header.head2 = DATAFLASH_HEAD_BYTE2;
    msg->header.msg_id = DF_MSG_IMU;
    msg->timestamp_us = timestamp_us;
    msg->gyro_x = gyro_x;
    msg->gyro_y = gyro_y;
    msg->gyro_z = gyro_z;
    msg->accel_x = accel_x;
    msg->accel_y = accel_y;
    msg->accel_z = accel_z;
    msg->instance = instance;
    msg->temperature = temperature;
    
    return sizeof(dataflash_imu_msg_t);
}

/*******************************************************************************
 * Format String Helpers
 ******************************************************************************/

/**
 * @brief Get DataFlash format info for a message type
 */
static inline bool bbox_get_dataflash_fmt_info(
    bbox_msg_id_t msg_id,
    const char **name,
    const char **format,
    const char **labels,
    uint8_t *msg_type)
{
    switch (msg_id) {
        case BBOX_MSG_IMU:
            *name = "IMU";
            *format = "QffffffBf";
            *labels = "TimeUS,GyrX,GyrY,GyrZ,AccX,AccY,AccZ,I,T";
            *msg_type = DF_MSG_IMU;
            return true;
            
        case BBOX_MSG_GPS:
            *name = "GPS";
            *format = "QBBiiiiHHHhBHH";
            *labels = "TimeUS,Fix,NSats,Lat,Lng,Alt,AGL,HDop,VDop,Spd,Crs,HAcc,VAcc";
            *msg_type = DF_MSG_GPS;
            return true;
            
        case BBOX_MSG_ATTITUDE:
            *name = "ATT";
            *format = "QccCccc";
            *labels = "TimeUS,Roll,Pitch,Yaw,RollE,PitchE,YawE";
            *msg_type = DF_MSG_ATT;
            return true;
            
        case BBOX_MSG_PID_ROLL:
            *name = "PIDR";
            *format = "QffffffffffB";
            *labels = "TimeUS,Tar,Act,Err,P,I,D,FF,DFF,Dmod,SRate,Flags";
            *msg_type = DF_MSG_PIDR;
            return true;
            
        case BBOX_MSG_PID_PITCH:
            *name = "PIDP";
            *format = "QffffffffffB";
            *labels = "TimeUS,Tar,Act,Err,P,I,D,FF,DFF,Dmod,SRate,Flags";
            *msg_type = DF_MSG_PIDP;
            return true;
            
        case BBOX_MSG_PID_YAW:
            *name = "PIDY";
            *format = "QffffffffffB";
            *labels = "TimeUS,Tar,Act,Err,P,I,D,FF,DFF,Dmod,SRate,Flags";
            *msg_type = DF_MSG_PIDY;
            return true;
            
        case BBOX_MSG_PID_ALT:
            *name = "PIDA";
            *format = "QffffffffffB";
            *labels = "TimeUS,Tar,Act,Err,P,I,D,FF,DFF,Dmod,SRate,Flags";
            *msg_type = DF_MSG_PIDA;
            return true;
            
        case BBOX_MSG_MOTOR:
            *name = "MOT";
            *format = "QHHHHHHHHBB";
            *labels = "TimeUS,M1,M2,M3,M4,M5,M6,M7,M8,Cnt,Arm";
            *msg_type = DF_MSG_MOT;
            return true;
            
        case BBOX_MSG_BATTERY:
            *name = "BAT";
            *format = "QHiBBHHHHHHbB";
            *labels = "TimeUS,V,I,Ah,Rem,C,V1,V2,V3,V4,V5,V6,T,Id";
            *msg_type = DF_MSG_BAT;
            return true;
            
        case BBOX_MSG_BARO:
            *name = "BARO";
            *format = "QfffB";
            *labels = "TimeUS,Press,Alt,Temp,I";
            *msg_type = DF_MSG_BARO;
            return true;
            
        case BBOX_MSG_MAG:
            *name = "MAG";
            *format = "QffffB";
            *labels = "TimeUS,MagX,MagY,MagZ,Temp,I";
            *msg_type = DF_MSG_MAG;
            return true;
            
        case BBOX_MSG_STATUS:
            *name = "STAT";
            *format = "QBBBBBBBBHiH";
            *labels = "TimeUS,Mode,Arm,FS,GPS,IMU,Bar,Mag,RC,CPU,Heap,Rate";
            *msg_type = DF_MSG_STAT;
            return true;
            
        default:
            return false;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_ENCODER_H */
