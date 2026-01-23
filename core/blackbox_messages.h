/**
 * @file blackbox_messages.h
 * @brief Structured message definitions for flight data logging
 *
 * Defines standard message types for IMU, GPS, Motor, PID, and other
 * flight-related data. Compatible with PX4 ULog, ArduPilot DataFlash,
 * and native BBOX formats.
 *
 * This file is platform-independent.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_MESSAGES_H
#define BLACKBOX_MESSAGES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Message Type IDs
 ******************************************************************************/

/**
 * @brief Standard message type identifiers
 * 
 * Range 0x00-0x0F: System messages
 * Range 0x10-0x3F: Sensor messages
 * Range 0x40-0x6F: Control messages
 * Range 0x70-0x9F: Navigation messages
 * Range 0xA0-0xCF: Power/Motor messages
 * Range 0xD0-0xFF: User-defined messages
 */
typedef enum {
    /* System messages (0x00-0x0F) */
    BBOX_MSG_FORMAT_DEF     = 0x00,
    BBOX_MSG_PARAM          = 0x01,
    BBOX_MSG_INFO           = 0x02,
    BBOX_MSG_SYNC           = 0x03,
    BBOX_MSG_DROPOUT        = 0x04,
    BBOX_MSG_EVENT          = 0x05,
    BBOX_MSG_MODE           = 0x06,
    BBOX_MSG_STATUS         = 0x07,
    
    /* Sensor messages (0x10-0x3F) */
    BBOX_MSG_IMU            = 0x10,
    BBOX_MSG_IMU_RAW        = 0x11,
    BBOX_MSG_MAG            = 0x12,
    BBOX_MSG_BARO           = 0x13,
    BBOX_MSG_GPS            = 0x20,
    BBOX_MSG_GPS_RAW        = 0x21,
    BBOX_MSG_GPS_VEL        = 0x22,
    BBOX_MSG_RANGEFINDER    = 0x30,
    BBOX_MSG_OPTICAL_FLOW   = 0x31,
    BBOX_MSG_AIRSPEED       = 0x32,
    
    /* Control messages (0x40-0x6F) */
    BBOX_MSG_ATTITUDE       = 0x40,
    BBOX_MSG_ATTITUDE_TARGET = 0x41,
    BBOX_MSG_RATE           = 0x42,
    BBOX_MSG_RATE_TARGET    = 0x43,
    BBOX_MSG_PID_ROLL       = 0x50,
    BBOX_MSG_PID_PITCH      = 0x51,
    BBOX_MSG_PID_YAW        = 0x52,
    BBOX_MSG_PID_ALT        = 0x53,
    BBOX_MSG_PID_POS        = 0x54,
    BBOX_MSG_RC_INPUT       = 0x60,
    BBOX_MSG_RC_OUTPUT      = 0x61,
    
    /* Navigation messages (0x70-0x9F) */
    BBOX_MSG_LOCAL_POS      = 0x70,
    BBOX_MSG_GLOBAL_POS     = 0x71,
    BBOX_MSG_VELOCITY       = 0x72,
    BBOX_MSG_ACCELERATION   = 0x73,
    BBOX_MSG_ESTIMATOR      = 0x74,
    BBOX_MSG_MISSION        = 0x80,
    BBOX_MSG_WAYPOINT       = 0x81,
    BBOX_MSG_FENCE          = 0x82,
    
    /* Power/Motor messages (0xA0-0xCF) */
    BBOX_MSG_MOTOR          = 0xA0,
    BBOX_MSG_MOTOR_STATUS   = 0xA1,
    BBOX_MSG_ESC            = 0xA2,
    BBOX_MSG_BATTERY        = 0xB0,
    BBOX_MSG_POWER          = 0xB1,
    BBOX_MSG_CURRENT        = 0xB2,
    
    /* User-defined messages (0xD0-0xFF) */
    BBOX_MSG_USER_0         = 0xD0,
    BBOX_MSG_USER_1         = 0xD1,
    BBOX_MSG_USER_2         = 0xD2,
    BBOX_MSG_USER_3         = 0xD3,
    BBOX_MSG_TEXT           = 0xFE,
    BBOX_MSG_CUSTOM         = 0xFF,
} bbox_msg_id_t;

/*******************************************************************************
 * IMU Messages
 ******************************************************************************/

/**
 * @brief IMU sensor data (calibrated)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float accel_x;            /**< X acceleration (m/s²) */
    float accel_y;            /**< Y acceleration (m/s²) */
    float accel_z;            /**< Z acceleration (m/s²) */
    float gyro_x;             /**< X angular rate (rad/s) */
    float gyro_y;             /**< Y angular rate (rad/s) */
    float gyro_z;             /**< Z angular rate (rad/s) */
    float temperature;        /**< Sensor temperature (°C) */
    uint8_t imu_id;           /**< IMU instance ID */
} bbox_msg_imu_t;

/**
 * @brief Raw IMU sensor data (uncalibrated)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    int16_t accel_x_raw;
    int16_t accel_y_raw;
    int16_t accel_z_raw;
    int16_t gyro_x_raw;
    int16_t gyro_y_raw;
    int16_t gyro_z_raw;
    int16_t temperature_raw;
    uint8_t imu_id;
} bbox_msg_imu_raw_t;

/**
 * @brief Magnetometer data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float mag_x;              /**< X magnetic field (Gauss) */
    float mag_y;              /**< Y magnetic field (Gauss) */
    float mag_z;              /**< Z magnetic field (Gauss) */
    float temperature;
    uint8_t mag_id;
} bbox_msg_mag_t;

/**
 * @brief Barometer data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float pressure;           /**< Pressure (Pa) */
    float altitude;           /**< Altitude (m) */
    float temperature;        /**< Temperature (°C) */
    uint8_t baro_id;
} bbox_msg_baro_t;

/*******************************************************************************
 * GPS Messages
 ******************************************************************************/

typedef enum {
    GPS_FIX_NONE = 0,
    GPS_FIX_2D = 2,
    GPS_FIX_3D = 3,
    GPS_FIX_DGPS = 4,
    GPS_FIX_RTK_FLOAT = 5,
    GPS_FIX_RTK_FIXED = 6,
} bbox_gps_fix_t;

/**
 * @brief GPS position data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    int32_t latitude;         /**< Latitude (degrees * 1e7) */
    int32_t longitude;        /**< Longitude (degrees * 1e7) */
    int32_t altitude_msl;     /**< Altitude above MSL (mm) */
    int32_t altitude_agl;     /**< Altitude above ground (mm) */
    uint16_t hdop;            /**< Horizontal DOP * 100 */
    uint16_t vdop;            /**< Vertical DOP * 100 */
    uint16_t speed_ground;    /**< Ground speed (cm/s) */
    int16_t course;           /**< Course over ground (degrees * 100) */
    uint8_t fix_type;
    uint8_t satellites;
    uint16_t accuracy_h;      /**< Horizontal accuracy (mm) */
    uint16_t accuracy_v;      /**< Vertical accuracy (mm) */
} bbox_msg_gps_t;

/**
 * @brief GPS velocity data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    int16_t vel_n;            /**< North velocity (cm/s) */
    int16_t vel_e;            /**< East velocity (cm/s) */
    int16_t vel_d;            /**< Down velocity (cm/s) */
    uint16_t speed_accuracy;
} bbox_msg_gps_vel_t;

/*******************************************************************************
 * Attitude/Control Messages
 ******************************************************************************/

/**
 * @brief Attitude data (Euler angles)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float roll;               /**< Roll angle (rad) */
    float pitch;              /**< Pitch angle (rad) */
    float yaw;                /**< Yaw angle (rad) */
    float rollspeed;          /**< Roll rate (rad/s) */
    float pitchspeed;         /**< Pitch rate (rad/s) */
    float yawspeed;           /**< Yaw rate (rad/s) */
} bbox_msg_attitude_t;

/**
 * @brief Attitude quaternion
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float q0, q1, q2, q3;
} bbox_msg_attitude_quat_t;

/**
 * @brief PID controller state
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float setpoint;
    float measured;
    float error;
    float p_term;
    float i_term;
    float d_term;
    float ff_term;
    float output;
    uint8_t axis;             /**< 0=roll, 1=pitch, 2=yaw, 3=alt */
} bbox_msg_pid_t;

/**
 * @brief RC input channels
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t channels[16];    /**< RC channel values (1000-2000 µs) */
    uint8_t channel_count;
    uint8_t rssi;             /**< Signal strength (0-100%) */
    uint8_t failsafe;
} bbox_msg_rc_input_t;

/**
 * @brief RC/Servo output channels
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t channels[16];
    uint8_t channel_count;
} bbox_msg_rc_output_t;

/*******************************************************************************
 * Motor/Power Messages
 ******************************************************************************/

/**
 * @brief Motor output data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t motor[8];        /**< Motor outputs (0-10000 = 0-100%) */
    uint8_t motor_count;
    uint8_t armed;
} bbox_msg_motor_t;

/**
 * @brief ESC telemetry data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t rpm;             /**< Motor RPM / 10 */
    uint16_t voltage;         /**< Voltage (mV) */
    uint16_t current;         /**< Current (mA) */
    int8_t temperature;       /**< Temperature (°C) */
    uint8_t motor_id;
} bbox_msg_esc_t;

/**
 * @brief Battery status
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t voltage;         /**< Pack voltage (mV) */
    int32_t current;          /**< Current (mA, negative = discharging) */
    int32_t consumed;         /**< Consumed capacity (mAh) */
    uint8_t remaining;        /**< Remaining capacity (0-100%) */
    uint8_t cell_count;
    uint16_t cell_voltage[6]; /**< Individual cell voltages (mV) */
    int8_t temperature;
    uint8_t battery_id;
} bbox_msg_battery_t;

/*******************************************************************************
 * Navigation Messages
 ******************************************************************************/

/**
 * @brief Local position (NED frame)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    float x;                  /**< X position (m) North */
    float y;                  /**< Y position (m) East */
    float z;                  /**< Z position (m) Down */
    float vx, vy, vz;         /**< Velocities (m/s) */
    float ax, ay, az;         /**< Accelerations (m/s²) */
    uint8_t xy_valid;
    uint8_t z_valid;
    uint8_t v_xy_valid;
    uint8_t v_z_valid;
} bbox_msg_local_pos_t;

/*******************************************************************************
 * System Messages
 ******************************************************************************/

typedef enum {
    FLIGHT_MODE_MANUAL = 0,
    FLIGHT_MODE_ACRO = 1,
    FLIGHT_MODE_ANGLE = 2,
    FLIGHT_MODE_HORIZON = 3,
    FLIGHT_MODE_ALTHOLD = 4,
    FLIGHT_MODE_POSHOLD = 5,
    FLIGHT_MODE_RTH = 6,
    FLIGHT_MODE_WAYPOINT = 7,
    FLIGHT_MODE_LAND = 8,
    FLIGHT_MODE_FAILSAFE = 9,
} bbox_flight_mode_t;

/**
 * @brief System status message
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint8_t flight_mode;
    uint8_t armed;
    uint8_t failsafe;
    uint8_t gps_ok;
    uint8_t imu_ok;
    uint8_t baro_ok;
    uint8_t mag_ok;
    uint8_t rc_ok;
    uint16_t cpu_load;        /**< CPU load (0-1000 = 0-100%) */
    uint32_t free_heap;       /**< Free heap memory (bytes) */
    uint16_t loop_rate;       /**< Main loop rate (Hz) */
} bbox_msg_status_t;

/**
 * @brief Event marker
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;
    uint16_t event_id;
    uint8_t severity;         /**< 0=info, 1=warn, 2=error, 3=critical */
    uint8_t data[8];
} bbox_msg_event_t;

/*******************************************************************************
 * Message Utilities
 ******************************************************************************/

/**
 * @brief Get the size of a message type
 */
static inline size_t bbox_msg_size(bbox_msg_id_t msg_id)
{
    switch (msg_id) {
        case BBOX_MSG_IMU:          return sizeof(bbox_msg_imu_t);
        case BBOX_MSG_IMU_RAW:      return sizeof(bbox_msg_imu_raw_t);
        case BBOX_MSG_MAG:          return sizeof(bbox_msg_mag_t);
        case BBOX_MSG_BARO:         return sizeof(bbox_msg_baro_t);
        case BBOX_MSG_GPS:          return sizeof(bbox_msg_gps_t);
        case BBOX_MSG_GPS_VEL:      return sizeof(bbox_msg_gps_vel_t);
        case BBOX_MSG_ATTITUDE:     return sizeof(bbox_msg_attitude_t);
        case BBOX_MSG_PID_ROLL:
        case BBOX_MSG_PID_PITCH:
        case BBOX_MSG_PID_YAW:
        case BBOX_MSG_PID_ALT:      return sizeof(bbox_msg_pid_t);
        case BBOX_MSG_RC_INPUT:     return sizeof(bbox_msg_rc_input_t);
        case BBOX_MSG_RC_OUTPUT:    return sizeof(bbox_msg_rc_output_t);
        case BBOX_MSG_MOTOR:        return sizeof(bbox_msg_motor_t);
        case BBOX_MSG_ESC:          return sizeof(bbox_msg_esc_t);
        case BBOX_MSG_BATTERY:      return sizeof(bbox_msg_battery_t);
        case BBOX_MSG_LOCAL_POS:    return sizeof(bbox_msg_local_pos_t);
        case BBOX_MSG_STATUS:       return sizeof(bbox_msg_status_t);
        case BBOX_MSG_EVENT:        return sizeof(bbox_msg_event_t);
        default:                    return 0;
    }
}

/**
 * @brief Get the name of a message type
 */
static inline const char *bbox_msg_name(bbox_msg_id_t msg_id)
{
    switch (msg_id) {
        case BBOX_MSG_IMU:          return "IMU";
        case BBOX_MSG_IMU_RAW:      return "IMU_RAW";
        case BBOX_MSG_MAG:          return "MAG";
        case BBOX_MSG_BARO:         return "BARO";
        case BBOX_MSG_GPS:          return "GPS";
        case BBOX_MSG_GPS_VEL:      return "GPS_VEL";
        case BBOX_MSG_ATTITUDE:     return "ATT";
        case BBOX_MSG_PID_ROLL:     return "PIDR";
        case BBOX_MSG_PID_PITCH:    return "PIDP";
        case BBOX_MSG_PID_YAW:      return "PIDY";
        case BBOX_MSG_PID_ALT:      return "PIDA";
        case BBOX_MSG_RC_INPUT:     return "RCIN";
        case BBOX_MSG_RC_OUTPUT:    return "RCOU";
        case BBOX_MSG_MOTOR:        return "MOT";
        case BBOX_MSG_ESC:          return "ESC";
        case BBOX_MSG_BATTERY:      return "BAT";
        case BBOX_MSG_LOCAL_POS:    return "LPOS";
        case BBOX_MSG_STATUS:       return "STAT";
        case BBOX_MSG_EVENT:        return "EV";
        case BBOX_MSG_TEXT:         return "MSG";
        default:                    return "UNK";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_MESSAGES_H */
