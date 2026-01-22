/**
 * @file blackbox_messages.h
 * @brief Structured message definitions for flight data logging
 *
 * Defines standard message types for IMU, GPS, Motor, PID, and other
 * flight-related data. Compatible with PX4 ULog, ArduPilot DataFlash,
 * and native BBOX formats.
 *
 * @author Nikhil Robinson
 * @version 2.0.0
 */

#ifndef BLACKBOX_MESSAGES_H
#define BLACKBOX_MESSAGES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Message Type IDs
 ******************************************************************************/

/**
 * @brief Standard message type identifiers
 * 
 * These IDs are used across all log formats for message identification.
 * Range 0x00-0x0F: System messages
 * Range 0x10-0x3F: Sensor messages
 * Range 0x40-0x6F: Control messages
 * Range 0x70-0x9F: Navigation messages
 * Range 0xA0-0xCF: Power/Motor messages
 * Range 0xD0-0xFF: User-defined messages
 */
typedef enum {
    /* System messages (0x00-0x0F) */
    BBOX_MSG_FORMAT_DEF     = 0x00,  /**< Format definition message */
    BBOX_MSG_PARAM          = 0x01,  /**< Parameter message */
    BBOX_MSG_INFO           = 0x02,  /**< System info message */
    BBOX_MSG_SYNC           = 0x03,  /**< Sync marker */
    BBOX_MSG_DROPOUT        = 0x04,  /**< Dropout marker */
    BBOX_MSG_EVENT          = 0x05,  /**< Event marker */
    BBOX_MSG_MODE           = 0x06,  /**< Flight mode change */
    BBOX_MSG_STATUS         = 0x07,  /**< System status */
    
    /* Sensor messages (0x10-0x3F) */
    BBOX_MSG_IMU            = 0x10,  /**< IMU data (accel + gyro) */
    BBOX_MSG_IMU_RAW        = 0x11,  /**< Raw IMU data (uncalibrated) */
    BBOX_MSG_MAG            = 0x12,  /**< Magnetometer data */
    BBOX_MSG_BARO           = 0x13,  /**< Barometer data */
    BBOX_MSG_GPS            = 0x20,  /**< GPS position data */
    BBOX_MSG_GPS_RAW        = 0x21,  /**< Raw GPS data */
    BBOX_MSG_GPS_VEL        = 0x22,  /**< GPS velocity data */
    BBOX_MSG_RANGEFINDER    = 0x30,  /**< Rangefinder/Lidar data */
    BBOX_MSG_OPTICAL_FLOW   = 0x31,  /**< Optical flow data */
    BBOX_MSG_AIRSPEED       = 0x32,  /**< Airspeed sensor data */
    
    /* Control messages (0x40-0x6F) */
    BBOX_MSG_ATTITUDE       = 0x40,  /**< Attitude (roll/pitch/yaw) */
    BBOX_MSG_ATTITUDE_TARGET = 0x41, /**< Target attitude */
    BBOX_MSG_RATE           = 0x42,  /**< Angular rates */
    BBOX_MSG_RATE_TARGET    = 0x43,  /**< Target angular rates */
    BBOX_MSG_PID_ROLL       = 0x50,  /**< Roll PID state */
    BBOX_MSG_PID_PITCH      = 0x51,  /**< Pitch PID state */
    BBOX_MSG_PID_YAW        = 0x52,  /**< Yaw PID state */
    BBOX_MSG_PID_ALT        = 0x53,  /**< Altitude PID state */
    BBOX_MSG_PID_POS        = 0x54,  /**< Position PID state */
    BBOX_MSG_RC_INPUT       = 0x60,  /**< RC input channels */
    BBOX_MSG_RC_OUTPUT      = 0x61,  /**< RC output/servo channels */
    
    /* Navigation messages (0x70-0x9F) */
    BBOX_MSG_LOCAL_POS      = 0x70,  /**< Local position (NED) */
    BBOX_MSG_GLOBAL_POS     = 0x71,  /**< Global position (lat/lon/alt) */
    BBOX_MSG_VELOCITY       = 0x72,  /**< Velocity (NED) */
    BBOX_MSG_ACCELERATION   = 0x73,  /**< Acceleration (NED) */
    BBOX_MSG_ESTIMATOR      = 0x74,  /**< Estimator status */
    BBOX_MSG_MISSION        = 0x80,  /**< Mission item */
    BBOX_MSG_WAYPOINT       = 0x81,  /**< Waypoint data */
    BBOX_MSG_FENCE          = 0x82,  /**< Geofence data */
    
    /* Power/Motor messages (0xA0-0xCF) */
    BBOX_MSG_MOTOR          = 0xA0,  /**< Motor outputs (all motors) */
    BBOX_MSG_MOTOR_STATUS   = 0xA1,  /**< Motor status (RPM, temp) */
    BBOX_MSG_ESC            = 0xA2,  /**< ESC telemetry */
    BBOX_MSG_BATTERY        = 0xB0,  /**< Battery status */
    BBOX_MSG_POWER          = 0xB1,  /**< Power system status */
    BBOX_MSG_CURRENT        = 0xB2,  /**< Current sensor data */
    
    /* User-defined messages (0xD0-0xFF) */
    BBOX_MSG_USER_0         = 0xD0,  /**< User-defined message 0 */
    BBOX_MSG_USER_1         = 0xD1,  /**< User-defined message 1 */
    BBOX_MSG_USER_2         = 0xD2,  /**< User-defined message 2 */
    BBOX_MSG_USER_3         = 0xD3,  /**< User-defined message 3 */
    BBOX_MSG_TEXT           = 0xFE,  /**< Text log message */
    BBOX_MSG_CUSTOM         = 0xFF,  /**< Custom binary data */
} bbox_msg_id_t;

/*******************************************************************************
 * IMU Messages
 ******************************************************************************/

/**
 * @brief IMU sensor data (calibrated)
 * 
 * Contains calibrated accelerometer and gyroscope data.
 * Units: acceleration in m/s², angular rate in rad/s
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float accel_x;            /**< X acceleration (m/s²) */
    float accel_y;            /**< Y acceleration (m/s²) */
    float accel_z;            /**< Z acceleration (m/s²) */
    float gyro_x;             /**< X angular rate (rad/s) */
    float gyro_y;             /**< Y angular rate (rad/s) */
    float gyro_z;             /**< Z angular rate (rad/s) */
    float temperature;        /**< Sensor temperature (°C) */
    uint8_t imu_id;           /**< IMU instance ID (for multi-IMU) */
} bbox_msg_imu_t;

/**
 * @brief Raw IMU sensor data (uncalibrated)
 * 
 * Contains raw sensor readings before calibration.
 * Units: raw ADC counts or sensor-specific units
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    int16_t accel_x_raw;      /**< Raw X acceleration */
    int16_t accel_y_raw;      /**< Raw Y acceleration */
    int16_t accel_z_raw;      /**< Raw Z acceleration */
    int16_t gyro_x_raw;       /**< Raw X angular rate */
    int16_t gyro_y_raw;       /**< Raw Y angular rate */
    int16_t gyro_z_raw;       /**< Raw Z angular rate */
    int16_t temperature_raw;  /**< Raw temperature */
    uint8_t imu_id;           /**< IMU instance ID */
} bbox_msg_imu_raw_t;

/**
 * @brief Magnetometer data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float mag_x;              /**< X magnetic field (Gauss) */
    float mag_y;              /**< Y magnetic field (Gauss) */
    float mag_z;              /**< Z magnetic field (Gauss) */
    float temperature;        /**< Sensor temperature (°C) */
    uint8_t mag_id;           /**< Magnetometer instance ID */
} bbox_msg_mag_t;

/**
 * @brief Barometer data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float pressure;           /**< Pressure (Pa) */
    float altitude;           /**< Altitude (m) above sea level */
    float temperature;        /**< Sensor temperature (°C) */
    uint8_t baro_id;          /**< Barometer instance ID */
} bbox_msg_baro_t;

/*******************************************************************************
 * GPS Messages
 ******************************************************************************/

/**
 * @brief GPS fix type
 */
typedef enum {
    GPS_FIX_NONE = 0,         /**< No fix */
    GPS_FIX_2D = 2,           /**< 2D fix */
    GPS_FIX_3D = 3,           /**< 3D fix */
    GPS_FIX_DGPS = 4,         /**< Differential GPS */
    GPS_FIX_RTK_FLOAT = 5,    /**< RTK float */
    GPS_FIX_RTK_FIXED = 6,    /**< RTK fixed */
} bbox_gps_fix_t;

/**
 * @brief GPS position data
 * 
 * Contains processed GPS position with accuracy estimates.
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    int32_t latitude;         /**< Latitude (degrees * 1e7) */
    int32_t longitude;        /**< Longitude (degrees * 1e7) */
    int32_t altitude_msl;     /**< Altitude above MSL (mm) */
    int32_t altitude_agl;     /**< Altitude above ground (mm) */
    uint16_t hdop;            /**< Horizontal DOP * 100 */
    uint16_t vdop;            /**< Vertical DOP * 100 */
    uint16_t speed_ground;    /**< Ground speed (cm/s) */
    int16_t course;           /**< Course over ground (degrees * 100) */
    uint8_t fix_type;         /**< Fix type (bbox_gps_fix_t) */
    uint8_t satellites;       /**< Number of satellites used */
    uint16_t accuracy_h;      /**< Horizontal accuracy (mm) */
    uint16_t accuracy_v;      /**< Vertical accuracy (mm) */
} bbox_msg_gps_t;

/**
 * @brief GPS velocity data
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    int16_t vel_n;            /**< North velocity (cm/s) */
    int16_t vel_e;            /**< East velocity (cm/s) */
    int16_t vel_d;            /**< Down velocity (cm/s) */
    uint16_t speed_accuracy;  /**< Speed accuracy (cm/s) */
} bbox_msg_gps_vel_t;

/*******************************************************************************
 * Attitude/Control Messages
 ******************************************************************************/

/**
 * @brief Attitude data (Euler angles)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float roll;               /**< Roll angle (rad) */
    float pitch;              /**< Pitch angle (rad) */
    float yaw;                /**< Yaw angle (rad) */
    float rollspeed;          /**< Roll rate (rad/s) */
    float pitchspeed;         /**< Pitch rate (rad/s) */
    float yawspeed;           /**< Yaw rate (rad/s) */
} bbox_msg_attitude_t;

/**
 * @brief Attitude quaternion (alternative representation)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float q0;                 /**< Quaternion w component */
    float q1;                 /**< Quaternion x component */
    float q2;                 /**< Quaternion y component */
    float q3;                 /**< Quaternion z component */
} bbox_msg_attitude_quat_t;

/**
 * @brief PID controller state
 * 
 * Captures the internal state of a PID controller for tuning analysis.
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float setpoint;           /**< Target setpoint */
    float measured;           /**< Measured value */
    float error;              /**< Error (setpoint - measured) */
    float p_term;             /**< Proportional term output */
    float i_term;             /**< Integral term output */
    float d_term;             /**< Derivative term output */
    float ff_term;            /**< Feed-forward term output */
    float output;             /**< Total controller output */
    uint8_t axis;             /**< Axis ID (0=roll, 1=pitch, 2=yaw, 3=alt) */
} bbox_msg_pid_t;

/**
 * @brief RC input channels
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t channels[16];    /**< RC channel values (1000-2000 µs) */
    uint8_t channel_count;    /**< Number of valid channels */
    uint8_t rssi;             /**< Signal strength (0-100%) */
    uint8_t failsafe;         /**< Failsafe active flag */
} bbox_msg_rc_input_t;

/**
 * @brief RC/Servo output channels
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t channels[16];    /**< Output channel values (1000-2000 µs) */
    uint8_t channel_count;    /**< Number of active channels */
} bbox_msg_rc_output_t;

/*******************************************************************************
 * Motor/Power Messages
 ******************************************************************************/

/**
 * @brief Motor output data
 * 
 * Contains commanded motor outputs for up to 8 motors.
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t motor[8];        /**< Motor outputs (0-10000 = 0-100%) */
    uint8_t motor_count;      /**< Number of active motors */
    uint8_t armed;            /**< Armed state */
} bbox_msg_motor_t;

/**
 * @brief ESC telemetry data (per motor)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t rpm;             /**< Motor RPM / 10 */
    uint16_t voltage;         /**< Voltage (mV) */
    uint16_t current;         /**< Current (mA) */
    int8_t temperature;       /**< Temperature (°C) */
    uint8_t motor_id;         /**< Motor index */
} bbox_msg_esc_t;

/**
 * @brief Battery status
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t voltage;         /**< Pack voltage (mV) */
    int32_t current;          /**< Current (mA, negative = discharging) */
    int32_t consumed;         /**< Consumed capacity (mAh) */
    uint8_t remaining;        /**< Remaining capacity (0-100%) */
    uint8_t cell_count;       /**< Number of cells */
    uint16_t cell_voltage[6]; /**< Individual cell voltages (mV) */
    int8_t temperature;       /**< Battery temperature (°C) */
    uint8_t battery_id;       /**< Battery instance ID */
} bbox_msg_battery_t;

/*******************************************************************************
 * Navigation Messages
 ******************************************************************************/

/**
 * @brief Local position (NED frame)
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    float x;                  /**< X position (m) North */
    float y;                  /**< Y position (m) East */
    float z;                  /**< Z position (m) Down */
    float vx;                 /**< X velocity (m/s) */
    float vy;                 /**< Y velocity (m/s) */
    float vz;                 /**< Z velocity (m/s) */
    float ax;                 /**< X acceleration (m/s²) */
    float ay;                 /**< Y acceleration (m/s²) */
    float az;                 /**< Z acceleration (m/s²) */
    uint8_t xy_valid;         /**< XY position valid */
    uint8_t z_valid;          /**< Z position valid */
    uint8_t v_xy_valid;       /**< XY velocity valid */
    uint8_t v_z_valid;        /**< Z velocity valid */
} bbox_msg_local_pos_t;

/*******************************************************************************
 * System Messages
 ******************************************************************************/

/**
 * @brief Flight mode
 */
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
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint8_t flight_mode;      /**< Current flight mode */
    uint8_t armed;            /**< Armed state */
    uint8_t failsafe;         /**< Failsafe state */
    uint8_t gps_ok;           /**< GPS health */
    uint8_t imu_ok;           /**< IMU health */
    uint8_t baro_ok;          /**< Barometer health */
    uint8_t mag_ok;           /**< Magnetometer health */
    uint8_t rc_ok;            /**< RC link health */
    uint16_t cpu_load;        /**< CPU load (0-1000 = 0-100%) */
    uint32_t free_heap;       /**< Free heap memory (bytes) */
    uint16_t loop_rate;       /**< Main loop rate (Hz) */
} bbox_msg_status_t;

/**
 * @brief Event marker
 */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;    /**< Timestamp in microseconds */
    uint16_t event_id;        /**< Event identifier */
    uint8_t severity;         /**< Severity (0=info, 1=warn, 2=error, 3=critical) */
    uint8_t data[8];          /**< Event-specific data */
} bbox_msg_event_t;

/*******************************************************************************
 * Message Size Lookup
 ******************************************************************************/

/**
 * @brief Get the size of a message type
 * @param msg_id Message type ID
 * @return Size in bytes, or 0 if unknown
 */
static inline size_t bbox_msg_get_size(bbox_msg_id_t msg_id)
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
 * @param msg_id Message type ID
 * @return Message name string
 */
static inline const char* bbox_msg_get_name(bbox_msg_id_t msg_id)
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
