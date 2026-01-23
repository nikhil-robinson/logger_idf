/**
 * @file main.c
 * @brief Blackbox Logger Example - PX4 ULog Format on SPIFFS
 *
 * This example demonstrates structured flight data logging using the
 * PX4 ULog (.ulg) format stored on SPIFFS internal flash storage.
 *
 * PX4 ULog Format Features:
 * - Self-describing binary format with message definitions
 * - Compatible with PX4 ecosystem tools
 * - Efficient binary encoding
 * - Supports nested data types
 *
 * Compatible Analysis Tools:
 * - QGroundControl: Built-in log analyzer
 * - FlightPlot: Java-based flight log analyzer
 * - PlotJuggler: Real-time plotting (with PX4 plugin)
 * - pyulog: Python library for ULog parsing
 *
 * @note Ensure you have a SPIFFS partition defined in your partition table.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_err.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "blackbox.h"
#include "blackbox_messages.h"

static const char *TAG = "PX4_ULOG_EXAMPLE";

/* Simulated vehicle state */
typedef struct {
    float roll;         /* radians */
    float pitch;        /* radians */
    float yaw;          /* radians */
    float altitude;     /* meters AGL */
    float alt_amsl;     /* meters AMSL */
    int32_t lat;        /* degrees * 1e7 */
    int32_t lon;        /* degrees * 1e7 */
    float vx, vy, vz;   /* NED velocities m/s */
    uint8_t nav_state;  /* PX4 navigation state */
    uint8_t arming_state;
} sim_px4_state_t;

static sim_px4_state_t s_px4 = {
    .lat = 472683300,   /* 47.26833° (Zurich, PX4 home) */
    .lon = 85340900,    /* 8.53409° */
    .altitude = 50.0f,
    .alt_amsl = 458.0f, /* Zurich elevation + 50m */
    .nav_state = 0,     /* MANUAL */
    .arming_state = 0   /* DISARMED */
};

/**
 * @brief Initialize SPIFFS filesystem
 */
static esp_err_t init_spiffs(void)
{
    ESP_LOGI(TAG, "Initializing SPIFFS filesystem...");

    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK)
    {
        if (ret == ESP_FAIL)
        {
            ESP_LOGE(TAG, "Failed to mount or format SPIFFS");
        }
        else if (ret == ESP_ERR_NOT_FOUND)
        {
            ESP_LOGE(TAG, "SPIFFS partition not found - check partitions.csv");
        }
        else
        {
            ESP_LOGE(TAG, "SPIFFS init failed: %s", esp_err_to_name(ret));
        }
        return ret;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK)
    {
        ESP_LOGI(TAG, "SPIFFS mounted: total=%u bytes, used=%u bytes (%.1f%%)",
                 (unsigned)total, (unsigned)used,
                 total > 0 ? 100.0f * used / total : 0);
    }

    return ESP_OK;
}

/**
 * @brief Deinitialize SPIFFS
 */
static void deinit_spiffs(void)
{
    esp_vfs_spiffs_unregister(NULL);
    ESP_LOGI(TAG, "SPIFFS unmounted");
}

/**
 * @brief Simulate IMU sensor data (PX4 sensor_combined style)
 */
static void simulate_imu(bbox_msg_imu_t *imu)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    /* High-frequency noise simulation */
    float noise_gyro = ((esp_random() % 200) - 100) / 5000.0f;
    float noise_accel = ((esp_random() % 200) - 100) / 1000.0f;

    imu->timestamp_us = (uint64_t)now_us;

    /* Gyroscope (rad/s) - PX4 uses FRD frame */
    imu->gyro_x = sinf(t * 0.5f) * 0.03f + noise_gyro;
    imu->gyro_y = cosf(t * 0.6f) * 0.025f + noise_gyro;
    imu->gyro_z = sinf(t * 0.2f) * 0.01f + noise_gyro;

    /* Accelerometer (m/s²) - gravity in FRD is +Z */
    imu->accel_x = noise_accel * 0.3f;
    imu->accel_y = noise_accel * 0.3f;
    imu->accel_z = 9.81f + noise_accel * 0.1f;  /* PX4 FRD: gravity is positive Z */

    /* Temperature from IMU */
    imu->temp = 42.0f + sinf(t * 0.005f) * 3.0f;

    /* Update vehicle attitude from integrated gyros */
    float dt = 0.01f;  /* 100Hz */
    s_px4.roll += imu->gyro_x * dt;
    s_px4.pitch += imu->gyro_y * dt;
    s_px4.yaw += imu->gyro_z * dt;

    /* Normalize yaw to 0-2π */
    while (s_px4.yaw > 2 * M_PI) s_px4.yaw -= 2 * M_PI;
    while (s_px4.yaw < 0) s_px4.yaw += 2 * M_PI;
}

/**
 * @brief Simulate GPS data (PX4 vehicle_gps_position style)
 */
static void simulate_gps(bbox_msg_gps_t *gps)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    /* Simulate figure-8 flight pattern */
    float radius = 0.0003f;  /* ~33 meters */
    float lat_offset = radius * sinf(t * 0.08f);
    float lon_offset = radius * sinf(t * 0.16f) * 0.5f;

    gps->timestamp_us = (uint64_t)now_us;
    gps->lat = s_px4.lat + (int32_t)(lat_offset * 1e7);
    gps->lon = s_px4.lon + (int32_t)(lon_offset * 1e7);
    gps->alt_mm = (int32_t)(s_px4.alt_amsl * 1000);

    /* GPS quality metrics */
    gps->hdop = 80;   /* 0.8 - excellent */
    gps->vdop = 100;  /* 1.0 - very good */
    gps->satellites = 16;
    gps->fix_type = 3;  /* 3D RTK fixed would be 6 */
    gps->flags = 0x03;  /* Valid position and velocity */

    /* Update NED velocities */
    float omega = 0.08f;
    s_px4.vx = radius * 1e7 * omega * cosf(t * omega) / 111320.0f;  /* North velocity */
    s_px4.vy = radius * 0.5f * 1e7 * 2 * omega * cosf(t * 2 * omega) / (111320.0f * cosf(s_px4.lat / 1e7 * M_PI / 180));
    s_px4.vz = 0.1f * sinf(t * 0.1f);  /* Small vertical movement */
}

/**
 * @brief Simulate barometer data (PX4 sensor_baro style)
 */
static void simulate_baro(bbox_msg_baro_t *baro)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;
    float noise = ((esp_random() % 100) - 50) / 2000.0f;

    baro->timestamp_us = (uint64_t)now_us;

    /* Simulate altitude variation */
    float alt_variation = sinf(t * 0.15f) * 3.0f;  /* ±3m oscillation */
    float current_alt = s_px4.alt_amsl + alt_variation;

    /* ISA atmospheric model */
    baro->pressure_pa = 101325.0f * powf(1 - 0.0000225577f * current_alt, 5.25588f);
    baro->pressure_pa += noise * 5.0f;

    /* Temperature decreases with altitude */
    baro->temp_c = 15.0f - 0.0065f * current_alt + noise * 0.5f;

    baro->altitude_m = current_alt;

    /* Update AGL altitude */
    s_px4.altitude = 50.0f + alt_variation;
}

/**
 * @brief Simulate magnetometer data (PX4 sensor_mag style)
 */
static void simulate_mag(bbox_msg_mag_t *mag)
{
    int64_t now_us = esp_timer_get_time();
    float noise = ((esp_random() % 100) - 50) / 200.0f;

    /* Earth's magnetic field in Zurich (approx) */
    float mag_intensity = 480.0f;  /* ~48 µT total */
    float mag_inclination = 64.0f * M_PI / 180.0f;  /* 64° down */
    float mag_declination = 2.5f * M_PI / 180.0f;   /* 2.5° east */

    /* Rotate by vehicle heading */
    float heading = s_px4.yaw + mag_declination;

    mag->timestamp_us = (uint64_t)now_us;
    mag->mag_x = mag_intensity * cosf(mag_inclination) * cosf(heading) + noise;
    mag->mag_y = mag_intensity * cosf(mag_inclination) * sinf(heading) + noise;
    mag->mag_z = mag_intensity * sinf(mag_inclination) + noise;
}

/**
 * @brief Simulate attitude estimate (PX4 vehicle_attitude style)
 */
static void simulate_attitude(bbox_msg_attitude_t *att)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    att->timestamp_us = (uint64_t)now_us;
    att->roll = s_px4.roll;
    att->pitch = s_px4.pitch;
    att->yaw = s_px4.yaw;

    /* Angular rates (from filtered gyro) */
    att->roll_rate = sinf(t * 0.5f) * 0.03f;
    att->pitch_rate = cosf(t * 0.6f) * 0.025f;
    att->yaw_rate = sinf(t * 0.2f) * 0.01f;
}

/**
 * @brief Simulate PID controller outputs (PX4 rate_ctrl_status style)
 */
static void simulate_pid(bbox_msg_pid_t *pid, uint8_t axis)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;
    float noise = ((esp_random() % 100) - 50) / 1000.0f;

    float actual = (axis == 0) ? s_px4.roll :
                   (axis == 1) ? s_px4.pitch : s_px4.yaw;

    pid->timestamp_us = (uint64_t)now_us;
    pid->axis = axis;
    pid->setpoint = sinf(t * 0.1f * (axis + 1)) * 0.05f;
    pid->error = pid->setpoint - actual;

    /* PX4-style PID gains */
    float kp = (axis < 2) ? 6.5f : 2.8f;
    float ki = (axis < 2) ? 0.5f : 0.35f;
    float kd = (axis < 2) ? 0.002f : 0.0f;

    pid->p_term = pid->error * kp;
    pid->i_term = pid->error * ki * 0.01f;
    pid->d_term = noise * kd * 100.0f;
    pid->output = pid->p_term + pid->i_term - pid->d_term;

    /* Clamp to normalized output */
    if (pid->output > 1.0f) pid->output = 1.0f;
    if (pid->output < -1.0f) pid->output = -1.0f;
}

/**
 * @brief Simulate motor outputs (PX4 actuator_outputs style)
 */
static void simulate_motors(bbox_msg_motor_t *motor)
{
    float t = esp_timer_get_time() / 1000000.0f;

    /* Hover throttle with small variations */
    float throttle = 0.52f + 0.03f * sinf(t * 0.25f);

    /* Control mixing */
    float roll_ctrl = s_px4.roll * 0.15f;
    float pitch_ctrl = s_px4.pitch * 0.15f;
    float yaw_ctrl = 0.01f * sinf(t * 0.3f);

    motor->timestamp_us = (uint64_t)esp_timer_get_time();

    /* PX4 quad-x motor order: FR, RL, FL, RR */
    motor->motor[0] = (uint16_t)((throttle - roll_ctrl - pitch_ctrl - yaw_ctrl) * 1000 + 1000);
    motor->motor[1] = (uint16_t)((throttle + roll_ctrl + pitch_ctrl - yaw_ctrl) * 1000 + 1000);
    motor->motor[2] = (uint16_t)((throttle + roll_ctrl - pitch_ctrl + yaw_ctrl) * 1000 + 1000);
    motor->motor[3] = (uint16_t)((throttle - roll_ctrl + pitch_ctrl + yaw_ctrl) * 1000 + 1000);
    motor->motor[4] = 0;
    motor->motor[5] = 0;
    motor->motor[6] = 0;
    motor->motor[7] = 0;
}

/**
 * @brief Simulate battery status (PX4 battery_status style)
 */
static void simulate_battery(bbox_msg_battery_t *bat)
{
    static float capacity_used = 0;
    int64_t now_us = esp_timer_get_time();

    /* Simulate 6S LiPo (22.2V nominal, PX4 standard) */
    float voltage_full = 25.2f;
    float voltage_empty = 19.8f;
    float discharge_rate = 0.000015f;

    capacity_used += discharge_rate * (s_px4.arming_state > 0 ? 1.0f : 0.1f);
    if (capacity_used > 5000) capacity_used = 0;  /* Reset for demo */

    float soc = 1.0f - (capacity_used / 5000.0f);
    float voltage = voltage_empty + (voltage_full - voltage_empty) * soc;

    bat->timestamp_us = (uint64_t)now_us;
    bat->voltage_mv = (uint32_t)(voltage * 1000);
    bat->current_ma = s_px4.arming_state > 0 ?
                      (int32_t)(20000 + (esp_random() % 5000)) : 800;
    bat->consumed_mah = (uint32_t)capacity_used;
    bat->remaining_pct = (uint8_t)(soc * 100);
    bat->temp_c = (int8_t)(28 + (s_px4.arming_state > 0 ? 15 : 0));
    bat->cell_count = 6;
    bat->flags = (soc < 0.2f) ? 0x02 : 0x01;  /* Warning if low */
}

/**
 * @brief Simulate RC input (PX4 input_rc style)
 */
static void simulate_rc_input(bbox_msg_rc_input_t *rc)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    rc->timestamp_us = (uint64_t)now_us;

    /* Simulate pilot stick inputs */
    rc->channels[0] = 1500 + (int16_t)(sinf(t * 0.25f) * 100);  /* Roll */
    rc->channels[1] = 1500 + (int16_t)(cosf(t * 0.3f) * 80);    /* Pitch */
    rc->channels[2] = s_px4.arming_state ? 1550 : 1000;         /* Throttle */
    rc->channels[3] = 1500 + (int16_t)(sinf(t * 0.15f) * 50);   /* Yaw */
    rc->channels[4] = s_px4.arming_state ? 2000 : 1000;         /* Arm switch */
    rc->channels[5] = 1000 + s_px4.nav_state * 250;             /* Mode (Position=1500) */
    rc->channels[6] = 1500;  /* Return switch */
    rc->channels[7] = 1500;  /* Aux */

    rc->channel_count = 8;
    rc->rssi = 98;
    rc->flags = 0x03;  /* Valid, failsafe not active */
}

/**
 * @brief Simulate ESC telemetry (PX4 esc_status style)
 */
static void simulate_esc(bbox_msg_esc_t *esc)
{
    int64_t now_us = esp_timer_get_time();
    float throttle = 0.52f + 0.03f * sinf(now_us / 1000000.0f * 0.25f);

    esc->timestamp_us = (uint64_t)now_us;
    esc->index = 0;  /* ESC 0-3 status combined */

    if (s_px4.arming_state > 0)
    {
        esc->rpm = (uint32_t)(throttle * 15000);  /* ~15k RPM at hover */
        esc->voltage_mv = 22000 + (esp_random() % 500);
        esc->current_ma = (uint32_t)(throttle * 8000);
        esc->temp_c = (int8_t)(45 + (esp_random() % 10));
    }
    else
    {
        esc->rpm = 0;
        esc->voltage_mv = 22500;
        esc->current_ma = 0;
        esc->temp_c = 25;
    }
    esc->flags = 0x01;
}

/**
 * @brief High-speed sensor logging task (PX4 rates)
 *
 * PX4 logging rates:
 * - sensor_combined (IMU): 250Hz
 * - vehicle_attitude: 250Hz
 * - actuator_outputs: 250Hz
 * - vehicle_gps_position: 10Hz
 * - battery_status: 1Hz
 *
 * We use 100Hz IMU for ESP32 compatibility.
 */
static void sensor_logging_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Sensor logging task started (PX4 ULog format)");

    bbox_msg_imu_t imu;
    bbox_msg_gps_t gps;
    bbox_msg_baro_t baro;
    bbox_msg_mag_t mag;
    bbox_msg_attitude_t att;
    bbox_msg_pid_t pid;
    bbox_msg_motor_t motor;
    bbox_msg_battery_t battery;
    bbox_msg_rc_input_t rc;
    bbox_msg_esc_t esc;

    int loop_count = 0;

    while (1)
    {
        /* IMU + Attitude at 100Hz */
        simulate_imu(&imu);
        BLACKBOX_LOG_IMU(&imu);

        simulate_attitude(&att);
        BLACKBOX_LOG_ATTITUDE(&att);

        /* PID at 50Hz */
        if (loop_count % 2 == 0)
        {
            for (int axis = 0; axis < 3; axis++)
            {
                simulate_pid(&pid, axis);
                BLACKBOX_LOG_PID(BBOX_MSG_PID_ROLL + axis, &pid);
            }
        }

        /* Motors at 50Hz */
        if (loop_count % 2 == 0)
        {
            simulate_motors(&motor);
            BLACKBOX_LOG_MOTOR(&motor);
        }

        /* GPS + Baro + Mag at 10Hz */
        if (loop_count % 10 == 0)
        {
            simulate_gps(&gps);
            BLACKBOX_LOG_GPS(&gps);

            simulate_baro(&baro);
            blackbox_log_baro(&baro);

            simulate_mag(&mag);
            blackbox_log_mag(&mag);

            simulate_rc_input(&rc);
            blackbox_log_rc_input(&rc);

            simulate_esc(&esc);
            blackbox_log_esc(&esc);
        }

        /* Battery at 2Hz */
        if (loop_count % 50 == 0)
        {
            simulate_battery(&battery);
            BLACKBOX_LOG_BATTERY(&battery);
        }

        loop_count++;
        if (loop_count >= 100) loop_count = 0;

        /* 100Hz = 10ms period */
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/**
 * @brief Status and flight mode task
 */
static void status_task(void *pvParameters)
{
    blackbox_stats_t stats;
    static int mode_cycle = 0;

    /* PX4 navigation states for demo */
    const char *nav_states[] = {"MANUAL", "ALTCTL", "POSCTL", "AUTO_LOITER", "AUTO_RTL"};

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));

        if (blackbox_get_stats(&stats) == ESP_OK)
        {
            ESP_LOGI(TAG, "=== PX4 ULog Stats ===");
            ESP_LOGI(TAG, "Messages: %llu logged, %llu dropped",
                     (unsigned long long)stats.messages_logged,
                     (unsigned long long)stats.messages_dropped);
            ESP_LOGI(TAG, "Bytes written: %llu, Files: %u",
                     (unsigned long long)stats.bytes_written,
                     (unsigned)stats.files_created);
            ESP_LOGI(TAG, "State: arm=%d, mode=%s, alt=%.1fm",
                     s_px4.arming_state,
                     nav_states[s_px4.nav_state % 5],
                     s_px4.altitude);
        }

        /* Cycle through flight modes for demo */
        mode_cycle++;

        if (mode_cycle == 3)
        {
            /* Arm after 15 seconds */
            s_px4.arming_state = 1;
            BLACKBOX_LOG_WARN(TAG, "ARMED - Motors enabled");
        }
        else if (mode_cycle == 6)
        {
            /* Switch to Position mode */
            s_px4.nav_state = 2;  /* POSCTL */
            BLACKBOX_LOG_INFO(TAG, "Mode: POSCTL");
        }
        else if (mode_cycle == 9)
        {
            /* Switch to Loiter */
            s_px4.nav_state = 3;  /* AUTO_LOITER */
            BLACKBOX_LOG_INFO(TAG, "Mode: AUTO_LOITER");
        }
        else if (mode_cycle == 12)
        {
            /* RTL */
            s_px4.nav_state = 4;  /* AUTO_RTL */
            BLACKBOX_LOG_WARN(TAG, "Mode: AUTO_RTL - Returning home");
        }
        else if (mode_cycle >= 15)
        {
            /* Land and disarm */
            s_px4.arming_state = 0;
            s_px4.nav_state = 0;
            BLACKBOX_LOG_WARN(TAG, "DISARMED - Landed");
            mode_cycle = 0;  /* Restart cycle */
        }
    }
}

/**
 * @brief Main application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "    Blackbox PX4 ULog Format Example");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Format: PX4 ULog (.ulg)");
    ESP_LOGI(TAG, "Storage: SPIFFS (internal flash)");
    ESP_LOGI(TAG, "");

    /* Step 1: Initialize SPIFFS */
    esp_err_t ret = init_spiffs();
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "SPIFFS init failed, aborting");
        return;
    }

    /* Step 2: Configure blackbox logger for PX4 ULog format */
    blackbox_config_t config;
    blackbox_get_default_config(&config);

    config.root_path = "/spiffs/logs";
    config.file_prefix = "px4_";
    config.log_format = BLACKBOX_FORMAT_PX4_ULOG;  /* PX4 ULog format */
    config.encrypt = false;  /* No encryption for PX4 compatibility */
    config.file_size_limit = 128 * 1024;  /* 128KB per file (SPIFFS constraint) */
    config.buffer_size = 8 * 1024;  /* 8KB ring buffer */
    config.flush_interval_ms = 500;  /* Flush every 500ms */
    config.min_level = BLACKBOX_LOG_LEVEL_INFO;
    config.console_output = true;
    config.file_output = true;

    ESP_LOGI(TAG, "Initializing blackbox logger...");
    ret = blackbox_init(&config);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Blackbox init failed: %s", esp_err_to_name(ret));
        deinit_spiffs();
        return;
    }

    ESP_LOGI(TAG, "Logger initialized - PX4 ULog format");
    ESP_LOGI(TAG, "Log files: %s/px4_*.ulg", config.root_path);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Compatible tools:");
    ESP_LOGI(TAG, "  - QGroundControl (Log Analyzer)");
    ESP_LOGI(TAG, "  - FlightPlot (flightplot.jar)");
    ESP_LOGI(TAG, "  - PlotJuggler (with PX4 plugin)");
    ESP_LOGI(TAG, "  - pyulog (ulog2csv, ulog_info)");
    ESP_LOGI(TAG, "");

    /* Step 3: Log startup messages */
    BLACKBOX_LOG_INFO(TAG, "PX4 ULog format logging started");
    BLACKBOX_LOG_INFO(TAG, "System: ESP32 Blackbox Logger");
    BLACKBOX_LOG_INFO(TAG, "Simulating PX4-style flight data");

    /* Step 4: Create logging tasks */
    xTaskCreate(sensor_logging_task, "px4_sensors", 4096, NULL, 5, NULL);
    xTaskCreate(status_task, "px4_status", 4096, NULL, 3, NULL);

    ESP_LOGI(TAG, "Logging tasks started");
    ESP_LOGI(TAG, "Simulating: ARM -> POSCTL -> LOITER -> RTL -> LAND");
}
