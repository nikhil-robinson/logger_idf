/**
 * @file main.c
 * @brief Blackbox Logger Example - ArduPilot DataFlash Format on SPIFFS
 *
 * This example demonstrates structured flight data logging using the
 * ArduPilot DataFlash (.bin) format stored on SPIFFS flash storage.
 *
 * ArduPilot DataFlash Format Features:
 * - Compatible with Mission Planner log analyzer
 * - Works with MAVExplorer and other ArduPilot tools
 * - Standard .bin file extension
 * - Self-describing format with FMT messages
 *
 * Compatible Analysis Tools:
 * - Mission Planner (Windows): Log Browser, Graph This
 * - MAVExplorer (Cross-platform): Python-based analysis
 * - APM Planner 2.0 (Cross-platform)
 * - dronekit-la (Command line)
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

static const char *TAG = "ARDUPILOT_EXAMPLE";

/* Simulated vehicle state */
typedef struct {
    float roll;         /* radians */
    float pitch;        /* radians */
    float yaw;          /* radians */
    float altitude;     /* meters */
    int32_t lat;        /* degrees * 1e7 */
    int32_t lon;        /* degrees * 1e7 */
    float airspeed;     /* m/s */
    float groundspeed;  /* m/s */
    uint8_t armed;      /* 0=disarmed, 1=armed */
} sim_vehicle_state_t;

static sim_vehicle_state_t s_vehicle = {
    .lat = 377490000,   /* 37.749° */
    .lon = -1224194000, /* -122.4194° */
    .altitude = 100.0f,
    .armed = 0
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
                 (unsigned)total, (unsigned)used, 100.0f * used / total);
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
 * @brief Simulate IMU sensor data (MPU6000-style)
 */
static void simulate_imu(bbox_msg_imu_t *imu)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;
    float noise = ((esp_random() % 200) - 100) / 2000.0f;

    imu->timestamp_us = (uint64_t)now_us;

    /* Gyroscope (rad/s) - gentle oscillation with noise */
    imu->gyro_x = sinf(t * 0.5f) * 0.05f + noise;
    imu->gyro_y = cosf(t * 0.7f) * 0.04f + noise;
    imu->gyro_z = sinf(t * 0.3f) * 0.02f + noise;

    /* Accelerometer (m/s²) - gravity + vibration */
    imu->accel_x = noise * 0.5f;
    imu->accel_y = noise * 0.5f;
    imu->accel_z = -9.81f + noise * 0.3f;

    /* Temperature (°C) */
    imu->temp = 35.0f + sinf(t * 0.01f) * 2.0f;

    /* Update vehicle attitude from gyros */
    s_vehicle.roll += imu->gyro_x * 0.01f;
    s_vehicle.pitch += imu->gyro_y * 0.01f;
    s_vehicle.yaw += imu->gyro_z * 0.01f;

    /* Wrap yaw to -PI to PI */
    while (s_vehicle.yaw > M_PI) s_vehicle.yaw -= 2 * M_PI;
    while (s_vehicle.yaw < -M_PI) s_vehicle.yaw += 2 * M_PI;
}

/**
 * @brief Simulate GPS data (uBlox-style)
 */
static void simulate_gps(bbox_msg_gps_t *gps)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    /* Simulate circular flight pattern */
    float radius = 0.0005f;  /* ~55 meters */
    float lat_offset = radius * sinf(t * 0.05f);
    float lon_offset = radius * cosf(t * 0.05f);

    gps->timestamp_us = (uint64_t)now_us;
    gps->lat = s_vehicle.lat + (int32_t)(lat_offset * 1e7);
    gps->lon = s_vehicle.lon + (int32_t)(lon_offset * 1e7);
    gps->alt_mm = (int32_t)(s_vehicle.altitude * 1000);
    gps->hdop = 90;   /* 0.9 - excellent */
    gps->vdop = 120;  /* 1.2 - good */
    gps->satellites = 14;
    gps->fix_type = 3;  /* 3D fix */
    gps->flags = 0x01;  /* Valid position */

    /* Update groundspeed from circular motion */
    s_vehicle.groundspeed = 2 * M_PI * radius * 111320.0f * 0.05f;  /* m/s */
}

/**
 * @brief Simulate barometer data (MS5611-style)
 */
static void simulate_baro(bbox_msg_baro_t *baro)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;
    float noise = ((esp_random() % 100) - 50) / 1000.0f;

    baro->timestamp_us = (uint64_t)now_us;

    /* Pressure at altitude (simplified barometric formula) */
    float altitude = s_vehicle.altitude + sinf(t * 0.1f) * 2.0f;  /* Small altitude variation */
    baro->pressure_pa = 101325.0f * powf(1 - 0.0000225577f * altitude, 5.25588f);
    baro->pressure_pa += noise * 10.0f;

    /* Temperature */
    baro->temp_c = 20.0f - 0.0065f * altitude + noise;

    /* Calculated altitude */
    baro->altitude_m = altitude;
}

/**
 * @brief Simulate magnetometer data (HMC5883-style)
 */
static void simulate_mag(bbox_msg_mag_t *mag)
{
    int64_t now_us = esp_timer_get_time();
    float noise = ((esp_random() % 100) - 50) / 500.0f;

    /* Earth's magnetic field in body frame (depends on heading) */
    float mag_north = 200.0f;  /* ~20 uT horizontal */
    float mag_down = 400.0f;   /* ~40 uT vertical (Northern hemisphere) */

    mag->timestamp_us = (uint64_t)now_us;
    mag->mag_x = mag_north * cosf(s_vehicle.yaw) + noise * 5.0f;
    mag->mag_y = mag_north * sinf(s_vehicle.yaw) + noise * 5.0f;
    mag->mag_z = mag_down + noise * 5.0f;
}

/**
 * @brief Simulate attitude estimate (EKF output)
 */
static void simulate_attitude(bbox_msg_attitude_t *att)
{
    att->timestamp_us = (uint64_t)esp_timer_get_time();
    att->roll = s_vehicle.roll;
    att->pitch = s_vehicle.pitch;
    att->yaw = s_vehicle.yaw;
    att->roll_rate = 0.0f;   /* Would come from filtered gyro */
    att->pitch_rate = 0.0f;
    att->yaw_rate = 0.0f;
}

/**
 * @brief Simulate motor outputs (quadcopter X-frame)
 */
static void simulate_motors(bbox_msg_motor_t *motor)
{
    float t = esp_timer_get_time() / 1000000.0f;

    /* Base throttle with small variation */
    float throttle = 0.45f + 0.05f * sinf(t * 0.2f);

    /* Mix in attitude corrections */
    float roll_mix = s_vehicle.roll * 0.1f;
    float pitch_mix = s_vehicle.pitch * 0.1f;
    float yaw_mix = 0.02f * sinf(t * 0.5f);

    motor->timestamp_us = (uint64_t)esp_timer_get_time();

    /* X-frame motor mixing (ArduCopter order) */
    motor->motor[0] = (uint16_t)((throttle - roll_mix + pitch_mix + yaw_mix) * 1000 + 1000);  /* Front Right CW */
    motor->motor[1] = (uint16_t)((throttle - roll_mix - pitch_mix - yaw_mix) * 1000 + 1000);  /* Rear Right CCW */
    motor->motor[2] = (uint16_t)((throttle + roll_mix - pitch_mix + yaw_mix) * 1000 + 1000);  /* Rear Left CW */
    motor->motor[3] = (uint16_t)((throttle + roll_mix + pitch_mix - yaw_mix) * 1000 + 1000);  /* Front Left CCW */
    motor->motor[4] = 0;
    motor->motor[5] = 0;
    motor->motor[6] = 0;
    motor->motor[7] = 0;
}

/**
 * @brief Simulate battery status
 */
static void simulate_battery(bbox_msg_battery_t *bat)
{
    static float capacity_consumed = 0;
    int64_t now_us = esp_timer_get_time();

    /* Simulate 4S LiPo battery (14.8V nominal) */
    float voltage_base = 15.8f;  /* Freshly charged */
    float discharge_rate = 0.00001f;  /* Slow discharge for demo */

    capacity_consumed += discharge_rate;
    if (capacity_consumed > 2000) capacity_consumed = 0;  /* Reset for demo */

    float voltage = voltage_base - (capacity_consumed / 2000.0f) * 2.0f;

    bat->timestamp_us = (uint64_t)now_us;
    bat->voltage_mv = (uint32_t)(voltage * 1000);
    bat->current_ma = (int32_t)(s_vehicle.armed ? 15000 + (esp_random() % 2000) : 500);
    bat->consumed_mah = (uint32_t)capacity_consumed;
    bat->remaining_pct = (uint8_t)(100 - (capacity_consumed / 20));
    bat->temp_c = (int8_t)(35 + (s_vehicle.armed ? 10 : 0));
    bat->cell_count = 4;
    bat->flags = s_vehicle.armed ? 0x01 : 0x00;
}

/**
 * @brief Simulate RC input
 */
static void simulate_rc_input(bbox_msg_rc_input_t *rc)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    rc->timestamp_us = (uint64_t)now_us;

    /* Center position with small stick movements */
    rc->channels[0] = 1500 + (int16_t)(sinf(t * 0.3f) * 50);   /* Roll */
    rc->channels[1] = 1500 + (int16_t)(cosf(t * 0.4f) * 30);   /* Pitch */
    rc->channels[2] = s_vehicle.armed ? 1400 : 1000;           /* Throttle */
    rc->channels[3] = 1500 + (int16_t)(sinf(t * 0.2f) * 20);   /* Yaw */
    rc->channels[4] = s_vehicle.armed ? 1800 : 1200;           /* Arm switch */
    rc->channels[5] = 1500;  /* Mode switch - Stabilize */
    rc->channels[6] = 1500;  /* Aux 1 */
    rc->channels[7] = 1500;  /* Aux 2 */

    rc->channel_count = 8;
    rc->rssi = 95;
    rc->flags = 0x01;  /* Valid signal */
}

/**
 * @brief High-speed sensor logging task (100Hz IMU, 50Hz others)
 */
static void sensor_logging_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Sensor logging task started (ArduPilot DataFlash format)");

    bbox_msg_imu_t imu;
    bbox_msg_gps_t gps;
    bbox_msg_baro_t baro;
    bbox_msg_mag_t mag;
    bbox_msg_attitude_t att;
    bbox_msg_motor_t motor;
    bbox_msg_battery_t battery;
    bbox_msg_rc_input_t rc;

    int loop_count = 0;

    while (1)
    {
        /* IMU at 100Hz */
        simulate_imu(&imu);
        BLACKBOX_LOG_IMU(&imu);

        /* Other sensors at 10Hz */
        if (loop_count % 10 == 0)
        {
            simulate_gps(&gps);
            BLACKBOX_LOG_GPS(&gps);

            simulate_baro(&baro);
            blackbox_log_baro(&baro);

            simulate_mag(&mag);
            blackbox_log_mag(&mag);

            simulate_attitude(&att);
            BLACKBOX_LOG_ATTITUDE(&att);

            simulate_motors(&motor);
            BLACKBOX_LOG_MOTOR(&motor);

            simulate_battery(&battery);
            BLACKBOX_LOG_BATTERY(&battery);

            simulate_rc_input(&rc);
            blackbox_log_rc_input(&rc);
        }

        loop_count++;

        /* 100Hz = 10ms period */
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/**
 * @brief Status reporting task
 */
static void status_task(void *pvParameters)
{
    blackbox_stats_t stats;

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));

        if (blackbox_get_stats(&stats) == ESP_OK)
        {
            ESP_LOGI(TAG, "=== ArduPilot Log Stats ===");
            ESP_LOGI(TAG, "Messages: %llu logged, %llu dropped",
                     (unsigned long long)stats.messages_logged,
                     (unsigned long long)stats.messages_dropped);
            ESP_LOGI(TAG, "Bytes written: %llu, Files: %u",
                     (unsigned long long)stats.bytes_written,
                     (unsigned)stats.files_created);
            ESP_LOGI(TAG, "Vehicle: armed=%d, alt=%.1fm, hdg=%.1f°",
                     s_vehicle.armed,
                     s_vehicle.altitude,
                     s_vehicle.yaw * 180.0f / M_PI);
        }

        /* Toggle armed state every 30 seconds for demo */
        static int toggle_count = 0;
        if (++toggle_count >= 6)
        {
            s_vehicle.armed = !s_vehicle.armed;
            toggle_count = 0;
            ESP_LOGW(TAG, "Vehicle %s", s_vehicle.armed ? "ARMED" : "DISARMED");

            /* Log arm/disarm event */
            BLACKBOX_LOG_INFO(TAG, "Vehicle %s at alt=%.1fm",
                             s_vehicle.armed ? "ARMED" : "DISARMED",
                             s_vehicle.altitude);
        }
    }
}

/**
 * @brief Main application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  Blackbox ArduPilot DataFlash Example");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Format: ArduPilot DataFlash (.bin)");
    ESP_LOGI(TAG, "Storage: SPIFFS (internal flash)");
    ESP_LOGI(TAG, "");

    /* Step 1: Initialize SPIFFS */
    esp_err_t ret = init_spiffs();
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "SPIFFS init failed, aborting");
        return;
    }

    /* Step 2: Configure blackbox logger for ArduPilot format */
    blackbox_config_t config;
    blackbox_get_default_config(&config);

    config.root_path = "/spiffs/logs";
    config.file_prefix = "ardu";
    config.log_format = BLACKBOX_FORMAT_ARDUPILOT;  /* ArduPilot DataFlash format */
    config.encrypt = false;  /* No encryption for compatibility */
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

    ESP_LOGI(TAG, "Logger initialized - ArduPilot DataFlash format");
    ESP_LOGI(TAG, "Log files: %s/ardu*.bin", config.root_path);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Compatible tools:");
    ESP_LOGI(TAG, "  - Mission Planner (Windows)");
    ESP_LOGI(TAG, "  - MAVExplorer (mavlogdump.py)");
    ESP_LOGI(TAG, "  - APM Planner 2.0");
    ESP_LOGI(TAG, "");

    /* Step 3: Log startup message */
    BLACKBOX_LOG_INFO(TAG, "ArduPilot format logging started");
    BLACKBOX_LOG_INFO(TAG, "Simulating quadcopter flight data");

    /* Step 4: Create logging tasks */
    xTaskCreate(sensor_logging_task, "sensors", 4096, NULL, 5, NULL);
    xTaskCreate(status_task, "status", 4096, NULL, 3, NULL);

    ESP_LOGI(TAG, "Logging tasks started");
    ESP_LOGI(TAG, "Press Ctrl+C or reset to stop and examine logs");
}
