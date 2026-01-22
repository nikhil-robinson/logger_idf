/**
 * @file main.c
 * @brief Blackbox Logger Example - Structured Flight Data Logging
 *
 * This example demonstrates structured data logging with IMU, GPS, attitude,
 * PID, motor, and battery telemetry. Shows how to select between different
 * log formats: BBOX (native), PX4 ULog, and ArduPilot DataFlash.
 *
 * Use Cases:
 * - Drone/quadcopter flight data recording
 * - Robotics sensor fusion debugging
 * - Vehicle telemetry logging
 * - Research data collection
 *
 * Log Format Compatibility:
 * - BBOX (.blackbox): Native format with optional encryption
 * - PX4 ULog (.ulg): Compatible with QGroundControl, FlightPlot, PlotJuggler
 * - ArduPilot (.bin): Compatible with Mission Planner, MAVExplorer
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_spiffs.h"

#include "blackbox.h"
#include "blackbox_messages.h"

static const char *TAG = "FLIGHT_DATA_EXAMPLE";

/* Simulated flight state */
typedef struct {
    float roll;         /* radians */
    float pitch;        /* radians */
    float yaw;          /* radians */
    float altitude;     /* meters */
    float vx, vy, vz;   /* m/s */
    int32_t lat;        /* degrees * 1e7 */
    int32_t lon;        /* degrees * 1e7 */
    uint8_t motor_pwm[4];
} sim_flight_state_t;

static sim_flight_state_t s_flight_state = {0};

/**
 * @brief Initialize SPIFFS for log storage
 */
static esp_err_t init_spiffs(void)
{
    ESP_LOGI(TAG, "Initializing SPIFFS...");

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
            ESP_LOGE(TAG, "Failed to mount SPIFFS");
        }
        else if (ret == ESP_ERR_NOT_FOUND)
        {
            ESP_LOGE(TAG, "SPIFFS partition not found");
        }
        return ret;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK)
    {
        ESP_LOGI(TAG, "SPIFFS: total=%u, used=%u", (unsigned)total, (unsigned)used);
    }

    return ESP_OK;
}

/**
 * @brief Generate simulated IMU data with noise
 */
static void simulate_imu(bbox_msg_imu_t *imu)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    /* Simulate gentle oscillations with noise */
    float noise = ((esp_random() % 100) - 50) / 1000.0f;

    imu->timestamp_us = (uint64_t)now_us;
    imu->gyro_x = sinf(t * 0.5f) * 0.1f + noise;
    imu->gyro_y = cosf(t * 0.7f) * 0.08f + noise;
    imu->gyro_z = sinf(t * 0.3f) * 0.05f + noise;
    imu->accel_x = 0.1f * sinf(t * 2.0f) + noise;
    imu->accel_y = 0.1f * cosf(t * 2.0f) + noise;
    imu->accel_z = -9.81f + 0.05f * sinf(t * 3.0f) + noise;
    imu->temp = 25.0f + 0.5f * sinf(t * 0.1f);

    /* Update simulated state */
    s_flight_state.roll += imu->gyro_x * 0.01f;
    s_flight_state.pitch += imu->gyro_y * 0.01f;
    s_flight_state.yaw += imu->gyro_z * 0.01f;
}

/**
 * @brief Generate simulated GPS data
 */
static void simulate_gps(bbox_msg_gps_t *gps)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;

    /* Simulated position around San Francisco */
    float base_lat = 37.7749f;
    float base_lon = -122.4194f;

    /* Small circular motion */
    float radius = 0.0001f; /* ~11 meters */
    float lat_offset = radius * sinf(t * 0.1f);
    float lon_offset = radius * cosf(t * 0.1f);

    gps->timestamp_us = (uint64_t)now_us;
    gps->lat = (int32_t)((base_lat + lat_offset) * 1e7);
    gps->lon = (int32_t)((base_lon + lon_offset) * 1e7);
    gps->alt_mm = 50000 + (int32_t)(sinf(t * 0.05f) * 1000); /* 50m +/- 1m */
    gps->hdop = 120;  /* 1.2 */
    gps->vdop = 180;  /* 1.8 */
    gps->satellites = 12;
    gps->fix_type = 3;  /* 3D fix */
    gps->flags = 0x01;  /* Valid */

    s_flight_state.lat = gps->lat;
    s_flight_state.lon = gps->lon;
    s_flight_state.altitude = gps->alt_mm / 1000.0f;
}

/**
 * @brief Generate simulated attitude data
 */
static void simulate_attitude(bbox_msg_attitude_t *att)
{
    att->timestamp_us = (uint64_t)esp_timer_get_time();
    att->roll = s_flight_state.roll;
    att->pitch = s_flight_state.pitch;
    att->yaw = s_flight_state.yaw;
    att->roll_rate = 0.0f;
    att->pitch_rate = 0.0f;
    att->yaw_rate = 0.0f;
}

/**
 * @brief Generate simulated PID data for roll axis
 */
static void simulate_pid(bbox_msg_pid_t *pid, uint8_t axis)
{
    int64_t now_us = esp_timer_get_time();
    float t = now_us / 1000000.0f;
    float noise = ((esp_random() % 100) - 50) / 500.0f;

    pid->timestamp_us = (uint64_t)now_us;
    pid->axis = axis;
    pid->setpoint = sinf(t * 0.2f) * 0.1f;  /* Desired angle */
    pid->error = pid->setpoint - (axis == 0 ? s_flight_state.roll :
                                  axis == 1 ? s_flight_state.pitch : s_flight_state.yaw);
    pid->p_term = pid->error * 4.5f;  /* Kp = 4.5 */
    pid->i_term = pid->error * 0.01f * t;  /* Simplified I */
    pid->d_term = noise * 0.5f;  /* Simplified D */
    pid->output = pid->p_term + pid->i_term + pid->d_term;

    /* Clamp output */
    if (pid->output > 1.0f) pid->output = 1.0f;
    if (pid->output < -1.0f) pid->output = -1.0f;
}

/**
 * @brief Generate simulated motor output data
 */
static void simulate_motors(bbox_msg_motor_t *motor)
{
    float throttle_base = 0.5f + 0.1f * sinf(esp_timer_get_time() / 1000000.0f * 0.3f);
    float roll_mix = s_flight_state.roll * 0.1f;
    float pitch_mix = s_flight_state.pitch * 0.1f;

    motor->timestamp_us = (uint64_t)esp_timer_get_time();
    motor->motor[0] = (uint16_t)((throttle_base - roll_mix - pitch_mix) * 2000 + 1000);
    motor->motor[1] = (uint16_t)((throttle_base + roll_mix - pitch_mix) * 2000 + 1000);
    motor->motor[2] = (uint16_t)((throttle_base + roll_mix + pitch_mix) * 2000 + 1000);
    motor->motor[3] = (uint16_t)((throttle_base - roll_mix + pitch_mix) * 2000 + 1000);
    motor->motor[4] = 0;
    motor->motor[5] = 0;
    motor->motor[6] = 0;
    motor->motor[7] = 0;

    /* Update PWM state */
    for (int i = 0; i < 4; i++)
    {
        s_flight_state.motor_pwm[i] = (motor->motor[i] - 1000) / 8; /* Scale to 0-255 */
    }
}

/**
 * @brief Generate simulated battery data
 */
static void simulate_battery(bbox_msg_battery_t *bat)
{
    static float capacity_remaining = 5000.0f;  /* mAh */
    float t = esp_timer_get_time() / 1000000.0f;

    /* Simulate discharge */
    float current_draw = 10.0f + 5.0f * sinf(t * 0.5f); /* 10-15A */
    capacity_remaining -= current_draw * 0.01f / 3600.0f; /* mAh consumed in 10ms */

    if (capacity_remaining < 0) capacity_remaining = 0;

    bat->timestamp_us = (uint64_t)esp_timer_get_time();
    bat->voltage_mv = 14800 - (uint32_t)((5000.0f - capacity_remaining) * 0.5f);  /* Voltage drops with discharge */
    bat->current_ma = (int32_t)(current_draw * 1000);
    bat->capacity_mah = (uint32_t)capacity_remaining;
    bat->remaining_pct = (uint8_t)(capacity_remaining / 50.0f);  /* 5000mAh = 100% */
    bat->cell_count = 4;
    bat->temperature = (int16_t)(35.0f * 100 + sinf(t) * 200);  /* 35°C +/- 2°C in centidegrees */
}

/**
 * @brief High-frequency IMU logging task (100 Hz)
 */
static void imu_logging_task(void *arg)
{
    ESP_LOGI(TAG, "IMU logging task started (100 Hz)");

    bbox_msg_imu_t imu;
    TickType_t last_wake = xTaskGetTickCount();

    while (1)
    {
        simulate_imu(&imu);
        blackbox_log_imu(&imu);

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(10));  /* 100 Hz */
    }
}

/**
 * @brief Medium-frequency sensor logging task (10 Hz)
 */
static void sensor_logging_task(void *arg)
{
    ESP_LOGI(TAG, "Sensor logging task started (10 Hz)");

    bbox_msg_gps_t gps;
    bbox_msg_attitude_t att;
    bbox_msg_motor_t motor;
    bbox_msg_battery_t battery;

    TickType_t last_wake = xTaskGetTickCount();

    while (1)
    {
        /* Log GPS at 10 Hz (typical GPS update rate) */
        simulate_gps(&gps);
        blackbox_log_gps(&gps);

        /* Log attitude at 10 Hz */
        simulate_attitude(&att);
        blackbox_log_attitude(&att);

        /* Log motor outputs at 10 Hz */
        simulate_motors(&motor);
        blackbox_log_motor(&motor);

        /* Log battery at 10 Hz */
        simulate_battery(&battery);
        blackbox_log_battery(&battery);

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(100));  /* 10 Hz */
    }
}

/**
 * @brief PID logging task (50 Hz - matches typical FC PID loop rate)
 */
static void pid_logging_task(void *arg)
{
    ESP_LOGI(TAG, "PID logging task started (50 Hz)");

    bbox_msg_pid_t pid;
    TickType_t last_wake = xTaskGetTickCount();

    while (1)
    {
        /* Log PID for each axis */
        for (uint8_t axis = 0; axis < 3; axis++)
        {
            simulate_pid(&pid, axis);
            /* Use axis ID: BBOX_MSG_PID_ROLL=0x40, PITCH=0x41, YAW=0x42 */
            blackbox_log_pid(BBOX_MSG_PID_ROLL + axis, &pid);
        }

        vTaskDelayUntil(&last_wake, pdMS_TO_TICKS(20));  /* 50 Hz */
    }
}

/**
 * @brief Print log statistics periodically
 */
static void stats_task(void *arg)
{
    ESP_LOGI(TAG, "Stats monitoring task started");

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));

        blackbox_stats_t stats;
        if (blackbox_get_stats(&stats) == ESP_OK)
        {
            ESP_LOGI(TAG, "=== Flight Data Stats ===");
            ESP_LOGI(TAG, "Messages logged: %lu", (unsigned long)stats.messages_logged);
            ESP_LOGI(TAG, "Messages dropped: %lu", (unsigned long)stats.messages_dropped);
            ESP_LOGI(TAG, "Bytes written: %lu", (unsigned long)stats.bytes_written);
            ESP_LOGI(TAG, "Files created: %lu", (unsigned long)stats.files_created);
            ESP_LOGI(TAG, "Format: %s",
                     blackbox_get_log_format() == BLACKBOX_FORMAT_PX4_ULOG ? "PX4 ULog" :
                     blackbox_get_log_format() == BLACKBOX_FORMAT_ARDUPILOT ? "ArduPilot" : "BBOX");
        }
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "Blackbox Structured Flight Data Logger Demo");
    ESP_LOGI(TAG, "===========================================");

    /* Initialize filesystem */
    esp_err_t ret = init_spiffs();
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to initialize SPIFFS, aborting");
        return;
    }

    /* Configure blackbox logger with desired format */
    blackbox_config_t config;
    blackbox_get_default_config(&config);

    config.root_path = "/spiffs/logs";
    config.file_prefix = "flight";
    config.file_size_limit = 256 * 1024;  /* 256KB per file */
    config.buffer_size = 32 * 1024;       /* 32KB ring buffer */
    config.flush_interval_ms = 100;       /* Fast flush for flight data */
    config.min_level = BLACKBOX_LOG_LEVEL_DEBUG;
    config.console_output = false;        /* Reduce console spam */
    config.file_output = true;

    /*
     * Select log format:
     * - BLACKBOX_FORMAT_BBOX     - Native format with optional encryption
     * - BLACKBOX_FORMAT_PX4_ULOG - PX4 ULog format (.ulg)
     * - BLACKBOX_FORMAT_ARDUPILOT - ArduPilot DataFlash format (.bin)
     */
    config.log_format = BLACKBOX_FORMAT_PX4_ULOG;  /* Use PX4 format for this demo */

    ESP_LOGI(TAG, "Initializing blackbox with format: %s",
             config.log_format == BLACKBOX_FORMAT_PX4_ULOG ? "PX4 ULog (.ulg)" :
             config.log_format == BLACKBOX_FORMAT_ARDUPILOT ? "ArduPilot (.bin)" :
             "BBOX Native (.blackbox)");

    ret = blackbox_init(&config);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to initialize blackbox: %s", esp_err_to_name(ret));
        return;
    }

    /* Log startup event */
    BLACKBOX_INFO(TAG, "Flight data logging started - format=%d", config.log_format);

    /* Start high-frequency IMU logging task */
    xTaskCreate(imu_logging_task, "imu_log", 4096, NULL, 5, NULL);

    /* Start medium-frequency sensor logging task */
    xTaskCreate(sensor_logging_task, "sensor_log", 4096, NULL, 4, NULL);

    /* Start PID logging task */
    xTaskCreate(pid_logging_task, "pid_log", 4096, NULL, 4, NULL);

    /* Start stats monitoring task */
    xTaskCreate(stats_task, "stats", 4096, NULL, 2, NULL);

    ESP_LOGI(TAG, "All logging tasks started");
    ESP_LOGI(TAG, "IMU: 100Hz, GPS/Att/Motor/Batt: 10Hz, PID: 50Hz");

    /* Keep main task alive */
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
