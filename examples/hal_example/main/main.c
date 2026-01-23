/**
 * @file main.c
 * @brief Simple example using the new HAL-based Blackbox API
 *
 * Demonstrates basic usage with the ESP-IDF HAL backend.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_spiffs.h"

/* New HAL-based API */
#include "blackbox.h"
#include "hal/blackbox_hal_esp.h"

static const char *TAG = "EXAMPLE";

/* Initialize SPIFFS */
static esp_err_t init_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SPIFFS: %s", esp_err_to_name(ret));
        return ret;
    }

    size_t total = 0, used = 0;
    esp_spiffs_info(NULL, &total, &used);
    ESP_LOGI(TAG, "SPIFFS: %u KB total, %u KB used", 
             (unsigned)(total / 1024), (unsigned)(used / 1024));

    return ESP_OK;
}

void app_main(void)
{
    ESP_LOGI(TAG, "Blackbox HAL Example - v3.0.0");

    /* Initialize SPIFFS filesystem */
    if (init_spiffs() != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS init failed, stopping");
        return;
    }

    /* Get the ESP-IDF HAL implementation */
    const bbox_hal_t *hal = bbox_hal_esp_get();

    /* Configure the logger */
    bbox_config_t config;
    bbox_get_default_config(&config);
    
    config.root_path = "/spiffs/logs";
    config.file_prefix = "hal_";
    config.log_format = BBOX_FORMAT_BBOX;
    config.encrypt = false;
    config.buffer_size = 8 * 1024;
    config.file_size_limit = 64 * 1024;
    config.min_level = BBOX_LOG_LEVEL_DEBUG;
    config.console_output = true;
    config.file_output = true;
    config.single_threaded = false;  /* Use background writer task */

    /* Initialize logger with HAL */
    bbox_err_t err = bbox_init(&config, hal);
    if (err != BBOX_OK) {
        ESP_LOGE(TAG, "Failed to initialize logger: %d", err);
        return;
    }

    ESP_LOGI(TAG, "Logger initialized successfully");

    /* Log some text messages using macros */
    BBOX_LOG_I(TAG, "Hello from the HAL-based logger!");
    BBOX_LOG_D(TAG, "Debug message with value: %d", 42);
    BBOX_LOG_W(TAG, "This is a warning");

    /* Log structured IMU data */
    for (int i = 0; i < 100; i++) {
        float t = i * 0.1f;
        
        bbox_msg_imu_t imu = {
            .timestamp_us = hal->get_time_us(),
            .accel_x = sinf(t) * 9.81f,
            .accel_y = cosf(t) * 0.5f,
            .accel_z = -9.81f + sinf(t * 2) * 0.2f,
            .gyro_x = sinf(t * 3) * 0.1f,
            .gyro_y = cosf(t * 2) * 0.15f,
            .gyro_z = sinf(t) * 0.05f,
            .temperature = 25.0f + sinf(t) * 2.0f,
            .imu_id = 0
        };
        bbox_log_imu(&imu);

        /* Log attitude */
        bbox_msg_attitude_t att = {
            .timestamp_us = hal->get_time_us(),
            .roll = sinf(t) * 0.1f,
            .pitch = cosf(t) * 0.15f,
            .yaw = t * 0.01f,
            .rollspeed = cosf(t) * 0.05f,
            .pitchspeed = -sinf(t) * 0.05f,
            .yawspeed = 0.01f
        };
        bbox_log_attitude(&att);

        /* Log motor outputs */
        bbox_msg_motor_t mot = {
            .timestamp_us = hal->get_time_us(),
            .motor = {5000, 5200, 4800, 5100, 0, 0, 0, 0},
            .motor_count = 4,
            .armed = 1
        };
        bbox_log_motor(&mot);

        if (i % 20 == 0) {
            BBOX_LOG_I(TAG, "Logged %d samples", i);
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    /* Get statistics */
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    
    ESP_LOGI(TAG, "Statistics:");
    ESP_LOGI(TAG, "  Messages logged: %llu", stats.messages_logged);
    ESP_LOGI(TAG, "  Struct messages: %llu", stats.struct_messages);
    ESP_LOGI(TAG, "  Messages dropped: %llu", stats.messages_dropped);
    ESP_LOGI(TAG, "  Bytes written: %llu", stats.bytes_written);
    ESP_LOGI(TAG, "  Files created: %u", (unsigned)stats.files_created);

    /* Flush and shutdown */
    bbox_flush();
    vTaskDelay(pdMS_TO_TICKS(500));
    
    bbox_deinit();

    ESP_LOGI(TAG, "Example complete!");
}
