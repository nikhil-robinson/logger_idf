/**
 * @file main.c
 * @brief Blackbox Logger Example - SPIFFS Storage
 * 
 * This example demonstrates using the blackbox logger library with SPIFFS
 * (SPI Flash File System) for storing log files.
 * 
 * SPIFFS is suitable for:
 * - Small log files (limited by flash partition size)
 * - Applications where SD card is not available
 * - Wear-leveling is handled by the filesystem
 * 
 * @note Ensure you have a SPIFFS partition defined in your partition table.
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_err.h"

#include "blackbox.h"

static const char *TAG = "SPIFFS_EXAMPLE";

/**
 * @brief Initialize SPIFFS filesystem
 * 
 * @return esp_err_t ESP_OK on success
 */
static esp_err_t init_spiffs(void)
{
    ESP_LOGI(TAG, "Initializing SPIFFS...");

    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,  // Use default partition
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ret;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "SPIFFS: Total: %d bytes, Used: %d bytes", total, used);
    }

    return ESP_OK;
}

/**
 * @brief Deinitialize SPIFFS filesystem
 */
static void deinit_spiffs(void)
{
    esp_vfs_spiffs_unregister(NULL);
    ESP_LOGI(TAG, "SPIFFS unmounted");
}

/**
 * @brief Simulated sensor task that generates log messages
 */
static void sensor_task(void *pvParameters)
{
    const char *SENSOR_TAG = "SENSOR";
    int reading_count = 0;
    float temperature = 25.0f;
    float humidity = 50.0f;

    while (1) {
        // Simulate sensor readings with some variation
        temperature += ((float)(esp_random() % 100) - 50) / 100.0f;
        humidity += ((float)(esp_random() % 100) - 50) / 100.0f;
        
        // Clamp values to reasonable ranges
        if (temperature < 15.0f) temperature = 15.0f;
        if (temperature > 35.0f) temperature = 35.0f;
        if (humidity < 30.0f) humidity = 30.0f;
        if (humidity > 70.0f) humidity = 70.0f;

        reading_count++;

        // Log at different levels based on conditions
        BLACKBOX_LOG_INFO(SENSOR_TAG, "Reading #%d: Temp=%.2f°C, Humidity=%.2f%%", 
                          reading_count, temperature, humidity);

        if (temperature > 32.0f) {
            BLACKBOX_LOG_WARN(SENSOR_TAG, "High temperature warning: %.2f°C", temperature);
        }

        if (temperature > 34.0f) {
            BLACKBOX_LOG_ERROR(SENSOR_TAG, "Critical temperature: %.2f°C - cooling required!", temperature);
        }

        BLACKBOX_LOG_DEBUG(SENSOR_TAG, "Raw ADC values: temp_adc=%d, hum_adc=%d", 
                           (int)(temperature * 100), (int)(humidity * 100));

        vTaskDelay(pdMS_TO_TICKS(1000));  // Log every second
    }
}

/**
 * @brief Main application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Blackbox Logger SPIFFS Example ===");

    // Step 1: Initialize SPIFFS filesystem
    esp_err_t ret = init_spiffs();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SPIFFS, aborting");
        return;
    }

    // Step 2: Configure the blackbox logger
    blackbox_config_t config;
    blackbox_get_default_config(&config);
    
    // SPIFFS-specific settings
    config.root_path = "/spiffs/logs";          // Log directory in SPIFFS
    config.file_prefix = "sensor";              // Log files will be sensor001.blackbox, etc.
    config.encrypt = false;                     // No encryption for this example
    config.file_size_limit = 64 * 1024;         // 64KB per file (smaller for SPIFFS)
    config.buffer_size = 16 * 1024;             // 16KB ring buffer (minimum)
    config.flush_interval_ms = 500;             // Flush every 500ms
    config.min_level = BLACKBOX_LOG_LEVEL_DEBUG; // Log DEBUG and above
    config.console_output = true;               // Also output to console
    config.file_output = true;                  // Enable file output

    // Step 3: Initialize the logger
    ret = blackbox_init(&config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize blackbox logger: %s", esp_err_to_name(ret));
        deinit_spiffs();
        return;
    }

    ESP_LOGI(TAG, "Blackbox logger initialized successfully");

    // Step 4: Log some initial messages
    BLACKBOX_LOG_INFO(TAG, "Application started - SPIFFS logging example");
    BLACKBOX_LOG_INFO(TAG, "Logger configured: path=%s, file_size_limit=%d", 
                      config.root_path, config.file_size_limit);

    // Step 5: Create a task to simulate sensor readings
    xTaskCreate(sensor_task, "sensor_task", 4096, NULL, 5, NULL);

    // Step 6: Main loop - periodically print statistics
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));  // Every 10 seconds

        blackbox_stats_t stats;
        if (blackbox_get_stats(&stats) == ESP_OK) {
            BLACKBOX_LOG_INFO(TAG, "Stats: logged=%llu, dropped=%llu, written=%llu bytes, files=%lu",
                              stats.messages_logged, stats.messages_dropped,
                              stats.bytes_written, stats.files_created);
        }

        // Check SPIFFS space
        size_t total = 0, used = 0;
        if (esp_spiffs_info(NULL, &total, &used) == ESP_OK) {
            BLACKBOX_LOG_INFO(TAG, "SPIFFS: %d/%d bytes used (%.1f%%)", 
                              used, total, (float)used / total * 100.0f);
            
            // Warn if running low on space
            if (used > total * 0.9) {
                BLACKBOX_LOG_WARN(TAG, "SPIFFS nearly full! Consider rotating or clearing old logs.");
            }
        }
    }

    // Cleanup (never reached in this example)
    blackbox_deinit();
    deinit_spiffs();
}
