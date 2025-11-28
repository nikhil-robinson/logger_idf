/**
 * @file main.c
 * @brief Blackbox Logger Example - SD Card Storage
 * 
 * This example demonstrates using the blackbox logger library with an SD card
 * for storing log files. SD cards are ideal for high-throughput logging.
 * 
 * SD Card is suitable for:
 * - Large log files (GB of storage)
 * - High-speed data logging
 * - Easy log retrieval (remove SD card)
 * - Long-term storage
 * 
 * Hardware Requirements:
 * - SD card module connected via SPI or SDMMC interface
 * - Properly formatted SD card (FAT32 recommended)
 * 
 * Default SPI Pins (can be changed in menuconfig):
 * - MOSI: GPIO 23
 * - MISO: GPIO 19
 * - CLK:  GPIO 18
 * - CS:   GPIO 5
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "blackbox.h"

static const char *TAG = "SDCARD_EXAMPLE";

// SD Card mount point
#define MOUNT_POINT "/sdcard"

// SPI Bus configuration (adjust for your hardware)
#define PIN_NUM_MISO  19
#define PIN_NUM_MOSI  23
#define PIN_NUM_CLK   18
#define PIN_NUM_CS    5

static sdmmc_card_t *s_card = NULL;

/**
 * @brief Initialize SD card via SPI interface
 * 
 * @return esp_err_t ESP_OK on success
 */
static esp_err_t init_sdcard_spi(void)
{
    ESP_LOGI(TAG, "Initializing SD card via SPI...");

    esp_err_t ret;

    // Configure SPI bus
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_NUM_MOSI,
        .miso_io_num = PIN_NUM_MISO,
        .sclk_io_num = PIN_NUM_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };

    ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SDSPI_DEFAULT_DMA);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        return ret;
    }

    // Configure SD card slot
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = PIN_NUM_CS;
    slot_config.host_id = SPI2_HOST;

    // Mount configuration
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();

    ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &s_card);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount filesystem. Check if SD card is formatted as FAT32.");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        }
        spi_bus_free(SPI2_HOST);
        return ret;
    }

    // Print card info
    ESP_LOGI(TAG, "SD card mounted successfully!");
    sdmmc_card_print_info(stdout, s_card);

    return ESP_OK;
}

/**
 * @brief Deinitialize SD card
 */
static void deinit_sdcard(void)
{
    if (s_card != NULL) {
        esp_vfs_fat_sdcard_unmount(MOUNT_POINT, s_card);
        ESP_LOGI(TAG, "SD card unmounted");
        spi_bus_free(SPI2_HOST);
        s_card = NULL;
    }
}

/**
 * @brief Create log directory if it doesn't exist
 */
static esp_err_t create_log_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        // Directory doesn't exist, create it
        if (mkdir(path, 0775) != 0) {
            ESP_LOGE(TAG, "Failed to create directory: %s", path);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Created directory: %s", path);
    }
    return ESP_OK;
}

/**
 * @brief List log files in directory
 */
static void list_log_files(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        ESP_LOGW(TAG, "Cannot open directory: %s", path);
        return;
    }

    ESP_LOGI(TAG, "Log files in %s:", path);
    struct dirent *entry;
    int file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".blackbox") != NULL) {
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            
            struct stat st;
            if (stat(filepath, &st) == 0) {
                ESP_LOGI(TAG, "  %s (%ld bytes)", entry->d_name, st.st_size);
                file_count++;
            }
        }
    }
    closedir(dir);
    
    if (file_count == 0) {
        ESP_LOGI(TAG, "  (no log files found)");
    }
}

/**
 * @brief High-frequency data logging task (simulates flight controller)
 */
static void flight_data_task(void *pvParameters)
{
    const char *FLIGHT_TAG = "FLIGHT";
    uint32_t frame_count = 0;
    
    // Simulated flight data
    float roll = 0.0f, pitch = 0.0f, yaw = 0.0f;
    float altitude = 100.0f;
    float battery_voltage = 12.6f;
    int throttle = 0;

    while (1) {
        frame_count++;

        // Simulate flight dynamics
        roll += ((float)(esp_random() % 200) - 100) / 1000.0f;
        pitch += ((float)(esp_random() % 200) - 100) / 1000.0f;
        yaw += ((float)(esp_random() % 100) - 50) / 1000.0f;
        altitude += ((float)(esp_random() % 100) - 50) / 100.0f;
        battery_voltage -= 0.0001f;  // Slowly discharge
        throttle = 1500 + (esp_random() % 200) - 100;

        // Clamp values
        if (roll > 30.0f) roll = 30.0f;
        if (roll < -30.0f) roll = -30.0f;
        if (pitch > 30.0f) pitch = 30.0f;
        if (pitch < -30.0f) pitch = -30.0f;
        if (altitude < 0.0f) altitude = 0.0f;
        if (altitude > 500.0f) altitude = 500.0f;

        // Log flight data at high rate
        BLACKBOX_LOG_DEBUG(FLIGHT_TAG, "F:%lu R:%.2f P:%.2f Y:%.2f A:%.1f T:%d V:%.2f",
                           frame_count, roll, pitch, yaw, altitude, throttle, battery_voltage);

        // Log warnings for critical conditions
        if (battery_voltage < 11.0f) {
            BLACKBOX_LOG_WARN(FLIGHT_TAG, "Low battery: %.2fV", battery_voltage);
        }

        if (altitude < 10.0f && throttle > 1200) {
            BLACKBOX_LOG_WARN(FLIGHT_TAG, "Low altitude warning: %.1fm", altitude);
        }

        if (fabsf(roll) > 25.0f || fabsf(pitch) > 25.0f) {
            BLACKBOX_LOG_WARN(FLIGHT_TAG, "High attitude angle: R=%.1f P=%.1f", roll, pitch);
        }

        // Log at 50Hz (20ms interval) - typical for flight controllers
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

/**
 * @brief GPS logging task (lower frequency)
 */
static void gps_task(void *pvParameters)
{
    const char *GPS_TAG = "GPS";
    
    // Simulated GPS position (somewhere interesting)
    double latitude = 37.7749;   // San Francisco
    double longitude = -122.4194;
    float speed = 0.0f;
    int satellites = 8;

    while (1) {
        // Simulate GPS movement
        latitude += ((double)(esp_random() % 100) - 50) / 1000000.0;
        longitude += ((double)(esp_random() % 100) - 50) / 1000000.0;
        speed = (float)(esp_random() % 100) / 10.0f;
        satellites = 6 + (esp_random() % 6);

        BLACKBOX_LOG_INFO(GPS_TAG, "Lat:%.6f Lon:%.6f Spd:%.1f Sat:%d",
                          latitude, longitude, speed, satellites);

        if (satellites < 4) {
            BLACKBOX_LOG_ERROR(GPS_TAG, "GPS signal lost! Satellites: %d", satellites);
        }

        // GPS typically updates at 1-10Hz
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/**
 * @brief Main application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Blackbox Logger SD Card Example ===");

    // Step 1: Initialize SD card
    esp_err_t ret = init_sdcard_spi();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SD card, aborting");
        return;
    }

    // Step 2: Create log directory
    const char *log_path = MOUNT_POINT "/logs";
    ret = create_log_directory(log_path);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create log directory");
        deinit_sdcard();
        return;
    }

    // List any existing log files
    list_log_files(log_path);

    // Step 3: Configure the blackbox logger
    blackbox_config_t config;
    blackbox_get_default_config(&config);
    
    // SD Card optimized settings
    config.root_path = log_path;                // Log directory on SD card
    config.file_prefix = "flight";              // Log files will be flight001.blackbox, etc.
    config.encrypt = false;                     // No encryption for this example
    config.file_size_limit = 512 * 1024;        // 512KB per file (larger for SD card)
    config.buffer_size = 32 * 1024;             // 32KB ring buffer
    config.flush_interval_ms = 100;             // Flush every 100ms (faster for high-rate logging)
    config.min_level = BLACKBOX_LOG_LEVEL_DEBUG; // Log everything
    config.console_output = true;               // Also output to console
    config.file_output = true;                  // Enable file output

    // Step 4: Initialize the logger
    ret = blackbox_init(&config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize blackbox logger: %s", esp_err_to_name(ret));
        deinit_sdcard();
        return;
    }

    ESP_LOGI(TAG, "Blackbox logger initialized successfully");

    // Log startup information
    BLACKBOX_LOG_INFO(TAG, "=== Flight Session Started ===");
    BLACKBOX_LOG_INFO(TAG, "SD Card logging enabled");
    BLACKBOX_LOG_INFO(TAG, "Log path: %s", log_path);
    BLACKBOX_LOG_INFO(TAG, "File size limit: %d KB", config.file_size_limit / 1024);
    BLACKBOX_LOG_INFO(TAG, "Buffer size: %d KB", config.buffer_size / 1024);

    // Step 5: Create logging tasks
    xTaskCreate(flight_data_task, "flight_data", 4096, NULL, 6, NULL);
    xTaskCreate(gps_task, "gps_task", 4096, NULL, 5, NULL);

    // Step 6: Main loop - monitor and report statistics
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));  // Every 5 seconds

        blackbox_stats_t stats;
        if (blackbox_get_stats(&stats) == ESP_OK) {
            BLACKBOX_LOG_INFO(TAG, "=== Logger Statistics ===");
            BLACKBOX_LOG_INFO(TAG, "Messages: logged=%llu, dropped=%llu",
                              stats.messages_logged, stats.messages_dropped);
            BLACKBOX_LOG_INFO(TAG, "Storage: written=%llu KB, files=%lu",
                              stats.bytes_written / 1024, stats.files_created);
            BLACKBOX_LOG_INFO(TAG, "Buffer: high_water=%lu bytes, errors=%lu",
                              stats.buffer_high_water, stats.write_errors);
            
            // Calculate message rate
            static uint64_t last_logged = 0;
            static TickType_t last_tick = 0;
            TickType_t now = xTaskGetTickCount();
            if (last_tick > 0) {
                uint64_t messages = stats.messages_logged - last_logged;
                float seconds = (float)(now - last_tick) / configTICK_RATE_HZ;
                float rate = messages / seconds;
                BLACKBOX_LOG_INFO(TAG, "Message rate: %.1f msg/sec", rate);
            }
            last_logged = stats.messages_logged;
            last_tick = now;
        }

        // Warn if messages are being dropped
        static uint64_t last_dropped = 0;
        if (stats.messages_dropped > last_dropped) {
            BLACKBOX_LOG_ERROR(TAG, "WARNING: %llu messages dropped since last check!",
                               stats.messages_dropped - last_dropped);
            last_dropped = stats.messages_dropped;
        }

        // List log files periodically
        list_log_files(log_path);
    }

    // Cleanup (never reached in this example)
    BLACKBOX_LOG_INFO(TAG, "=== Flight Session Ended ===");
    blackbox_deinit();
    deinit_sdcard();
}
