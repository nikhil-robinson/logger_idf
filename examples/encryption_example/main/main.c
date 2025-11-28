/**
 * @file main.c
 * @brief Blackbox Logger Example - AES-256 Encryption
 * 
 * This example demonstrates using the blackbox logger library with AES-256
 * encryption enabled for secure logging. Encrypted logs protect sensitive
 * data and can only be read with the correct decryption key.
 * 
 * Use cases for encrypted logging:
 * - Protecting proprietary flight algorithms/data
 * - Secure storage of GPS coordinates or user data
 * - Compliance with data protection requirements
 * - Preventing tampering with audit logs
 * 
 * This example uses SD card storage, but encryption works with any
 * storage backend (SPIFFS, SD card, etc.)
 * 
 * @warning Keep your encryption key secure! Anyone with the key can decrypt logs.
 * @note Encrypted logs have slightly higher CPU overhead for AES operations.
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "blackbox.h"

static const char *TAG = "ENCRYPTED_EXAMPLE";

// SD Card mount point
#define MOUNT_POINT "/sdcard"

// SPI Bus configuration (adjust for your hardware)
#define PIN_NUM_MISO  19
#define PIN_NUM_MOSI  23
#define PIN_NUM_CLK   18
#define PIN_NUM_CS    5

static sdmmc_card_t *s_card = NULL;

/**
 * @brief Example 256-bit AES encryption key
 * 
 * @warning In production, NEVER hardcode keys! Use:
 * - Secure key storage (NVS with encryption)
 * - Hardware security module (if available)
 * - Key derived from device-specific data
 * - Secure provisioning during manufacturing
 */
static const uint8_t ENCRYPTION_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

/**
 * @brief Initialize SD card via SPI interface
 */
static esp_err_t init_sdcard_spi(void)
{
    ESP_LOGI(TAG, "Initializing SD card via SPI...");

    esp_err_t ret;

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

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = PIN_NUM_CS;
    slot_config.host_id = SPI2_HOST;

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();

    ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &s_card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        spi_bus_free(SPI2_HOST);
        return ret;
    }

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
        if (mkdir(path, 0775) != 0) {
            ESP_LOGE(TAG, "Failed to create directory: %s", path);
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Created directory: %s", path);
    }
    return ESP_OK;
}

/**
 * @brief Print encryption key (for demonstration purposes only!)
 * @warning Never do this in production!
 */
static void print_key_info(void)
{
    ESP_LOGW(TAG, "=========================================");
    ESP_LOGW(TAG, "DEMO: Encryption key information");
    ESP_LOGW(TAG, "In production, NEVER log or expose keys!");
    ESP_LOGW(TAG, "=========================================");
    
    // Just show first/last bytes as demo
    ESP_LOGI(TAG, "Key (first 4 bytes): %02X %02X %02X %02X ...",
             ENCRYPTION_KEY[0], ENCRYPTION_KEY[1], 
             ENCRYPTION_KEY[2], ENCRYPTION_KEY[3]);
    ESP_LOGI(TAG, "Key (last 4 bytes):  ... %02X %02X %02X %02X",
             ENCRYPTION_KEY[28], ENCRYPTION_KEY[29],
             ENCRYPTION_KEY[30], ENCRYPTION_KEY[31]);
    ESP_LOGI(TAG, "Key length: 256 bits (32 bytes)");
    ESP_LOGI(TAG, "Cipher: AES-256-CTR");
}

/**
 * @brief Simulated secure data logging task
 * 
 * This task logs "sensitive" data that should be encrypted.
 */
static void secure_data_task(void *pvParameters)
{
    const char *SECURE_TAG = "SECURE";
    uint32_t record_id = 0;

    // Simulated sensitive data
    char user_id[32] = "USR-12345-ABCDE";
    double latitude = 37.7749;
    double longitude = -122.4194;
    float account_balance = 1234.56f;
    int access_code = 0;

    while (1) {
        record_id++;
        
        // Simulate changing data
        latitude += ((double)(esp_random() % 100) - 50) / 100000.0;
        longitude += ((double)(esp_random() % 100) - 50) / 100000.0;
        account_balance += ((float)(esp_random() % 200) - 100) / 100.0f;
        access_code = esp_random() % 10000;

        // Log sensitive user data (encrypted!)
        BLACKBOX_LOG_INFO(SECURE_TAG, "[%lu] User: %s | Location: %.6f, %.6f",
                          record_id, user_id, latitude, longitude);
        
        BLACKBOX_LOG_DEBUG(SECURE_TAG, "[%lu] Balance: $%.2f | Access: %04d",
                           record_id, account_balance, access_code);

        // Log security events
        if (esp_random() % 100 < 5) {  // 5% chance
            BLACKBOX_LOG_WARN(SECURE_TAG, "[%lu] Unusual activity detected for %s",
                              record_id, user_id);
        }

        if (esp_random() % 100 < 1) {  // 1% chance
            BLACKBOX_LOG_ERROR(SECURE_TAG, "[%lu] SECURITY ALERT: Failed auth for %s",
                               record_id, user_id);
        }

        vTaskDelay(pdMS_TO_TICKS(500));  // Log every 500ms
    }
}

/**
 * @brief System monitoring task
 */
static void system_monitor_task(void *pvParameters)
{
    const char *SYS_TAG = "SYSTEM";

    while (1) {
        // Log system information (also encrypted)
        uint32_t free_heap = esp_get_free_heap_size();
        uint32_t min_free_heap = esp_get_minimum_free_heap_size();
        
        BLACKBOX_LOG_INFO(SYS_TAG, "Heap: free=%lu, min_free=%lu", 
                          free_heap, min_free_heap);

        if (free_heap < 50000) {
            BLACKBOX_LOG_WARN(SYS_TAG, "Low memory warning: %lu bytes free", free_heap);
        }

        // Log encryption status
        BLACKBOX_LOG_DEBUG(SYS_TAG, "Encryption: ACTIVE (AES-256-CTR)");

        vTaskDelay(pdMS_TO_TICKS(5000));  // Every 5 seconds
    }
}

/**
 * @brief Main application entry point
 */
void app_main(void)
{
    ESP_LOGI(TAG, "===========================================");
    ESP_LOGI(TAG, "  Blackbox Logger - Encrypted Example");
    ESP_LOGI(TAG, "===========================================");

    // Step 1: Initialize SD card
    esp_err_t ret = init_sdcard_spi();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SD card, aborting");
        return;
    }

    // Step 2: Create log directory
    const char *log_path = MOUNT_POINT "/secure_logs";
    ret = create_log_directory(log_path);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create log directory");
        deinit_sdcard();
        return;
    }

    // Print key info (demo only!)
    print_key_info();

    // Step 3: Configure the blackbox logger with ENCRYPTION ENABLED
    blackbox_config_t config;
    blackbox_get_default_config(&config);
    
    // Encryption-specific settings
    config.root_path = log_path;                // Secure log directory
    config.file_prefix = "secure";              // Log files: secure001.blackbox, etc.
    
    // *** ENABLE ENCRYPTION ***
    config.encrypt = true;                      // Enable AES-256 encryption!
    memcpy(config.encryption_key, ENCRYPTION_KEY, 32);  // Copy the 256-bit key
    
    // Other settings
    config.file_size_limit = 256 * 1024;        // 256KB per file
    config.buffer_size = 32 * 1024;             // 32KB ring buffer
    config.flush_interval_ms = 200;             // Flush every 200ms
    config.min_level = BLACKBOX_LOG_LEVEL_DEBUG; // Log everything
    config.console_output = true;               // Console shows plaintext (for demo)
    config.file_output = true;                  // File output is ENCRYPTED

    // Step 4: Initialize the logger
    ret = blackbox_init(&config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize blackbox logger: %s", esp_err_to_name(ret));
        deinit_sdcard();
        return;
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  ENCRYPTED LOGGING ENABLED!");
    ESP_LOGI(TAG, "  - Cipher: AES-256-CTR");
    ESP_LOGI(TAG, "  - Log path: %s", log_path);
    ESP_LOGI(TAG, "  - Files are encrypted on disk");
    ESP_LOGI(TAG, "  - Console output is plaintext");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "");

    // Log startup messages (these will be encrypted in the file!)
    BLACKBOX_LOG_INFO(TAG, "=== Encrypted Logging Session Started ===");
    BLACKBOX_LOG_INFO(TAG, "Encryption: AES-256-CTR");
    BLACKBOX_LOG_INFO(TAG, "Log path: %s", log_path);
    BLACKBOX_LOG_WARN(TAG, "File contents are encrypted and require the key to read");

    // Step 5: Create logging tasks
    xTaskCreate(secure_data_task, "secure_data", 4096, NULL, 5, NULL);
    xTaskCreate(system_monitor_task, "sys_monitor", 4096, NULL, 4, NULL);

    // Step 6: Main loop - monitor and display statistics
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));  // Every 10 seconds

        blackbox_stats_t stats;
        if (blackbox_get_stats(&stats) == ESP_OK) {
            ESP_LOGI(TAG, "");
            BLACKBOX_LOG_INFO(TAG, "=== Encrypted Logger Statistics ===");
            BLACKBOX_LOG_INFO(TAG, "Messages logged: %llu", stats.messages_logged);
            BLACKBOX_LOG_INFO(TAG, "Messages dropped: %llu", stats.messages_dropped);
            BLACKBOX_LOG_INFO(TAG, "Bytes written (encrypted): %llu KB", 
                              stats.bytes_written / 1024);
            BLACKBOX_LOG_INFO(TAG, "Files created: %lu", stats.files_created);
            BLACKBOX_LOG_INFO(TAG, "Write errors: %lu", stats.write_errors);
            
            if (stats.messages_dropped > 0) {
                BLACKBOX_LOG_WARN(TAG, "Some messages were dropped due to buffer overflow!");
            }
        }

        // Reminder about encryption
        ESP_LOGI(TAG, "");
        ESP_LOGI(TAG, "Note: To read the log files, you need:");
        ESP_LOGI(TAG, "  1. The decryption key (same as encryption key)");
        ESP_LOGI(TAG, "  2. A blackbox decoder that supports AES-256-CTR");
        ESP_LOGI(TAG, "  3. The IV stored in the file header");
    }

    // Cleanup (never reached in this example)
    BLACKBOX_LOG_INFO(TAG, "=== Encrypted Logging Session Ended ===");
    blackbox_deinit();
    deinit_sdcard();
}
