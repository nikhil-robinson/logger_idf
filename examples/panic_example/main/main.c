/**
 * @file main.c
 * @brief Blackbox Logger Example - Panic/Coredump Logging
 *
 * This example demonstrates the blackbox logger's automatic panic handler.
 * The library internally handles all panic/crash logging - no callbacks needed.
 *
 * When a crash occurs, the blackbox library automatically:
 * - Captures crash information
 * - Logs stack backtrace
 * - Dumps CPU registers
 * - Writes everything to the log file
 *
 * Hardware Requirements:
 * - SD card module connected via SPI interface
 * - Properly formatted SD card (FAT32)
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "blackbox.h"

static const char *TAG = "PANIC_EXAMPLE";

#define MOUNT_POINT "/sdcard"
#define PIN_NUM_MISO 19
#define PIN_NUM_MOSI 23
#define PIN_NUM_CLK 18
#define PIN_NUM_CS 5

static sdmmc_card_t *s_card = NULL;

/**
 * @brief Initialize SD card
 */
static esp_err_t init_sdcard(void)
{
    ESP_LOGI(TAG, "Initializing SD card...");

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_NUM_MOSI,
        .miso_io_num = PIN_NUM_MISO,
        .sclk_io_num = PIN_NUM_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };

    esp_err_t ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SDSPI_DEFAULT_DMA);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SPI bus");
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
        ESP_LOGE(TAG, "Failed to mount SD card");
        spi_bus_free(SPI2_HOST);
        return ret;
    }

    ESP_LOGI(TAG, "SD card mounted");
    return ESP_OK;
}

/**
 * @brief Create directory if needed
 */
static void create_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        mkdir(path, 0775);
    }
}

/**
 * @brief Main application
 */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Blackbox Panic Handler Example ===");

    // 1. Initialize SD card
    if (init_sdcard() != ESP_OK) {
        ESP_LOGE(TAG, "SD card init failed");
        return;
    }

    // 2. Create log directory
    const char *log_path = MOUNT_POINT "/logs";
    create_dir(log_path);

    // 3. Configure blackbox logger with panic handler enabled
    blackbox_config_t config;
    blackbox_get_default_config(&config);
    
    config.root_path = log_path;
    config.file_prefix = "crash";
    config.min_level = BLACKBOX_LOG_LEVEL_DEBUG;
    
    // Enable panic handler - library handles everything internally!
    // Default already enables panic with backtrace and registers
    config.panic_flags = BLACKBOX_PANIC_FLAGS_ALL;

    // 4. Initialize logger - panic handler is automatically registered
    if (blackbox_init(&config) != ESP_OK) {
        ESP_LOGE(TAG, "Blackbox init failed");
        return;
    }

    ESP_LOGI(TAG, "Blackbox initialized with panic handler");

    // 5. Normal application logging
    BLACKBOX_LOG_INFO(TAG, "Application started");
    BLACKBOX_LOG_INFO(TAG, "Free heap: %lu bytes", esp_get_free_heap_size());

    // 6. Application loop
    int counter = 0;
    while (1) {
        BLACKBOX_LOG_DEBUG(TAG, "Running... count=%d", counter++);
        vTaskDelay(pdMS_TO_TICKS(1000));

        // Demo: trigger crash after 10 seconds
        if (counter == 10) {
            BLACKBOX_LOG_WARN(TAG, "Triggering intentional crash for demo...");
            blackbox_flush();
            vTaskDelay(pdMS_TO_TICKS(100));
            
            // Crash - panic handler automatically logs it
            volatile int *p = NULL;
            *p = 0;
        }
    }
}
