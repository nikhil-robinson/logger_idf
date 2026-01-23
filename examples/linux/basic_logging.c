/**
 * @file basic_logging.c
 * @brief Blackbox Logger Example - Basic File Logging (Linux/macOS)
 *
 * This example demonstrates basic text logging using the blackbox library
 * on a Linux/macOS system. Equivalent to the ESP-IDF spiffs_example.
 *
 * Build:
 *   make basic_logging
 *
 * Run:
 *   ./basic_logging
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>

#include "include/blackbox.h"
#include "hal/blackbox_hal_posix.h"

static const char *TAG = "BASIC_EXAMPLE";
static volatile int s_running = 1;

/**
 * @brief Signal handler for graceful shutdown
 */
static void signal_handler(int sig)
{
    (void)sig;
    printf("\nShutting down...\n");
    s_running = 0;
}

/**
 * @brief Create directory if it doesn't exist
 */
static int create_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        if (mkdir(path, 0755) != 0) {
            perror("Failed to create directory");
            return -1;
        }
        printf("Created directory: %s\n", path);
    }
    return 0;
}

/**
 * @brief Simulate sensor reading with some variation
 */
static void get_sensor_reading(float *temperature, float *humidity)
{
    static float temp = 25.0f;
    static float hum = 50.0f;
    
    /* Add random variation */
    temp += ((float)(rand() % 100) - 50) / 100.0f;
    hum += ((float)(rand() % 100) - 50) / 100.0f;
    
    /* Clamp to reasonable ranges */
    if (temp < 15.0f) temp = 15.0f;
    if (temp > 35.0f) temp = 35.0f;
    if (hum < 30.0f) hum = 30.0f;
    if (hum > 70.0f) hum = 70.0f;
    
    *temperature = temp;
    *humidity = hum;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("=== Blackbox Logger Basic Example (Linux/macOS) ===\n\n");
    
    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Seed random */
    srand((unsigned int)time(NULL));
    
    /* Create log directory */
    const char *log_path = "/tmp/blackbox_logs";
    if (create_directory(log_path) != 0) {
        return 1;
    }
    
    /* Get the POSIX HAL */
    const bbox_hal_t *hal = bbox_hal_posix_get();
    
    /* Configure the blackbox logger */
    bbox_config_t config;
    bbox_get_default_config(&config);
    
    config.root_path = log_path;
    config.file_prefix = "sensor";
    config.encrypt = false;
    config.file_size_limit = 64 * 1024;    /* 64KB per file */
    config.buffer_size = 16 * 1024;         /* 16KB ring buffer */
    config.flush_interval_ms = 500;
    config.min_level = BBOX_LOG_LEVEL_DEBUG;
    config.console_output = true;
    config.file_output = true;
    config.single_threaded = false;         /* Use background thread */
    
    /* Initialize the logger */
    bbox_err_t ret = bbox_init(&config, hal);
    if (ret != BBOX_OK) {
        fprintf(stderr, "Failed to initialize blackbox logger: %d\n", ret);
        return 1;
    }
    
    printf("Blackbox logger initialized successfully\n");
    printf("Log directory: %s\n\n", log_path);
    
    /* Log initial messages */
    BBOX_LOG_I(TAG, "Application started - Basic logging example");
    BBOX_LOG_I(TAG, "Logger configured: path=%s, file_size_limit=%u",
               config.root_path, config.file_size_limit);
    
    /* Main loop - simulate sensor readings */
    int reading_count = 0;
    time_t last_stats_time = time(NULL);
    
    printf("Logging sensor data... Press Ctrl+C to stop.\n\n");
    
    while (s_running) {
        float temperature, humidity;
        get_sensor_reading(&temperature, &humidity);
        reading_count++;
        
        /* Log at different levels based on conditions */
        BBOX_LOG_I("SENSOR", "Reading #%d: Temp=%.2f°C, Humidity=%.2f%%",
                   reading_count, temperature, humidity);
        
        if (temperature > 32.0f) {
            BBOX_LOG_W("SENSOR", "High temperature warning: %.2f°C", temperature);
        }
        
        if (temperature > 34.0f) {
            BBOX_LOG_E("SENSOR", "Critical temperature: %.2f°C - cooling required!",
                       temperature);
        }
        
        BBOX_LOG_D("SENSOR", "Raw values: temp_raw=%d, hum_raw=%d",
                   (int)(temperature * 100), (int)(humidity * 100));
        
        /* Print stats every 10 seconds */
        time_t now = time(NULL);
        if (now - last_stats_time >= 10) {
            bbox_stats_t stats;
            if (bbox_get_stats(&stats) == BBOX_OK) {
                printf("\n--- Stats: logged=%llu, dropped=%llu, written=%llu bytes, files=%u ---\n\n",
                       (unsigned long long)stats.messages_logged,
                       (unsigned long long)stats.messages_dropped,
                       (unsigned long long)stats.bytes_written,
                       stats.files_created);
            }
            last_stats_time = now;
        }
        
        usleep(1000000);  /* 1 second */
    }
    
    /* Cleanup */
    printf("\nFlushing and shutting down...\n");
    bbox_flush();
    usleep(100000);  /* Allow time for background thread */
    
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    printf("\nFinal stats:\n");
    printf("  Messages logged:  %llu\n", (unsigned long long)stats.messages_logged);
    printf("  Messages dropped: %llu\n", (unsigned long long)stats.messages_dropped);
    printf("  Bytes written:    %llu\n", (unsigned long long)stats.bytes_written);
    printf("  Files created:    %u\n", stats.files_created);
    
    bbox_deinit();
    
    printf("\nDone! Check log files in %s\n", log_path);
    
    return 0;
}
