/**
 * @file single_threaded.c
 * @brief Blackbox Logger Example - Single-Threaded / Polling Mode (Linux/macOS)
 *
 * This example demonstrates using the blackbox library in single-threaded
 * (polling) mode, which is useful for:
 * - Bare-metal systems without an RTOS
 * - Embedded systems with limited resources
 * - Applications that need full control over when writes happen
 * - Testing the polling API
 *
 * Build:
 *   make single_threaded
 *
 * Run:
 *   ./single_threaded
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>
#include <time.h>
#include <signal.h>

#include "include/blackbox.h"
#include "hal/blackbox_hal_posix.h"

static const char *TAG = "POLLING";
static volatile int s_running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    s_running = 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("=== Blackbox Single-Threaded Mode Example ===\n\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    srand((unsigned int)time(NULL));
    
    /* Create log directory */
    const char *log_path = "/tmp/blackbox_polling";
    struct stat st;
    if (stat(log_path, &st) != 0) {
        mkdir(log_path, 0755);
    }
    
    /* Get single-threaded POSIX HAL (no pthreads used) */
    const bbox_hal_t *hal = bbox_hal_posix_single_threaded_get();
    
    /* Configure for single-threaded operation */
    bbox_config_t config;
    bbox_get_default_config(&config);
    
    config.root_path = log_path;
    config.file_prefix = "poll";
    config.encrypt = false;
    config.buffer_size = 8 * 1024;     /* Smaller buffer for polling */
    config.file_size_limit = 64 * 1024;
    config.min_level = BBOX_LOG_LEVEL_DEBUG;
    config.console_output = true;
    config.file_output = true;
    config.single_threaded = true;      /* IMPORTANT: Enable polling mode */
    
    printf("Mode: Single-threaded (polling)\n");
    printf("Log directory: %s\n\n", log_path);
    
    /* Initialize */
    bbox_err_t ret = bbox_init(&config, hal);
    if (ret != BBOX_OK) {
        fprintf(stderr, "Failed to initialize: %d\n", ret);
        return 1;
    }
    
    BBOX_LOG_I(TAG, "Single-threaded logging started");
    
    printf("In single-threaded mode, you must call bbox_process() regularly.\n");
    printf("Press Ctrl+C to stop.\n\n");
    
    int loop_count = 0;
    
    while (s_running && loop_count < 100) {
        /* Simulate some work and logging */
        float value = sinf(loop_count * 0.1f);
        
        BBOX_LOG_D(TAG, "Loop %d: value = %.3f", loop_count, value);
        
        /* Log some structured data */
        bbox_msg_imu_t imu = {
            .timestamp_us = hal->get_time_us(),
            .accel_x = value,
            .accel_y = cosf(loop_count * 0.1f),
            .accel_z = -9.81f,
            .gyro_x = 0.01f,
            .gyro_y = 0.02f,
            .gyro_z = 0.0f,
            .temperature = 25.0f,
            .imu_id = 0
        };
        bbox_log_imu(&imu);
        
        /* CRITICAL: Call bbox_process() to drain the ring buffer and write to file.
         * In single-threaded mode, no background thread does this for you.
         * Call this regularly - ideally every loop iteration or at fixed intervals.
         */
        bbox_process();
        
        loop_count++;
        usleep(100000);  /* 100ms */
    }
    
    printf("\n\nProcessing remaining data...\n");
    
    /* Process any remaining data */
    for (int i = 0; i < 10; i++) {
        bbox_process();
        usleep(10000);
    }
    
    /* Get stats */
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    
    printf("\nFinal stats:\n");
    printf("  Messages logged:  %llu\n", (unsigned long long)stats.messages_logged);
    printf("  Messages dropped: %llu\n", (unsigned long long)stats.messages_dropped);
    printf("  Bytes written:    %llu\n", (unsigned long long)stats.bytes_written);
    
    bbox_deinit();
    
    printf("\nDone! Check log files in %s\n", log_path);
    
    return 0;
}
