/**
 * @file multi_format.c
 * @brief Blackbox Logger Example - Multiple Format Comparison (Linux/macOS)
 *
 * This example creates log files in all three supported formats:
 * - BBOX (native)
 * - PX4 ULog (.ulg)
 * - ArduPilot DataFlash (.bin)
 *
 * Useful for comparing file sizes and compatibility with different tools.
 *
 * Build:
 *   make multi_format
 *
 * Run:
 *   ./multi_format
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>
#include <time.h>

#include "include/blackbox.h"
#include "hal/blackbox_hal_posix.h"

static const char *TAG = "MULTI_FORMAT";
static const bbox_hal_t *s_hal = NULL;

/**
 * @brief Log sample flight data
 */
static void log_sample_data(int sample_count)
{
    float t = sample_count * 0.01f;
    
    /* IMU */
    bbox_msg_imu_t imu = {
        .timestamp_us = s_hal->get_time_us(),
        .accel_x = sinf(t) * 2.0f,
        .accel_y = cosf(t) * 1.5f,
        .accel_z = -9.81f + sinf(t * 2) * 0.5f,
        .gyro_x = sinf(t * 3) * 0.1f,
        .gyro_y = cosf(t * 3) * 0.1f,
        .gyro_z = 0.05f,
        .temperature = 25.0f,
        .imu_id = 0
    };
    bbox_log_imu(&imu);
    
    /* Attitude */
    bbox_msg_attitude_t att = {
        .timestamp_us = s_hal->get_time_us(),
        .roll = sinf(t * 0.5f) * 0.2f,
        .pitch = cosf(t * 0.5f) * 0.15f,
        .yaw = fmodf(t * 0.1f, 6.28f),
        .rollspeed = 0.01f,
        .pitchspeed = -0.01f,
        .yawspeed = 0.05f
    };
    bbox_log_attitude(&att);
    
    /* Motors */
    bbox_msg_motor_t motor = {
        .timestamp_us = s_hal->get_time_us(),
        .motor = {1500, 1500, 1500, 1500, 0, 0, 0, 0},
        .motor_count = 4,
        .armed = 1
    };
    bbox_log_motor(&motor);
    
    /* GPS (every 10 samples) */
    if (sample_count % 10 == 0) {
        bbox_msg_gps_t gps = {
            .timestamp_us = s_hal->get_time_us(),
            .latitude = 377490000 + (int32_t)(sinf(t) * 100),
            .longitude = -1224194000 + (int32_t)(cosf(t) * 100),
            .altitude_msl = 50000,
            .altitude_agl = 50000,
            .hdop = 100,
            .vdop = 150,
            .speed_ground = 500,
            .course = 9000,
            .fix_type = GPS_FIX_3D,
            .satellites = 12,
            .accuracy_h = 2000,
            .accuracy_v = 3000
        };
        bbox_log_gps(&gps);
    }
}

/**
 * @brief Run logging session with specified format
 */
static int run_logging_session(bbox_format_t format, const char *name, const char *extension)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/blackbox_formats/%s", name);
    
    struct stat st;
    if (stat(path, &st) != 0) {
        mkdir(path, 0755);
    }
    
    printf("\n--- Creating %s log ---\n", name);
    
    bbox_config_t config;
    bbox_get_default_config(&config);
    
    config.root_path = path;
    config.file_prefix = name;
    config.log_format = format;
    config.encrypt = false;
    config.buffer_size = 32 * 1024;
    config.file_size_limit = 1 * 1024 * 1024;
    config.min_level = BBOX_LOG_LEVEL_INFO;
    config.console_output = false;
    config.file_output = true;
    config.single_threaded = false;
    
    bbox_err_t ret = bbox_init(&config, s_hal);
    if (ret != BBOX_OK) {
        fprintf(stderr, "Failed to init %s: %d\n", name, ret);
        return -1;
    }
    
    BBOX_LOG_I(TAG, "Started %s format logging", name);
    
    /* Log 1000 samples */
    for (int i = 0; i < 1000; i++) {
        log_sample_data(i);
        usleep(1000);  /* 1ms */
    }
    
    BBOX_LOG_I(TAG, "Finished %s format logging", name);
    
    bbox_flush();
    usleep(100000);
    
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    
    char filepath[256];
    bbox_get_current_file(filepath, sizeof(filepath));
    
    printf("  File: %s\n", filepath);
    printf("  Messages: %llu\n", (unsigned long long)stats.messages_logged);
    printf("  Bytes: %llu (%.2f KB)\n", 
           (unsigned long long)stats.bytes_written,
           stats.bytes_written / 1024.0);
    
    bbox_deinit();
    
    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("=== Blackbox Multi-Format Comparison ===\n");
    
    srand((unsigned int)time(NULL));
    
    /* Create base directory */
    struct stat st;
    if (stat("/tmp/blackbox_formats", &st) != 0) {
        mkdir("/tmp/blackbox_formats", 0755);
    }
    
    /* Get HAL */
    s_hal = bbox_hal_posix_get();
    
    /* Run all three formats */
    run_logging_session(BBOX_FORMAT_BBOX, "bbox", ".blackbox");
    run_logging_session(BBOX_FORMAT_PX4_ULOG, "ulog", ".ulg");
    run_logging_session(BBOX_FORMAT_ARDUPILOT, "ardupilot", ".bin");
    
    printf("\n=== Summary ===\n");
    printf("Log files created in /tmp/blackbox_formats/\n");
    printf("\nTo analyze:\n");
    printf("  BBOX:      python3 tools/blackbox_decoder.py /tmp/blackbox_formats/bbox/*.blackbox\n");
    printf("  ULog:      ulog_info /tmp/blackbox_formats/ulog/*.ulg\n");
    printf("  ArduPilot: Use Mission Planner to open /tmp/blackbox_formats/ardupilot/*.bin\n");
    
    return 0;
}
