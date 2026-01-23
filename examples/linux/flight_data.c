/**
 * @file flight_data.c
 * @brief Blackbox Logger Example - Structured Flight Data Logging (Linux/macOS)
 *
 * This example demonstrates structured data logging with IMU, GPS, attitude,
 * PID, motor, and battery telemetry. Shows how to select between different
 * log formats: BBOX (native), PX4 ULog, and ArduPilot DataFlash.
 *
 * Build:
 *   make flight_data
 *
 * Run:
 *   ./flight_data
 *   ./flight_data --format ulog      # Use PX4 ULog format
 *   ./flight_data --format ardupilot # Use ArduPilot DataFlash format
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

static const char *TAG = "FLIGHT_DATA";
static volatile int s_running = 1;
static const bbox_hal_t *s_hal = NULL;

/* Simulated flight state */
typedef struct {
    float roll;         /* radians */
    float pitch;        /* radians */
    float yaw;          /* radians */
    float altitude;     /* meters */
    float vx, vy, vz;   /* m/s */
    int32_t lat;        /* degrees * 1e7 */
    int32_t lon;        /* degrees * 1e7 */
} sim_flight_state_t;

static sim_flight_state_t s_flight_state = {0};

/**
 * @brief Signal handler
 */
static void signal_handler(int sig)
{
    (void)sig;
    s_running = 0;
}

/**
 * @brief Generate simulated IMU data
 */
static void simulate_imu(bbox_msg_imu_t *imu)
{
    uint64_t now_us = s_hal->get_time_us();
    float t = now_us / 1000000.0f;
    float noise = ((float)(rand() % 100) - 50) / 1000.0f;

    imu->timestamp_us = now_us;
    imu->gyro_x = sinf(t * 0.5f) * 0.1f + noise;
    imu->gyro_y = cosf(t * 0.7f) * 0.08f + noise;
    imu->gyro_z = sinf(t * 0.3f) * 0.05f + noise;
    imu->accel_x = 0.1f * sinf(t * 2.0f) + noise;
    imu->accel_y = 0.1f * cosf(t * 2.0f) + noise;
    imu->accel_z = -9.81f + 0.05f * sinf(t * 3.0f) + noise;
    imu->temperature = 25.0f + 0.5f * sinf(t * 0.1f);
    imu->imu_id = 0;

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
    uint64_t now_us = s_hal->get_time_us();
    float t = now_us / 1000000.0f;

    /* Simulated position around San Francisco */
    float base_lat = 37.7749f;
    float base_lon = -122.4194f;

    /* Small circular motion */
    float radius = 0.0001f;
    float lat_offset = radius * sinf(t * 0.1f);
    float lon_offset = radius * cosf(t * 0.1f);

    gps->timestamp_us = now_us;
    gps->latitude = (int32_t)((base_lat + lat_offset) * 1e7);
    gps->longitude = (int32_t)((base_lon + lon_offset) * 1e7);
    gps->altitude_msl = 50000 + (int32_t)(sinf(t * 0.05f) * 1000);
    gps->altitude_agl = 50000;
    gps->hdop = 120;
    gps->vdop = 180;
    gps->speed_ground = (uint16_t)(fabsf(sinf(t * 0.2f)) * 500);
    gps->course = (int16_t)(fmodf(t * 10, 360.0f) * 100);
    gps->fix_type = GPS_FIX_3D;
    gps->satellites = 12;
    gps->accuracy_h = 2000;
    gps->accuracy_v = 3000;

    s_flight_state.lat = gps->latitude;
    s_flight_state.lon = gps->longitude;
    s_flight_state.altitude = gps->altitude_msl / 1000.0f;
}

/**
 * @brief Generate simulated attitude data
 */
static void simulate_attitude(bbox_msg_attitude_t *att)
{
    att->timestamp_us = s_hal->get_time_us();
    att->roll = s_flight_state.roll;
    att->pitch = s_flight_state.pitch;
    att->yaw = s_flight_state.yaw;
    att->rollspeed = 0.0f;
    att->pitchspeed = 0.0f;
    att->yawspeed = 0.0f;
}

/**
 * @brief Generate simulated PID data
 */
static void simulate_pid(bbox_msg_pid_t *pid, uint8_t axis)
{
    uint64_t now_us = s_hal->get_time_us();
    float t = now_us / 1000000.0f;
    float noise = ((float)(rand() % 100) - 50) / 500.0f;

    float current = (axis == 0) ? s_flight_state.roll :
                    (axis == 1) ? s_flight_state.pitch : s_flight_state.yaw;

    pid->timestamp_us = now_us;
    pid->setpoint = sinf(t * 0.2f) * 0.1f;
    pid->error = pid->setpoint - current;
    pid->p_term = pid->error * 4.5f;
    pid->i_term = pid->error * 0.01f;
    pid->d_term = noise * 0.5f;
    pid->output = pid->p_term + pid->i_term + pid->d_term;
    pid->ff_term = 0.0f;
    
    if (pid->output > 1.0f) pid->output = 1.0f;
    if (pid->output < -1.0f) pid->output = -1.0f;
}

/**
 * @brief Generate simulated motor output data
 */
static void simulate_motors(bbox_msg_motor_t *motor)
{
    float t = s_hal->get_time_us() / 1000000.0f;
    float throttle_base = 0.5f + 0.1f * sinf(t * 0.3f);
    float roll_mix = s_flight_state.roll * 0.1f;
    float pitch_mix = s_flight_state.pitch * 0.1f;

    motor->timestamp_us = s_hal->get_time_us();
    motor->motor[0] = (uint16_t)((throttle_base - roll_mix - pitch_mix) * 2000 + 1000);
    motor->motor[1] = (uint16_t)((throttle_base + roll_mix - pitch_mix) * 2000 + 1000);
    motor->motor[2] = (uint16_t)((throttle_base + roll_mix + pitch_mix) * 2000 + 1000);
    motor->motor[3] = (uint16_t)((throttle_base - roll_mix + pitch_mix) * 2000 + 1000);
    motor->motor[4] = 0;
    motor->motor[5] = 0;
    motor->motor[6] = 0;
    motor->motor[7] = 0;
    motor->motor_count = 4;
    motor->armed = 1;
}

/**
 * @brief Generate simulated battery data
 */
static void simulate_battery(bbox_msg_battery_t *battery)
{
    static float voltage = 16.8f;  /* 4S LiPo full */
    static float mah_used = 0.0f;
    
    /* Slow discharge */
    voltage -= 0.0001f;
    mah_used += 0.1f;
    
    if (voltage < 14.0f) voltage = 14.0f;  /* Clamp */

    battery->timestamp_us = s_hal->get_time_us();
    battery->voltage = (uint16_t)(voltage * 1000);   /* mV */
    battery->current = -15000;   /* -15A (discharging) */
    battery->consumed = (int32_t)mah_used;
    battery->remaining = (uint8_t)((voltage - 14.0f) / (16.8f - 14.0f) * 100);
    battery->temperature = 35;   /* 35°C */
    battery->cell_count = 4;
}

/**
 * @brief Print usage
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  --format bbox      Use BBOX native format (default)\n");
    printf("  --format ulog      Use PX4 ULog format (.ulg)\n");
    printf("  --format ardupilot Use ArduPilot DataFlash format (.bin)\n");
    printf("  --single-threaded  Use polling mode instead of background thread\n");
    printf("  --duration <sec>   Run for specified seconds (default: infinite)\n");
    printf("  --rate <hz>        Sample rate in Hz (default: 100)\n");
    printf("  -h, --help         Show this help\n");
}

int main(int argc, char *argv[])
{
    bbox_format_t format = BBOX_FORMAT_BBOX;
    int single_threaded = 0;
    int duration = 0;
    int rate_hz = 100;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "bbox") == 0) {
                format = BBOX_FORMAT_BBOX;
            } else if (strcmp(argv[i], "ulog") == 0) {
                format = BBOX_FORMAT_PX4_ULOG;
            } else if (strcmp(argv[i], "ardupilot") == 0) {
                format = BBOX_FORMAT_ARDUPILOT;
            } else {
                fprintf(stderr, "Unknown format: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--single-threaded") == 0) {
            single_threaded = 1;
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            rate_hz = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    printf("=== Blackbox Flight Data Logger (Linux/macOS) ===\n\n");
    
    /* Setup */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    srand((unsigned int)time(NULL));
    
    /* Create log directory */
    const char *log_path = "/tmp/blackbox_flight";
    struct stat st;
    if (stat(log_path, &st) != 0) {
        mkdir(log_path, 0755);
    }
    
    /* Get HAL */
    s_hal = bbox_hal_posix_get();
    
    /* Configure logger */
    bbox_config_t config;
    bbox_get_default_config(&config);
    
    config.root_path = log_path;
    config.file_prefix = "flight";
    config.log_format = format;
    config.encrypt = false;
    config.file_size_limit = 1 * 1024 * 1024;  /* 1MB per file */
    config.buffer_size = 64 * 1024;             /* 64KB buffer */
    config.min_level = BBOX_LOG_LEVEL_INFO;
    config.console_output = false;
    config.file_output = true;
    config.single_threaded = single_threaded;
    
    const char *format_names[] = {"BBOX", "PX4 ULog", "ArduPilot DataFlash"};
    printf("Log format: %s\n", format_names[format]);
    printf("Sample rate: %d Hz\n", rate_hz);
    printf("Mode: %s\n", single_threaded ? "polling" : "background thread");
    printf("Log directory: %s\n\n", log_path);
    
    /* Initialize */
    bbox_err_t ret = bbox_init(&config, s_hal);
    if (ret != BBOX_OK) {
        fprintf(stderr, "Failed to initialize: %d\n", ret);
        return 1;
    }
    
    BBOX_LOG_I(TAG, "Flight data logging started");
    
    /* Main loop */
    int sample_count = 0;
    int sleep_us = 1000000 / rate_hz;
    time_t start_time = time(NULL);
    time_t last_print = start_time;
    
    printf("Logging flight data... Press Ctrl+C to stop.\n");
    
    while (s_running) {
        /* Check duration */
        if (duration > 0 && (time(NULL) - start_time) >= duration) {
            break;
        }
        
        /* Log IMU at full rate */
        bbox_msg_imu_t imu;
        simulate_imu(&imu);
        bbox_log_imu(&imu);
        
        /* Log attitude at full rate */
        bbox_msg_attitude_t att;
        simulate_attitude(&att);
        bbox_log_attitude(&att);
        
        /* Log motors at full rate */
        bbox_msg_motor_t motor;
        simulate_motors(&motor);
        bbox_log_motor(&motor);
        
        /* Log PID for all axes at half rate */
        if (sample_count % 2 == 0) {
            bbox_msg_pid_t pid;
            simulate_pid(&pid, 0);
            bbox_log_pid(BBOX_MSG_PID_ROLL, &pid);
            simulate_pid(&pid, 1);
            bbox_log_pid(BBOX_MSG_PID_PITCH, &pid);
            simulate_pid(&pid, 2);
            bbox_log_pid(BBOX_MSG_PID_YAW, &pid);
        }
        
        /* Log GPS at 10Hz */
        if (sample_count % (rate_hz / 10) == 0) {
            bbox_msg_gps_t gps;
            simulate_gps(&gps);
            bbox_log_gps(&gps);
        }
        
        /* Log battery at 1Hz */
        if (sample_count % rate_hz == 0) {
            bbox_msg_battery_t battery;
            simulate_battery(&battery);
            bbox_log_battery(&battery);
        }
        
        /* Process if single-threaded */
        if (single_threaded) {
            bbox_process();
        }
        
        sample_count++;
        
        /* Print progress every second */
        time_t now = time(NULL);
        if (now > last_print) {
            bbox_stats_t stats;
            bbox_get_stats(&stats);
            printf("\r[%llds] Samples: %d, Written: %lluKB, Dropped: %llu    ",
                   (long long)(now - start_time),
                   sample_count,
                   (unsigned long long)(stats.bytes_written / 1024),
                   (unsigned long long)stats.messages_dropped);
            fflush(stdout);
            last_print = now;
        }
        
        usleep(sleep_us);
    }
    
    printf("\n\nShutting down...\n");
    
    /* Flush and get final stats */
    bbox_flush();
    usleep(200000);
    
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    
    char filepath[256];
    bbox_get_current_file(filepath, sizeof(filepath));
    
    printf("\n=== Final Statistics ===\n");
    printf("Total samples:     %d\n", sample_count);
    printf("Messages logged:   %llu\n", (unsigned long long)stats.messages_logged);
    printf("Struct messages:   %llu\n", (unsigned long long)stats.struct_messages);
    printf("Messages dropped:  %llu\n", (unsigned long long)stats.messages_dropped);
    printf("Bytes written:     %llu (%.2f MB)\n",
           (unsigned long long)stats.bytes_written,
           stats.bytes_written / (1024.0 * 1024.0));
    printf("Files created:     %u\n", stats.files_created);
    printf("Current file:      %s\n", filepath);
    
    bbox_deinit();
    
    printf("\nUse the decoder to analyze:\n");
    if (format == BBOX_FORMAT_BBOX) {
        printf("  python3 tools/blackbox_decoder.py %s\n", filepath);
    } else if (format == BBOX_FORMAT_PX4_ULOG) {
        printf("  ulog_info %s\n", filepath);
        printf("  ulog2csv %s\n", filepath);
    } else {
        printf("  Use Mission Planner or MAVExplorer to open %s\n", filepath);
    }
    
    return 0;
}
