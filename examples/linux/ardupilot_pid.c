/**
 * @file ardupilot_pid.c
 * @brief ArduPilot DataFlash PID Logging Example (Linux)
 *
 * This example demonstrates PID controller logging using ArduPilot's
 * DataFlash binary format (.bin). The output is compatible with:
 *
 *   - MAVExplorer (recommended for Linux)
 *   - Mission Planner Log Browser
 *   - APM Planner 2.0
 *   - dronekit-la
 *
 * ArduPilot PID Message Format:
 *   The standard PIDR/PIDP/PIDY messages contain:
 *   - Tar: Target/setpoint value
 *   - Act: Actual/measured value
 *   - Err: Error (Tar - Act)
 *   - P: Proportional term output
 *   - I: Integral term output
 *   - D: Derivative term output
 *   - FF: Feed-forward term
 *   - Out: Total output
 *
 * Build:
 *   make ardupilot_pid
 *
 * Run:
 *   ./ardupilot_pid
 *   ./ardupilot_pid --duration 30
 *
 * View with MAVExplorer:
 *   mavexplorer.py /tmp/blackbox_ardupilot/flight000001.bin
 *   # Then: Graph -> PIDR, PIDP, PIDY
 *
 * Install MAVExplorer:
 *   pip install MAVProxy
 *   # mavexplorer.py is included
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

static const char *TAG = "ARDUPILOT_PID";
static volatile int s_running = 1;
static const bbox_hal_t *s_hal = NULL;

/* Simulated flight controller state */
typedef struct {
    /* Attitude targets (from RC/navigation) */
    float roll_target;      /* rad */
    float pitch_target;     /* rad */
    float yaw_rate_target;  /* rad/s */
    
    /* Actual attitude (from sensors) */
    float roll;
    float pitch;
    float yaw;
    float roll_rate;
    float pitch_rate;
    float yaw_rate;
    
    /* PID states */
    float roll_i;
    float pitch_i;
    float yaw_i;
    float roll_prev_err;
    float pitch_prev_err;
    float yaw_prev_err;
} flight_state_t;

static flight_state_t s_state = {0};

/* PID gains (typical multirotor values) */
typedef struct {
    float kp;
    float ki;
    float kd;
    float ff;
    float i_max;
} pid_gains_t;

static const pid_gains_t ROLL_GAINS  = { .kp = 0.15f, .ki = 0.10f, .kd = 0.004f, .ff = 0.0f, .i_max = 0.5f };
static const pid_gains_t PITCH_GAINS = { .kp = 0.15f, .ki = 0.10f, .kd = 0.004f, .ff = 0.0f, .i_max = 0.5f };
static const pid_gains_t YAW_GAINS   = { .kp = 0.20f, .ki = 0.02f, .kd = 0.0f,   .ff = 0.0f, .i_max = 0.3f };

static void signal_handler(int sig)
{
    (void)sig;
    printf("\nShutting down...\n");
    s_running = 0;
}

/**
 * @brief Simulate stick input / navigation commands
 */
static void simulate_pilot_input(float t)
{
    /* Simulate gentle stick movements */
    s_state.roll_target = 0.1f * sinf(t * 0.5f);      /* ±5.7 deg roll */
    s_state.pitch_target = 0.08f * sinf(t * 0.3f);    /* ±4.6 deg pitch */
    s_state.yaw_rate_target = 0.2f * sinf(t * 0.2f);  /* ±11.5 deg/s yaw rate */
}

/**
 * @brief Simulate vehicle dynamics (simplified)
 */
static void simulate_vehicle_dynamics(float dt)
{
    /* Simple first-order response to attitude */
    float tau = 0.1f;  /* time constant */
    float alpha = dt / (tau + dt);
    
    /* Add some noise to simulate real sensors */
    float noise = ((rand() % 100) - 50) * 0.0001f;
    
    s_state.roll += alpha * (s_state.roll_target - s_state.roll) + noise;
    s_state.pitch += alpha * (s_state.pitch_target - s_state.pitch) + noise;
    s_state.yaw_rate += alpha * (s_state.yaw_rate_target - s_state.yaw_rate) + noise * 10;
    
    /* Compute rates */
    s_state.roll_rate = (s_state.roll_target - s_state.roll) / tau;
    s_state.pitch_rate = (s_state.pitch_target - s_state.pitch) / tau;
}

/**
 * @brief Compute PID and log output
 */
static void run_pid_and_log(float dt, uint8_t axis, 
                            float setpoint, float measured,
                            const pid_gains_t *gains,
                            float *i_term, float *prev_err)
{
    /* Compute PID terms */
    float error = setpoint - measured;
    float p_term = gains->kp * error;
    
    /* Integrate with anti-windup */
    *i_term += gains->ki * error * dt;
    if (*i_term > gains->i_max) *i_term = gains->i_max;
    if (*i_term < -gains->i_max) *i_term = -gains->i_max;
    
    /* Derivative on error */
    float d_term = 0.0f;
    if (dt > 0) {
        d_term = gains->kd * (error - *prev_err) / dt;
    }
    *prev_err = error;
    
    /* Feed-forward */
    float ff_term = gains->ff * setpoint;
    
    /* Total output */
    float output = p_term + *i_term + d_term + ff_term;
    
    /* Clamp output */
    if (output > 1.0f) output = 1.0f;
    if (output < -1.0f) output = -1.0f;
    
    /* Log PID data */
    bbox_msg_pid_t pid = {
        .timestamp_us = s_hal->get_time_us(),
        .setpoint = setpoint,
        .measured = measured,
        .error = error,
        .p_term = p_term,
        .i_term = *i_term,
        .d_term = d_term,
        .ff_term = ff_term,
        .output = output,
        .axis = axis
    };
    bbox_log_pid((bbox_msg_id_t)(BBOX_MSG_PID_ROLL + axis), &pid);
}

/**
 * @brief Log attitude for context
 */
static void log_attitude(void)
{
    bbox_msg_attitude_t att = {
        .timestamp_us = s_hal->get_time_us(),
        .roll = s_state.roll,
        .pitch = s_state.pitch,
        .yaw = s_state.yaw,
        .rollspeed = s_state.roll_rate,
        .pitchspeed = s_state.pitch_rate,
        .yawspeed = s_state.yaw_rate
    };
    bbox_log_attitude(&att);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  --duration <sec>   Run for specified seconds (default: 10)\n");
    printf("  --rate <hz>        PID loop rate in Hz (default: 400)\n");
    printf("  -h, --help         Show this help\n");
    printf("\nOutput:\n");
    printf("  Creates .bin files in /tmp/blackbox_ardupilot/\n");
    printf("  View with: mavexplorer.py <file.bin>\n");
}

int main(int argc, char *argv[])
{
    int duration_sec = 10;
    int rate_hz = 400;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration_sec = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            rate_hz = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    printf("=== ArduPilot PID Logging Example ===\n\n");
    printf("Format: ArduPilot DataFlash (.bin)\n");
    printf("Duration: %d seconds\n", duration_sec);
    printf("PID Rate: %d Hz\n", rate_hz);
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    srand((unsigned int)time(NULL));
    
    /* Create log directory */
    const char *log_path = "/tmp/blackbox_ardupilot";
    struct stat st;
    if (stat(log_path, &st) != 0) {
        mkdir(log_path, 0755);
    }
    printf("Log directory: %s\n\n", log_path);
    
    /* Get POSIX HAL */
    s_hal = bbox_hal_posix_get();
    
    /* Configure for ArduPilot format */
    bbox_config_t config;
    bbox_get_default_config(&config);
    config.root_path = log_path;
    config.log_format = BBOX_FORMAT_ARDUPILOT;  /* DataFlash format */
    config.file_prefix = "flight";
    config.buffer_size = 64 * 1024;
    config.file_size_limit = 10 * 1024 * 1024;  /* 10MB per file */
    config.single_threaded = false;
    config.encrypt = false;
    
    bbox_err_t err = bbox_init(&config, s_hal);
    if (err != BBOX_OK) {
        printf("Failed to initialize blackbox: %d\n", err);
        return 1;
    }
    
    BBOX_LOG_I(TAG, "ArduPilot PID logging started");
    BBOX_LOG_I(TAG, "PID Rate: %d Hz, Duration: %d sec", rate_hz, duration_sec);
    
    printf("Logging PID data... Press Ctrl+C to stop.\n\n");
    
    float dt = 1.0f / rate_hz;
    int usleep_time = (int)(1000000.0f / rate_hz);
    uint64_t start_time = s_hal->get_time_us();
    uint64_t end_time = start_time + (uint64_t)duration_sec * 1000000ULL;
    uint64_t last_print = start_time;
    uint32_t sample_count = 0;
    
    while (s_running && s_hal->get_time_us() < end_time) {
        uint64_t now = s_hal->get_time_us();
        float t = (now - start_time) / 1000000.0f;
        
        /* Simulate pilot input */
        simulate_pilot_input(t);
        
        /* Simulate vehicle dynamics */
        simulate_vehicle_dynamics(dt);
        
        /* Run PIDs and log */
        run_pid_and_log(dt, 0, s_state.roll_target, s_state.roll,
                       &ROLL_GAINS, &s_state.roll_i, &s_state.roll_prev_err);
        
        run_pid_and_log(dt, 1, s_state.pitch_target, s_state.pitch,
                       &PITCH_GAINS, &s_state.pitch_i, &s_state.pitch_prev_err);
        
        run_pid_and_log(dt, 2, s_state.yaw_rate_target, s_state.yaw_rate,
                       &YAW_GAINS, &s_state.yaw_i, &s_state.yaw_prev_err);
        
        /* Log attitude at 100Hz */
        if (sample_count % 4 == 0) {
            log_attitude();
        }
        
        sample_count++;
        
        /* Print progress every second */
        if (now - last_print >= 1000000) {
            bbox_stats_t stats;
            bbox_get_stats(&stats);
            int elapsed = (int)((now - start_time) / 1000000);
            printf("[%ds] Samples: %u, PID msgs: %lu, Written: %luKB\n",
                   elapsed, sample_count, stats.struct_messages, stats.bytes_written / 1024);
            last_print = now;
        }
        
        usleep(usleep_time);
    }
    
    /* Final statistics */
    bbox_stats_t stats;
    bbox_get_stats(&stats);
    
    printf("\n=== Final Statistics ===\n");
    printf("Total PID samples:  %u (x3 axes = %u messages)\n", sample_count, sample_count * 3);
    printf("Struct messages:    %llu\n", (unsigned long long)stats.struct_messages);
    printf("Messages dropped:   %llu\n", (unsigned long long)stats.messages_dropped);
    printf("Bytes written:      %llu (%.2f MB)\n", (unsigned long long)stats.bytes_written, 
           stats.bytes_written / (1024.0 * 1024.0));
    printf("Files created:      %u\n", stats.files_created);
    
    BBOX_LOG_I(TAG, "Logging complete. %u PID samples", sample_count);
    
    bbox_deinit();
    
    printf("\n=== How to View ===\n");
    printf("Install MAVProxy (includes MAVExplorer):\n");
    printf("  pip install MAVProxy\n\n");
    printf("Open log with MAVExplorer:\n");
    printf("  mavexplorer.py %s/flight000001.bin\n\n", log_path);
    printf("In MAVExplorer:\n");
    printf("  1. Click 'Graph' menu\n");
    printf("  2. Select PIDR (Roll), PIDP (Pitch), or PIDY (Yaw)\n");
    printf("  3. Choose fields: Tar, Act, P, I, D, Out\n");
    printf("\nAlternatively, use Mission Planner (Windows) Log Browser.\n");
    
    return 0;
}
