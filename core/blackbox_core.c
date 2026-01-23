/**
 * @file blackbox_core.c
 * @brief Blackbox Logger Core Implementation (Platform Independent)
 *
 * This file contains the core logging logic with no platform dependencies.
 * All platform-specific operations go through the HAL interface.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#include "include/blackbox.h"
#include "core/blackbox_ringbuf.h"
#include "core/blackbox_encoder.h"

#include <stdio.h>
#include <string.h>

/*******************************************************************************
 * Configuration
 ******************************************************************************/

#ifndef BBOX_WRITER_TASK_STACK_SIZE
#define BBOX_WRITER_TASK_STACK_SIZE 4096
#endif

#ifndef BBOX_WRITER_TASK_PRIORITY
#define BBOX_WRITER_TASK_PRIORITY 2
#endif

/*******************************************************************************
 * Internal State
 ******************************************************************************/

typedef struct {
    bool initialized;
    bbox_config_t config;
    const bbox_hal_t *hal;
    
    /* Deep-copied config strings */
    char root_path[BLACKBOX_MAX_PATH_LENGTH];
    char file_prefix[32];
    
    /* Ring buffer */
    bbox_ringbuf_t ringbuf;
    uint8_t *ringbuf_mem;
    
    /* File management */
    bbox_file_t current_file;
    char current_file_path[BLACKBOX_MAX_PATH_LENGTH];
    size_t current_file_size;
    uint32_t file_counter;
    void *file_mutex;          /* Optional: file access mutex */
    
    /* Format encoder */
    bbox_encoder_ctx_t encoder;
    
    /* Encryption (optional) */
    void *cipher_ctx;
    uint8_t iv[16];
    
    /* Background task (optional) */
    void *writer_task;
    void *flush_sem;
    void *shutdown_sem;
    volatile bool shutdown_requested;
    
    /* Statistics */
    bbox_stats_t stats;
    void *stats_mutex;         /* Optional: stats access mutex */
    
    /* Runtime settings */
    volatile bbox_log_level_t min_level;
    volatile bool console_output;
    volatile bool file_output;
    
} bbox_state_t;

static bbox_state_t s_bbox = {0};

static const char *TAG = "BLACKBOX";

/*******************************************************************************
 * Forward Declarations
 ******************************************************************************/

static bbox_err_t create_new_log_file(void);
static bbox_err_t write_file_header(void);
static bbox_err_t write_data_to_file(const void *data, size_t len);
static void close_current_file(void);
static bbox_err_t process_ringbuf(void);
static void writer_task_func(void *arg);

/*******************************************************************************
 * HAL Wrapper Macros
 ******************************************************************************/

#define HAL_LOG_INFO(fmt, ...) \
    bbox_hal_log_info(s_bbox.hal, TAG, fmt, ##__VA_ARGS__)

#define HAL_LOG_ERROR(fmt, ...) \
    bbox_hal_log_error(s_bbox.hal, TAG, fmt, ##__VA_ARGS__)

#define HAL_MALLOC(size) bbox_hal_malloc(s_bbox.hal, size)
#define HAL_FREE(ptr) bbox_hal_free(s_bbox.hal, ptr)

/*******************************************************************************
 * Initialization
 ******************************************************************************/

void bbox_get_default_config(bbox_config_t *config)
{
    if (!config) return;
    
    memset(config, 0, sizeof(bbox_config_t));
    config->root_path = "/logs";
    config->file_prefix = "flight";
    config->log_format = BBOX_FORMAT_BBOX;
    config->encrypt = false;
    config->buffer_size = BLACKBOX_DEFAULT_BUFFER_SIZE;
    config->file_size_limit = BLACKBOX_DEFAULT_FILE_SIZE_LIMIT;
    config->flush_interval_ms = BLACKBOX_DEFAULT_FLUSH_INTERVAL;
    config->min_level = BBOX_LOG_LEVEL_INFO;
    config->console_output = true;
    config->file_output = true;
    config->single_threaded = false;
}

bbox_err_t bbox_init(const bbox_config_t *config, const bbox_hal_t *hal)
{
    if (s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    if (!config || !hal) {
        return BBOX_ERR_INVALID_ARG;
    }
    
    /* Validate HAL */
    bbox_err_t err = bbox_hal_validate(hal);
    if (err != BBOX_OK) {
        return err;
    }
    
    /* Store HAL pointer */
    s_bbox.hal = hal;
    
    /* Validate encryption requirements */
    if (config->encrypt && !bbox_hal_has_crypto(hal)) {
        HAL_LOG_ERROR("Encryption requested but HAL has no crypto support");
        return BBOX_ERR_NOT_SUPPORTED;
    }
    
    /* Validate threading requirements */
    if (!config->single_threaded && !bbox_hal_has_threading(hal)) {
        HAL_LOG_ERROR("Background task requested but HAL has no threading support");
        return BBOX_ERR_NOT_SUPPORTED;
    }
    
    /* Copy configuration */
    memcpy(&s_bbox.config, config, sizeof(bbox_config_t));
    
    /* Deep copy string config */
    if (config->root_path) {
        strncpy(s_bbox.root_path, config->root_path, sizeof(s_bbox.root_path) - 1);
        s_bbox.config.root_path = s_bbox.root_path;
    }
    
    const char *prefix = config->file_prefix ? config->file_prefix : "flight";
    strncpy(s_bbox.file_prefix, prefix, sizeof(s_bbox.file_prefix) - 1);
    s_bbox.config.file_prefix = s_bbox.file_prefix;
    
    /* Apply defaults */
    if (s_bbox.config.buffer_size < BLACKBOX_MIN_BUFFER_SIZE) {
        s_bbox.config.buffer_size = BLACKBOX_MIN_BUFFER_SIZE;
    }
    if (s_bbox.config.flush_interval_ms == 0) {
        s_bbox.config.flush_interval_ms = BLACKBOX_DEFAULT_FLUSH_INTERVAL;
    }
    if (s_bbox.config.file_size_limit == 0) {
        s_bbox.config.file_size_limit = BLACKBOX_DEFAULT_FILE_SIZE_LIMIT;
    }
    
    /* Allocate ring buffer memory */
    s_bbox.ringbuf_mem = (uint8_t *)HAL_MALLOC(s_bbox.config.buffer_size);
    if (!s_bbox.ringbuf_mem) {
        HAL_LOG_ERROR("Failed to allocate ring buffer");
        return BBOX_ERR_NO_MEM;
    }
    
    /* Initialize ring buffer */
    if (!bbox_ringbuf_init(&s_bbox.ringbuf, s_bbox.ringbuf_mem, s_bbox.config.buffer_size)) {
        HAL_FREE(s_bbox.ringbuf_mem);
        return BBOX_ERR_INVALID_ARG;
    }
    
    /* Create mutexes if threading is available */
    if (bbox_hal_has_threading(hal)) {
        s_bbox.file_mutex = hal->mutex_create();
        s_bbox.stats_mutex = hal->mutex_create();
        
        if (!s_bbox.file_mutex || !s_bbox.stats_mutex) {
            HAL_LOG_ERROR("Failed to create mutexes");
            goto cleanup;
        }
    }
    
    /* Initialize encryption if enabled */
    if (config->encrypt && bbox_hal_has_crypto(hal)) {
        s_bbox.cipher_ctx = hal->aes_init(config->encryption_key, 32);
        if (!s_bbox.cipher_ctx) {
            HAL_LOG_ERROR("Failed to initialize encryption");
            goto cleanup;
        }
    }
    
    /* Initialize format encoder */
    bbox_encoder_init(&s_bbox.encoder, config->log_format);
    
    /* Initialize file state */
    s_bbox.current_file = BBOX_FILE_INVALID;
    s_bbox.file_counter = 0;
    s_bbox.current_file_size = 0;
    
    /* Initialize runtime settings */
    s_bbox.min_level = config->min_level;
    s_bbox.console_output = config->console_output;
    s_bbox.file_output = config->file_output;
    s_bbox.shutdown_requested = false;
    
    /* Reset statistics */
    memset(&s_bbox.stats, 0, sizeof(bbox_stats_t));
    
    /* Create log directory if HAL supports it */
    if (hal->mkdir && hal->file_exists) {
        if (!hal->file_exists(s_bbox.root_path)) {
            hal->mkdir(s_bbox.root_path);
        }
    }
    
    /* Create background writer task if not single-threaded */
    if (!config->single_threaded && bbox_hal_has_threading(hal)) {
        s_bbox.flush_sem = hal->sem_create();
        s_bbox.shutdown_sem = hal->sem_create();
        
        if (!s_bbox.flush_sem || !s_bbox.shutdown_sem) {
            HAL_LOG_ERROR("Failed to create semaphores");
            goto cleanup;
        }
        
        s_bbox.writer_task = hal->task_create(
            writer_task_func,
            "bbox_writer",
            BBOX_WRITER_TASK_STACK_SIZE,
            NULL,
            BBOX_WRITER_TASK_PRIORITY
        );
        
        if (!s_bbox.writer_task) {
            HAL_LOG_ERROR("Failed to create writer task");
            goto cleanup;
        }
    }
    
    s_bbox.initialized = true;
    
    HAL_LOG_INFO("Initialized: path=%s, format=%s, buffer=%uKB",
                 s_bbox.root_path,
                 bbox_format_name(config->log_format),
                 (unsigned)(s_bbox.config.buffer_size / 1024));
    
    return BBOX_OK;

cleanup:
    if (s_bbox.cipher_ctx && hal->aes_free) {
        hal->aes_free(s_bbox.cipher_ctx);
    }
    if (s_bbox.file_mutex && hal->mutex_destroy) {
        hal->mutex_destroy(s_bbox.file_mutex);
    }
    if (s_bbox.stats_mutex && hal->mutex_destroy) {
        hal->mutex_destroy(s_bbox.stats_mutex);
    }
    if (s_bbox.flush_sem && hal->sem_destroy) {
        hal->sem_destroy(s_bbox.flush_sem);
    }
    if (s_bbox.shutdown_sem && hal->sem_destroy) {
        hal->sem_destroy(s_bbox.shutdown_sem);
    }
    HAL_FREE(s_bbox.ringbuf_mem);
    memset(&s_bbox, 0, sizeof(s_bbox));
    
    return BBOX_ERR_HAL;
}

bbox_err_t bbox_deinit(void)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    const bbox_hal_t *hal = s_bbox.hal;
    
    HAL_LOG_INFO("Shutting down...");
    
    /* Signal writer task to exit */
    if (s_bbox.writer_task) {
        s_bbox.shutdown_requested = true;
        if (s_bbox.flush_sem && hal->sem_give) {
            hal->sem_give(s_bbox.flush_sem);
        }
        
        /* Wait for task to complete */
        if (s_bbox.shutdown_sem && hal->sem_take) {
            hal->sem_take(s_bbox.shutdown_sem, 5000);
        }
        
        if (hal->task_delete) {
            hal->task_delete(s_bbox.writer_task);
        }
        s_bbox.writer_task = NULL;
    }
    
    /* Process any remaining data (for single-threaded mode) */
    process_ringbuf();
    
    /* Close current file */
    close_current_file();
    
    /* Free encryption context */
    if (s_bbox.cipher_ctx && hal->aes_free) {
        hal->aes_free(s_bbox.cipher_ctx);
    }
    
    /* Delete synchronization primitives */
    if (s_bbox.file_mutex && hal->mutex_destroy) {
        hal->mutex_destroy(s_bbox.file_mutex);
    }
    if (s_bbox.stats_mutex && hal->mutex_destroy) {
        hal->mutex_destroy(s_bbox.stats_mutex);
    }
    if (s_bbox.flush_sem && hal->sem_destroy) {
        hal->sem_destroy(s_bbox.flush_sem);
    }
    if (s_bbox.shutdown_sem && hal->sem_destroy) {
        hal->sem_destroy(s_bbox.shutdown_sem);
    }
    
    /* Free ring buffer */
    HAL_FREE(s_bbox.ringbuf_mem);
    
    HAL_LOG_INFO("Shutdown complete");
    
    memset(&s_bbox, 0, sizeof(s_bbox));
    
    return BBOX_OK;
}

bool bbox_is_initialized(void)
{
    return s_bbox.initialized;
}

/*******************************************************************************
 * Text Logging
 ******************************************************************************/

void bbox_log(bbox_log_level_t level, const char *tag, const char *file,
              uint32_t line, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    bbox_log_va(level, tag, file, line, fmt, args);
    va_end(args);
}

void bbox_log_va(bbox_log_level_t level, const char *tag, const char *file,
                 uint32_t line, const char *fmt, va_list args)
{
    if (!s_bbox.initialized) {
        return;
    }
    
    /* Level filter */
    if (level > s_bbox.min_level || level == BBOX_LOG_LEVEL_NONE) {
        return;
    }
    
    /* Format message */
    char message[BLACKBOX_MAX_MESSAGE_SIZE];
    int len = vsnprintf(message, sizeof(message), fmt, args);
    if (len < 0) len = 0;
    if (len >= (int)sizeof(message)) len = sizeof(message) - 1;
    message[len] = '\0';
    
    /* Console output */
    if (s_bbox.console_output && s_bbox.hal->log_output) {
        va_list args_copy;
        va_copy(args_copy, args);
        s_bbox.hal->log_output(tag, level, fmt, args_copy);
        va_end(args_copy);
    }
    
    /* File output - skip for binary-only formats (ArduPilot, ULog) */
    if (s_bbox.file_output && 
        s_bbox.config.log_format != BBOX_FORMAT_ARDUPILOT &&
        s_bbox.config.log_format != BBOX_FORMAT_PX4_ULOG) {
        bbox_packet_t packet;
        uint64_t timestamp = s_bbox.hal->get_time_us();
        
        size_t packet_size = bbox_encode_text_packet(
            &packet, level, timestamp, tag, file, line, message);
        
        /* Push to ring buffer (lock-free) */
        if (bbox_ringbuf_write(&s_bbox.ringbuf, &packet, packet_size)) {
            s_bbox.stats.messages_logged++;
            
            /* Signal writer task */
            if (s_bbox.flush_sem && s_bbox.hal->sem_give) {
                s_bbox.hal->sem_give(s_bbox.flush_sem);
            }
        } else {
            s_bbox.stats.messages_dropped++;
        }
    }
}

/*******************************************************************************
 * Structured Message Logging
 ******************************************************************************/

/**
 * @brief Encode a message in the current format
 */
static size_t encode_message(
    uint8_t *buffer,
    size_t buffer_size,
    bbox_msg_id_t msg_id,
    uint64_t timestamp,
    const void *data,
    size_t size)
{
    switch (s_bbox.config.log_format) {
        case BBOX_FORMAT_ARDUPILOT: {
            /* ArduPilot DataFlash format */
            const char *name, *format, *labels;
            uint8_t msg_type;
            
            if (!bbox_get_dataflash_fmt_info(msg_id, &name, &format, &labels, &msg_type)) {
                return 0;
            }
            
            /* Get message size for FMT record */
            uint8_t msg_length = 0;
            if (msg_id == BBOX_MSG_PID_ROLL || msg_id == BBOX_MSG_PID_PITCH || 
                msg_id == BBOX_MSG_PID_YAW || msg_id == BBOX_MSG_PID_ALT) {
                msg_length = sizeof(dataflash_pid_msg_t);
            } else if (msg_id == BBOX_MSG_ATTITUDE) {
                msg_length = sizeof(dataflash_att_msg_t);
            } else if (msg_id == BBOX_MSG_IMU) {
                msg_length = sizeof(dataflash_imu_msg_t);
            } else {
                msg_length = 3 + size;  /* header + raw data */
            }
            
            size_t offset = 0;
            
            /* Write FMT message if first time seeing this message type */
            if (!s_bbox.encoder.format_written[msg_type]) {
                /* Write FMT message */
                size_t fmt_size = bbox_encode_dataflash_fmt(
                    buffer + offset, msg_type, msg_length, name, format, labels);
                offset += fmt_size;
                
                /* Write FMTU message for Mission Planner compatibility */
                const char *unit_ids, *mult_ids;
                if (bbox_get_dataflash_fmtu_info(msg_type, &unit_ids, &mult_ids)) {
                    offset += bbox_encode_dataflash_fmtu(
                        buffer + offset, timestamp, msg_type, unit_ids, mult_ids);
                }
                
                s_bbox.encoder.format_written[msg_type] = true;
            }
            
            /* Encode based on message type */
            if (msg_id == BBOX_MSG_PID_ROLL || msg_id == BBOX_MSG_PID_PITCH || 
                msg_id == BBOX_MSG_PID_YAW || msg_id == BBOX_MSG_PID_ALT) {
                const bbox_msg_pid_t *pid = (const bbox_msg_pid_t *)data;
                size_t msg_size = bbox_encode_dataflash_pid(
                    buffer + offset, buffer_size - offset,
                    msg_type, timestamp,
                    pid->setpoint, pid->measured, pid->error,
                    pid->p_term, pid->i_term, pid->d_term,
                    pid->ff_term, pid->output, pid->axis);
                return offset + msg_size;
            }
            else if (msg_id == BBOX_MSG_ATTITUDE) {
                const bbox_msg_attitude_t *att = (const bbox_msg_attitude_t *)data;
                size_t msg_size = bbox_encode_dataflash_att(
                    buffer + offset, buffer_size - offset,
                    timestamp, att->roll, att->pitch, att->yaw,
                    att->rollspeed, att->pitchspeed, att->yawspeed);
                return offset + msg_size;
            }
            else if (msg_id == BBOX_MSG_IMU) {
                const bbox_msg_imu_t *imu = (const bbox_msg_imu_t *)data;
                size_t msg_size = bbox_encode_dataflash_imu(
                    buffer + offset, buffer_size - offset,
                    timestamp,
                    imu->accel_x, imu->accel_y, imu->accel_z,
                    imu->gyro_x, imu->gyro_y, imu->gyro_z,
                    imu->temperature, imu->imu_id);
                return offset + msg_size;
            }
            else {
                /* Generic: just write header + raw data */
                if (buffer_size - offset < 3 + size) {
                    return 0;
                }
                bbox_encode_dataflash_header(buffer + offset, msg_type);
                offset += 3;
                memcpy(buffer + offset, data, size);
                return offset + size;
            }
        }
        
        case BBOX_FORMAT_PX4_ULOG:
            /* TODO: Proper ULog encoding with message definitions */
            /* Fall through to BBOX for now */
            
        case BBOX_FORMAT_BBOX:
        default:
            return bbox_encode_struct_packet(buffer, buffer_size, msg_id, timestamp, data, size);
    }
}

bbox_err_t bbox_log_struct(bbox_msg_id_t msg_id, const void *data, size_t size)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    if (!data || size == 0) {
        return BBOX_ERR_INVALID_ARG;
    }
    
    if (!s_bbox.file_output) {
        return BBOX_OK;
    }
    
    /* Encode message in appropriate format */
    uint8_t buffer[512];
    uint64_t timestamp = s_bbox.hal->get_time_us();
    
    size_t packet_size = encode_message(buffer, sizeof(buffer), msg_id, timestamp, data, size);
    
    if (packet_size == 0) {
        return BBOX_ERR_BUFFER_FULL;
    }
    
    /* Push to ring buffer */
    if (bbox_ringbuf_write(&s_bbox.ringbuf, buffer, packet_size)) {
        s_bbox.stats.struct_messages++;
        s_bbox.stats.messages_logged++;
        
        /* Signal writer task */
        if (s_bbox.flush_sem && s_bbox.hal->sem_give) {
            s_bbox.hal->sem_give(s_bbox.flush_sem);
        }
        
        return BBOX_OK;
    }
    
    s_bbox.stats.messages_dropped++;
    return BBOX_ERR_BUFFER_FULL;
}

bbox_err_t bbox_log_imu(const bbox_msg_imu_t *imu)
{
    return bbox_log_struct(BBOX_MSG_IMU, imu, sizeof(*imu));
}

bbox_err_t bbox_log_gps(const bbox_msg_gps_t *gps)
{
    return bbox_log_struct(BBOX_MSG_GPS, gps, sizeof(*gps));
}

bbox_err_t bbox_log_attitude(const bbox_msg_attitude_t *att)
{
    return bbox_log_struct(BBOX_MSG_ATTITUDE, att, sizeof(*att));
}

bbox_err_t bbox_log_pid(bbox_msg_id_t axis, const bbox_msg_pid_t *pid)
{
    return bbox_log_struct(axis, pid, sizeof(*pid));
}

bbox_err_t bbox_log_motor(const bbox_msg_motor_t *motor)
{
    return bbox_log_struct(BBOX_MSG_MOTOR, motor, sizeof(*motor));
}

bbox_err_t bbox_log_battery(const bbox_msg_battery_t *battery)
{
    return bbox_log_struct(BBOX_MSG_BATTERY, battery, sizeof(*battery));
}

bbox_err_t bbox_log_rc_input(const bbox_msg_rc_input_t *rc)
{
    return bbox_log_struct(BBOX_MSG_RC_INPUT, rc, sizeof(*rc));
}

bbox_err_t bbox_log_status(const bbox_msg_status_t *status)
{
    return bbox_log_struct(BBOX_MSG_STATUS, status, sizeof(*status));
}

bbox_err_t bbox_log_baro(const bbox_msg_baro_t *baro)
{
    return bbox_log_struct(BBOX_MSG_BARO, baro, sizeof(*baro));
}

bbox_err_t bbox_log_mag(const bbox_msg_mag_t *mag)
{
    return bbox_log_struct(BBOX_MSG_MAG, mag, sizeof(*mag));
}

bbox_err_t bbox_log_esc(const bbox_msg_esc_t *esc)
{
    return bbox_log_struct(BBOX_MSG_ESC, esc, sizeof(*esc));
}

/*******************************************************************************
 * File Management
 ******************************************************************************/

static bbox_err_t create_new_log_file(void)
{
    const bbox_hal_t *hal = s_bbox.hal;
    
    /* Close existing file */
    close_current_file();
    
    /* Generate new filename */
    s_bbox.file_counter++;
    
    const char *ext = bbox_format_extension(s_bbox.config.log_format);
    snprintf(s_bbox.current_file_path, sizeof(s_bbox.current_file_path),
             "%s/%s%06u.%s",
             s_bbox.root_path,
             s_bbox.file_prefix,
             (unsigned)s_bbox.file_counter,
             ext);
    
    /* Open file */
    s_bbox.current_file = hal->file_open(s_bbox.current_file_path, false);
    if (s_bbox.current_file == BBOX_FILE_INVALID) {
        HAL_LOG_ERROR("Failed to create: %s", s_bbox.current_file_path);
        return BBOX_ERR_IO;
    }
    
    s_bbox.current_file_size = 0;
    
    /* Generate fresh IV for encryption */
    if (s_bbox.config.encrypt && hal->random_fill && hal->aes_set_iv) {
        hal->random_fill(s_bbox.iv, sizeof(s_bbox.iv));
        hal->aes_set_iv(s_bbox.cipher_ctx, s_bbox.iv, sizeof(s_bbox.iv));
    }
    
    /* Write file header */
    bbox_err_t err = write_file_header();
    if (err != BBOX_OK) {
        hal->file_close(s_bbox.current_file);
        s_bbox.current_file = BBOX_FILE_INVALID;
        return err;
    }
    
    s_bbox.stats.files_created++;
    
    HAL_LOG_INFO("Created: %s", s_bbox.current_file_path);
    
    return BBOX_OK;
}

static bbox_err_t write_file_header(void)
{
    const bbox_hal_t *hal = s_bbox.hal;
    uint8_t header_buf[512];  /* Larger buffer for ArduPilot FMT+FMTU headers */
    size_t header_size = 0;
    
    switch (s_bbox.config.log_format) {
        case BBOX_FORMAT_PX4_ULOG: {
            header_size = bbox_encode_ulog_file_header(header_buf, hal->get_time_us());
            break;
        }
        
        case BBOX_FORMAT_ARDUPILOT: {
            /* Write complete ArduPilot DataFlash header for Mission Planner compatibility */
            uint64_t timestamp = hal->get_time_us();
            size_t offset = 0;
            
            /* 1. FMT message for FMT itself */
            offset += bbox_encode_dataflash_fmt(
                header_buf + offset, DF_MSG_FORMAT, sizeof(dataflash_fmt_msg_t),
                "FMT", "BBnNZ", "Type,Length,Name,Format,Columns");
            
            /* 2. FMT message for FMTU (Format Units) - required by Mission Planner */
            offset += bbox_encode_dataflash_fmt(
                header_buf + offset, DF_MSG_FMTU, sizeof(dataflash_fmtu_msg_t),
                "FMTU", "QBNN", "TimeUS,FmtType,UnitIds,MultIds");
            
            /* 3. FMTU data for FMTU itself */
            offset += bbox_encode_dataflash_fmtu(
                header_buf + offset, timestamp, DF_MSG_FMTU, "s---", "F---");
            
            /* 4. FMTU data for FMT */
            offset += bbox_encode_dataflash_fmtu(
                header_buf + offset, timestamp, DF_MSG_FORMAT, "-----", "-----");
            
            header_size = offset;
            break;
        }
        
        case BBOX_FORMAT_BBOX:
        default: {
            bbox_file_header_t *hdr = (bbox_file_header_t *)header_buf;
            memset(hdr, 0, sizeof(*hdr));
            
            hdr->magic[0] = BLACKBOX_LOG_MAGIC_BYTE0;
            hdr->magic[1] = BLACKBOX_LOG_MAGIC_BYTE1;
            hdr->magic[2] = BLACKBOX_LOG_MAGIC_BYTE2;
            hdr->magic[3] = BLACKBOX_LOG_MAGIC_BYTE3;
            hdr->version = BLACKBOX_LOG_VERSION;
            hdr->flags = s_bbox.config.encrypt ? 0x01 : 0x00;
            hdr->header_size = sizeof(bbox_file_header_t);
            hdr->timestamp_us = hal->get_time_us();
            
            /* Get device ID if available */
            if (hal->get_device_id) {
                hal->get_device_id(hdr->device_id, sizeof(hdr->device_id));
            }
            
            header_size = sizeof(bbox_file_header_t);
            
            /* Write IV if encrypted */
            if (s_bbox.config.encrypt) {
                size_t written = hal->file_write(s_bbox.current_file, hdr, header_size);
                if (written != header_size) {
                    return BBOX_ERR_IO;
                }
                s_bbox.current_file_size += written;
                
                /* Write IV after header */
                written = hal->file_write(s_bbox.current_file, s_bbox.iv, sizeof(s_bbox.iv));
                if (written != sizeof(s_bbox.iv)) {
                    return BBOX_ERR_IO;
                }
                s_bbox.current_file_size += written;
                s_bbox.stats.bytes_written += header_size + sizeof(s_bbox.iv);
                
                /* Reset encoder for new file */
                bbox_encoder_init(&s_bbox.encoder, s_bbox.config.log_format);
                
                return BBOX_OK;
            }
            break;
        }
    }
    
    /* Write header */
    size_t written = hal->file_write(s_bbox.current_file, header_buf, header_size);
    if (written != header_size) {
        return BBOX_ERR_IO;
    }
    
    s_bbox.current_file_size += written;
    s_bbox.stats.bytes_written += written;
    
    /* Reset encoder for new file */
    bbox_encoder_init(&s_bbox.encoder, s_bbox.config.log_format);
    
    return BBOX_OK;
}

static bbox_err_t write_data_to_file(const void *data, size_t len)
{
    const bbox_hal_t *hal = s_bbox.hal;
    
    /* Create file if needed */
    if (s_bbox.current_file == BBOX_FILE_INVALID) {
        bbox_err_t err = create_new_log_file();
        if (err != BBOX_OK) {
            return err;
        }
    }
    
    /* Check for rotation */
    if (s_bbox.current_file_size + len > s_bbox.config.file_size_limit) {
        bbox_err_t err = create_new_log_file();
        if (err != BBOX_OK) {
            return err;
        }
    }
    
    /* Write data (with encryption if enabled) */
    size_t written;
    
    if (s_bbox.config.encrypt && s_bbox.cipher_ctx && hal->aes_encrypt) {
        /* Encrypt in place (copy first) */
        uint8_t encrypted[512];
        size_t offset = 0;
        
        while (offset < len) {
            size_t chunk = (len - offset) > sizeof(encrypted) ? sizeof(encrypted) : (len - offset);
            
            hal->aes_encrypt(s_bbox.cipher_ctx, 
                            (const uint8_t *)data + offset,
                            encrypted, chunk);
            
            written = hal->file_write(s_bbox.current_file, encrypted, chunk);
            if (written != chunk) {
                s_bbox.stats.write_errors++;
                return BBOX_ERR_IO;
            }
            
            offset += chunk;
        }
        
        written = len;
    } else {
        written = hal->file_write(s_bbox.current_file, data, len);
        if (written != len) {
            s_bbox.stats.write_errors++;
            return BBOX_ERR_IO;
        }
    }
    
    s_bbox.current_file_size += written;
    s_bbox.stats.bytes_written += written;
    
    return BBOX_OK;
}

static void close_current_file(void)
{
    if (s_bbox.current_file != BBOX_FILE_INVALID) {
        s_bbox.hal->file_sync(s_bbox.current_file);
        s_bbox.hal->file_close(s_bbox.current_file);
        s_bbox.current_file = BBOX_FILE_INVALID;
        
        HAL_LOG_INFO("Closed: %s (%u bytes)",
                     s_bbox.current_file_path,
                     (unsigned)s_bbox.current_file_size);
    }
}

/*******************************************************************************
 * Ring Buffer Processing
 ******************************************************************************/

static bbox_err_t process_ringbuf(void)
{
    uint8_t buffer[512];
    size_t len;
    
    /* Lock file mutex if available */
    if (s_bbox.file_mutex && s_bbox.hal->mutex_lock) {
        s_bbox.hal->mutex_lock(s_bbox.file_mutex);
    }
    
    /* Process all available items */
    while (bbox_ringbuf_read(&s_bbox.ringbuf, buffer, sizeof(buffer), &len)) {
        write_data_to_file(buffer, len);
    }
    
    /* Update high water mark */
    size_t hwm = bbox_ringbuf_high_water(&s_bbox.ringbuf);
    if (hwm > s_bbox.stats.buffer_high_water) {
        s_bbox.stats.buffer_high_water = (uint32_t)hwm;
    }
    
    /* Unlock file mutex */
    if (s_bbox.file_mutex && s_bbox.hal->mutex_unlock) {
        s_bbox.hal->mutex_unlock(s_bbox.file_mutex);
    }
    
    return BBOX_OK;
}

/*******************************************************************************
 * Background Writer Task
 ******************************************************************************/

static void writer_task_func(void *arg)
{
    (void)arg;
    
    const bbox_hal_t *hal = s_bbox.hal;
    uint32_t flush_interval = s_bbox.config.flush_interval_ms;
    
    HAL_LOG_INFO("Writer task started");
    
    while (!s_bbox.shutdown_requested) {
        /* Wait for flush signal or timeout */
        if (s_bbox.flush_sem && hal->sem_take) {
            hal->sem_take(s_bbox.flush_sem, flush_interval);
        } else if (hal->task_delay_ms) {
            hal->task_delay_ms(flush_interval);
        }
        
        /* Process ring buffer */
        process_ringbuf();
        
        /* Periodic file sync */
        if (s_bbox.current_file != BBOX_FILE_INVALID) {
            hal->file_sync(s_bbox.current_file);
        }
    }
    
    /* Final drain */
    process_ringbuf();
    
    HAL_LOG_INFO("Writer task exiting");
    
    /* Signal completion */
    if (s_bbox.shutdown_sem && hal->sem_give) {
        hal->sem_give(s_bbox.shutdown_sem);
    }
}

/*******************************************************************************
 * Control Functions
 ******************************************************************************/

bbox_err_t bbox_flush(void)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    if (s_bbox.flush_sem && s_bbox.hal->sem_give) {
        s_bbox.hal->sem_give(s_bbox.flush_sem);
    }
    
    /* Small delay for background task to process */
    if (s_bbox.hal->task_delay_ms) {
        s_bbox.hal->task_delay_ms(50);
    }
    
    return BBOX_OK;
}

bbox_err_t bbox_process(void)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    return process_ringbuf();
}

bbox_err_t bbox_rotate_file(void)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    /* Lock file mutex if available */
    if (s_bbox.file_mutex && s_bbox.hal->mutex_lock) {
        s_bbox.hal->mutex_lock(s_bbox.file_mutex);
    }
    
    bbox_err_t err = create_new_log_file();
    
    if (s_bbox.file_mutex && s_bbox.hal->mutex_unlock) {
        s_bbox.hal->mutex_unlock(s_bbox.file_mutex);
    }
    
    return err;
}

bbox_err_t bbox_set_level(bbox_log_level_t level)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    s_bbox.min_level = level;
    return BBOX_OK;
}

bbox_log_level_t bbox_get_level(void)
{
    return s_bbox.min_level;
}

bbox_err_t bbox_set_console_output(bool enable)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    s_bbox.console_output = enable;
    return BBOX_OK;
}

bbox_err_t bbox_set_file_output(bool enable)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    s_bbox.file_output = enable;
    return BBOX_OK;
}

bbox_err_t bbox_get_stats(bbox_stats_t *stats)
{
    if (!s_bbox.initialized || !stats) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    /* Lock stats mutex if available */
    if (s_bbox.stats_mutex && s_bbox.hal->mutex_lock) {
        s_bbox.hal->mutex_lock(s_bbox.stats_mutex);
    }
    
    memcpy(stats, &s_bbox.stats, sizeof(bbox_stats_t));
    
    if (s_bbox.stats_mutex && s_bbox.hal->mutex_unlock) {
        s_bbox.hal->mutex_unlock(s_bbox.stats_mutex);
    }
    
    return BBOX_OK;
}

bbox_err_t bbox_reset_stats(void)
{
    if (!s_bbox.initialized) {
        return BBOX_ERR_INVALID_STATE;
    }
    
    if (s_bbox.stats_mutex && s_bbox.hal->mutex_lock) {
        s_bbox.hal->mutex_lock(s_bbox.stats_mutex);
    }
    
    memset(&s_bbox.stats, 0, sizeof(bbox_stats_t));
    
    if (s_bbox.stats_mutex && s_bbox.hal->mutex_unlock) {
        s_bbox.hal->mutex_unlock(s_bbox.stats_mutex);
    }
    
    return BBOX_OK;
}

bbox_format_t bbox_get_format(void)
{
    return s_bbox.config.log_format;
}

bbox_err_t bbox_get_current_file(char *buf, size_t buf_len)
{
    if (!s_bbox.initialized || !buf || buf_len == 0) {
        return BBOX_ERR_INVALID_ARG;
    }
    
    strncpy(buf, s_bbox.current_file_path, buf_len - 1);
    buf[buf_len - 1] = '\0';
    
    return BBOX_OK;
}
