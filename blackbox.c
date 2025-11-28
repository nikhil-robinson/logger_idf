/**
 * @file blackbox.c
 * @brief blackbox Logger Library Implementation for ESP-IDF
 * 
 * Features:
 * - Lock-free ring buffer for non-blocking writes
 * - FreeRTOS writer task for file I/O
 * - Optional AES-256 encryption
 * - Automatic file rotation
 * - Console mirroring via ESP_LOG
 * 
 * @author Nikhil Robinson
 * @version 1.0.0
 */

#include "blackbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/ringbuf.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_attr.h"

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"

#include <stdatomic.h>

static const char* TAG = "BLACKBOX_LOG";

/*******************************************************************************
 * Private Structures
 ******************************************************************************/

/**
 * @brief Ring buffer entry header for internal use
 */
typedef struct {
    uint16_t total_size;    /**< Total size of this entry including header */
} ring_entry_header_t;

/**
 * @brief Logger state structure
 */
typedef struct {
    bool initialized;
    blackbox_config_t config;
    
    /* Ring buffer */
    RingbufHandle_t ring_buffer;
    
    /* Writer task */
    TaskHandle_t writer_task;
    SemaphoreHandle_t flush_sem;
    volatile bool shutdown_requested;
    
    /* File management */
    FILE* current_file;
    char current_file_path[BLACKBOX_LOG_MAX_PATH_LENGTH];
    size_t current_file_size;
    uint32_t file_counter;
    
    /* Encryption context */
    mbedtls_cipher_context_t cipher_ctx;
    uint8_t iv[16];
    uint32_t iv_counter;
    
    /* Statistics (atomic for lock-free hot path) */
    atomic_uint_fast64_t messages_logged;
    atomic_uint_fast64_t messages_dropped;
    blackbox_stats_t stats;
    SemaphoreHandle_t stats_mutex;
    
    /* Cached file hash to avoid repeated computation */
    uint32_t cached_file_hash;
    const char* cached_file_path;
    
    /* Cached tag hash to avoid repeated computation */
    uint32_t cached_tag_hash;
    const char* cached_tag_ptr;
    
    /* Runtime settings */
    blackbox_level_t min_level;
    bool console_output;
    bool file_output;
} blackbox_state_t;

static blackbox_state_t s_blackbox = {0};

/*******************************************************************************
 * Private Function Declarations
 ******************************************************************************/

static void writer_task(void* arg);
static esp_err_t create_new_log_file(void);
static esp_err_t write_file_header(void);
static esp_err_t write_packet_to_file(const blackbox_packet_t* packet, size_t packet_size);
static esp_err_t encrypt_and_write(const uint8_t* data, size_t len);
static void close_current_file(void);
static void console_output(blackbox_level_t level, const char* tag, const char* message);
static size_t build_blackbox_packet(blackbox_packet_t* packet, blackbox_level_t level, 
                                const char* tag, const char* file, uint32_t line,
                                const char* fmt, va_list args);

/*******************************************************************************
 * Inline Performance Helpers
 ******************************************************************************/

/**
 * @brief Get cached or compute file hash (reduces repeated hashing)
 */
static inline IRAM_ATTR uint32_t get_file_hash(const char* file)
{
    if (s_blackbox.cached_file_path == file) {
        return s_blackbox.cached_file_hash;
    }
    uint32_t hash = blackbox_hash_string(file);
    s_blackbox.cached_file_path = file;
    s_blackbox.cached_file_hash = hash;
    return hash;
}

/**
 * @brief Get cached or compute tag hash (reduces repeated hashing)
 */
static inline IRAM_ATTR uint32_t get_tag_hash(const char* tag)
{
    if (s_blackbox.cached_tag_ptr == tag) {
        return s_blackbox.cached_tag_hash;
    }
    uint32_t hash = blackbox_hash_string(tag);
    s_blackbox.cached_tag_ptr = tag;
    s_blackbox.cached_tag_hash = hash;
    return hash;
}

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

IRAM_ATTR uint32_t blackbox_hash_string(const char* str)
{
    if (str == NULL) {
        return 0;
    }
    
    /* FNV-1a hash - optimized for speed */
    uint32_t hash = 2166136261u;
    const uint8_t* p = (const uint8_t*)str;
    while (*p) {
        hash = (hash ^ *p++) * 16777619u;
    }
    return hash;
}

const char* blackbox_level_to_string(blackbox_level_t level)
{
    switch (level) {
        case BLACKBOX_LOG_LEVEL_ERROR:   return "ERROR";
        case BLACKBOX_LOG_LEVEL_WARN:    return "WARN";
        case BLACKBOX_LOG_LEVEL_INFO:    return "INFO";
        case BLACKBOX_LOG_LEVEL_DEBUG:   return "DEBUG";
        case BLACKBOX_LOG_LEVEL_VERBOSE: return "VERBOSE";
        default:                 return "UNKNOWN";
    }
}



/*******************************************************************************
 * Default Configuration
 ******************************************************************************/

void blackbox_get_default_config(blackbox_config_t* config)
{
    if (config == NULL) {
        return;
    }
    
    memset(config, 0, sizeof(blackbox_config_t));
    config->root_path = "/sdcard/logs";
    config->file_prefix = "flight";
    config->encrypt = false;
    config->file_size_limit = BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT;
    config->buffer_size = BLACKBOX_LOG_DEFAULT_BUFFER_SIZE;
    config->flush_interval_ms = BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS;
    config->min_level = BLACKBOX_LOG_LEVEL_INFO;
    config->console_output = true;
    config->file_output = true;
}

/*******************************************************************************
 * Initialization and Deinitialization
 ******************************************************************************/

esp_err_t blackbox_init(const blackbox_config_t* config)
{
    if (s_blackbox.initialized) {
        ESP_LOGW(TAG, "Logger already initialized");
        return ESP_ERR_INVALID_STATE;
    }
    
    if (config == NULL) {
        ESP_LOGE(TAG, "Config is NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    if (config->root_path == NULL) {
        ESP_LOGE(TAG, "Root path is NULL");
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Store configuration */
    memcpy(&s_blackbox.config, config, sizeof(blackbox_config_t));
    
    /* Enforce minimum buffer size */
    if (s_blackbox.config.buffer_size < BLACKBOX_LOG_MIN_BUFFER_SIZE) {
        s_blackbox.config.buffer_size = BLACKBOX_LOG_MIN_BUFFER_SIZE;
    }
    
    /* Set default file prefix if not provided */
    if (s_blackbox.config.file_prefix == NULL) {
        s_blackbox.config.file_prefix = "flight";
    }
    
    /* Set default flush interval */
    if (s_blackbox.config.flush_interval_ms == 0) {
        s_blackbox.config.flush_interval_ms = BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS;
    }
    
    /* Set default file size limit */
    if (s_blackbox.config.file_size_limit == 0) {
        s_blackbox.config.file_size_limit = BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT;
    }
    
    /* Initialize runtime settings */
    s_blackbox.min_level = config->min_level;
    s_blackbox.console_output = config->console_output;
    s_blackbox.file_output = config->file_output;
    
    /* Create ring buffer */
    s_blackbox.ring_buffer = xRingbufferCreate(s_blackbox.config.buffer_size, RINGBUF_TYPE_NOSPLIT);
    if (s_blackbox.ring_buffer == NULL) {
        ESP_LOGE(TAG, "Failed to create ring buffer");
        return ESP_ERR_NO_MEM;
    }
    
    /* Create flush semaphore */
    s_blackbox.flush_sem = xSemaphoreCreateBinary();
    if (s_blackbox.flush_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create flush semaphore");
        vRingbufferDelete(s_blackbox.ring_buffer);
        return ESP_ERR_NO_MEM;
    }
    
    /* Create stats mutex */
    s_blackbox.stats_mutex = xSemaphoreCreateMutex();
    if (s_blackbox.stats_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create stats mutex");
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        return ESP_ERR_NO_MEM;
    }
    
    /* Initialize encryption if enabled */
    if (s_blackbox.config.encrypt) {
        mbedtls_cipher_init(&s_blackbox.cipher_ctx);
        
        int ret = mbedtls_cipher_setup(&s_blackbox.cipher_ctx, 
                                        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to setup cipher: %d", ret);
            vSemaphoreDelete(s_blackbox.stats_mutex);
            vSemaphoreDelete(s_blackbox.flush_sem);
            vRingbufferDelete(s_blackbox.ring_buffer);
            return ESP_FAIL;
        }
        
        ret = mbedtls_cipher_setkey(&s_blackbox.cipher_ctx, s_blackbox.config.encryption_key, 
                                     256, MBEDTLS_ENCRYPT);
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to set encryption key: %d", ret);
            mbedtls_cipher_free(&s_blackbox.cipher_ctx);
            vSemaphoreDelete(s_blackbox.stats_mutex);
            vSemaphoreDelete(s_blackbox.flush_sem);
            vRingbufferDelete(s_blackbox.ring_buffer);
            return ESP_FAIL;
        }
        
        /* Initialize IV with random data */
        esp_fill_random(s_blackbox.iv, sizeof(s_blackbox.iv));
        s_blackbox.iv_counter = 0;
    }
    
    /* Reset statistics */
    memset(&s_blackbox.stats, 0, sizeof(blackbox_stats_t));
    atomic_store(&s_blackbox.messages_logged, 0);
    atomic_store(&s_blackbox.messages_dropped, 0);
    
    /* Initialize file hash cache */
    s_blackbox.cached_file_path = NULL;
    s_blackbox.cached_file_hash = 0;
    
    /* Initialize tag hash cache */
    s_blackbox.cached_tag_ptr = NULL;
    s_blackbox.cached_tag_hash = 0;
    
    /* Initialize file management */
    s_blackbox.current_file = NULL;
    s_blackbox.current_file_size = 0;
    s_blackbox.file_counter = 0;
    s_blackbox.shutdown_requested = false;
    
    /* Create writer task */
    BaseType_t ret = xTaskCreate(writer_task, "blackbox_writer", 
                                  BLACKBOX_LOG_WRITER_TASK_STACK_SIZE,
                                  NULL, BLACKBOX_LOG_WRITER_TASK_PRIORITY,
                                  &s_blackbox.writer_task);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create writer task");
        if (s_blackbox.config.encrypt) {
            mbedtls_cipher_free(&s_blackbox.cipher_ctx);
        }
        vSemaphoreDelete(s_blackbox.stats_mutex);
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        return ESP_ERR_NO_MEM;
    }
    
    s_blackbox.initialized = true;
    
    ESP_LOGI(TAG, "Logger initialized: path=%s, encrypt=%d, buffer=%uKB",
             s_blackbox.config.root_path, s_blackbox.config.encrypt,
             (unsigned)(s_blackbox.config.buffer_size / 1024));
    
    return ESP_OK;
}

esp_err_t blackbox_deinit(void)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Shutting down logger...");
    
    /* Request shutdown */
    s_blackbox.shutdown_requested = true;
    xSemaphoreGive(s_blackbox.flush_sem);
    
    /* Wait for writer task to finish (max 5 seconds) */
    for (int i = 0; i < 50 && s_blackbox.writer_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    /* Force delete task if still running */
    if (s_blackbox.writer_task != NULL) {
        vTaskDelete(s_blackbox.writer_task);
        s_blackbox.writer_task = NULL;
    }
    
    /* Close current file */
    close_current_file();
    
    /* Free encryption context */
    if (s_blackbox.config.encrypt) {
        mbedtls_cipher_free(&s_blackbox.cipher_ctx);
    }
    
    /* Delete semaphores and ring buffer */
    vSemaphoreDelete(s_blackbox.stats_mutex);
    vSemaphoreDelete(s_blackbox.flush_sem);
    vRingbufferDelete(s_blackbox.ring_buffer);
    
    s_blackbox.initialized = false;
    
    ESP_LOGI(TAG, "Logger shutdown complete");
    
    return ESP_OK;
}

bool blackbox_is_initialized(void)
{
    return s_blackbox.initialized;
}

/*******************************************************************************
 * Core Logging Functions
 ******************************************************************************/

static IRAM_ATTR size_t build_blackbox_packet(blackbox_packet_t* packet, blackbox_level_t level,
                                const char* tag, const char* file, uint32_t line,
                                const char* fmt, va_list args)
{
    /* Fill header - use pre-initialized magic to avoid repeated stores */
    static const uint8_t magic[4] = {
        BLACKBOX_LOG_MAGIC_BYTE0, BLACKBOX_LOG_MAGIC_BYTE1,
        BLACKBOX_LOG_MAGIC_BYTE2, BLACKBOX_LOG_MAGIC_BYTE3
    };
    memcpy(packet->header.magic, magic, 4);
    packet->header.version = BLACKBOX_LOG_VERSION;
    packet->header.msg_type = BLACKBOX_LOG_MSG_TYPE_LOG;
    packet->header.level = (uint8_t)level;
    packet->header.reserved = 0;
    packet->header.timestamp_us = esp_timer_get_time();
    packet->header.tag_hash = get_tag_hash(tag);
    packet->header.file_hash = get_file_hash(file);
    packet->header.line = (uint16_t)line;
    
    /* Format message payload */
    int payload_len = vsnprintf(packet->payload, BLACKBOX_LOG_MAX_MESSAGE_SIZE, fmt, args);
    if (payload_len < 0) {
        payload_len = 0;
    } else if (payload_len >= BLACKBOX_LOG_MAX_MESSAGE_SIZE) {
        payload_len = BLACKBOX_LOG_MAX_MESSAGE_SIZE - 1;
    }
    packet->header.payload_length = (uint16_t)payload_len;
    
    /* Return total packet size (header + actual payload size) */
    return sizeof(blackbox_header_t) + payload_len;
}

void IRAM_ATTR blackbox_log(blackbox_level_t level, const char* tag, const char* file,
              uint32_t line, const char* fmt, ...)
{
    /* Early exit checks - keep these at the top for branch prediction */
    if (!s_blackbox.initialized) {
        return;
    }
    
    if (level > s_blackbox.min_level || level == BLACKBOX_LOG_LEVEL_NONE) {
        return;
    }
    
    /* Build packet on stack */
    blackbox_packet_t packet;
    
    va_list args;
    va_start(args, fmt);
    size_t packet_size = build_blackbox_packet(&packet, level, tag, file, line, fmt, args);
    va_end(args);
    
    /* Console output (if enabled) */
    if (s_blackbox.console_output) {
        console_output(level, tag, packet.payload);
    }
    
    /* File output - push to ring buffer (lock-free) */
    if (s_blackbox.file_output && s_blackbox.ring_buffer != NULL) {
        /* Non-blocking send to ring buffer */
        BaseType_t result = xRingbufferSend(s_blackbox.ring_buffer, &packet, packet_size, 0);
        
        /* Atomic stats update - no mutex needed! */
        if (result == pdTRUE) {
            atomic_fetch_add(&s_blackbox.messages_logged, 1);
        } else {
            atomic_fetch_add(&s_blackbox.messages_dropped, 1);
        }
    }
}

void IRAM_ATTR blackbox_log_va(blackbox_level_t level, const char* tag, const char* file,
                 uint32_t line, const char* fmt, va_list args)
{
    /* Early exit checks - keep these at the top for branch prediction */
    if (!s_blackbox.initialized) {
        return;
    }
    
    if (level > s_blackbox.min_level || level == BLACKBOX_LOG_LEVEL_NONE) {
        return;
    }
    
    /* Build packet on stack */
    blackbox_packet_t packet;
    
    size_t packet_size = build_blackbox_packet(&packet, level, tag, file, line, fmt, args);
    
    /* Console output (if enabled) */
    if (s_blackbox.console_output) {
        console_output(level, tag, packet.payload);
    }
    
    /* File output - push to ring buffer (lock-free) */
    if (s_blackbox.file_output && s_blackbox.ring_buffer != NULL) {
        /* Non-blocking send to ring buffer */
        BaseType_t result = xRingbufferSend(s_blackbox.ring_buffer, &packet, packet_size, 0);
        
        /* Atomic stats update - no mutex needed! */
        if (result == pdTRUE) {
            atomic_fetch_add(&s_blackbox.messages_logged, 1);
        } else {
            atomic_fetch_add(&s_blackbox.messages_dropped, 1);
        }
    }
}

static void console_output(blackbox_level_t level, const char* tag, const char* message)
{
    switch (level) {
        case BLACKBOX_LOG_LEVEL_ERROR:
            ESP_LOGE(tag, "%s", message);
            break;
        case BLACKBOX_LOG_LEVEL_WARN:
            ESP_LOGW(tag, "%s", message);
            break;
        case BLACKBOX_LOG_LEVEL_INFO:
            ESP_LOGI(tag, "%s", message);
            break;
        case BLACKBOX_LOG_LEVEL_DEBUG:
            ESP_LOGD(tag, "%s", message);
            break;
        case BLACKBOX_LOG_LEVEL_VERBOSE:
            ESP_LOGV(tag, "%s", message);
            break;
        default:
            break;
    }
}

/*******************************************************************************
 * File Management
 ******************************************************************************/

static esp_err_t create_new_log_file(void)
{
    /* Close existing file if open */
    close_current_file();
    
    /* Generate new file name */
    s_blackbox.file_counter++;
    snprintf(s_blackbox.current_file_path, BLACKBOX_LOG_MAX_PATH_LENGTH, 
             "%s/%s%03lu.blackbox", 
             s_blackbox.config.root_path, 
             s_blackbox.config.file_prefix,
             (unsigned long)s_blackbox.file_counter);
    
    /* Open file for writing */
    s_blackbox.current_file = fopen(s_blackbox.current_file_path, "wb");
    if (s_blackbox.current_file == NULL) {
        ESP_LOGE(TAG, "Failed to create log file: %s", s_blackbox.current_file_path);
        return ESP_FAIL;
    }
    
    s_blackbox.current_file_size = 0;
    
    /* Write file header */
    esp_err_t ret = write_file_header();
    if (ret != ESP_OK) {
        fclose(s_blackbox.current_file);
        s_blackbox.current_file = NULL;
        return ret;
    }
    
    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE) {
        s_blackbox.stats.files_created++;
        xSemaphoreGive(s_blackbox.stats_mutex);
    }
    
    ESP_LOGI(TAG, "Created log file: %s", s_blackbox.current_file_path);
    
    return ESP_OK;
}

static esp_err_t write_file_header(void)
{
    blackbox_file_header_t header = {0};
    
    header.magic[0] = BLACKBOX_LOG_MAGIC_BYTE0;
    header.magic[1] = BLACKBOX_LOG_MAGIC_BYTE1;
    header.magic[2] = BLACKBOX_LOG_MAGIC_BYTE2;
    header.magic[3] = BLACKBOX_LOG_MAGIC_BYTE3;
    header.version = BLACKBOX_LOG_VERSION;
    header.flags = s_blackbox.config.encrypt ? 0x01 : 0x00;
    header.header_size = sizeof(blackbox_file_header_t);
    header.timestamp_us = esp_timer_get_time();
    
    /* Get device MAC as identifier */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(header.device_id, sizeof(header.device_id), 
             "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    /* Write header directly (not encrypted) */
    size_t written = fwrite(&header, 1, sizeof(header), s_blackbox.current_file);
    if (written != sizeof(header)) {
        ESP_LOGE(TAG, "Failed to write file header");
        return ESP_FAIL;
    }
    
    s_blackbox.current_file_size += written;
    
    /* If encrypted, also write the IV after the header */
    if (s_blackbox.config.encrypt) {
        written = fwrite(s_blackbox.iv, 1, sizeof(s_blackbox.iv), s_blackbox.current_file);
        if (written != sizeof(s_blackbox.iv)) {
            ESP_LOGE(TAG, "Failed to write IV");
            return ESP_FAIL;
        }
        s_blackbox.current_file_size += written;
        
        /* Reset cipher for new file */
        mbedtls_cipher_reset(&s_blackbox.cipher_ctx);
        mbedtls_cipher_set_iv(&s_blackbox.cipher_ctx, s_blackbox.iv, sizeof(s_blackbox.iv));
    }
    
    return ESP_OK;
}

static esp_err_t write_packet_to_file(const blackbox_packet_t* packet, size_t packet_size)
{
    if (s_blackbox.current_file == NULL) {
        esp_err_t ret = create_new_log_file();
        if (ret != ESP_OK) {
            return ret;
        }
    }
    
    /* Check if rotation is needed */
    if (s_blackbox.current_file_size + packet_size > s_blackbox.config.file_size_limit) {
        esp_err_t ret = create_new_log_file();
        if (ret != ESP_OK) {
            return ret;
        }
    }
    
    size_t written = 0;
    
    if (s_blackbox.config.encrypt) {
        /* Encrypt and write */
        esp_err_t ret = encrypt_and_write((const uint8_t*)packet, packet_size);
        if (ret != ESP_OK) {
            return ret;
        }
        written = packet_size;
    } else {
        /* Write directly */
        written = fwrite(packet, 1, packet_size, s_blackbox.current_file);
        if (written != packet_size) {
            ESP_LOGE(TAG, "Write failed: expected %u, wrote %u", 
                     (unsigned)packet_size, (unsigned)written);
            if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE) {
                s_blackbox.stats.write_errors++;
                xSemaphoreGive(s_blackbox.stats_mutex);
            }
            return ESP_FAIL;
        }
    }
    
    s_blackbox.current_file_size += written;
    
    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE) {
        s_blackbox.stats.bytes_written += written;
        xSemaphoreGive(s_blackbox.stats_mutex);
    }
    
    return ESP_OK;
}

static esp_err_t encrypt_and_write(const uint8_t* data, size_t len)
{
    uint8_t encrypted[512];  /* Buffer for encrypted output */
    size_t offset = 0;
    
    while (offset < len) {
        size_t chunk_size = (len - offset) > sizeof(encrypted) ? sizeof(encrypted) : (len - offset);
        size_t olen = 0;
        
        int ret = mbedtls_cipher_update(&s_blackbox.cipher_ctx, 
                                         data + offset, chunk_size,
                                         encrypted, &olen);
        if (ret != 0) {
            ESP_LOGE(TAG, "Encryption failed: %d", ret);
            return ESP_FAIL;
        }
        
        size_t written = fwrite(encrypted, 1, olen, s_blackbox.current_file);
        if (written != olen) {
            ESP_LOGE(TAG, "Write encrypted data failed");
            return ESP_FAIL;
        }
        
        offset += chunk_size;
    }
    
    return ESP_OK;
}

static void close_current_file(void)
{
    if (s_blackbox.current_file != NULL) {
        fflush(s_blackbox.current_file);
        fclose(s_blackbox.current_file);
        s_blackbox.current_file = NULL;
        ESP_LOGI(TAG, "Closed log file: %s (size: %u bytes)", 
                 s_blackbox.current_file_path, (unsigned)s_blackbox.current_file_size);
    }
}

/*******************************************************************************
 * Writer Task
 ******************************************************************************/

static void writer_task(void* arg)
{
    ESP_LOGI(TAG, "Writer task started");
    
    TickType_t last_flush = xTaskGetTickCount();
    const TickType_t flush_interval = pdMS_TO_TICKS(s_blackbox.config.flush_interval_ms);
    
    while (!s_blackbox.shutdown_requested) {
        /* Wait for flush signal or timeout */
        xSemaphoreTake(s_blackbox.flush_sem, flush_interval);
        
        /* Process all items in the ring buffer */
        size_t item_size;
        void* item;
        
        while ((item = xRingbufferReceive(s_blackbox.ring_buffer, &item_size, 0)) != NULL) {
            /* Write to file */
            write_packet_to_file((const blackbox_packet_t*)item, item_size);
            
            /* Return item to ring buffer */
            vRingbufferReturnItem(s_blackbox.ring_buffer, item);
            
            /* Check for shutdown during processing */
            if (s_blackbox.shutdown_requested) {
                break;
            }
        }
        
        /* Periodic flush */
        TickType_t now = xTaskGetTickCount();
        if ((now - last_flush) >= flush_interval) {
            if (s_blackbox.current_file != NULL) {
                fflush(s_blackbox.current_file);
            }
            last_flush = now;
        }
    }
    
    /* Final drain of ring buffer before shutdown */
    ESP_LOGI(TAG, "Writer task draining buffer...");
    
    size_t item_size;
    void* item;
    while ((item = xRingbufferReceive(s_blackbox.ring_buffer, &item_size, 0)) != NULL) {
        write_packet_to_file((const blackbox_packet_t*)item, item_size);
        vRingbufferReturnItem(s_blackbox.ring_buffer, item);
    }
    
    /* Close file */
    close_current_file();
    
    ESP_LOGI(TAG, "Writer task exiting");
    
    s_blackbox.writer_task = NULL;
    vTaskDelete(NULL);
}

/*******************************************************************************
 * Control Functions
 ******************************************************************************/

esp_err_t blackbox_flush(void)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    xSemaphoreGive(s_blackbox.flush_sem);
    
    /* Wait a bit for flush to complete */
    vTaskDelay(pdMS_TO_TICKS(100));
    
    return ESP_OK;
}

esp_err_t blackbox_rotate_file(void)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    /* Flush first */
    blackbox_flush();
    
    /* Force file size over limit to trigger rotation */
    s_blackbox.current_file_size = s_blackbox.config.file_size_limit + 1;
    
    return ESP_OK;
}

esp_err_t blackbox_set_level(blackbox_level_t level)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    s_blackbox.min_level = level;
    return ESP_OK;
}

blackbox_level_t blackbox_get_level(void)
{
    return s_blackbox.min_level;
}

esp_err_t blackbox_set_console_output(bool enable)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    s_blackbox.console_output = enable;
    return ESP_OK;
}

esp_err_t blackbox_set_file_output(bool enable)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    s_blackbox.file_output = enable;
    return ESP_OK;
}

/*******************************************************************************
 * Statistics Functions
 ******************************************************************************/

esp_err_t blackbox_get_stats(blackbox_stats_t* stats)
{
    if (!s_blackbox.initialized || stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE) {
        memcpy(stats, &s_blackbox.stats, sizeof(blackbox_stats_t));
        
        /* Copy atomic counters */
        stats->messages_logged = atomic_load(&s_blackbox.messages_logged);
        stats->messages_dropped = atomic_load(&s_blackbox.messages_dropped);
        
        /* Calculate buffer high water mark */
        size_t free_size = xRingbufferGetCurFreeSize(s_blackbox.ring_buffer);
        size_t used = s_blackbox.config.buffer_size - free_size;
        if (used > stats->buffer_high_water) {
            stats->buffer_high_water = used;
            s_blackbox.stats.buffer_high_water = used;
        }
        
        xSemaphoreGive(s_blackbox.stats_mutex);
    }
    
    return ESP_OK;
}

esp_err_t blackbox_reset_stats(void)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE) {
        memset(&s_blackbox.stats, 0, sizeof(blackbox_stats_t));
        atomic_store(&s_blackbox.messages_logged, 0);
        atomic_store(&s_blackbox.messages_dropped, 0);
        xSemaphoreGive(s_blackbox.stats_mutex);
    }
    
    return ESP_OK;
}
