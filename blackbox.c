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
#include "blackbox_formats.h"

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
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"

#include <stdatomic.h>

/* Panic handler support - always included, enabled at runtime */
#include "esp_debug_helpers.h"
#include "esp_cpu.h"
#include "esp_memory_utils.h"
#include "sdkconfig.h"

/* Architecture-specific includes for register access */
#if CONFIG_IDF_TARGET_ESP32 || CONFIG_IDF_TARGET_ESP32S2 || CONFIG_IDF_TARGET_ESP32S3
#include "xtensa_context.h"
#elif CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C2 || CONFIG_IDF_TARGET_ESP32C6 || CONFIG_IDF_TARGET_ESP32H2
#include "riscv/rv_utils.h"
#endif

static const char *TAG = "BLACKBOX_LOG";

/*******************************************************************************
 * Private Structures
 ******************************************************************************/

/**
 * @brief Ring buffer entry header for internal use
 */
typedef struct
{
    uint16_t total_size; /**< Total size of this entry including header */
} ring_entry_header_t;

/**
 * @brief Logger state structure
 */
typedef struct
{
    bool initialized;
    blackbox_config_t config;

    /* Deep-copied config strings (owned by logger) */
    char *root_path_copy;
    char *file_prefix_copy;

    /* Ring buffer */
    RingbufHandle_t ring_buffer;

    /* Writer task */
    TaskHandle_t writer_task;
    SemaphoreHandle_t flush_sem;
    atomic_bool shutdown_requested;
    SemaphoreHandle_t task_done_sem;  /**< Signaled when writer task exits */

    /* File management */
    FILE *current_file;
    char current_file_path[BLACKBOX_LOG_MAX_PATH_LENGTH];
    atomic_size_t current_file_size;  /**< Atomic for thread-safe rotation check */
    atomic_uint_fast32_t file_counter;
    SemaphoreHandle_t file_mutex;     /**< Protects file operations */

    /* Format encoder context */
    bbox_format_ctx_t format_ctx;

    /* Encryption context (BBOX format only) */
    mbedtls_cipher_context_t cipher_ctx;
    uint8_t iv[16];
    uint32_t iv_counter;

    /* Statistics (atomic for lock-free hot path) */
    atomic_uint_fast64_t messages_logged;
    atomic_uint_fast64_t messages_dropped;
    atomic_uint_fast64_t struct_messages_logged;  /**< Struct messages logged */
    blackbox_stats_t stats;
    SemaphoreHandle_t stats_mutex;

    /* Runtime settings (atomic for thread-safe access from multiple cores) */
    atomic_int min_level;
    atomic_bool console_output;
    atomic_bool file_output;

    /* Panic handler flags (runtime configurable, 32-bit bitmask) */
    atomic_uint panic_flags;
} blackbox_state_t;

static blackbox_state_t s_blackbox = {0};

/*******************************************************************************
 * Private Function Declarations
 ******************************************************************************/

static void writer_task(void *arg);
static esp_err_t create_new_log_file(void);
static esp_err_t write_file_header(void);
static esp_err_t write_packet_to_file(const blackbox_packet_t *packet, size_t packet_size);
static esp_err_t encrypt_and_write(const uint8_t *data, size_t len);
static void close_current_file(void);
static void console_output(blackbox_level_t level, const char *tag, const char *message);
static size_t build_blackbox_packet(blackbox_packet_t *packet, blackbox_level_t level,
                                    const char *tag, const char *file, uint32_t line,
                                    const char *fmt, va_list args);

/* Panic handler functions (always available, enabled at runtime) */
static void write_panic_packet_direct(blackbox_msg_type_t msg_type, const char *data, size_t len);
static void blackbox_shutdown_handler(void);

/* CRC-16 calculation (CCITT polynomial) */
static uint16_t calculate_crc16(const uint8_t *data, size_t len);

/*******************************************************************************
 * Inline Performance Helpers
 ******************************************************************************/

/**
 * @brief Compute file hash (no caching to avoid data races in concurrent access)
 *
 */
static inline uint32_t get_file_hash(const char *file)
{
    return blackbox_hash_string(file);
}

/**
 * @brief Compute tag hash (no caching to avoid data races in concurrent access)
 */
static inline uint32_t get_tag_hash(const char *tag)
{
    return blackbox_hash_string(tag);
}

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

/**
 * @brief Calculate CRC-16 checksum (CCITT polynomial 0x1021)
 */
static uint16_t calculate_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 0x8000)
            {
                crc = (crc << 1) ^ 0x1021;
            }
            else
            {
                crc <<= 1;
            }
        }
    }
    return crc;
}

IRAM_ATTR uint32_t blackbox_hash_string(const char *str)
{
    if (str == NULL)
    {
        return 0;
    }

    /* FNV-1a hash*/
    uint32_t hash = 2166136261u;
    const uint8_t *p = (const uint8_t *)str;
    while (*p)
    {
        hash = (hash ^ *p++) * 16777619u;
    }
    return hash;
}

const char *blackbox_level_to_string(blackbox_level_t level)
{
    switch (level)
    {
    case BLACKBOX_LOG_LEVEL_ERROR:
        return "ERROR";
    case BLACKBOX_LOG_LEVEL_WARN:
        return "WARN";
    case BLACKBOX_LOG_LEVEL_INFO:
        return "INFO";
    case BLACKBOX_LOG_LEVEL_DEBUG:
        return "DEBUG";
    case BLACKBOX_LOG_LEVEL_VERBOSE:
        return "VERBOSE";
    default:
        return "UNKNOWN";
    }
}

/*******************************************************************************
 * Default Configuration
 ******************************************************************************/

void blackbox_get_default_config(blackbox_config_t *config)
{
    if (config == NULL)
    {
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
    config->log_format = BLACKBOX_FORMAT_BBOX;  /* Default to native format */

    /* Panic handler defaults - enabled with backtrace and registers */
    config->panic_flags = BLACKBOX_PANIC_FLAGS_DEFAULT;
}

/*******************************************************************************
 * Initialization and Deinitialization
 ******************************************************************************/

esp_err_t blackbox_init(const blackbox_config_t *config)
{
    if (s_blackbox.initialized)
    {
        ESP_LOGW(TAG, "Logger already initialized");
        return ESP_ERR_INVALID_STATE;
    }

    if (config == NULL)
    {
        ESP_LOGE(TAG, "Config is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    if (config->root_path == NULL)
    {
        ESP_LOGE(TAG, "Root path is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    /* Validate encryption key if encryption is enabled */
    if (config->encrypt)
    {
        bool key_is_zero = true;
        for (int i = 0; i < 32; i++)
        {
            if (config->encryption_key[i] != 0)
            {
                key_is_zero = false;
                break;
            }
        }
        if (key_is_zero)
        {
            ESP_LOGE(TAG, "Encryption enabled but key is all zeros");
            return ESP_ERR_INVALID_ARG;
        }
    }

    /* Store configuration */
    memcpy(&s_blackbox.config, config, sizeof(blackbox_config_t));

    /* Deep-copy string members to avoid use-after-free */
    s_blackbox.root_path_copy = strdup(config->root_path);
    if (s_blackbox.root_path_copy == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate root_path copy");
        return ESP_ERR_NO_MEM;
    }
    s_blackbox.config.root_path = s_blackbox.root_path_copy;

    const char *prefix = config->file_prefix ? config->file_prefix : "flight";
    s_blackbox.file_prefix_copy = strdup(prefix);
    if (s_blackbox.file_prefix_copy == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate file_prefix copy");
        free(s_blackbox.root_path_copy);
        s_blackbox.root_path_copy = NULL;
        return ESP_ERR_NO_MEM;
    }
    s_blackbox.config.file_prefix = s_blackbox.file_prefix_copy;

    /* Enforce minimum buffer size */
    if (s_blackbox.config.buffer_size < BLACKBOX_LOG_MIN_BUFFER_SIZE)
    {
        s_blackbox.config.buffer_size = BLACKBOX_LOG_MIN_BUFFER_SIZE;
    }

    /* Set default flush interval */
    if (s_blackbox.config.flush_interval_ms == 0)
    {
        s_blackbox.config.flush_interval_ms = BLACKBOX_LOG_DEFAULT_FLUSH_INTERVAL_MS;
    }

    /* Set default file size limit */
    if (s_blackbox.config.file_size_limit == 0)
    {
        s_blackbox.config.file_size_limit = BLACKBOX_LOG_DEFAULT_FILE_SIZE_LIMIT;
    }

    /* Initialize runtime settings (atomic for thread-safe access) */
    atomic_store(&s_blackbox.min_level, (int)config->min_level);
    atomic_store(&s_blackbox.console_output, config->console_output);
    atomic_store(&s_blackbox.file_output, config->file_output);
    atomic_store(&s_blackbox.shutdown_requested, false);
    atomic_store(&s_blackbox.file_counter, 0);
    atomic_store(&s_blackbox.current_file_size, 0);

    /* Create ring buffer */
    s_blackbox.ring_buffer = xRingbufferCreate(s_blackbox.config.buffer_size, RINGBUF_TYPE_NOSPLIT);
    if (s_blackbox.ring_buffer == NULL)
    {
        ESP_LOGE(TAG, "Failed to create ring buffer");
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    /* Create flush semaphore */
    s_blackbox.flush_sem = xSemaphoreCreateBinary();
    if (s_blackbox.flush_sem == NULL)
    {
        ESP_LOGE(TAG, "Failed to create flush semaphore");
        vRingbufferDelete(s_blackbox.ring_buffer);
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    /* Create task completion semaphore */
    s_blackbox.task_done_sem = xSemaphoreCreateBinary();
    if (s_blackbox.task_done_sem == NULL)
    {
        ESP_LOGE(TAG, "Failed to create task done semaphore");
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    /* Create file mutex for thread-safe file operations */
    s_blackbox.file_mutex = xSemaphoreCreateMutex();
    if (s_blackbox.file_mutex == NULL)
    {
        ESP_LOGE(TAG, "Failed to create file mutex");
        vSemaphoreDelete(s_blackbox.task_done_sem);
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    /* Create stats mutex */
    s_blackbox.stats_mutex = xSemaphoreCreateMutex();
    if (s_blackbox.stats_mutex == NULL)
    {
        ESP_LOGE(TAG, "Failed to create stats mutex");
        vSemaphoreDelete(s_blackbox.file_mutex);
        vSemaphoreDelete(s_blackbox.task_done_sem);
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    /* Initialize encryption if enabled */
    if (s_blackbox.config.encrypt)
    {
        mbedtls_cipher_init(&s_blackbox.cipher_ctx);

        int ret = mbedtls_cipher_setup(&s_blackbox.cipher_ctx,
                                       mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
        if (ret != 0)
        {
            ESP_LOGE(TAG, "Failed to setup cipher: %d", ret);
            vSemaphoreDelete(s_blackbox.stats_mutex);
            vSemaphoreDelete(s_blackbox.file_mutex);
            vSemaphoreDelete(s_blackbox.task_done_sem);
            vSemaphoreDelete(s_blackbox.flush_sem);
            vRingbufferDelete(s_blackbox.ring_buffer);
            free(s_blackbox.root_path_copy);
            free(s_blackbox.file_prefix_copy);
            return ESP_FAIL;
        }

        ret = mbedtls_cipher_setkey(&s_blackbox.cipher_ctx, s_blackbox.config.encryption_key,
                                    256, MBEDTLS_ENCRYPT);
        if (ret != 0)
        {
            ESP_LOGE(TAG, "Failed to set encryption key: %d", ret);
            mbedtls_cipher_free(&s_blackbox.cipher_ctx);
            vSemaphoreDelete(s_blackbox.stats_mutex);
            vSemaphoreDelete(s_blackbox.file_mutex);
            vSemaphoreDelete(s_blackbox.task_done_sem);
            vSemaphoreDelete(s_blackbox.flush_sem);
            vRingbufferDelete(s_blackbox.ring_buffer);
            free(s_blackbox.root_path_copy);
            free(s_blackbox.file_prefix_copy);
            return ESP_FAIL;
        }

        /* IV will be generated fresh for each file in create_new_log_file() */
        s_blackbox.iv_counter = 0;
    }

    /* Reset statistics */
    memset(&s_blackbox.stats, 0, sizeof(blackbox_stats_t));
    atomic_store(&s_blackbox.messages_logged, 0);
    atomic_store(&s_blackbox.messages_dropped, 0);
    atomic_store(&s_blackbox.struct_messages_logged, 0);

    /* Initialize format context for structured logging */
    bbox_format_ctx_init(&s_blackbox.format_ctx, (bbox_log_format_t)s_blackbox.config.log_format);

    /* Initialize file management */
    s_blackbox.current_file = NULL;

    /* Create writer task */
    BaseType_t xret = xTaskCreate(writer_task, "blackbox_writer",
                                 BLACKBOX_LOG_WRITER_TASK_STACK_SIZE,
                                 NULL, BLACKBOX_LOG_WRITER_TASK_PRIORITY,
                                 &s_blackbox.writer_task);
    if (xret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create writer task");
        if (s_blackbox.config.encrypt)
        {
            mbedtls_cipher_free(&s_blackbox.cipher_ctx);
        }
        vSemaphoreDelete(s_blackbox.stats_mutex);
        vSemaphoreDelete(s_blackbox.file_mutex);
        vSemaphoreDelete(s_blackbox.task_done_sem);
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
        free(s_blackbox.root_path_copy);
        free(s_blackbox.file_prefix_copy);
        return ESP_ERR_NO_MEM;
    }

    s_blackbox.initialized = true;

    /* Initialize panic handler flags from config */
    atomic_store(&s_blackbox.panic_flags, config->panic_flags);

    /* Register shutdown handler if panic handler is enabled */
    if (config->panic_flags & BLACKBOX_PANIC_FLAG_ENABLED)
    {
        esp_register_shutdown_handler((shutdown_handler_t)blackbox_shutdown_handler);
        ESP_LOGI(TAG, "Panic handler registered (flags=0x%08x)", (unsigned int)config->panic_flags);
    }

    ESP_LOGI(TAG, "Logger initialized: path=%s, encrypt=%d, buffer=%uKB, format=%s",
             s_blackbox.config.root_path, s_blackbox.config.encrypt,
             (unsigned)(s_blackbox.config.buffer_size / 1024),
             s_blackbox.config.log_format == BLACKBOX_FORMAT_PX4_ULOG ? "PX4_ULOG" :
             s_blackbox.config.log_format == BLACKBOX_FORMAT_ARDUPILOT ? "ARDUPILOT" : "BBOX");

    return ESP_OK;
}

esp_err_t blackbox_deinit(void)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Shutting down logger...");

    /* Unregister shutdown handler to avoid stale pointer on re-init */
    if (atomic_load(&s_blackbox.panic_flags) & BLACKBOX_PANIC_FLAG_ENABLED)
    {
        esp_unregister_shutdown_handler((shutdown_handler_t)blackbox_shutdown_handler);
    }

    /* Request shutdown using atomic store */
    atomic_store(&s_blackbox.shutdown_requested, true);
    xSemaphoreGive(s_blackbox.flush_sem);

    /* Wait for writer task to signal completion (max 5 seconds) */
    if (xSemaphoreTake(s_blackbox.task_done_sem, pdMS_TO_TICKS(5000)) != pdTRUE)
    {
        ESP_LOGW(TAG, "Writer task did not exit gracefully, force deleting");
        if (s_blackbox.writer_task != NULL)
        {
            vTaskDelete(s_blackbox.writer_task);
        }
    }
    s_blackbox.writer_task = NULL;

    /* Close current file (protected by mutex) */
    if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(1000)) == pdTRUE)
    {
        close_current_file();
        xSemaphoreGive(s_blackbox.file_mutex);
    }
    else
    {
        /* Force close anyway */
        close_current_file();
    }

    /* Free encryption context */
    if (s_blackbox.config.encrypt)
    {
        mbedtls_cipher_free(&s_blackbox.cipher_ctx);
    }

    /* Delete semaphores and ring buffer */
    vSemaphoreDelete(s_blackbox.stats_mutex);
    vSemaphoreDelete(s_blackbox.file_mutex);
    vSemaphoreDelete(s_blackbox.task_done_sem);
    vSemaphoreDelete(s_blackbox.flush_sem);
    vRingbufferDelete(s_blackbox.ring_buffer);

    /* Free deep-copied strings */
    free(s_blackbox.root_path_copy);
    free(s_blackbox.file_prefix_copy);
    s_blackbox.root_path_copy = NULL;
    s_blackbox.file_prefix_copy = NULL;

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

/**
 * @brief Build a log packet (not IRAM-safe due to vsnprintf usage)
 *
 * Note: IRAM_ATTR was removed because this function calls vsnprintf which
 * is not IRAM-safe when the flash cache is disabled (e.g., from high-priority
 * ISRs or during panic handling).
 */
static size_t build_blackbox_packet(blackbox_packet_t *packet, blackbox_level_t level,
                                    const char *tag, const char *file, uint32_t line,
                                    const char *fmt, va_list args)
{
    /* Fill header - use pre-initialized magic to avoid repeated stores */
    static const uint8_t magic[4] = {
        BLACKBOX_LOG_MAGIC_BYTE0, BLACKBOX_LOG_MAGIC_BYTE1,
        BLACKBOX_LOG_MAGIC_BYTE2, BLACKBOX_LOG_MAGIC_BYTE3};
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
    if (payload_len < 0)
    {
        payload_len = 0;
    }
    else if (payload_len >= BLACKBOX_LOG_MAX_MESSAGE_SIZE)
    {
        payload_len = BLACKBOX_LOG_MAX_MESSAGE_SIZE - 1;
    }
    packet->header.payload_length = (uint16_t)payload_len;

    /* Calculate total packet size */
    size_t packet_size = sizeof(blackbox_header_t) + payload_len;

    /* Calculate CRC-16 over header (excluding crc16 field) and payload */
    size_t crc_data_len = sizeof(blackbox_header_t) - sizeof(uint16_t) + payload_len;
    packet->header.crc16 = calculate_crc16((const uint8_t *)packet, crc_data_len);

    /* Return total packet size (header + actual payload size) */
    return packet_size;
}

/**
 * @brief Log a message with the given level, tag, file, and line
 *
 * Note: IRAM_ATTR was removed because this function calls vsnprintf, ESP_LOGx,
 * and ring buffer API which are not IRAM-safe when the flash cache is disabled.
 * Do not call from ISRs or during panic handling.
 */
void blackbox_log(blackbox_level_t level, const char *tag, const char *file,
                  uint32_t line, const char *fmt, ...)
{
    /* Early exit checks - keep these at the top for branch prediction */
    if (!s_blackbox.initialized)
    {
        return;
    }

    blackbox_level_t current_min_level = (blackbox_level_t)atomic_load(&s_blackbox.min_level);
    if (level > current_min_level || level == BLACKBOX_LOG_LEVEL_NONE)
    {
        return;
    }

    /* Build packet on stack */
    blackbox_packet_t packet;

    va_list args;
    va_start(args, fmt);
    size_t packet_size = build_blackbox_packet(&packet, level, tag, file, line, fmt, args);
    va_end(args);

    /* Console output (if enabled) */
    if (atomic_load(&s_blackbox.console_output))
    {
        console_output(level, tag, packet.payload);
    }

    /* File output - push to ring buffer (lock-free) */
    if (atomic_load(&s_blackbox.file_output) && s_blackbox.ring_buffer != NULL)
    {
        /* Non-blocking send to ring buffer */
        BaseType_t result = xRingbufferSend(s_blackbox.ring_buffer, &packet, packet_size, 0);

        /* Atomic stats update - no mutex needed! */
        if (result == pdTRUE)
        {
            atomic_fetch_add(&s_blackbox.messages_logged, 1);
            /* Signal writer task to process new data promptly */
            xSemaphoreGive(s_blackbox.flush_sem);
        }
        else
        {
            atomic_fetch_add(&s_blackbox.messages_dropped, 1);
        }
    }
}

/**
 * @brief Log a message with the given level, tag, file, line, and va_list
 *
 * Note: IRAM_ATTR was removed because this function calls vsnprintf, ESP_LOGx,
 * and ring buffer API which are not IRAM-safe when the flash cache is disabled.
 * Do not call from ISRs or during panic handling.
 */
void blackbox_log_va(blackbox_level_t level, const char *tag, const char *file,
                     uint32_t line, const char *fmt, va_list args)
{
    /* Early exit checks - keep these at the top for branch prediction */
    if (!s_blackbox.initialized)
    {
        return;
    }

    blackbox_level_t current_min_level = (blackbox_level_t)atomic_load(&s_blackbox.min_level);
    if (level > current_min_level || level == BLACKBOX_LOG_LEVEL_NONE)
    {
        return;
    }

    /* Build packet on stack */
    blackbox_packet_t packet;

    size_t packet_size = build_blackbox_packet(&packet, level, tag, file, line, fmt, args);

    /* Console output (if enabled) */
    if (atomic_load(&s_blackbox.console_output))
    {
        console_output(level, tag, packet.payload);
    }

    /* File output - push to ring buffer (lock-free) */
    if (atomic_load(&s_blackbox.file_output) && s_blackbox.ring_buffer != NULL)
    {
        /* Non-blocking send to ring buffer */
        BaseType_t result = xRingbufferSend(s_blackbox.ring_buffer, &packet, packet_size, 0);

        /* Atomic stats update - no mutex needed! */
        if (result == pdTRUE)
        {
            atomic_fetch_add(&s_blackbox.messages_logged, 1);
            /* Signal writer task to process new data promptly */
            xSemaphoreGive(s_blackbox.flush_sem);
        }
        else
        {
            atomic_fetch_add(&s_blackbox.messages_dropped, 1);
        }
    }
}

static void console_output(blackbox_level_t level, const char *tag, const char *message)
{
    switch (level)
    {
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

    /* Generate new file counter with overflow protection */
    uint32_t counter = atomic_fetch_add(&s_blackbox.file_counter, 1);
    
    /* Wrap counter to prevent overflow (max 999999 files before wrapping) */
    if (counter > 999999)
    {
        atomic_store(&s_blackbox.file_counter, 1);
        counter = 0;
        ESP_LOGW(TAG, "File counter wrapped around - old logs may be overwritten");
    }

    /* Determine file extension based on log format */
    const char *extension;
    switch (s_blackbox.config.log_format)
    {
        case BLACKBOX_FORMAT_PX4_ULOG:
            extension = "ulg";
            break;
        case BLACKBOX_FORMAT_ARDUPILOT:
            extension = "bin";
            break;
        case BLACKBOX_FORMAT_BBOX:
        default:
            extension = "blackbox";
            break;
    }

    snprintf(s_blackbox.current_file_path, BLACKBOX_LOG_MAX_PATH_LENGTH,
             "%s/%s%06lu.%s",
             s_blackbox.config.root_path,
             s_blackbox.config.file_prefix,
             (unsigned long)(counter + 1),
             extension);

    /* Open file for writing */
    s_blackbox.current_file = fopen(s_blackbox.current_file_path, "wb");
    if (s_blackbox.current_file == NULL)
    {
        ESP_LOGE(TAG, "Failed to create log file: %s", s_blackbox.current_file_path);
        return ESP_FAIL;
    }

    atomic_store(&s_blackbox.current_file_size, 0);

    /* Generate fresh IV for this file (security: prevent IV reuse) */
    if (s_blackbox.config.encrypt)
    {
        esp_fill_random(s_blackbox.iv, sizeof(s_blackbox.iv));
        s_blackbox.iv_counter = 0;
    }

    /* Write file header */
    esp_err_t ret = write_file_header();
    if (ret != ESP_OK)
    {
        fclose(s_blackbox.current_file);
        s_blackbox.current_file = NULL;
        return ret;
    }

    if (xSemaphoreTake(s_blackbox.stats_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        s_blackbox.stats.files_created++;
        xSemaphoreGive(s_blackbox.stats_mutex);
    }

    ESP_LOGI(TAG, "Created log file: %s", s_blackbox.current_file_path);

    return ESP_OK;
}

static esp_err_t write_file_header(void)
{
    size_t written;

    /* Write format-specific header based on log format */
    switch (s_blackbox.config.log_format)
    {
        case BLACKBOX_FORMAT_PX4_ULOG:
        {
            /* PX4 ULog file header (16 bytes magic + 8 bytes timestamp) */
            ulog_file_header_t ulog_header = {0};
            memcpy(ulog_header.magic, ULOG_MAGIC, 7);
            ulog_header.version = 1;
            ulog_header.timestamp_us = esp_timer_get_time();

            written = fwrite(&ulog_header, 1, sizeof(ulog_header), s_blackbox.current_file);
            if (written != sizeof(ulog_header))
            {
                ESP_LOGE(TAG, "Failed to write ULog file header");
                return ESP_FAIL;
            }
            atomic_fetch_add(&s_blackbox.current_file_size, written);

            /* Write INFO message with system name */
            uint8_t info_buf[64];
            ulog_info_msg_t *info = (ulog_info_msg_t *)info_buf;
            info->header.msg_size = 0;  /* Will be set below */
            info->header.msg_type = ULOG_MSG_INFO;
            info->key_len = 10;  /* "sys_name\0" */
            const char *key_val = "sys_name\0ESP_BBOX";
            memcpy(info->key_value, key_val, 17);
            info->header.msg_size = 1 + 17;  /* key_len + key/value */

            size_t info_size = sizeof(ulog_msg_header_t) + 1 + 17;
            written = fwrite(info, 1, info_size, s_blackbox.current_file);
            if (written != info_size)
            {
                ESP_LOGE(TAG, "Failed to write ULog info message");
                return ESP_FAIL;
            }
            atomic_fetch_add(&s_blackbox.current_file_size, written);
            break;
        }

        case BLACKBOX_FORMAT_ARDUPILOT:
        {
            /* ArduPilot DataFlash: Write FMT message for FMT itself */
            dataflash_fmt_msg_t fmt_fmt = {0};
            fmt_fmt.header.head1 = DATAFLASH_HEAD_BYTE1;
            fmt_fmt.header.head2 = DATAFLASH_HEAD_BYTE2;
            fmt_fmt.header.msg_id = DF_MSG_FORMAT;
            fmt_fmt.type = DF_MSG_FORMAT;
            fmt_fmt.length = sizeof(dataflash_fmt_msg_t);
            strncpy(fmt_fmt.name, "FMT", sizeof(fmt_fmt.name));
            strncpy(fmt_fmt.format, "BBnNZ", sizeof(fmt_fmt.format));
            strncpy(fmt_fmt.labels, "Type,Length,Name,Format,Columns", sizeof(fmt_fmt.labels));

            written = fwrite(&fmt_fmt, 1, sizeof(fmt_fmt), s_blackbox.current_file);
            if (written != sizeof(fmt_fmt))
            {
                ESP_LOGE(TAG, "Failed to write DataFlash FMT header");
                return ESP_FAIL;
            }
            atomic_fetch_add(&s_blackbox.current_file_size, written);
            break;
        }

        case BLACKBOX_FORMAT_BBOX:
        default:
        {
            /* Native BBOX format header */
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
            written = fwrite(&header, 1, sizeof(header), s_blackbox.current_file);
            if (written != sizeof(header))
            {
                ESP_LOGE(TAG, "Failed to write file header");
                return ESP_FAIL;
            }

            atomic_fetch_add(&s_blackbox.current_file_size, written);

            /* If encrypted, also write the IV after the header */
            if (s_blackbox.config.encrypt)
            {
                written = fwrite(s_blackbox.iv, 1, sizeof(s_blackbox.iv), s_blackbox.current_file);
                if (written != sizeof(s_blackbox.iv))
                {
                    ESP_LOGE(TAG, "Failed to write IV");
                    return ESP_FAIL;
                }
                atomic_fetch_add(&s_blackbox.current_file_size, written);

                /* Reset cipher for new file with fresh IV */
                mbedtls_cipher_reset(&s_blackbox.cipher_ctx);
                mbedtls_cipher_set_iv(&s_blackbox.cipher_ctx, s_blackbox.iv, sizeof(s_blackbox.iv));
            }
            break;
        }
    }

    /* Reset format context for new file (clears format definitions written flag) */
    bbox_format_ctx_init(&s_blackbox.format_ctx, (bbox_log_format_t)s_blackbox.config.log_format);

    return ESP_OK;
}

static esp_err_t write_packet_to_file(const blackbox_packet_t *packet, size_t packet_size)
{
    if (s_blackbox.current_file == NULL)
    {
        esp_err_t ret = create_new_log_file();
        if (ret != ESP_OK)
        {
            return ret;
        }
    }

    /* Check if rotation is needed (atomic read for thread safety) */
    size_t current_size = atomic_load(&s_blackbox.current_file_size);
    if (current_size + packet_size > s_blackbox.config.file_size_limit)
    {
        esp_err_t ret = create_new_log_file();
        if (ret != ESP_OK)
        {
            return ret;
        }
    }

    size_t written = 0;

    if (s_blackbox.config.encrypt)
    {
        /* Encrypt and write */
        esp_err_t ret = encrypt_and_write((const uint8_t *)packet, packet_size);
        if (ret != ESP_OK)
        {
            return ret;
        }
        written = packet_size;
    }
    else
    {
        /* Write directly */
        written = fwrite(packet, 1, packet_size, s_blackbox.current_file);
        if (written != packet_size)
        {
            ESP_LOGE(TAG, "Write failed: expected %u, wrote %u",
                     (unsigned)packet_size, (unsigned)written);
            if (xSemaphoreTake(s_blackbox.stats_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
            {
                s_blackbox.stats.write_errors++;
                xSemaphoreGive(s_blackbox.stats_mutex);
            }
            return ESP_FAIL;
        }
    }

    atomic_fetch_add(&s_blackbox.current_file_size, written);

    if (xSemaphoreTake(s_blackbox.stats_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        s_blackbox.stats.bytes_written += written;
        xSemaphoreGive(s_blackbox.stats_mutex);
    }

    return ESP_OK;
}

static esp_err_t encrypt_and_write(const uint8_t *data, size_t len)
{
    uint8_t encrypted[512]; /* Buffer for encrypted output */
    size_t offset = 0;

    while (offset < len)
    {
        size_t chunk_size = (len - offset) > sizeof(encrypted) ? sizeof(encrypted) : (len - offset);
        size_t olen = 0;

        int ret = mbedtls_cipher_update(&s_blackbox.cipher_ctx,
                                        data + offset, chunk_size,
                                        encrypted, &olen);
        if (ret != 0)
        {
            ESP_LOGE(TAG, "Encryption failed: %d", ret);
            return ESP_FAIL;
        }

        size_t written = fwrite(encrypted, 1, olen, s_blackbox.current_file);
        if (written != olen)
        {
            ESP_LOGE(TAG, "Write encrypted data failed");
            return ESP_FAIL;
        }

        offset += chunk_size;
    }

    return ESP_OK;
}

static void close_current_file(void)
{
    if (s_blackbox.current_file != NULL)
    {
        fflush(s_blackbox.current_file);
        fclose(s_blackbox.current_file);
        s_blackbox.current_file = NULL;
        size_t final_size = atomic_load(&s_blackbox.current_file_size);
        ESP_LOGI(TAG, "Closed log file: %s (size: %u bytes)",
                 s_blackbox.current_file_path, (unsigned)final_size);
    }
}

/*******************************************************************************
 * Writer Task
 ******************************************************************************/

static void writer_task(void *arg)
{
    ESP_LOGI(TAG, "Writer task started");

    TickType_t last_flush = xTaskGetTickCount();
    const TickType_t flush_interval = pdMS_TO_TICKS(s_blackbox.config.flush_interval_ms);

    while (!atomic_load(&s_blackbox.shutdown_requested))
    {
        /* Wait for flush signal or timeout */
        xSemaphoreTake(s_blackbox.flush_sem, flush_interval);

        /* Process all items in the ring buffer (protected by file mutex) */
        size_t item_size;
        void *item;

        while ((item = xRingbufferReceive(s_blackbox.ring_buffer, &item_size, 0)) != NULL)
        {
            /* Write to file (file operations are protected internally) */
            if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
            {
                write_packet_to_file((const blackbox_packet_t *)item, item_size);
                xSemaphoreGive(s_blackbox.file_mutex);
            }

            /* Return item to ring buffer */
            vRingbufferReturnItem(s_blackbox.ring_buffer, item);

            /* Check for shutdown during processing */
            if (atomic_load(&s_blackbox.shutdown_requested))
            {
                break;
            }
        }

        /* Periodic flush */
        TickType_t now = xTaskGetTickCount();
        if ((now - last_flush) >= flush_interval)
        {
            if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
            {
                if (s_blackbox.current_file != NULL)
                {
                    fflush(s_blackbox.current_file);
                }
                xSemaphoreGive(s_blackbox.file_mutex);
            }
            last_flush = now;
        }
    }

    /* Final drain of ring buffer before shutdown */
    ESP_LOGI(TAG, "Writer task draining buffer...");

    size_t item_size;
    void *item;
    while ((item = xRingbufferReceive(s_blackbox.ring_buffer, &item_size, 0)) != NULL)
    {
        if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
        {
            write_packet_to_file((const blackbox_packet_t *)item, item_size);
            xSemaphoreGive(s_blackbox.file_mutex);
        }
        vRingbufferReturnItem(s_blackbox.ring_buffer, item);
    }

    /* Close file (protected by mutex) */
    if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(1000)) == pdTRUE)
    {
        close_current_file();
        xSemaphoreGive(s_blackbox.file_mutex);
    }

    ESP_LOGI(TAG, "Writer task exiting");

    /* Signal completion before deleting task */
    xSemaphoreGive(s_blackbox.task_done_sem);
    s_blackbox.writer_task = NULL;
    vTaskDelete(NULL);
}

/*******************************************************************************
 * Control Functions
 ******************************************************************************/

esp_err_t blackbox_flush(void)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreGive(s_blackbox.flush_sem);

    /* Wait a bit for flush to complete */
    vTaskDelay(pdMS_TO_TICKS(100));

    return ESP_OK;
}

esp_err_t blackbox_rotate_file(void)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    /* Flush first */
    blackbox_flush();

    /* Force file size over limit to trigger rotation (thread-safe atomic store) */
    atomic_store(&s_blackbox.current_file_size, s_blackbox.config.file_size_limit + 1);

    /* Trigger another flush to process the rotation */
    xSemaphoreGive(s_blackbox.flush_sem);

    return ESP_OK;
}

esp_err_t blackbox_set_level(blackbox_level_t level)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    atomic_store(&s_blackbox.min_level, (int)level);
    return ESP_OK;
}

blackbox_level_t blackbox_get_level(void)
{
    return (blackbox_level_t)atomic_load(&s_blackbox.min_level);
}

esp_err_t blackbox_set_console_output(bool enable)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    atomic_store(&s_blackbox.console_output, enable);
    return ESP_OK;
}

esp_err_t blackbox_set_file_output(bool enable)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    atomic_store(&s_blackbox.file_output, enable);
    return ESP_OK;
}

/*******************************************************************************
 * Statistics Functions
 ******************************************************************************/

esp_err_t blackbox_get_stats(blackbox_stats_t *stats)
{
    if (!s_blackbox.initialized || stats == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE)
    {
        memcpy(stats, &s_blackbox.stats, sizeof(blackbox_stats_t));

        /* Copy atomic counters */
        stats->messages_logged = atomic_load(&s_blackbox.messages_logged);
        stats->messages_dropped = atomic_load(&s_blackbox.messages_dropped);

        /* Calculate buffer high water mark */
        size_t free_size = xRingbufferGetCurFreeSize(s_blackbox.ring_buffer);
        size_t used = s_blackbox.config.buffer_size - free_size;
        if (used > stats->buffer_high_water)
        {
            stats->buffer_high_water = used;
            s_blackbox.stats.buffer_high_water = used;
        }

        xSemaphoreGive(s_blackbox.stats_mutex);
    }

    return ESP_OK;
}

esp_err_t blackbox_reset_stats(void)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE)
    {
        memset(&s_blackbox.stats, 0, sizeof(blackbox_stats_t));
        atomic_store(&s_blackbox.messages_logged, 0);
        atomic_store(&s_blackbox.messages_dropped, 0);
        xSemaphoreGive(s_blackbox.stats_mutex);
    }

    return ESP_OK;
}

/*******************************************************************************
 * Panic Handler Functions
 ******************************************************************************/

/**
 * @brief Write a panic packet directly to file (synchronous, no ring buffer)
 *
 * This function is designed to be called from panic context where we cannot
 * use FreeRTOS primitives or the ring buffer. It writes directly to the
 * file handle if one is open.
 */
static void write_panic_packet_direct(blackbox_msg_type_t msg_type, const char *data, size_t len)
{
    if (s_blackbox.current_file == NULL)
    {
        return;
    }

    /* Build a minimal packet for panic data */
    blackbox_packet_t packet = {0};

    packet.header.magic[0] = BLACKBOX_LOG_MAGIC_BYTE0;
    packet.header.magic[1] = BLACKBOX_LOG_MAGIC_BYTE1;
    packet.header.magic[2] = BLACKBOX_LOG_MAGIC_BYTE2;
    packet.header.magic[3] = BLACKBOX_LOG_MAGIC_BYTE3;
    packet.header.version = BLACKBOX_LOG_VERSION;
    packet.header.msg_type = (uint8_t)msg_type;
    packet.header.level = (uint8_t)BLACKBOX_LOG_LEVEL_ERROR;
    packet.header.reserved = 0;
    packet.header.timestamp_us = esp_timer_get_time();
    packet.header.tag_hash = blackbox_hash_string("PANIC");
    packet.header.file_hash = 0;
    packet.header.line = 0;

    /* Truncate if necessary */
    size_t payload_len = len;
    if (payload_len >= BLACKBOX_LOG_MAX_MESSAGE_SIZE)
    {
        payload_len = BLACKBOX_LOG_MAX_MESSAGE_SIZE - 1;
    }
    packet.header.payload_length = (uint16_t)payload_len;

    /* Copy payload */
    memcpy(packet.payload, data, payload_len);

    /* Calculate CRC-16 for data integrity */
    size_t crc_data_len = sizeof(blackbox_header_t) - sizeof(uint16_t) + payload_len;
    packet.header.crc16 = calculate_crc16((const uint8_t *)&packet, crc_data_len);

    /* Calculate total size */
    size_t packet_size = sizeof(blackbox_header_t) + payload_len;

    /* Write directly to file - no encryption during panic (too complex) */
    fwrite(&packet, 1, packet_size, s_blackbox.current_file);
    fflush(s_blackbox.current_file);
}

/**
 * @brief Custom shutdown handler that logs crash information to file
 *
 * This handler is called during system shutdown/panic. It captures as much
 * information as possible and writes it to the log file.
 *
 * Note: This runs in a limited context - be careful with memory operations.
 */
static void blackbox_shutdown_handler(void)
{
    if (!s_blackbox.initialized)
    {
        return;
    }

    uint32_t flags = atomic_load(&s_blackbox.panic_flags);
    if (!(flags & BLACKBOX_PANIC_FLAG_ENABLED))
    {
        return;
    }

    if (s_blackbox.current_file == NULL)
    {
        return;
    }

    char panic_buf[BLACKBOX_LOG_MAX_MESSAGE_SIZE];
    int len;

    /* Log shutdown/panic marker */
    len = snprintf(panic_buf, sizeof(panic_buf), "PANIC/SHUTDOWN: System reset detected");
    write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_PANIC, panic_buf, len);

    /* Log backtrace if enabled */
    if (flags & BLACKBOX_PANIC_FLAG_BACKTRACE)
    {
        len = snprintf(panic_buf, sizeof(panic_buf), "--- BACKTRACE ---");
        write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_BACKTRACE, panic_buf, len);

        /* Get backtrace using ESP-IDF debug helpers */
        esp_backtrace_frame_t bt_frame;
        esp_backtrace_get_start(&bt_frame.pc, &bt_frame.sp, &bt_frame.next_pc);

        int depth = 0;
        const int max_depth = 32;

        while (depth < max_depth)
        {
            len = snprintf(panic_buf, sizeof(panic_buf),
                           "BT#%02d: PC=0x%08x SP=0x%08x",
                           depth,
                           (unsigned int)bt_frame.pc,
                           (unsigned int)bt_frame.sp);
            write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_BACKTRACE, panic_buf, len);

            if (!esp_backtrace_get_next_frame(&bt_frame))
            {
                break;
            }
            depth++;
        }
    }

    /* Log registers if enabled - note: we don't have frame info in shutdown handler */
    if (flags & BLACKBOX_PANIC_FLAG_REGISTERS)
    {
        len = snprintf(panic_buf, sizeof(panic_buf), "--- REGISTERS (at shutdown) ---");
        write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_PANIC, panic_buf, len);

        /* We can still get some info from backtrace */
        esp_backtrace_frame_t bt_frame;
        esp_backtrace_get_start(&bt_frame.pc, &bt_frame.sp, &bt_frame.next_pc);

        len = snprintf(panic_buf, sizeof(panic_buf),
                       "PC=0x%08x SP=0x%08x NextPC=0x%08x",
                       (unsigned int)bt_frame.pc,
                       (unsigned int)bt_frame.sp,
                       (unsigned int)bt_frame.next_pc);
        write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_PANIC, panic_buf, len);
    }

    /* Memory dump if enabled */
    if (flags & BLACKBOX_PANIC_FLAG_MEMORY_DUMP)
    {
        esp_backtrace_frame_t bt_frame;
        esp_backtrace_get_start(&bt_frame.pc, &bt_frame.sp, &bt_frame.next_pc);

        uint32_t sp = bt_frame.sp;
        if (sp != 0)
        {
            len = snprintf(panic_buf, sizeof(panic_buf), "--- STACK DUMP @ 0x%08x ---", (unsigned int)sp);
            write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_PANIC, panic_buf, len);

            /* Dump memory around SP */
            const int dump_size = BLACKBOX_LOG_PANIC_MEMORY_DUMP_SIZE;
            const int words_per_line = 4;
            uint32_t *ptr = (uint32_t *)(sp & ~3); /* Align to 4 bytes */

            for (int i = 0; i < dump_size / (words_per_line * 4); i++)
            {
                uint32_t addr = (uint32_t)(uintptr_t)ptr;
                /* SOC-agnostic memory validation using ESP-IDF helpers */
                if (esp_ptr_internal((const void *)ptr) || esp_ptr_external_ram((const void *)ptr))
                {
                    len = snprintf(panic_buf, sizeof(panic_buf),
                                   "%08x: %08x %08x %08x %08x",
                                   (unsigned int)addr,
                                   (unsigned int)ptr[0],
                                   (unsigned int)ptr[1],
                                   (unsigned int)ptr[2],
                                   (unsigned int)ptr[3]);
                    write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_PANIC, panic_buf, len);
                }
                ptr += words_per_line;
            }
        }
    }

    /* Mark end of panic data */
    len = snprintf(panic_buf, sizeof(panic_buf), "--- END PANIC DUMP ---");
    write_panic_packet_direct(BLACKBOX_LOG_MSG_TYPE_COREDUMP, panic_buf, len);

    /* Ensure all data is flushed to storage */
    if (s_blackbox.current_file != NULL)
    {
        fflush(s_blackbox.current_file);
        /* Note: fsync/fdatasync might not work in panic context on all platforms */
    }

    /* 
     * NOTE: We intentionally do NOT call blackbox_flush() here because it uses
     * FreeRTOS primitives (xSemaphoreGive, vTaskDelay) which are unsafe in panic
     * context when the scheduler may be stopped.
     */
}

/*******************************************************************************
 * Panic Handler API Functions
 ******************************************************************************/

esp_err_t blackbox_set_panic_flags(uint32_t flags)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store(&s_blackbox.panic_flags, flags);
    ESP_LOGI(TAG, "Panic flags set to 0x%08x", (unsigned int)flags);
    return ESP_OK;
}

uint32_t blackbox_get_panic_flags(void)
{
    if (!s_blackbox.initialized)
    {
        return 0;
    }
    return atomic_load(&s_blackbox.panic_flags);
}

esp_err_t blackbox_set_panic_handler(bool enable)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }
    
    uint32_t flags = atomic_load(&s_blackbox.panic_flags);
    if (enable)
    {
        flags |= BLACKBOX_PANIC_FLAG_ENABLED;
    }
    else
    {
        flags &= ~BLACKBOX_PANIC_FLAG_ENABLED;
    }
    atomic_store(&s_blackbox.panic_flags, flags);
    
    ESP_LOGI(TAG, "Panic handler %s", enable ? "enabled" : "disabled");
    return ESP_OK;
}

bool blackbox_is_panic_handler_enabled(void)
{
    return s_blackbox.initialized && 
           (atomic_load(&s_blackbox.panic_flags) & BLACKBOX_PANIC_FLAG_ENABLED);
}

esp_err_t blackbox_log_test_panic(const char *reason)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (reason == NULL)
    {
        reason = "Test panic entry";
    }

    /* Create a test panic packet using the normal logging path */
    char panic_buf[BLACKBOX_LOG_MAX_MESSAGE_SIZE];
    int len = snprintf(panic_buf, sizeof(panic_buf),
                       "TEST PANIC: %s | Core: %d | Time: %llu us",
                       reason,
                       xPortGetCoreID(),
                       (unsigned long long)esp_timer_get_time());

    /* Build and send test panic packet through normal path */
    blackbox_packet_t packet = {0};

    packet.header.magic[0] = BLACKBOX_LOG_MAGIC_BYTE0;
    packet.header.magic[1] = BLACKBOX_LOG_MAGIC_BYTE1;
    packet.header.magic[2] = BLACKBOX_LOG_MAGIC_BYTE2;
    packet.header.magic[3] = BLACKBOX_LOG_MAGIC_BYTE3;
    packet.header.version = BLACKBOX_LOG_VERSION;
    packet.header.msg_type = (uint8_t)BLACKBOX_LOG_MSG_TYPE_PANIC;
    packet.header.level = (uint8_t)BLACKBOX_LOG_LEVEL_ERROR;
    packet.header.reserved = 0;
    packet.header.timestamp_us = esp_timer_get_time();
    packet.header.tag_hash = blackbox_hash_string("PANIC_TEST");
    packet.header.file_hash = blackbox_hash_string(__FILE__);
    packet.header.line = (uint16_t)__LINE__;
    packet.header.payload_length = (uint16_t)len;
    memcpy(packet.payload, panic_buf, len);

    size_t packet_size = sizeof(blackbox_header_t) + len;

    /* Console output */
    if (atomic_load(&s_blackbox.console_output))
    {
        ESP_LOGE("PANIC_TEST", "%s", panic_buf);
    }

    /* File output via ring buffer */
    if (atomic_load(&s_blackbox.file_output) && s_blackbox.ring_buffer != NULL)
    {
        BaseType_t result = xRingbufferSend(s_blackbox.ring_buffer, &packet, packet_size, 0);
        if (result == pdTRUE)
        {
            atomic_fetch_add(&s_blackbox.messages_logged, 1);
            xSemaphoreGive(s_blackbox.flush_sem);
        }
        else
        {
            atomic_fetch_add(&s_blackbox.messages_dropped, 1);
            return ESP_ERR_NO_MEM;
        }
    }

    return ESP_OK;
}

/*******************************************************************************
 * Structured Message Logging Implementation
 ******************************************************************************/

/**
 * @brief Struct message packet for ring buffer
 */
typedef struct __attribute__((packed)) {
    uint8_t magic[4];         /**< Magic bytes */
    uint8_t version;          /**< Version */
    uint8_t msg_type;         /**< Message type (BBOX_MSG_*) */
    uint8_t format;           /**< Log format (bbox_log_format_t) */
    uint8_t reserved;         /**< Reserved */
    uint64_t timestamp_us;    /**< Timestamp */
    uint16_t data_size;       /**< Size of data following this header */
    uint16_t crc16;           /**< CRC-16 checksum */
    uint8_t data[];           /**< Message data */
} struct_packet_header_t;

#define STRUCT_PACKET_MAGIC_BYTE0 0x53  /* 'S' */
#define STRUCT_PACKET_MAGIC_BYTE1 0x54  /* 'T' */
#define STRUCT_PACKET_MAGIC_BYTE2 0x52  /* 'R' */
#define STRUCT_PACKET_MAGIC_BYTE3 0x55  /* 'U' */

/**
 * @brief Write format definition for PX4 ULog
 */
static esp_err_t write_ulog_format_def(bbox_msg_id_t msg_id)
{
    if (s_blackbox.format_ctx.format_written[msg_id]) {
        return ESP_OK;  /* Already written */
    }

    const char *format_str = bbox_get_ulog_format(msg_id);
    if (format_str == NULL) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* Build format message */
    uint8_t buf[300];
    ulog_msg_header_t *header = (ulog_msg_header_t *)buf;
    size_t format_len = strlen(format_str);
    
    header->msg_type = ULOG_MSG_FORMAT;
    header->msg_size = format_len;
    
    memcpy(buf + sizeof(ulog_msg_header_t), format_str, format_len);
    
    size_t total_size = sizeof(ulog_msg_header_t) + format_len;
    
    if (s_blackbox.current_file != NULL) {
        fwrite(buf, 1, total_size, s_blackbox.current_file);
        atomic_fetch_add(&s_blackbox.current_file_size, total_size);
    }
    
    s_blackbox.format_ctx.format_written[msg_id] = true;
    
    return ESP_OK;
}

/**
 * @brief Write format definition for ArduPilot DataFlash
 */
static esp_err_t write_dataflash_format_def(bbox_msg_id_t msg_id)
{
    if (s_blackbox.format_ctx.format_written[msg_id]) {
        return ESP_OK;  /* Already written */
    }

    dataflash_fmt_msg_t fmt_msg;
    memset(&fmt_msg, 0, sizeof(fmt_msg));
    
    fmt_msg.header.head1 = DATAFLASH_HEAD_BYTE1;
    fmt_msg.header.head2 = DATAFLASH_HEAD_BYTE2;
    fmt_msg.header.msg_id = DF_MSG_FORMAT;
    fmt_msg.type = (uint8_t)msg_id;
    
    char name[5], format[17], labels[65];
    bbox_get_dataflash_format(msg_id, name, format, labels);
    
    strncpy(fmt_msg.name, name, 4);
    strncpy(fmt_msg.format, format, 16);
    strncpy(fmt_msg.labels, labels, 64);
    
    /* Calculate message length */
    fmt_msg.length = sizeof(dataflash_fmt_msg_t);
    
    if (s_blackbox.current_file != NULL) {
        fwrite(&fmt_msg, 1, sizeof(fmt_msg), s_blackbox.current_file);
        atomic_fetch_add(&s_blackbox.current_file_size, sizeof(fmt_msg));
    }
    
    s_blackbox.format_ctx.format_written[msg_id] = true;
    
    return ESP_OK;
}

/**
 * @brief Write struct data in PX4 ULog format
 */
static esp_err_t write_struct_ulog(bbox_msg_id_t msg_id, const void *data, size_t size)
{
    /* Ensure format is written */
    write_ulog_format_def(msg_id);
    
    /* Build data message */
    uint8_t buf[512];
    ulog_data_header_t *header = (ulog_data_header_t *)buf;
    
    header->header.msg_type = ULOG_MSG_DATA;
    header->header.msg_size = sizeof(uint16_t) + size;
    header->msg_id = s_blackbox.format_ctx.next_msg_id;
    
    memcpy(buf + sizeof(ulog_data_header_t), data, size);
    
    size_t total_size = sizeof(ulog_data_header_t) + size;
    
    if (s_blackbox.current_file != NULL) {
        fwrite(buf, 1, total_size, s_blackbox.current_file);
        atomic_fetch_add(&s_blackbox.current_file_size, total_size);
    }
    
    return ESP_OK;
}

/**
 * @brief Write struct data in ArduPilot DataFlash format
 */
static esp_err_t write_struct_dataflash(bbox_msg_id_t msg_id, const void *data, size_t size)
{
    /* Ensure format is written */
    write_dataflash_format_def(msg_id);
    
    /* Build data message */
    uint8_t buf[512];
    dataflash_msg_header_t *header = (dataflash_msg_header_t *)buf;
    
    header->head1 = DATAFLASH_HEAD_BYTE1;
    header->head2 = DATAFLASH_HEAD_BYTE2;
    header->msg_id = (uint8_t)msg_id;
    
    memcpy(buf + sizeof(dataflash_msg_header_t), data, size);
    
    size_t total_size = sizeof(dataflash_msg_header_t) + size;
    
    if (s_blackbox.current_file != NULL) {
        fwrite(buf, 1, total_size, s_blackbox.current_file);
        atomic_fetch_add(&s_blackbox.current_file_size, total_size);
    }
    
    return ESP_OK;
}

/**
 * @brief Write struct data in native BBOX format
 */
static esp_err_t write_struct_bbox(bbox_msg_id_t msg_id, const void *data, size_t size)
{
    /* Build BBOX struct packet */
    uint8_t buf[512];
    struct_packet_header_t *header = (struct_packet_header_t *)buf;
    
    header->magic[0] = STRUCT_PACKET_MAGIC_BYTE0;
    header->magic[1] = STRUCT_PACKET_MAGIC_BYTE1;
    header->magic[2] = STRUCT_PACKET_MAGIC_BYTE2;
    header->magic[3] = STRUCT_PACKET_MAGIC_BYTE3;
    header->version = BLACKBOX_LOG_VERSION;
    header->msg_type = (uint8_t)msg_id;
    header->format = BLACKBOX_FORMAT_BBOX;
    header->reserved = 0;
    header->timestamp_us = esp_timer_get_time();
    header->data_size = (uint16_t)size;
    
    memcpy(buf + sizeof(struct_packet_header_t), data, size);
    
    /* Calculate CRC */
    size_t crc_len = sizeof(struct_packet_header_t) - sizeof(uint16_t) + size;
    header->crc16 = calculate_crc16(buf, crc_len);
    
    size_t total_size = sizeof(struct_packet_header_t) + size;
    
    if (s_blackbox.current_file != NULL) {
        if (s_blackbox.config.encrypt) {
            encrypt_and_write(buf, total_size);
        } else {
            fwrite(buf, 1, total_size, s_blackbox.current_file);
        }
        atomic_fetch_add(&s_blackbox.current_file_size, total_size);
    }
    
    return ESP_OK;
}

esp_err_t blackbox_log_struct(bbox_msg_id_t msg_id, const void *data, size_t size)
{
    if (!s_blackbox.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    
    if (data == NULL || size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    if (!atomic_load(&s_blackbox.file_output)) {
        return ESP_OK;  /* File output disabled */
    }
    
    esp_err_t ret = ESP_OK;
    
    /* Take file mutex for direct write */
    if (xSemaphoreTake(s_blackbox.file_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        atomic_fetch_add(&s_blackbox.messages_dropped, 1);
        return ESP_ERR_TIMEOUT;
    }
    
    /* Ensure file is open */
    if (s_blackbox.current_file == NULL) {
        ret = create_new_log_file();
        if (ret != ESP_OK) {
            xSemaphoreGive(s_blackbox.file_mutex);
            return ret;
        }
    }
    
    /* Check file rotation */
    size_t current_size = atomic_load(&s_blackbox.current_file_size);
    if (current_size + size + 32 > s_blackbox.config.file_size_limit) {
        ret = create_new_log_file();
        if (ret != ESP_OK) {
            xSemaphoreGive(s_blackbox.file_mutex);
            return ret;
        }
    }
    
    /* Write based on format */
    switch (s_blackbox.config.log_format) {
        case BLACKBOX_FORMAT_PX4_ULOG:
            ret = write_struct_ulog(msg_id, data, size);
            break;
        case BLACKBOX_FORMAT_ARDUPILOT:
            ret = write_struct_dataflash(msg_id, data, size);
            break;
        case BLACKBOX_FORMAT_BBOX:
        default:
            ret = write_struct_bbox(msg_id, data, size);
            break;
    }
    
    xSemaphoreGive(s_blackbox.file_mutex);
    
    if (ret == ESP_OK) {
        atomic_fetch_add(&s_blackbox.struct_messages_logged, 1);
    }
    
    return ret;
}

/* Convenience functions for specific message types */

esp_err_t blackbox_log_imu(const bbox_msg_imu_t *imu)
{
    return blackbox_log_struct(BBOX_MSG_IMU, imu, sizeof(bbox_msg_imu_t));
}

esp_err_t blackbox_log_gps(const bbox_msg_gps_t *gps)
{
    return blackbox_log_struct(BBOX_MSG_GPS, gps, sizeof(bbox_msg_gps_t));
}

esp_err_t blackbox_log_attitude(const bbox_msg_attitude_t *att)
{
    return blackbox_log_struct(BBOX_MSG_ATTITUDE, att, sizeof(bbox_msg_attitude_t));
}

esp_err_t blackbox_log_pid(bbox_msg_id_t axis, const bbox_msg_pid_t *pid)
{
    if (axis < BBOX_MSG_PID_ROLL || axis > BBOX_MSG_PID_ALT) {
        return ESP_ERR_INVALID_ARG;
    }
    return blackbox_log_struct(axis, pid, sizeof(bbox_msg_pid_t));
}

esp_err_t blackbox_log_motor(const bbox_msg_motor_t *motor)
{
    return blackbox_log_struct(BBOX_MSG_MOTOR, motor, sizeof(bbox_msg_motor_t));
}

esp_err_t blackbox_log_battery(const bbox_msg_battery_t *battery)
{
    return blackbox_log_struct(BBOX_MSG_BATTERY, battery, sizeof(bbox_msg_battery_t));
}

esp_err_t blackbox_log_rc_input(const bbox_msg_rc_input_t *rc)
{
    return blackbox_log_struct(BBOX_MSG_RC_INPUT, rc, sizeof(bbox_msg_rc_input_t));
}

esp_err_t blackbox_log_status(const bbox_msg_status_t *status)
{
    return blackbox_log_struct(BBOX_MSG_STATUS, status, sizeof(bbox_msg_status_t));
}

esp_err_t blackbox_log_baro(const bbox_msg_baro_t *baro)
{
    return blackbox_log_struct(BBOX_MSG_BARO, baro, sizeof(bbox_msg_baro_t));
}

esp_err_t blackbox_log_mag(const bbox_msg_mag_t *mag)
{
    return blackbox_log_struct(BBOX_MSG_MAG, mag, sizeof(bbox_msg_mag_t));
}

esp_err_t blackbox_log_esc(const bbox_msg_esc_t *esc)
{
    return blackbox_log_struct(BBOX_MSG_ESC, esc, sizeof(bbox_msg_esc_t));
}

blackbox_log_format_t blackbox_get_log_format(void)
{
    if (!s_blackbox.initialized) {
        return BLACKBOX_FORMAT_BBOX;
    }
    return s_blackbox.config.log_format;
}
