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
#include "esp_random.h"
#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"

#include <stdatomic.h>

/* Panic handler support - always included, enabled at runtime */
#include "esp_debug_helpers.h"
#include "esp_cpu.h"
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

    /* Ring buffer */
    RingbufHandle_t ring_buffer;

    /* Writer task */
    TaskHandle_t writer_task;
    SemaphoreHandle_t flush_sem;
    volatile bool shutdown_requested;

    /* File management */
    FILE *current_file;
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

    /* Store configuration */
    memcpy(&s_blackbox.config, config, sizeof(blackbox_config_t));

    /* Enforce minimum buffer size */
    if (s_blackbox.config.buffer_size < BLACKBOX_LOG_MIN_BUFFER_SIZE)
    {
        s_blackbox.config.buffer_size = BLACKBOX_LOG_MIN_BUFFER_SIZE;
    }

    /* Set default file prefix if not provided */
    if (s_blackbox.config.file_prefix == NULL)
    {
        s_blackbox.config.file_prefix = "flight";
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

    /* Create ring buffer */
    s_blackbox.ring_buffer = xRingbufferCreate(s_blackbox.config.buffer_size, RINGBUF_TYPE_NOSPLIT);
    if (s_blackbox.ring_buffer == NULL)
    {
        ESP_LOGE(TAG, "Failed to create ring buffer");
        return ESP_ERR_NO_MEM;
    }

    /* Create flush semaphore */
    s_blackbox.flush_sem = xSemaphoreCreateBinary();
    if (s_blackbox.flush_sem == NULL)
    {
        ESP_LOGE(TAG, "Failed to create flush semaphore");
        vRingbufferDelete(s_blackbox.ring_buffer);
        return ESP_ERR_NO_MEM;
    }

    /* Create stats mutex */
    s_blackbox.stats_mutex = xSemaphoreCreateMutex();
    if (s_blackbox.stats_mutex == NULL)
    {
        ESP_LOGE(TAG, "Failed to create stats mutex");
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
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
            vSemaphoreDelete(s_blackbox.flush_sem);
            vRingbufferDelete(s_blackbox.ring_buffer);
            return ESP_FAIL;
        }

        ret = mbedtls_cipher_setkey(&s_blackbox.cipher_ctx, s_blackbox.config.encryption_key,
                                    256, MBEDTLS_ENCRYPT);
        if (ret != 0)
        {
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
    if (ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create writer task");
        if (s_blackbox.config.encrypt)
        {
            mbedtls_cipher_free(&s_blackbox.cipher_ctx);
        }
        vSemaphoreDelete(s_blackbox.stats_mutex);
        vSemaphoreDelete(s_blackbox.flush_sem);
        vRingbufferDelete(s_blackbox.ring_buffer);
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

    ESP_LOGI(TAG, "Logger initialized: path=%s, encrypt=%d, buffer=%uKB",
             s_blackbox.config.root_path, s_blackbox.config.encrypt,
             (unsigned)(s_blackbox.config.buffer_size / 1024));

    return ESP_OK;
}

esp_err_t blackbox_deinit(void)
{
    if (!s_blackbox.initialized)
    {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Shutting down logger...");

    /* Request shutdown */
    s_blackbox.shutdown_requested = true;
    xSemaphoreGive(s_blackbox.flush_sem);

    /* Wait for writer task to finish (max 5 seconds) */
    for (int i = 0; i < 50 && s_blackbox.writer_task != NULL; i++)
    {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    /* Force delete task if still running */
    if (s_blackbox.writer_task != NULL)
    {
        vTaskDelete(s_blackbox.writer_task);
        s_blackbox.writer_task = NULL;
    }

    /* Close current file */
    close_current_file();

    /* Free encryption context */
    if (s_blackbox.config.encrypt)
    {
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

    /* Return total packet size (header + actual payload size) */
    return sizeof(blackbox_header_t) + payload_len;
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

    /* Generate new file name */
    s_blackbox.file_counter++;
    snprintf(s_blackbox.current_file_path, BLACKBOX_LOG_MAX_PATH_LENGTH,
             "%s/%s%03lu.blackbox",
             s_blackbox.config.root_path,
             s_blackbox.config.file_prefix,
             (unsigned long)s_blackbox.file_counter);

    /* Open file for writing */
    s_blackbox.current_file = fopen(s_blackbox.current_file_path, "wb");
    if (s_blackbox.current_file == NULL)
    {
        ESP_LOGE(TAG, "Failed to create log file: %s", s_blackbox.current_file_path);
        return ESP_FAIL;
    }

    s_blackbox.current_file_size = 0;

    /* Write file header */
    esp_err_t ret = write_file_header();
    if (ret != ESP_OK)
    {
        fclose(s_blackbox.current_file);
        s_blackbox.current_file = NULL;
        return ret;
    }

    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE)
    {
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
    if (written != sizeof(header))
    {
        ESP_LOGE(TAG, "Failed to write file header");
        return ESP_FAIL;
    }

    s_blackbox.current_file_size += written;

    /* If encrypted, also write the IV after the header */
    if (s_blackbox.config.encrypt)
    {
        written = fwrite(s_blackbox.iv, 1, sizeof(s_blackbox.iv), s_blackbox.current_file);
        if (written != sizeof(s_blackbox.iv))
        {
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

    /* Check if rotation is needed */
    if (s_blackbox.current_file_size + packet_size > s_blackbox.config.file_size_limit)
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
            if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE)
            {
                s_blackbox.stats.write_errors++;
                xSemaphoreGive(s_blackbox.stats_mutex);
            }
            return ESP_FAIL;
        }
    }

    s_blackbox.current_file_size += written;

    if (xSemaphoreTake(s_blackbox.stats_mutex, portMAX_DELAY) == pdTRUE)
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
        ESP_LOGI(TAG, "Closed log file: %s (size: %u bytes)",
                 s_blackbox.current_file_path, (unsigned)s_blackbox.current_file_size);
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

    while (!s_blackbox.shutdown_requested)
    {
        /* Wait for flush signal or timeout */
        xSemaphoreTake(s_blackbox.flush_sem, flush_interval);

        /* Process all items in the ring buffer */
        size_t item_size;
        void *item;

        while ((item = xRingbufferReceive(s_blackbox.ring_buffer, &item_size, 0)) != NULL)
        {
            /* Write to file */
            write_packet_to_file((const blackbox_packet_t *)item, item_size);

            /* Return item to ring buffer */
            vRingbufferReturnItem(s_blackbox.ring_buffer, item);

            /* Check for shutdown during processing */
            if (s_blackbox.shutdown_requested)
            {
                break;
            }
        }

        /* Periodic flush */
        TickType_t now = xTaskGetTickCount();
        if ((now - last_flush) >= flush_interval)
        {
            if (s_blackbox.current_file != NULL)
            {
                fflush(s_blackbox.current_file);
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
        write_packet_to_file((const blackbox_packet_t *)item, item_size);
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

    /* Force file size over limit to trigger rotation */
    s_blackbox.current_file_size = s_blackbox.config.file_size_limit + 1;

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
                /* Simple bounds check - may not be perfect in panic context */
                if (addr >= 0x3FF00000 && addr < 0x40000000)
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

    /* Also flush any remaining ring buffer data */
    blackbox_flush();
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
