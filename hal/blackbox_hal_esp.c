/**
 * @file blackbox_hal_esp.c
 * @brief ESP-IDF HAL implementation for Blackbox logger
 *
 * Implements all HAL functions using ESP-IDF APIs:
 * - File I/O: stdio (works with SPIFFS, FATFS, LittleFS)
 * - Threading: FreeRTOS tasks, semaphores, mutexes
 * - Crypto: mbedTLS AES-256-CTR
 * - Logging: ESP_LOG
 * - Memory: heap_caps
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#include "blackbox_hal_esp.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_heap_caps.h"

#include "mbedtls/cipher.h"

static const char *TAG = "BBOX_HAL";

/*******************************************************************************
 * File Operations
 ******************************************************************************/

static bbox_file_t hal_esp_file_open(const char *path, bool append)
{
    const char *mode = append ? "ab" : "wb";
    FILE *f = fopen(path, mode);
    if (!f) {
        ESP_LOGE(TAG, "Failed to open file: %s (%s)", path, strerror(errno));
    }
    return (bbox_file_t)f;
}

static size_t hal_esp_file_write(bbox_file_t file, const void *data, size_t len)
{
    if (!file) return 0;
    return fwrite(data, 1, len, (FILE *)file);
}

static int hal_esp_file_sync(bbox_file_t file)
{
    if (!file) return -1;
    return fflush((FILE *)file);
}

static int hal_esp_file_close(bbox_file_t file)
{
    if (!file) return -1;
    return fclose((FILE *)file);
}

static size_t hal_esp_file_size(bbox_file_t file)
{
    if (!file) return 0;
    
    FILE *f = (FILE *)file;
    long current = ftell(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, current, SEEK_SET);
    
    return (size_t)(size > 0 ? size : 0);
}

static bool hal_esp_file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

static int hal_esp_mkdir(const char *path)
{
    /* Create directory (mkdir doesn't create parents on most ESP filesystems) */
    int ret = mkdir(path, 0755);
    if (ret != 0 && errno != EEXIST) {
        ESP_LOGE(TAG, "Failed to create directory: %s (%s)", path, strerror(errno));
        return -1;
    }
    return 0;
}

/*******************************************************************************
 * Time
 ******************************************************************************/

static uint64_t hal_esp_get_time_us(void)
{
    return (uint64_t)esp_timer_get_time();
}

/*******************************************************************************
 * Threading: Mutex
 ******************************************************************************/

static void *hal_esp_mutex_create(void)
{
    return (void *)xSemaphoreCreateMutex();
}

static void hal_esp_mutex_destroy(void *mtx)
{
    if (mtx) {
        vSemaphoreDelete((SemaphoreHandle_t)mtx);
    }
}

static void hal_esp_mutex_lock(void *mtx)
{
    if (mtx) {
        xSemaphoreTake((SemaphoreHandle_t)mtx, portMAX_DELAY);
    }
}

static void hal_esp_mutex_unlock(void *mtx)
{
    if (mtx) {
        xSemaphoreGive((SemaphoreHandle_t)mtx);
    }
}

/*******************************************************************************
 * Threading: Tasks
 ******************************************************************************/

typedef struct {
    void (*func)(void *);
    void *arg;
} task_wrapper_t;

static void task_wrapper(void *arg)
{
    task_wrapper_t *wrapper = (task_wrapper_t *)arg;
    void (*func)(void *) = wrapper->func;
    void *user_arg = wrapper->arg;
    
    free(wrapper);
    
    func(user_arg);
    
    vTaskDelete(NULL);
}

static void *hal_esp_task_create(void (*func)(void *arg), const char *name,
                                  size_t stack_size, void *arg, int priority)
{
    task_wrapper_t *wrapper = malloc(sizeof(task_wrapper_t));
    if (!wrapper) return NULL;
    
    wrapper->func = func;
    wrapper->arg = arg;
    
    TaskHandle_t task = NULL;
    BaseType_t ret = xTaskCreate(task_wrapper, name, stack_size, wrapper, priority, &task);
    
    if (ret != pdPASS) {
        free(wrapper);
        return NULL;
    }
    
    return (void *)task;
}

static void hal_esp_task_delete(void *task)
{
    if (task) {
        vTaskDelete((TaskHandle_t)task);
    }
}

static void hal_esp_task_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

/*******************************************************************************
 * Threading: Semaphores
 ******************************************************************************/

static void *hal_esp_sem_create(void)
{
    return (void *)xSemaphoreCreateBinary();
}

static void hal_esp_sem_destroy(void *sem)
{
    if (sem) {
        vSemaphoreDelete((SemaphoreHandle_t)sem);
    }
}

static bool hal_esp_sem_take(void *sem, uint32_t timeout_ms)
{
    if (!sem) return false;
    
    TickType_t ticks = (timeout_ms == UINT32_MAX) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    return (xSemaphoreTake((SemaphoreHandle_t)sem, ticks) == pdTRUE);
}

static void hal_esp_sem_give(void *sem)
{
    if (sem) {
        xSemaphoreGive((SemaphoreHandle_t)sem);
    }
}

/*******************************************************************************
 * Crypto: AES-256-CTR
 ******************************************************************************/

typedef struct {
    mbedtls_cipher_context_t ctx;
    bool initialized;
} esp_aes_ctx_t;

static void *hal_esp_aes_init(const uint8_t *key, size_t key_len)
{
    if (key_len != 32) {
        ESP_LOGE(TAG, "AES key must be 32 bytes (256 bits)");
        return NULL;
    }
    
    esp_aes_ctx_t *ctx = calloc(1, sizeof(esp_aes_ctx_t));
    if (!ctx) return NULL;
    
    mbedtls_cipher_init(&ctx->ctx);
    
    int ret = mbedtls_cipher_setup(&ctx->ctx,
                                   mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_cipher_setup failed: %d", ret);
        free(ctx);
        return NULL;
    }
    
    ret = mbedtls_cipher_setkey(&ctx->ctx, key, 256, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_cipher_setkey failed: %d", ret);
        mbedtls_cipher_free(&ctx->ctx);
        free(ctx);
        return NULL;
    }
    
    ctx->initialized = true;
    return ctx;
}

static int hal_esp_aes_set_iv(void *ctx, const uint8_t *iv, size_t iv_len)
{
    esp_aes_ctx_t *aes = (esp_aes_ctx_t *)ctx;
    if (!aes || !aes->initialized) return -1;
    
    mbedtls_cipher_reset(&aes->ctx);
    return mbedtls_cipher_set_iv(&aes->ctx, iv, iv_len);
}

static int hal_esp_aes_encrypt(void *ctx, const uint8_t *input, uint8_t *output, size_t len)
{
    esp_aes_ctx_t *aes = (esp_aes_ctx_t *)ctx;
    if (!aes || !aes->initialized) return -1;
    
    size_t olen = 0;
    return mbedtls_cipher_update(&aes->ctx, input, len, output, &olen);
}

static void hal_esp_aes_free(void *ctx)
{
    esp_aes_ctx_t *aes = (esp_aes_ctx_t *)ctx;
    if (aes) {
        if (aes->initialized) {
            mbedtls_cipher_free(&aes->ctx);
        }
        free(aes);
    }
}

static void hal_esp_random_fill(uint8_t *buf, size_t len)
{
    esp_fill_random(buf, len);
}

/*******************************************************************************
 * Logging
 ******************************************************************************/

static void hal_esp_log_output(const char *tag, bbox_log_level_t level,
                                const char *fmt, va_list args)
{
    esp_log_level_t esp_level;
    
    switch (level) {
        case BBOX_LOG_LEVEL_ERROR:   esp_level = ESP_LOG_ERROR; break;
        case BBOX_LOG_LEVEL_WARN:    esp_level = ESP_LOG_WARN; break;
        case BBOX_LOG_LEVEL_INFO:    esp_level = ESP_LOG_INFO; break;
        case BBOX_LOG_LEVEL_DEBUG:   esp_level = ESP_LOG_DEBUG; break;
        case BBOX_LOG_LEVEL_VERBOSE: esp_level = ESP_LOG_VERBOSE; break;
        default:                     esp_level = ESP_LOG_INFO; break;
    }
    
    esp_log_writev(esp_level, tag, fmt, args);
}

/*******************************************************************************
 * Memory
 ******************************************************************************/

static void *hal_esp_malloc(size_t size)
{
    return heap_caps_malloc(size, MALLOC_CAP_DEFAULT);
}

static void hal_esp_free(void *ptr)
{
    heap_caps_free(ptr);
}

/*******************************************************************************
 * Device Info
 ******************************************************************************/

static void hal_esp_get_device_id(char *buf, size_t buf_len)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    
    snprintf(buf, buf_len, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*******************************************************************************
 * HAL Interface
 ******************************************************************************/

static const bbox_hal_t s_hal_esp = {
    /* Required: File operations */
    .file_open = hal_esp_file_open,
    .file_write = hal_esp_file_write,
    .file_sync = hal_esp_file_sync,
    .file_close = hal_esp_file_close,
    .file_size = hal_esp_file_size,
    
    /* Required: Time */
    .get_time_us = hal_esp_get_time_us,
    
    /* Optional: File utilities */
    .file_exists = hal_esp_file_exists,
    .mkdir = hal_esp_mkdir,
    
    /* Optional: Threading - Mutex */
    .mutex_create = hal_esp_mutex_create,
    .mutex_destroy = hal_esp_mutex_destroy,
    .mutex_lock = hal_esp_mutex_lock,
    .mutex_unlock = hal_esp_mutex_unlock,
    
    /* Optional: Threading - Tasks */
    .task_create = hal_esp_task_create,
    .task_delete = hal_esp_task_delete,
    .task_delay_ms = hal_esp_task_delay_ms,
    
    /* Optional: Threading - Semaphores */
    .sem_create = hal_esp_sem_create,
    .sem_destroy = hal_esp_sem_destroy,
    .sem_take = hal_esp_sem_take,
    .sem_give = hal_esp_sem_give,
    
    /* Optional: Crypto */
    .aes_init = hal_esp_aes_init,
    .aes_set_iv = hal_esp_aes_set_iv,
    .aes_encrypt = hal_esp_aes_encrypt,
    .aes_free = hal_esp_aes_free,
    .random_fill = hal_esp_random_fill,
    
    /* Optional: Logging */
    .log_output = hal_esp_log_output,
    
    /* Optional: Memory */
    .malloc = hal_esp_malloc,
    .free = hal_esp_free,
    
    /* Optional: Device info */
    .get_device_id = hal_esp_get_device_id,
};

const bbox_hal_t *bbox_hal_esp_get(void)
{
    return &s_hal_esp;
}

bbox_err_t bbox_hal_esp_init(void)
{
    /* Nothing to initialize currently */
    ESP_LOGI(TAG, "ESP-IDF HAL initialized");
    return BBOX_OK;
}

bbox_err_t bbox_hal_esp_deinit(void)
{
    /* Nothing to cleanup currently */
    ESP_LOGI(TAG, "ESP-IDF HAL deinitialized");
    return BBOX_OK;
}
