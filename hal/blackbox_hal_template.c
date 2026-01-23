/**
 * @file blackbox_hal_template.c
 * @brief HAL Template for new platform ports
 *
 * Copy this file and implement all functions for your target platform.
 * See blackbox_hal.h for detailed function documentation.
 *
 * Required functions (must implement):
 *   - file_open, file_write, file_sync, file_close, file_size
 *   - get_time_us
 *
 * Optional functions (set to NULL if not available):
 *   - file_exists, mkdir
 *   - mutex_*, task_*, sem_* (for threading)
 *   - aes_*, random_fill (for encryption)
 *   - log_output (for debug logging)
 *   - malloc, free (falls back to stdlib)
 *   - get_device_id
 *
 * @author Your Name
 * @version 1.0.0
 */

#include "../hal/blackbox_hal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*******************************************************************************
 * File Operations (REQUIRED)
 ******************************************************************************/

static bbox_file_t hal_template_file_open(const char *path, bool append)
{
    /* TODO: Implement file open for your platform */
    /* const char *mode = append ? "ab" : "wb"; */
    /* return fopen(path, mode); */
    (void)path;
    (void)append;
    return NULL;
}

static size_t hal_template_file_write(bbox_file_t file, const void *data, size_t len)
{
    /* TODO: Implement file write for your platform */
    (void)file;
    (void)data;
    (void)len;
    return 0;
}

static int hal_template_file_sync(bbox_file_t file)
{
    /* TODO: Implement file sync/flush for your platform */
    (void)file;
    return -1;
}

static int hal_template_file_close(bbox_file_t file)
{
    /* TODO: Implement file close for your platform */
    (void)file;
    return -1;
}

static size_t hal_template_file_size(bbox_file_t file)
{
    /* TODO: Implement file size query for your platform */
    (void)file;
    return 0;
}

/*******************************************************************************
 * Time (REQUIRED)
 ******************************************************************************/

static uint64_t hal_template_get_time_us(void)
{
    /* TODO: Implement microsecond timestamp for your platform */
    /* This should be monotonic if possible */
    return 0;
}

/*******************************************************************************
 * Optional: File Utilities
 ******************************************************************************/

/*
static bool hal_template_file_exists(const char *path)
{
    // TODO: Check if file/directory exists
    return false;
}

static int hal_template_mkdir(const char *path)
{
    // TODO: Create directory
    return -1;
}
*/

/*******************************************************************************
 * Optional: Threading - Mutex
 ******************************************************************************/

/*
static void *hal_template_mutex_create(void)
{
    // TODO: Create mutex
    return NULL;
}

static void hal_template_mutex_destroy(void *mtx)
{
    // TODO: Destroy mutex
}

static void hal_template_mutex_lock(void *mtx)
{
    // TODO: Lock mutex
}

static void hal_template_mutex_unlock(void *mtx)
{
    // TODO: Unlock mutex
}
*/

/*******************************************************************************
 * Optional: Threading - Tasks
 ******************************************************************************/

/*
static void *hal_template_task_create(void (*func)(void *), const char *name,
                                       size_t stack_size, void *arg, int priority)
{
    // TODO: Create background task/thread
    return NULL;
}

static void hal_template_task_delete(void *task)
{
    // TODO: Delete task/thread
}

static void hal_template_task_delay_ms(uint32_t ms)
{
    // TODO: Delay for ms milliseconds
}
*/

/*******************************************************************************
 * Optional: Threading - Semaphores
 ******************************************************************************/

/*
static void *hal_template_sem_create(void)
{
    // TODO: Create binary semaphore
    return NULL;
}

static void hal_template_sem_destroy(void *sem)
{
    // TODO: Destroy semaphore
}

static bool hal_template_sem_take(void *sem, uint32_t timeout_ms)
{
    // TODO: Take semaphore with timeout (UINT32_MAX = wait forever)
    return false;
}

static void hal_template_sem_give(void *sem)
{
    // TODO: Give/signal semaphore
}
*/

/*******************************************************************************
 * Optional: Crypto (AES-256-CTR)
 ******************************************************************************/

/*
static void *hal_template_aes_init(const uint8_t *key, size_t key_len)
{
    // TODO: Initialize AES-256-CTR context with key
    return NULL;
}

static int hal_template_aes_set_iv(void *ctx, const uint8_t *iv, size_t iv_len)
{
    // TODO: Set IV for encryption
    return -1;
}

static int hal_template_aes_encrypt(void *ctx, const uint8_t *input,
                                     uint8_t *output, size_t len)
{
    // TODO: Encrypt data in CTR mode
    return -1;
}

static void hal_template_aes_free(void *ctx)
{
    // TODO: Free AES context
}

static void hal_template_random_fill(uint8_t *buf, size_t len)
{
    // TODO: Fill buffer with random bytes (for IV generation)
}
*/

/*******************************************************************************
 * Optional: Logging
 ******************************************************************************/

/*
static void hal_template_log_output(const char *tag, bbox_log_level_t level,
                                     const char *fmt, va_list args)
{
    // TODO: Output log message to console/debug port
}
*/

/*******************************************************************************
 * Optional: Device Info
 ******************************************************************************/

/*
static void hal_template_get_device_id(char *buf, size_t buf_len)
{
    // TODO: Get unique device identifier (MAC, serial, etc.)
    strncpy(buf, "DEVICE", buf_len);
}
*/

/*******************************************************************************
 * HAL Interface
 ******************************************************************************/

static const bbox_hal_t s_hal_template = {
    /* Required: File operations */
    .file_open = hal_template_file_open,
    .file_write = hal_template_file_write,
    .file_sync = hal_template_file_sync,
    .file_close = hal_template_file_close,
    .file_size = hal_template_file_size,
    
    /* Required: Time */
    .get_time_us = hal_template_get_time_us,
    
    /* Optional: Set to NULL if not implemented */
    .file_exists = NULL,
    .mkdir = NULL,
    
    .mutex_create = NULL,
    .mutex_destroy = NULL,
    .mutex_lock = NULL,
    .mutex_unlock = NULL,
    
    .task_create = NULL,
    .task_delete = NULL,
    .task_delay_ms = NULL,
    
    .sem_create = NULL,
    .sem_destroy = NULL,
    .sem_take = NULL,
    .sem_give = NULL,
    
    .aes_init = NULL,
    .aes_set_iv = NULL,
    .aes_encrypt = NULL,
    .aes_free = NULL,
    .random_fill = NULL,
    
    .log_output = NULL,
    
    .malloc = NULL,
    .free = NULL,
    
    .get_device_id = NULL,
};

/**
 * @brief Get the template HAL implementation
 */
const bbox_hal_t *bbox_hal_template_get(void)
{
    return &s_hal_template;
}
