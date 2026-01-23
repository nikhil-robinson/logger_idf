/**
 * @file blackbox_hal.h
 * @brief Hardware Abstraction Layer interface for Blackbox logger
 *
 * This file defines the platform abstraction interface. Implement these
 * functions for your target platform (ESP-IDF, STM32, POSIX, etc.)
 *
 * Required functions:
 *   - File I/O (open, write, sync, close, size)
 *   - Timestamp
 *
 * Optional functions (set to NULL if not available):
 *   - Threading (mutex, background task)
 *   - Encryption (AES-256-CTR)
 *   - Debug logging
 *   - Memory allocation
 *   - Device ID
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_HAL_H
#define BLACKBOX_HAL_H

#include "blackbox_types.h"
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * File Handle Type
 ******************************************************************************/

/**
 * @brief Opaque file handle type
 * 
 * Platforms should typedef their own handle type (FILE*, int fd, etc.)
 */
typedef void* bbox_file_t;

/** Invalid file handle value */
#define BBOX_FILE_INVALID NULL

/*******************************************************************************
 * HAL Function Pointer Types
 ******************************************************************************/

/* File operations */
typedef bbox_file_t (*bbox_hal_file_open_fn)(const char *path, bool append);
typedef size_t (*bbox_hal_file_write_fn)(bbox_file_t file, const void *data, size_t len);
typedef int (*bbox_hal_file_sync_fn)(bbox_file_t file);
typedef int (*bbox_hal_file_close_fn)(bbox_file_t file);
typedef size_t (*bbox_hal_file_size_fn)(bbox_file_t file);
typedef bool (*bbox_hal_file_exists_fn)(const char *path);
typedef int (*bbox_hal_mkdir_fn)(const char *path);

/* Time */
typedef uint64_t (*bbox_hal_get_time_us_fn)(void);

/* Threading (optional) */
typedef void* (*bbox_hal_mutex_create_fn)(void);
typedef void (*bbox_hal_mutex_destroy_fn)(void *mtx);
typedef void (*bbox_hal_mutex_lock_fn)(void *mtx);
typedef void (*bbox_hal_mutex_unlock_fn)(void *mtx);

/* Background task (optional) */
typedef void* (*bbox_hal_task_create_fn)(void (*func)(void *arg), const char *name, 
                                          size_t stack_size, void *arg, int priority);
typedef void (*bbox_hal_task_delete_fn)(void *task);
typedef void (*bbox_hal_task_delay_ms_fn)(uint32_t ms);

/* Semaphore (optional) */
typedef void* (*bbox_hal_sem_create_fn)(void);
typedef void (*bbox_hal_sem_destroy_fn)(void *sem);
typedef bool (*bbox_hal_sem_take_fn)(void *sem, uint32_t timeout_ms);
typedef void (*bbox_hal_sem_give_fn)(void *sem);

/* Crypto (optional - NULL disables encryption) */
typedef void* (*bbox_hal_aes_init_fn)(const uint8_t *key, size_t key_len);
typedef int (*bbox_hal_aes_set_iv_fn)(void *ctx, const uint8_t *iv, size_t iv_len);
typedef int (*bbox_hal_aes_encrypt_fn)(void *ctx, const uint8_t *input, 
                                        uint8_t *output, size_t len);
typedef void (*bbox_hal_aes_free_fn)(void *ctx);
typedef void (*bbox_hal_random_fn)(uint8_t *buf, size_t len);

/* Debug logging (optional - NULL = silent) */
typedef void (*bbox_hal_log_fn)(const char *tag, bbox_log_level_t level, 
                                 const char *fmt, va_list args);

/* Memory (optional - NULL = use stdlib) */
typedef void* (*bbox_hal_malloc_fn)(size_t size);
typedef void (*bbox_hal_free_fn)(void *ptr);

/* Device info (optional) */
typedef void (*bbox_hal_get_device_id_fn)(char *buf, size_t buf_len);

/*******************************************************************************
 * HAL Interface Structure
 ******************************************************************************/

/**
 * @brief Hardware Abstraction Layer interface
 * 
 * Populate this structure with platform-specific function pointers.
 * Required functions must be non-NULL. Optional functions can be NULL.
 */
typedef struct {
    /* ====== REQUIRED FUNCTIONS ====== */
    
    /** Open a file for writing. Returns BBOX_FILE_INVALID on error. */
    bbox_hal_file_open_fn file_open;
    
    /** Write data to file. Returns number of bytes written. */
    bbox_hal_file_write_fn file_write;
    
    /** Sync/flush file to storage. Returns 0 on success. */
    bbox_hal_file_sync_fn file_sync;
    
    /** Close file. Returns 0 on success. */
    bbox_hal_file_close_fn file_close;
    
    /** Get current file size in bytes. */
    bbox_hal_file_size_fn file_size;
    
    /** Get current timestamp in microseconds. */
    bbox_hal_get_time_us_fn get_time_us;
    
    /* ====== OPTIONAL FUNCTIONS ====== */
    
    /** Check if file/directory exists */
    bbox_hal_file_exists_fn file_exists;
    
    /** Create directory (including parents) */
    bbox_hal_mkdir_fn mkdir;
    
    /* Threading */
    bbox_hal_mutex_create_fn mutex_create;
    bbox_hal_mutex_destroy_fn mutex_destroy;
    bbox_hal_mutex_lock_fn mutex_lock;
    bbox_hal_mutex_unlock_fn mutex_unlock;
    
    /* Background task */
    bbox_hal_task_create_fn task_create;
    bbox_hal_task_delete_fn task_delete;
    bbox_hal_task_delay_ms_fn task_delay_ms;
    
    /* Semaphore */
    bbox_hal_sem_create_fn sem_create;
    bbox_hal_sem_destroy_fn sem_destroy;
    bbox_hal_sem_take_fn sem_take;
    bbox_hal_sem_give_fn sem_give;
    
    /* Encryption (AES-256-CTR) */
    bbox_hal_aes_init_fn aes_init;
    bbox_hal_aes_set_iv_fn aes_set_iv;
    bbox_hal_aes_encrypt_fn aes_encrypt;
    bbox_hal_aes_free_fn aes_free;
    bbox_hal_random_fn random_fill;
    
    /* Debug logging */
    bbox_hal_log_fn log_output;
    
    /* Memory allocation */
    bbox_hal_malloc_fn malloc;
    bbox_hal_free_fn free;
    
    /* Device info */
    bbox_hal_get_device_id_fn get_device_id;
    
} bbox_hal_t;

/*******************************************************************************
 * HAL Validation
 ******************************************************************************/

/**
 * @brief Validate that required HAL functions are provided
 * 
 * @param hal Pointer to HAL interface
 * @return BBOX_OK if valid, error code otherwise
 */
static inline bbox_err_t bbox_hal_validate(const bbox_hal_t *hal)
{
    if (!hal) {
        return BBOX_ERR_INVALID_ARG;
    }
    
    /* Check required functions */
    if (!hal->file_open) return BBOX_ERR_INVALID_ARG;
    if (!hal->file_write) return BBOX_ERR_INVALID_ARG;
    if (!hal->file_sync) return BBOX_ERR_INVALID_ARG;
    if (!hal->file_close) return BBOX_ERR_INVALID_ARG;
    if (!hal->file_size) return BBOX_ERR_INVALID_ARG;
    if (!hal->get_time_us) return BBOX_ERR_INVALID_ARG;
    
    return BBOX_OK;
}

/**
 * @brief Check if threading is available
 */
static inline bool bbox_hal_has_threading(const bbox_hal_t *hal)
{
    return hal && hal->mutex_create && hal->mutex_lock && hal->mutex_unlock &&
           hal->task_create && hal->sem_create && hal->sem_give && hal->sem_take;
}

/**
 * @brief Check if encryption is available
 */
static inline bool bbox_hal_has_crypto(const bbox_hal_t *hal)
{
    return hal && hal->aes_init && hal->aes_set_iv && 
           hal->aes_encrypt && hal->aes_free && hal->random_fill;
}

/*******************************************************************************
 * HAL Memory Helpers
 ******************************************************************************/

/**
 * @brief Allocate memory using HAL or stdlib
 */
static inline void *bbox_hal_malloc(const bbox_hal_t *hal, size_t size)
{
    if (hal && hal->malloc) {
        return hal->malloc(size);
    }
    /* Fall back to stdlib */
    extern void *malloc(size_t);
    return malloc(size);
}

/**
 * @brief Free memory using HAL or stdlib
 */
static inline void bbox_hal_free(const bbox_hal_t *hal, void *ptr)
{
    if (hal && hal->free) {
        hal->free(ptr);
    } else {
        extern void free(void *);
        free(ptr);
    }
}

/*******************************************************************************
 * HAL Logging Helpers
 ******************************************************************************/

/**
 * @brief Log a debug message via HAL
 */
static inline void bbox_hal_log_debug(const bbox_hal_t *hal, const char *tag, 
                                       const char *fmt, ...)
{
    if (hal && hal->log_output) {
        va_list args;
        va_start(args, fmt);
        hal->log_output(tag, BBOX_LOG_LEVEL_DEBUG, fmt, args);
        va_end(args);
    }
}

/**
 * @brief Log an error message via HAL
 */
static inline void bbox_hal_log_error(const bbox_hal_t *hal, const char *tag,
                                       const char *fmt, ...)
{
    if (hal && hal->log_output) {
        va_list args;
        va_start(args, fmt);
        hal->log_output(tag, BBOX_LOG_LEVEL_ERROR, fmt, args);
        va_end(args);
    }
}

/**
 * @brief Log an info message via HAL
 */
static inline void bbox_hal_log_info(const bbox_hal_t *hal, const char *tag,
                                      const char *fmt, ...)
{
    if (hal && hal->log_output) {
        va_list args;
        va_start(args, fmt);
        hal->log_output(tag, BBOX_LOG_LEVEL_INFO, fmt, args);
        va_end(args);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_HAL_H */
