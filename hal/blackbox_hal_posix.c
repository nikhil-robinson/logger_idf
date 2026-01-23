/**
 * @file blackbox_hal_posix.c
 * @brief POSIX HAL implementation for Blackbox logger
 *
 * Implements HAL functions using POSIX APIs for desktop platforms:
 * - File I/O: stdio
 * - Threading: pthreads
 * - Time: gettimeofday / clock_gettime
 * - No encryption support (use for testing only)
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifdef __unix__

#include "blackbox_hal_posix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

/*******************************************************************************
 * File Operations
 ******************************************************************************/

static bbox_file_t hal_posix_file_open(const char *path, bool append)
{
    const char *mode = append ? "ab" : "wb";
    FILE *f = fopen(path, mode);
    if (!f) {
        fprintf(stderr, "[BBOX] Failed to open file: %s (%s)\n", path, strerror(errno));
    }
    return (bbox_file_t)f;
}

static size_t hal_posix_file_write(bbox_file_t file, const void *data, size_t len)
{
    if (!file) return 0;
    return fwrite(data, 1, len, (FILE *)file);
}

static int hal_posix_file_sync(bbox_file_t file)
{
    if (!file) return -1;
    return fflush((FILE *)file);
}

static int hal_posix_file_close(bbox_file_t file)
{
    if (!file) return -1;
    return fclose((FILE *)file);
}

static size_t hal_posix_file_size(bbox_file_t file)
{
    if (!file) return 0;
    
    FILE *f = (FILE *)file;
    long current = ftell(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, current, SEEK_SET);
    
    return (size_t)(size > 0 ? size : 0);
}

static bool hal_posix_file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

static int hal_posix_mkdir(const char *path)
{
    /* Simple mkdir (doesn't create parents) */
    int ret = mkdir(path, 0755);
    if (ret != 0 && errno != EEXIST) {
        fprintf(stderr, "[BBOX] Failed to create directory: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

/*******************************************************************************
 * Time
 ******************************************************************************/

static uint64_t hal_posix_get_time_us(void)
{
#ifdef CLOCK_MONOTONIC
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
#endif
}

/*******************************************************************************
 * Threading: Mutex
 ******************************************************************************/

static void *hal_posix_mutex_create(void)
{
    pthread_mutex_t *mtx = malloc(sizeof(pthread_mutex_t));
    if (mtx) {
        pthread_mutex_init(mtx, NULL);
    }
    return mtx;
}

static void hal_posix_mutex_destroy(void *mtx)
{
    if (mtx) {
        pthread_mutex_destroy((pthread_mutex_t *)mtx);
        free(mtx);
    }
}

static void hal_posix_mutex_lock(void *mtx)
{
    if (mtx) {
        pthread_mutex_lock((pthread_mutex_t *)mtx);
    }
}

static void hal_posix_mutex_unlock(void *mtx)
{
    if (mtx) {
        pthread_mutex_unlock((pthread_mutex_t *)mtx);
    }
}

/*******************************************************************************
 * Threading: Tasks (pthreads)
 ******************************************************************************/

typedef struct {
    void (*func)(void *);
    void *arg;
} posix_task_wrapper_t;

static void *posix_task_wrapper(void *arg)
{
    posix_task_wrapper_t *wrapper = (posix_task_wrapper_t *)arg;
    void (*func)(void *) = wrapper->func;
    void *user_arg = wrapper->arg;
    
    free(wrapper);
    
    func(user_arg);
    
    return NULL;
}

static void *hal_posix_task_create(void (*func)(void *arg), const char *name,
                                    size_t stack_size, void *arg, int priority)
{
    (void)name;
    (void)stack_size;
    (void)priority;
    
    posix_task_wrapper_t *wrapper = malloc(sizeof(posix_task_wrapper_t));
    if (!wrapper) return NULL;
    
    wrapper->func = func;
    wrapper->arg = arg;
    
    pthread_t *thread = malloc(sizeof(pthread_t));
    if (!thread) {
        free(wrapper);
        return NULL;
    }
    
    int ret = pthread_create(thread, NULL, posix_task_wrapper, wrapper);
    if (ret != 0) {
        free(wrapper);
        free(thread);
        return NULL;
    }
    
    return thread;
}

static void hal_posix_task_delete(void *task)
{
    if (task) {
        pthread_t *thread = (pthread_t *)task;
        pthread_cancel(*thread);
        pthread_join(*thread, NULL);
        free(thread);
    }
}

static void hal_posix_task_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

/*******************************************************************************
 * Threading: Semaphores
 ******************************************************************************/

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int value;
} posix_sem_t;

static void *hal_posix_sem_create(void)
{
    posix_sem_t *sem = malloc(sizeof(posix_sem_t));
    if (sem) {
        pthread_mutex_init(&sem->mutex, NULL);
        pthread_cond_init(&sem->cond, NULL);
        sem->value = 0;
    }
    return sem;
}

static void hal_posix_sem_destroy(void *s)
{
    posix_sem_t *sem = (posix_sem_t *)s;
    if (sem) {
        pthread_mutex_destroy(&sem->mutex);
        pthread_cond_destroy(&sem->cond);
        free(sem);
    }
}

static bool hal_posix_sem_take(void *s, uint32_t timeout_ms)
{
    posix_sem_t *sem = (posix_sem_t *)s;
    if (!sem) return false;
    
    pthread_mutex_lock(&sem->mutex);
    
    if (timeout_ms == UINT32_MAX) {
        /* Wait forever */
        while (sem->value == 0) {
            pthread_cond_wait(&sem->cond, &sem->mutex);
        }
    } else {
        /* Timed wait */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        
        while (sem->value == 0) {
            int ret = pthread_cond_timedwait(&sem->cond, &sem->mutex, &ts);
            if (ret != 0) {
                pthread_mutex_unlock(&sem->mutex);
                return false;
            }
        }
    }
    
    sem->value--;
    pthread_mutex_unlock(&sem->mutex);
    return true;
}

static void hal_posix_sem_give(void *s)
{
    posix_sem_t *sem = (posix_sem_t *)s;
    if (sem) {
        pthread_mutex_lock(&sem->mutex);
        sem->value++;
        pthread_cond_signal(&sem->cond);
        pthread_mutex_unlock(&sem->mutex);
    }
}

/*******************************************************************************
 * Logging
 ******************************************************************************/

static void hal_posix_log_output(const char *tag, bbox_log_level_t level,
                                  const char *fmt, va_list args)
{
    const char *level_str;
    FILE *out = stdout;
    
    switch (level) {
        case BBOX_LOG_LEVEL_ERROR:
            level_str = "E";
            out = stderr;
            break;
        case BBOX_LOG_LEVEL_WARN:
            level_str = "W";
            break;
        case BBOX_LOG_LEVEL_INFO:
            level_str = "I";
            break;
        case BBOX_LOG_LEVEL_DEBUG:
            level_str = "D";
            break;
        case BBOX_LOG_LEVEL_VERBOSE:
            level_str = "V";
            break;
        default:
            level_str = "?";
            break;
    }
    
    fprintf(out, "[%s] %s: ", level_str, tag);
    vfprintf(out, fmt, args);
    fprintf(out, "\n");
    fflush(out);
}

/*******************************************************************************
 * Device Info
 ******************************************************************************/

static void hal_posix_get_device_id(char *buf, size_t buf_len)
{
    /* Use hostname as device ID */
    if (gethostname(buf, buf_len) != 0) {
        strncpy(buf, "POSIX", buf_len);
    }
    buf[buf_len - 1] = '\0';
}

/*******************************************************************************
 * HAL Interfaces
 ******************************************************************************/

/* Full-featured HAL with threading */
static const bbox_hal_t s_hal_posix = {
    /* Required: File operations */
    .file_open = hal_posix_file_open,
    .file_write = hal_posix_file_write,
    .file_sync = hal_posix_file_sync,
    .file_close = hal_posix_file_close,
    .file_size = hal_posix_file_size,
    
    /* Required: Time */
    .get_time_us = hal_posix_get_time_us,
    
    /* Optional: File utilities */
    .file_exists = hal_posix_file_exists,
    .mkdir = hal_posix_mkdir,
    
    /* Optional: Threading - Mutex */
    .mutex_create = hal_posix_mutex_create,
    .mutex_destroy = hal_posix_mutex_destroy,
    .mutex_lock = hal_posix_mutex_lock,
    .mutex_unlock = hal_posix_mutex_unlock,
    
    /* Optional: Threading - Tasks */
    .task_create = hal_posix_task_create,
    .task_delete = hal_posix_task_delete,
    .task_delay_ms = hal_posix_task_delay_ms,
    
    /* Optional: Threading - Semaphores */
    .sem_create = hal_posix_sem_create,
    .sem_destroy = hal_posix_sem_destroy,
    .sem_take = hal_posix_sem_take,
    .sem_give = hal_posix_sem_give,
    
    /* Optional: Crypto - Not supported on POSIX (use encrypt=false) */
    .aes_init = NULL,
    .aes_set_iv = NULL,
    .aes_encrypt = NULL,
    .aes_free = NULL,
    .random_fill = NULL,
    
    /* Optional: Logging */
    .log_output = hal_posix_log_output,
    
    /* Optional: Memory - Use stdlib */
    .malloc = NULL,
    .free = NULL,
    
    /* Optional: Device info */
    .get_device_id = hal_posix_get_device_id,
};

/* Single-threaded HAL (no pthreads required) */
static const bbox_hal_t s_hal_posix_single = {
    /* Required: File operations */
    .file_open = hal_posix_file_open,
    .file_write = hal_posix_file_write,
    .file_sync = hal_posix_file_sync,
    .file_close = hal_posix_file_close,
    .file_size = hal_posix_file_size,
    
    /* Required: Time */
    .get_time_us = hal_posix_get_time_us,
    
    /* Optional: File utilities */
    .file_exists = hal_posix_file_exists,
    .mkdir = hal_posix_mkdir,
    
    /* No threading support */
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
    
    /* No crypto */
    .aes_init = NULL,
    .aes_set_iv = NULL,
    .aes_encrypt = NULL,
    .aes_free = NULL,
    .random_fill = NULL,
    
    /* Optional: Logging */
    .log_output = hal_posix_log_output,
    
    /* Optional: Memory - Use stdlib */
    .malloc = NULL,
    .free = NULL,
    
    /* Optional: Device info */
    .get_device_id = hal_posix_get_device_id,
};

const bbox_hal_t *bbox_hal_posix_get(void)
{
    return &s_hal_posix;
}

const bbox_hal_t *bbox_hal_posix_single_threaded_get(void)
{
    return &s_hal_posix_single;
}

#endif /* __unix__ */
