/**
 * @file blackbox_ringbuf.h
 * @brief Simple circular buffer implementation (platform independent)
 *
 * A lock-free single-producer single-consumer ring buffer for non-blocking
 * log message queueing. No RTOS dependencies.
 *
 * @author Nikhil Robinson
 * @version 3.0.0
 */

#ifndef BLACKBOX_RINGBUF_H
#define BLACKBOX_RINGBUF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Ring Buffer Structure
 ******************************************************************************/

/**
 * @brief Ring buffer handle
 */
typedef struct {
    uint8_t *buffer;          /**< Data buffer */
    size_t size;              /**< Total buffer size */
    volatile size_t head;     /**< Write position (producer) */
    volatile size_t tail;     /**< Read position (consumer) */
    size_t high_water_mark;   /**< Maximum usage observed */
} bbox_ringbuf_t;

/**
 * @brief Entry header for variable-size items
 */
typedef struct __attribute__((packed)) {
    uint16_t item_size;       /**< Size of the following item */
} bbox_ringbuf_entry_t;

/*******************************************************************************
 * API Functions
 ******************************************************************************/

/**
 * @brief Initialize a ring buffer
 * 
 * @param rb Pointer to ring buffer structure
 * @param buffer Pre-allocated buffer memory
 * @param size Size of buffer in bytes
 * @return true on success
 */
static inline bool bbox_ringbuf_init(bbox_ringbuf_t *rb, uint8_t *buffer, size_t size)
{
    if (!rb || !buffer || size < 64) {
        return false;
    }
    
    rb->buffer = buffer;
    rb->size = size;
    rb->head = 0;
    rb->tail = 0;
    rb->high_water_mark = 0;
    
    return true;
}

/**
 * @brief Get available space for writing
 */
static inline size_t bbox_ringbuf_free(const bbox_ringbuf_t *rb)
{
    size_t head = rb->head;
    size_t tail = rb->tail;
    
    if (head >= tail) {
        return rb->size - (head - tail) - 1;
    } else {
        return tail - head - 1;
    }
}

/**
 * @brief Get number of bytes available to read
 */
static inline size_t bbox_ringbuf_used(const bbox_ringbuf_t *rb)
{
    size_t head = rb->head;
    size_t tail = rb->tail;
    
    if (head >= tail) {
        return head - tail;
    } else {
        return rb->size - tail + head;
    }
}

/**
 * @brief Check if buffer is empty
 */
static inline bool bbox_ringbuf_empty(const bbox_ringbuf_t *rb)
{
    return rb->head == rb->tail;
}

/**
 * @brief Write a variable-size item to the buffer
 * 
 * @param rb Ring buffer
 * @param data Data to write
 * @param len Length of data
 * @return true if item was written, false if buffer full
 */
static inline bool bbox_ringbuf_write(bbox_ringbuf_t *rb, const void *data, size_t len)
{
    if (!rb || !data || len == 0) {
        return false;
    }
    
    size_t total_size = sizeof(bbox_ringbuf_entry_t) + len;
    
    /* Check if there's enough space */
    if (bbox_ringbuf_free(rb) < total_size) {
        return false;
    }
    
    /* Write entry header */
    bbox_ringbuf_entry_t entry = { .item_size = (uint16_t)len };
    
    size_t head = rb->head;
    const uint8_t *src;
    
    /* Write header byte by byte (handles wrap-around) */
    src = (const uint8_t *)&entry;
    for (size_t i = 0; i < sizeof(entry); i++) {
        rb->buffer[head] = src[i];
        head = (head + 1) % rb->size;
    }
    
    /* Write data byte by byte (handles wrap-around) */
    src = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        rb->buffer[head] = src[i];
        head = (head + 1) % rb->size;
    }
    
    /* Memory barrier before updating head (for multi-core safety) */
    __sync_synchronize();
    rb->head = head;
    
    /* Track high water mark */
    size_t used = bbox_ringbuf_used(rb);
    if (used > rb->high_water_mark) {
        rb->high_water_mark = used;
    }
    
    return true;
}

/**
 * @brief Peek at the next item size without removing it
 * 
 * @param rb Ring buffer
 * @param size_out Output: size of next item
 * @return true if item exists
 */
static inline bool bbox_ringbuf_peek_size(const bbox_ringbuf_t *rb, size_t *size_out)
{
    if (bbox_ringbuf_empty(rb)) {
        return false;
    }
    
    /* Read entry header */
    bbox_ringbuf_entry_t entry;
    size_t tail = rb->tail;
    uint8_t *dst = (uint8_t *)&entry;
    
    for (size_t i = 0; i < sizeof(entry); i++) {
        dst[i] = rb->buffer[tail];
        tail = (tail + 1) % rb->size;
    }
    
    *size_out = entry.item_size;
    return true;
}

/**
 * @brief Read and remove the next item from the buffer
 * 
 * @param rb Ring buffer
 * @param data Output buffer (must be large enough)
 * @param max_len Maximum bytes to read
 * @param len_out Output: actual bytes read
 * @return true if item was read
 */
static inline bool bbox_ringbuf_read(bbox_ringbuf_t *rb, void *data, size_t max_len, size_t *len_out)
{
    if (bbox_ringbuf_empty(rb)) {
        return false;
    }
    
    /* Read entry header */
    bbox_ringbuf_entry_t entry;
    size_t tail = rb->tail;
    uint8_t *dst = (uint8_t *)&entry;
    
    for (size_t i = 0; i < sizeof(entry); i++) {
        dst[i] = rb->buffer[tail];
        tail = (tail + 1) % rb->size;
    }
    
    size_t item_size = entry.item_size;
    
    /* Check if output buffer is large enough */
    if (item_size > max_len) {
        /* Skip this item */
        for (size_t i = 0; i < item_size; i++) {
            tail = (tail + 1) % rb->size;
        }
        __sync_synchronize();
        rb->tail = tail;
        if (len_out) *len_out = 0;
        return false;
    }
    
    /* Read data */
    dst = (uint8_t *)data;
    for (size_t i = 0; i < item_size; i++) {
        dst[i] = rb->buffer[tail];
        tail = (tail + 1) % rb->size;
    }
    
    /* Memory barrier before updating tail */
    __sync_synchronize();
    rb->tail = tail;
    
    if (len_out) *len_out = item_size;
    return true;
}

/**
 * @brief Reset the ring buffer (clear all data)
 */
static inline void bbox_ringbuf_reset(bbox_ringbuf_t *rb)
{
    rb->head = 0;
    rb->tail = 0;
}

/**
 * @brief Get high water mark (maximum usage)
 */
static inline size_t bbox_ringbuf_high_water(const bbox_ringbuf_t *rb)
{
    return rb->high_water_mark;
}

#ifdef __cplusplus
}
#endif

#endif /* BLACKBOX_RINGBUF_H */
