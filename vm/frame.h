#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/list.h"
#include "vm/page.h"
static uint32_t clock_hand, clock_reset;
static struct lock frame_table_lock;
static struct frame *frame_table;
static struct bitmap *freemap;

struct frame {
    uint32_t frame_number;          // Frame number
    void *physical_address;         // Physicall address of frame
    struct thread *process;         // Process that occupies the frame
    struct page *page;              // The specific page that owns the frame
    struct list_elem frame_elem;    // List elem of the frame
};

void init_frame_table(size_t pages);
struct frame *allocate_frame(uint32_t frame_number);
struct frame *get_free_frame(void);
void clear_frame (struct frame *frame);
void evict(void);
struct frame *get_frame (uint32_t frame_number);
#endif