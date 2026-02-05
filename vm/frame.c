#include "lib/round.h"
#include "lib/stddef.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <stdlib.h>

/* Initialize the frame table with *pages* pages. */
void init_frame_table(size_t pages) {
    lock_init(&frame_table_lock);

    pages -= DIV_ROUND_UP(bitmap_buf_size(pages), PGSIZE);
    uint32_t total_pages = pages;
    clock_hand = 0;
    clock_reset = pages;  
    freemap = bitmap_create(pages);
    frame_table = malloc(pages * (sizeof(struct frame)));

    while (pages) {
        struct frame new_frame = (struct frame)
        {.frame_number = total_pages - pages,
         .physical_address = NULL,
         .process = NULL,
         .page = NULL};

        frame_table[total_pages - pages--] = new_frame;
    }

}

/* Finds and evicts a frame (if needed),
 returning a pointer to the newly freed frame. */
struct frame* get_free_frame() {    
    lock_acquire(&frame_table_lock);    
    size_t index = bitmap_scan_and_flip(freemap, 0, 1, false);
    if(index == BITMAP_ERROR){
        evict();        

        struct frame *evicted_frame = &frame_table[clock_hand];
        struct page *evicted_page = evicted_frame->page;

        if ((pagedir_is_dirty(evicted_page->owner->pagedir,
             evicted_page->virtual_address)  ||
             pagedir_is_dirty(evicted_page->owner->pagedir,
              evicted_page->frame->physical_address)))
            write_to_swap(evicted_page);
        else            
            clear_swap_block(evicted_page);
        
        evicted_page->frame = NULL;
        evicted_page->location = SWAP_PART;
        pagedir_clear_page(evicted_page->owner->pagedir,
         evicted_page->virtual_address);
        
        clock_hand == clock_reset ? clock_hand = 0 : clock_hand++;

        lock_release(&frame_table_lock);
        return evicted_frame;
    }                      
    frame_table[index].physical_address = palloc_get_page(PAL_USER
        | PAL_ZERO | PAL_ASSERT);
    lock_release(&frame_table_lock);
    return &frame_table[index];
}

/* Helper method used to clear and reset the contents of a frame. */
void clear_frame (struct frame *frame) {
    pagedir_clear_page(frame->page->owner->pagedir,
     frame->page->virtual_address);
    palloc_free_page(frame->physical_address);
    bitmap_flip(freemap, frame->frame_number);

    frame->process = NULL;
    frame->page = NULL;
}

/* A helper method for the get_free_frame() method.
 Uses the clock algorithm to find a
   page to evict. */
void evict() {
    struct frame *frame = &frame_table[clock_hand];
    struct thread *thread = thread_current();

    while (pagedir_is_accessed(thread->pagedir,
        frame->page->virtual_address)){            
            pagedir_set_accessed(thread->pagedir,
            frame->page->virtual_address, false);
        clock_hand == clock_reset ? clock_hand = 0 : clock_hand++;
    }    

}