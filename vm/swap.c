#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "lib/stddef.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"

static struct block *swap_partition;
static struct bitmap *freemap;
static struct lock swap_lock;

/* Initializes the swap partition by getting the block preassigned
by pintos. */
void init_swap_partition() {
    swap_partition = block_get_role(BLOCK_SWAP);
    freemap = bitmap_create(block_size(swap_partition));
    lock_init(&swap_lock);
}

/* Given a page, writes that page into the swap partition. */
void write_to_swap(struct page *page) {
    lock_acquire(&swap_lock);
    char *buffer = (char *)page->frame->physical_address;
    size_t sector = bitmap_scan(freemap, 0, 1, false);
    page->block_sector = sector;

    for (int x = 0; x < PGSIZE / BLOCK_SECTOR_SIZE; x++) {
        block_write(swap_partition, sector + x, buffer);
        bitmap_flip(freemap, sector + x);
        buffer += BLOCK_SECTOR_SIZE;
    }
    lock_release(&swap_lock);
}

void swap_load_page(void *kpage, struct page *page) {
    lock_acquire(&swap_lock);
    size_t sector = page->block_sector;
    char *buffer = (char *)kpage;
    
    // We need to read 1 page starting from sector
    for (int x = 0; x < PGSIZE / BLOCK_SECTOR_SIZE; x++) {
        block_read(swap_partition, sector + x, (void *)buffer);  
        bitmap_set(freemap, page->block_sector + x, false);
        buffer += BLOCK_SECTOR_SIZE;
    }         
    page->block_sector = -1;
    lock_release(&swap_lock);
}

/* Given a page, clears that page's position in the swap partition.*/
void clear_swap_block(struct page *page) {
    lock_acquire(&swap_lock);
    for (int x = 0; x < PGSIZE / BLOCK_SECTOR_SIZE; x++)
        bitmap_set(freemap, page->block_sector + x, false);
    lock_release(&swap_lock);
}
