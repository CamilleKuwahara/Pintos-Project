#ifndef VM_PAGE_H
#define VM_PAGE_H


#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "filesys/file.h"

enum page_location {
    FRAME,
    FILE_SYS,
    SWAP_PART
};

struct page {
    void *virtual_address;             // Virtual address of the page
    struct thread *owner;              // Thread that owns the page
    struct frame *frame;               // Frame that holds the page
    struct hash_elem hash_elem;        // Hash table elem
    struct file *file;                 // The page's file (if in file system)
    off_t file_offset;                 // The file's offset
    size_t file_bytes;                 // The number of bytes read
    uint32_t block_sector;             // Location in swap partition (if there)
    bool reference_bit;                // For clock algorithm
    bool writable;                     // Is the page writable?
    bool dirty;                        // Has the page been modified?
    enum page_location location;       // Location of the page
};
//load the page to physical memory
bool page_load(void *kpage, struct page *page);
//hash function for pages
unsigned hash_func(struct hash_elem *elem, void *aux);
bool less_func(struct hash_elem *a, struct hash_elem *b, void *aux);
struct page *page_find(const void *vadd); 
struct page *new_page(void *vaddr);
bool install(void *upage, void *kpage, bool writable);
void destroy_page(struct hash_elem *e);
#endif