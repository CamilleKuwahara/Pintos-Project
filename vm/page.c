#include <debug.h>
#include <hash.h>
#include <stdint.h>
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* A hashing function used to intialize a page's hash table. */
unsigned hash_func(struct hash_elem *elem, void *aux) {
    (void)aux; // Supress warning
    //get the page structure from the hash element
    struct page *page = hash_entry(elem, struct page, hash_elem);
    //returns a hash value
    return hash_bytes(&page->virtual_address, sizeof(page->virtual_address));
}

/* A compare function used to intialize a page's hash table. */
bool less_func(struct hash_elem *a, struct hash_elem *b, void *aux) {
    (void)aux;
    struct page *page_A = hash_entry(a, struct page, hash_elem);
    struct page *page_B = hash_entry(b, struct page, hash_elem);

    return page_A->virtual_address < page_B->virtual_address;
}
 	
/* Given a vadd, return the page that contains the vadd or null pointer */
struct page *page_find (const void *address)
{
    struct page p;
    struct hash_elem *elem;
    p.virtual_address = (void *) address;
    elem = hash_find(&thread_current()->suppl_pt, &p.hash_elem);

    if(elem != NULL)
        return hash_entry(elem, struct page, hash_elem);

    return NULL;
}

/* Loads the page to physical memory */
bool load_page(void *kpage, struct page *page){    
    //Get the amount of bytes read by reading in the file pointed in page
    off_t bytes_read = file_read_at(page->file, kpage, 
    (off_t)page->file_bytes, page->file_offset);

    //Compare the number of bytes reads to expected bytes
    bool success = bytes_read == (off_t) page->file_bytes;

    //zero out the remaining portion of the page
    memset ((char*)kpage + page->file_bytes, 0, PGSIZE - page->file_bytes);
    return success;
}

/* Checks if a page is not mapped and the new mapping is successfully created */

bool install (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();
    bool get_page = pagedir_get_page(t->pagedir, upage) == NULL;
    bool set_page = pagedir_set_page(t->pagedir, upage, kpage, writable);
    return get_page && set_page;
}

// initialize new stack page
struct page *new_page(void *vaddr) {
    struct page *suppl = malloc(sizeof(struct page));

    suppl->reference_bit = false;
    suppl->virtual_address = vaddr;
    suppl->owner = thread_current();
    suppl->location = FRAME;
    suppl->writable = true;
    suppl->dirty = false;
    suppl->file = NULL;
    suppl->file_offset = 0;
    suppl->file_bytes = 0;
    suppl->block_sector = -1;

    return suppl;
}

// Free a page by getting a hash elem
void destroy_page(struct hash_elem *e){  
    struct page *page = hash_entry(e, struct page, hash_elem);
    if (page->frame) {
        clear_frame(page->frame);
        page->frame = NULL;
    }
    if (page->block_sector != -1) {
        clear_swap_block(page);
    }
    free(page);
}
