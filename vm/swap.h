#ifndef VM_SWAP_H
#define VM_SWAP_H


struct page;
static struct lock swap_lock;

void init_swap_partition(void);
void write_to_swap(struct page *page);
void swap_load_page(void *kpage, struct page *page);
void clear_swap_block(struct page *page);

#endif