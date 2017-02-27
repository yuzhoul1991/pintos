#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "vm/page.h"
#include "threads/palloc.h"
#include "devices/block.h"

struct block *swap_block;    /* Pointer to struct block representing swap space */
struct bitmap *swap_bitmap;  /* Bitmap which holds bits = block_size (swap_block)/bitmap_to_sector, where bitmap_to_sector=PGSIZE/BLOCK_SECTOR_SIZE */
uint32_t bitmap_to_sector;   /* This gives number of swap index needed to make a page */
struct lock swap_lock;       /* Lock when using swap_block */

void swap_init(void);
void swap_release_idx(uint32_t idx);
void swap_read_idx (uint32_t idx, void *kpage);
void swap_write_idx (uint32_t idx, void *kpage);
size_t swap_get_idx (void);
#endif
