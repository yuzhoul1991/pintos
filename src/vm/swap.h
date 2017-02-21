#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "vm/page.h"
#include "threads/palloc.h"
#include "devices/block.h"

struct block *swap_block;
struct bitmap *swap_bitmap;
uint32_t bitmap_to_sector;
struct lock swap_lock;

void swap_init(void);
void swap_release_idx(uint32_t idx);
void swap_read_idx (uint32_t idx, void *kpage);
void swap_write_idx (uint32_t idx, void *kpage);
size_t swap_get_idx (void);
#endif
