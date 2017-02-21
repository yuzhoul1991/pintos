#include <debug.h>
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"


void
swap_init (void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  bitmap_to_sector = PGSIZE/BLOCK_SECTOR_SIZE;
  swap_bitmap = bitmap_create (block_size (swap_block)/bitmap_to_sector);
  lock_init(&swap_lock);
}

void
swap_release_idx (uint32_t idx)
{
  lock_acquire(&swap_lock);
  bitmap_set (swap_bitmap, idx, false); 
  lock_release(&swap_lock);
}

void 
swap_read_idx (uint32_t idx, void *kpage)
{
  lock_acquire(&swap_lock);
  block_read (swap_block, idx*bitmap_to_sector, kpage);
  lock_release(&swap_lock);

}

void 
swap_write_idx (uint32_t idx, void *kpage)
{
  lock_acquire(&swap_lock);
  block_write (swap_block, idx*bitmap_to_sector, kpage);
  lock_release(&swap_lock);

}

size_t
swap_get_idx (void)
{
  size_t idx = 0;
  lock_acquire(&swap_lock);
  idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  lock_release(&swap_lock);
  return idx;
}
