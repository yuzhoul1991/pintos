#include <debug.h>
#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"


/* Initialize swap_bock, bitmap and swap_lock */
void
swap_init (void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  bitmap_to_sector = PGSIZE/BLOCK_SECTOR_SIZE;
  swap_bitmap = bitmap_create (block_size (swap_block)/bitmap_to_sector);
  lock_init(&swap_lock);
}

/* Release bitmap idx which corresponds to a swap sector */
void
swap_release_idx (uint32_t idx)
{
  lock_acquire(&swap_lock);
  bitmap_set (swap_bitmap, idx, false); 
  lock_release(&swap_lock);
}

/* Read from bitmap idx which corresponds to a swap sector into kpage */
void 
swap_read_idx (uint32_t idx, void *kpage)
{
  lock_acquire(&swap_lock);
  uint32_t sector_offset;
  uint32_t sector_start = idx*bitmap_to_sector;
  void *kpage_offset = kpage;
  for(sector_offset = 0; sector_offset<bitmap_to_sector; sector_offset++)
  {
    block_read (swap_block, sector_start+sector_offset, kpage_offset);
    kpage_offset+=BLOCK_SECTOR_SIZE;
  }
  lock_release(&swap_lock);

}

/* Read from kpage into bitmap idx which corresponds to a swap sector */
void 
swap_write_idx (uint32_t idx, void *kpage)
{
  lock_acquire(&swap_lock);
  uint32_t sector_offset;
  uint32_t sector_start = idx*bitmap_to_sector;
  void *kpage_offset = kpage;
  for(sector_offset = 0; sector_offset<bitmap_to_sector; sector_offset++)
  {
    block_write (swap_block, sector_start+sector_offset, kpage_offset);
    kpage_offset+=BLOCK_SECTOR_SIZE;
  }
  lock_release(&swap_lock);

}

/* Get a free bitmap idx which corresponds to a swap sector */
size_t
swap_get_idx (void)
{
  size_t idx = 0;
  lock_acquire(&swap_lock);
  idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  lock_release(&swap_lock);
  if(idx == BITMAP_ERROR)
    PANIC ("No swap slot found");
  return idx;
}
