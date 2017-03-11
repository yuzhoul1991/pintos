#include <debug.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"

void
cache_init (void)
{
  lock_init(&cache_lock);
  list_init(&cache_list);
  cache_hand = NULL;
  cache_bitmap = bitmap_create (CACHE_ENTRIES);
  total_sectors = block_size (fs_device);
  
  free_map_entry = malloc(sizeof(struct cache_entry));
  if (free_map_entry == NULL)
      PANIC ("free_map entry malloc failed!");
  free_map_entry->old_sector    = total_sectors;
  free_map_entry->sector        = FREE_MAP_SECTOR;
  free_map_entry->cache_block   = CACHE_ENTRIES;
  free_map_entry->type          = META_DATA;
  free_map_entry->dirty         = false;
  free_map_entry->accessed      = false;
  free_map_entry->meta_retry    = false;
  free_map_entry->entry_blocked = false;
  free_map_entry->pin           = 0;
  free_map_entry->uninitialized = true;
  free_map_entry->data          = NULL;
  free_map_entry->data = malloc (BLOCK_SECTOR_SIZE);
      if(free_map_entry->data == NULL)
        PANIC ("free_map entry data malloc failed!");
  lock_init(&free_map_entry->entry_lock);
  cond_init(&free_map_entry->entry_cond);
  
  cache_read_ahead_init ();
   
}

static uint32_t 
cache_get_pin (struct cache_entry *c_entry)
{
  lock_acquire (&c_entry->entry_lock);
  uint32_t pin = c_entry->pin;
  lock_release (&c_entry->entry_lock);
  return pin;
}

static void 
cache_entry_pin (struct cache_entry *c_entry)
{
  lock_acquire (&c_entry->entry_lock);
  c_entry->pin++;
  lock_release (&c_entry->entry_lock);
}

static void 
cache_entry_unpin (struct cache_entry *c_entry)
{
  lock_acquire (&c_entry->entry_lock);
  c_entry->pin--;
  lock_release (&c_entry->entry_lock);
}

static void 
cache_mark_dirty (struct cache_entry *c_entry)
{
  c_entry->dirty = true;
}

static void 
cache_clear_dirty (struct cache_entry *c_entry)
{
  c_entry->dirty = false;
}

static bool 
cache_get_dirty (struct cache_entry *c_entry)
{
  return c_entry->dirty;
}

static void 
cache_mark_accessed (struct cache_entry *c_entry)
{
  c_entry->accessed = true;
}

static void 
cache_clear_accessed (struct cache_entry *c_entry)
{
  c_entry->accessed = false;
}

static bool 
cache_get_accessed (struct cache_entry *c_entry)
{
  return c_entry->accessed;
}

static void
cache_update_meta (struct cache_entry *c_entry, uint32_t type)
{
  c_entry->type = type;
}

static void 
cache_mark_meta_retry (struct cache_entry *c_entry)
{
  c_entry->meta_retry = true;
}

static void 
cache_clear_meta_retry (struct cache_entry *c_entry)
{
  c_entry->meta_retry = false;
}

static bool 
cache_get_meta_retry (struct cache_entry *c_entry)
{
  return c_entry->meta_retry;
}

static void 
cache_entry_block (struct cache_entry *c_entry)
{
  c_entry->entry_blocked = true;
}

static void 
cache_entry_unblock (struct cache_entry *c_entry)
{
  c_entry->entry_blocked = false;
}

static block_sector_t
cache_get_sector(struct cache_entry * c_entry)
{
  lock_acquire (&cache_lock);
  block_sector_t sector = c_entry->sector;
  lock_release (&cache_lock);
  return sector;
}

static block_sector_t
cache_get_old_sector(struct cache_entry * c_entry)
{
  lock_acquire (&cache_lock);
  block_sector_t old_sector = c_entry->old_sector;
  lock_release (&cache_lock);
  return old_sector;
}

static void
cache_reset_old_sector(struct cache_entry * c_entry)
{
  lock_acquire (&cache_lock);
  c_entry->old_sector = total_sectors;
  lock_release (&cache_lock);
}

static struct cache_entry *
cache_eviction (void)
{
  struct cache_entry *evicted_entry = NULL;
  while (cache_hand)
    {
      /* Move cache_hand to next block. Includes wrap around to block int he head of cache_list */
      if(list_next(cache_hand) == list_tail(&cache_list))
        cache_hand = list_begin(&cache_list);
      else
        cache_hand = list_next(cache_hand);
    
      struct cache_entry *potential_entry = list_entry (cache_hand, struct cache_entry, elem);
      if(cache_get_pin (potential_entry))
        continue;
      else if((potential_entry->type == META_DATA) && cache_get_meta_retry (potential_entry))
        cache_clear_meta_retry (potential_entry);
      else if(cache_get_accessed (potential_entry))
        cache_clear_accessed (potential_entry);
      else 
        evicted_entry = potential_entry;

      if(evicted_entry != NULL)
        break;
    }
   return evicted_entry;
}

static struct cache_entry *
cache_allocate (block_sector_t sector)
{
  size_t cache_block = 0; 
  cache_block = bitmap_scan_and_flip(cache_bitmap, 0, 1, false);
  if(cache_block != BITMAP_ERROR)
    {
      struct cache_entry *c_entry = malloc(sizeof(struct cache_entry));
      if (c_entry == NULL)
        PANIC ("cache entry malloc failed!");

      c_entry->old_sector    = total_sectors;
      c_entry->sector        = sector;
      c_entry->cache_block   = cache_block;
      c_entry->type          = REAL_DATA;
      c_entry->dirty         = false; 
      c_entry->accessed      = false; 
      c_entry->meta_retry    = false; 
      c_entry->entry_blocked = false; 
      c_entry->pin           = 0; 
      c_entry->uninitialized = true; 
      c_entry->data          = NULL;
      c_entry->data          = malloc (BLOCK_SECTOR_SIZE);
      if(c_entry->data == NULL)
        PANIC ("cache entry data malloc failed!");
      lock_init(&c_entry->entry_lock);
      cond_init(&c_entry->entry_cond);
      
      /* Insert the new element next to cache_hand. Update cache_hand to point to new element.*/
     if(list_empty(&cache_list))
       list_push_back (&cache_list, &c_entry->elem);
     else
       list_insert(list_next(cache_hand), &c_entry->elem);
     cache_hand = &c_entry->elem;
      
     cache_entry_block (c_entry);
     return c_entry;
    }
  else
    {
      struct cache_entry *c_entry = cache_eviction ();
      c_entry->old_sector = c_entry->sector;
      c_entry->sector     = sector;
      cache_clear_meta_retry(c_entry);
      cache_entry_block (c_entry);
      return c_entry;
    } 
}

static struct cache_entry *
cache_lookup (block_sector_t sector)
{
  if(!list_empty(&cache_list))
  {
    bool found = false;
    struct cache_entry *c_entry = NULL;
    struct list_elem *e;
    for (e = list_begin (&cache_list); e != list_end (&cache_list); e = list_next (e))
    {
      c_entry = list_entry (e, struct cache_entry, elem);
      if (c_entry->sector == sector)
      {
        found = true;
        break;
      }
    }

    if(found)
      return c_entry;
    else
      return NULL;
  }
  else
    return NULL;
}

static bool
cache_lookup_old (block_sector_t sector)
{
  if(!list_empty(&cache_list))
  {
    bool found = false;
    struct cache_entry *c_entry = NULL;
    struct list_elem *e;
    for (e = list_begin (&cache_list); e != list_end (&cache_list); e = list_next (e))
    {
      c_entry = list_entry (e, struct cache_entry, elem);
      if (c_entry->old_sector == sector)
      {
        found = true;
        break;
      }
    }

    return found;
  }
  else
    return false;
}

void
cache_read_write (uint32_t read_write, block_sector_t sector, block_sector_t prefetch_sector, bool meta, void *buffer_, off_t bytes_read, off_t bytes_written, int sector_ofs, int chunk_size)
{
  uint8_t *buffer = buffer_;
  struct cache_entry *c_entry = NULL; 
  bool hit = false;

  start:
  lock_acquire (&cache_lock);
  if(sector == FREE_MAP_SECTOR)
    {
      c_entry = free_map_entry;
      if(c_entry->uninitialized && (read_write == READ))
        block_read (fs_device, sector, c_entry->data);
      c_entry->uninitialized = false;
      hit = true;
    }
  else
    {
      c_entry = cache_lookup (sector);

      if(c_entry == NULL)
        {
          if(cache_lookup_old (sector))
            {
              lock_release (&cache_lock);
              goto start;
            }
          c_entry = cache_allocate (sector);
        }
      else
        hit = true;

      cache_entry_pin(c_entry);
    }
  lock_release (&cache_lock);

  if (hit)
    {
      lock_acquire (&c_entry->entry_lock);
      while (c_entry->entry_blocked)
        cond_wait (&c_entry->entry_cond, &c_entry->entry_lock);
      lock_release (&c_entry->entry_lock);
    }
     
  if (!hit)
    {
      if(cache_get_dirty (c_entry))
        {
          block_sector_t old_sector = cache_get_old_sector (c_entry);
          block_write (fs_device, old_sector, c_entry->data);
          cache_clear_dirty (c_entry);
        }
      cache_reset_old_sector(c_entry);
      block_read (fs_device, sector, c_entry->data);
    }

  if (read_write == READ)
    {
      memcpy (buffer + bytes_read, c_entry->data + sector_ofs, chunk_size);
      lock_acquire (&cache_read_ahead_lock);
      if((list_size (&cache_read_ahead_list) != READ_AHEAD_ENTRIES) &&
          prefetch_sector < block_size (fs_device))
        {
          struct cache_read_ahead_entry *r_entry = malloc(sizeof(struct cache_read_ahead_entry));
          if (r_entry == NULL)
             PANIC ("cache_read_ahead entry malloc failed!");
          r_entry->sector = prefetch_sector;
          r_entry->type   = meta? META_DATA: REAL_DATA;
          list_push_back (&cache_read_ahead_list, &r_entry->elem);
        }
      lock_release (&cache_read_ahead_lock);
    }
  else
    {
      memcpy (c_entry->data + sector_ofs, buffer + bytes_written, chunk_size);
      cache_mark_dirty(c_entry);
    }
  cache_update_meta (c_entry, meta? META_DATA: REAL_DATA);
  if(meta)
      cache_mark_meta_retry(c_entry);
  cache_mark_accessed(c_entry);

  if (!hit)
    {
      lock_acquire (&c_entry->entry_lock);
      cache_entry_unblock (c_entry);
      cond_broadcast (&c_entry->entry_cond, &c_entry->entry_lock);
      lock_release (&c_entry->entry_lock);
    }

  cache_entry_unpin(c_entry);
}

void
cache_empty (void)
{
  lock_acquire (&cache_lock);
  if(cache_get_dirty (free_map_entry))
    {
          block_sector_t sector = free_map_entry->sector;
          block_write (fs_device, sector, free_map_entry->data);
    }
  free (free_map_entry->data);
  free (free_map_entry);

  while (!list_empty (&cache_list))
    {
      struct list_elem *e = list_begin (&cache_list);
      struct cache_entry *c_entry = list_entry (e, struct cache_entry, elem);
      if(cache_get_pin (c_entry))
        continue;
      if(cache_get_dirty (c_entry))
        {
          block_sector_t sector = c_entry->sector;
          block_write (fs_device, sector, c_entry->data);
        }
      bitmap_set (cache_bitmap, c_entry->cache_block, false); 
      list_remove (e);
      free (c_entry->data);
      free (c_entry);
      
    }
  cache_hand = NULL;
  lock_release (&cache_lock);
}

void
cache_write_behind (void)
{
  lock_acquire (&cache_lock);
  struct cache_entry *dirty_entry = NULL;
  struct list_elem *e = cache_hand;
  uint32_t loops = 0;
  while (e)
    {
      loops++;
      if(loops == list_size (&cache_list))
        break;
      /* Move e to next block. Includes wrap around to block in the head of cache_list */
      if(list_next(e) == list_tail(&cache_list))
        e = list_begin(&cache_list);
      else
        e = list_next(e);
    
      struct cache_entry *c_entry = list_entry (e, struct cache_entry, elem);
      if(cache_get_pin (c_entry))
        continue;
      else if(cache_get_dirty (c_entry))
        dirty_entry = c_entry;

      if(dirty_entry != NULL)
        break;
    }

  if(dirty_entry != NULL)
    {
      cache_entry_block (dirty_entry);
      cache_entry_pin(dirty_entry);
    }
  lock_release (&cache_lock);
  
  if(dirty_entry != NULL) 
    {       
      block_sector_t sector = cache_get_sector (dirty_entry);
      block_write (fs_device, sector, dirty_entry->data);
      cache_clear_dirty (dirty_entry);
      lock_acquire (&dirty_entry->entry_lock);
      cache_entry_unblock (dirty_entry);
      cond_broadcast (&dirty_entry->entry_cond, &dirty_entry->entry_lock);
      lock_release (&dirty_entry->entry_lock);
      cache_entry_unpin(dirty_entry);
    }
}

void 
cache_read_ahead_init ()
{
  list_init (&cache_read_ahead_list);
  lock_init (&cache_read_ahead_lock);
}

static void
cache_read_ahead_sector (block_sector_t sector, uint32_t type)
{
  struct cache_entry *c_entry = NULL; 
  bool hit = false;

  start:
  lock_acquire (&cache_lock);
  if(sector == FREE_MAP_SECTOR)
    {
      c_entry = free_map_entry;
      hit = true;
    }
  else
    {
      c_entry = cache_lookup (sector);

      if(c_entry == NULL)
        {
          if(cache_lookup_old (sector))
            {
              lock_release (&cache_lock);
              goto start;
            }
          c_entry = cache_allocate (sector);
          cache_entry_pin(c_entry);
        }
      else
        hit = true;

    }
  lock_release (&cache_lock);

  if (hit)
    return;
     
  if(cache_get_dirty (c_entry))
    {
      block_sector_t old_sector = cache_get_old_sector (c_entry);
      block_write (fs_device, old_sector, c_entry->data);
      cache_clear_dirty (c_entry);
    }
  cache_reset_old_sector(c_entry);
  block_read (fs_device, sector, c_entry->data);

  cache_update_meta (c_entry, type);
  if(type == META_DATA)
      cache_mark_meta_retry(c_entry);

  if (!hit)
    {
      lock_acquire (&c_entry->entry_lock);
      cache_entry_unblock (c_entry);
      cond_broadcast (&c_entry->entry_cond, &c_entry->entry_lock);
      lock_release (&c_entry->entry_lock);
    }

  cache_entry_unpin(c_entry);

}

void 
cache_read_ahead (void)
{
  struct cache_read_ahead_entry *r_entry = NULL;
  lock_acquire (&cache_read_ahead_lock);
  if(!list_empty (&cache_read_ahead_list))
    r_entry = list_entry (list_pop_front (&cache_read_ahead_list), struct cache_read_ahead_entry, elem);
  lock_release (&cache_read_ahead_lock);
  
  if(r_entry != NULL)
    cache_read_ahead_sector (r_entry->sector, r_entry->type);
}
