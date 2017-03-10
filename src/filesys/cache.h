#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <bitmap.h>
#include <list.h>
#include <string.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/filesys.h"

#define META_DATA 0x1
#define REAL_DATA 0x2

#define READ 0x1
#define WRITE 0x2

#define CACHE_ENTRIES 64
#define READ_AHEAD_ENTRIES 16


struct cache_entry
  {
    uint8_t* data;                 /* BLOCK SIZED DATA */
    block_sector_t old_sector;     /* When evicting this block, sector which is being evicted */
    block_sector_t sector;         /* sector currently held by cache block */
    uint32_t cache_block;          /* cache block number corresponding to bitmap */
    uint32_t type;                 /* Indicates whether it is a meta data or real data */
    bool dirty;                    /* Indicates whether the data is dirty */
    bool accessed;                 /* Indicates if the sector has been accessed since last eviction attempt */
    bool meta_retry;               /* If true for a meta data, then give an additional chance rather than evicting */
    bool entry_blocked;            /* Indicates if entry is blocked for reading/writing */
    bool uninitialized;            /* Indicates if the cache data was uninitialized. Used only by free_map_entry */
    uint32_t pin;                  /* if pinned, cache block cannot be evicted */
    struct lock entry_lock;        /* lock per cache entry */
    struct condition entry_cond;   /* lock per cache entry */
    struct list_elem elem;         /* list element to add to cache_list */
    
  };

struct cache_read_ahead_entry
  {
    block_sector_t sector;         /* sector currently held by prefetch entry */
    uint32_t type;                 /* Indicates whether it is a meta data or real data */
    struct list_elem elem;         /* list element to add to prefetch_list */
    
  };


struct list cache_list;             /* List of all valid cache blocks */
struct list_elem *cache_hand;       /* cache_hand points to an element in cache_list and is used for clock algorithm */
struct lock cache_lock;             /* lock used by common variables of cache */
struct bitmap *cache_bitmap;        /* Bitmap which holds bits = CACHE_ENTRIES */
uint32_t total_sectors;
struct cache_entry *free_map_entry; /* Special cache entry for free_map*/ 

struct list cache_read_ahead_list;  /* List of all valid cache_read_ahead entries */
struct lock cache_read_ahead_lock;  /* lock used by common variables of cache_read_ahead */

void cache_init(void);
void cache_read_write (uint32_t read_write, block_sector_t sector, block_sector_t prefetch_sector, bool meta, void *buffer_, off_t bytes_read, off_t bytes_written, int sector_ofs, int chunk_size);
void cache_empty (void);
void cache_write_behind (void);
void cache_read_ahead (void);

void cache_read_ahead_init(void);

#endif
