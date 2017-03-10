#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT_BLOCKS 12
#define DIRECT_CAP (NUM_DIRECT_BLOCKS * BLOCK_SECTOR_SIZE)
#define INDIRECT_CAP (DIRECT_CAP + BLOCK_ENTRY_NUM * BLOCK_SECTOR_SIZE)
#define DBL_INDIRECT_CAP (INDIRECT_CAP + BLOCK_ENTRY_NUM * BLOCK_ENTRY_NUM * BLOCK_SECTOR_SIZE)

#define BLOCK_ENTRY_NUM (BLOCK_SECTOR_SIZE / 4)

static char zeros[BLOCK_SECTOR_SIZE];

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                           /* File size in bytes. */
    unsigned magic;                         /* Magic number. */
    uint32_t unused[109];                   /* Not used. */
    block_sector_t indirect_block;          /* Sector number of the indirect block */
    block_sector_t dbl_indirect_block;      /* Sector numberr of the double indirect block */
    block_sector_t direct_blocks[NUM_DIRECT_BLOCKS];  /* Array for storing the pointers in inode */
    uint32_t type; 
    block_sector_t parent_sector_number;
    uint32_t num_of_valid_entries; // includes files and subdirectories
  };

struct indirect_block
  {
    block_sector_t blocks[BLOCK_ENTRY_NUM];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock;             /* indoe lock */
  };

static off_t
get_direct_block_index (off_t pos)
{
  ASSERT (pos < DIRECT_CAP);
  return pos / BLOCK_SECTOR_SIZE;
}

static off_t
get_indirect_block_index (off_t pos)
{
  ASSERT (pos >= DIRECT_CAP && pos < INDIRECT_CAP);
  return (pos - DIRECT_CAP) / BLOCK_SECTOR_SIZE;
}

static off_t
get_dbl_indirect_block_index_l1 (off_t pos)
{
  ASSERT (pos >= INDIRECT_CAP && pos < DBL_INDIRECT_CAP);
  return (pos - INDIRECT_CAP) / (BLOCK_SECTOR_SIZE * BLOCK_ENTRY_NUM);
}

static off_t
get_dbl_indirect_block_index_l2 (off_t pos)
{
  ASSERT (pos >= INDIRECT_CAP && pos < DBL_INDIRECT_CAP);
  off_t l1_index = get_dbl_indirect_block_index_l1(pos);
  return (pos - INDIRECT_CAP - l1_index * BLOCK_ENTRY_NUM * BLOCK_SECTOR_SIZE) / BLOCK_SECTOR_SIZE;
}

static block_sector_t
block_get_sector_num(block_sector_t indirect_block_sector, off_t index)
{
  struct indirect_block* this_block;
  this_block = malloc (sizeof(struct indirect_block));

  if (this_block == NULL)
    return -1;

  cache_read_write (READ, indirect_block_sector, indirect_block_sector+1, META_DATA, this_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
  off_t sector_num = this_block->blocks[index];
  free (this_block);
  return sector_num;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);

  struct inode_disk *inode_disk = NULL;
  inode_disk = calloc (1, sizeof *inode_disk);
  block_sector_t sector_num = -1;

  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);

  if (pos > inode_disk->length)
    {
      free (inode_disk);
      return -1;
    }

  if (pos < DIRECT_CAP)
    {
      sector_num = inode_disk->direct_blocks[get_direct_block_index(pos)];
    }
  else if (pos < INDIRECT_CAP)
    {
      off_t indirect_block_index = get_indirect_block_index(pos);
      sector_num = block_get_sector_num(inode_disk->indirect_block, indirect_block_index);
    }
  else if (pos < DBL_INDIRECT_CAP)
    {
      off_t l1_index = get_dbl_indirect_block_index_l1(pos);
      off_t l2_index = get_dbl_indirect_block_index_l2(pos);
      block_sector_t l1_sector = block_get_sector_num(inode_disk->dbl_indirect_block, l1_index);
      sector_num = block_get_sector_num(l1_sector, l2_index);
    }
  else
    {
      sector_num = -1;
    }
  free (inode_disk);
  return sector_num;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;

/* Allocate a new sector fill with zeros and return the sector number */
static block_sector_t
inode_create_new_block (uint32_t fill)
{
  block_sector_t sector;
  if (free_map_allocate (1, &sector))
    {
      if (fill == 0)
        cache_read_write (WRITE, sector, sector+1, META_DATA, zeros, 0, 0, 0, BLOCK_SECTOR_SIZE);
      else
        {
          char block_fill[BLOCK_SECTOR_SIZE];
          int i;
          for (i = 0; i < BLOCK_SECTOR_SIZE; i++)
            block_fill[i] = fill;
          cache_read_write (WRITE, sector, sector+1, META_DATA, block_fill, 0, 0, 0, BLOCK_SECTOR_SIZE);
        }
      return sector;
    }
  return -1;
}

/* Extend a indirect block located on SECTOR with a new zero block */
static bool
inode_extend_indirect_block (block_sector_t sector, off_t index)
{
  if ((int)sector == -1)
    return false;

  struct indirect_block *this_block = malloc (sizeof(struct indirect_block));
  if (this_block == NULL)
    return false;

  cache_read_write (READ, sector, sector+1, META_DATA, this_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
  ASSERT ((int)this_block->blocks[index] == -1);
  this_block->blocks[index] = inode_create_new_block(0);
  if ((int)this_block->blocks[index] == -1)
    {
      free (this_block);
      return false;
    }
  cache_read_write (WRITE, sector, sector+1, META_DATA, this_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
  free (this_block);
  return true;
}

/* Extend a double indirect block located on SECTOR */
static bool
inode_extend_dbl_indirect_block (block_sector_t sector, off_t l1_idx, off_t l2_idx)
{
  if ((int)sector == -1)
    return false;

  struct indirect_block *layer1_block = malloc (sizeof(struct indirect_block));
  if (layer1_block == NULL)
    return false;

  bool need_write_back = false;
  cache_read_write (READ, sector, sector+1, META_DATA, layer1_block, 0, 0, 0, BLOCK_SECTOR_SIZE);

  if ((int)layer1_block->blocks[l1_idx] == -1)
    {
      layer1_block->blocks[l1_idx] = inode_create_new_block(-1);
      need_write_back = true;
    }

  if (inode_extend_indirect_block (layer1_block->blocks[l1_idx], l2_idx))
    {
      if (need_write_back)
        cache_read_write (WRITE, sector, sector+1, META_DATA, layer1_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
      free (layer1_block);
      return true;
    }
  free (layer1_block);
  return false;
}

/* Grow the file the inode represents by 1 sector and zero it out */
static bool
inode_grow_one_sector (struct inode_disk *inode_disk)
{
  ASSERT (inode_disk != NULL);

  off_t new_length = inode_disk->length + BLOCK_SECTOR_SIZE;
  inode_disk->length = new_length;

  // Extend by allocating a new dicrect_block
  if (new_length <= DIRECT_CAP)
    {
      off_t direct_block_idx = get_direct_block_index (new_length - 1);
      inode_disk->direct_blocks[direct_block_idx] = inode_create_new_block(0);
      return ((int)inode_disk->direct_blocks[direct_block_idx] != -1);
    }
  // Extend by adding to indirect_block
  else if (new_length <= INDIRECT_CAP)
    {
      if ((int)inode_disk->indirect_block == -1)
        inode_disk->indirect_block = inode_create_new_block(-1);

      off_t indirect_block_idx = get_indirect_block_index (new_length - 1);
      if (inode_extend_indirect_block (inode_disk->indirect_block, indirect_block_idx))
        return true;
    }
  // Extend by adding to dbl_indirect_block
  else if (new_length <= DBL_INDIRECT_CAP)
    {
      if ((int)inode_disk->dbl_indirect_block == -1)
        inode_disk->dbl_indirect_block = inode_create_new_block(-1);

      off_t l1_idx = get_dbl_indirect_block_index_l1 (new_length - 1);
      off_t l2_idx = get_dbl_indirect_block_index_l2 (new_length - 1);
      if (inode_extend_dbl_indirect_block (inode_disk->dbl_indirect_block, l1_idx, l2_idx))
        return true;
    }
  // File is probably too large
  return false;
}

/* Grow the file the inode represents to LENGTH bytes */
/* writting back of the grown inode should be handled outside of this
  funciton */
static bool
inode_grow (struct inode_disk *inode_disk, off_t length)
{
  ASSERT (inode_disk != NULL);
  if (length <= inode_disk->length)
    return true;

  size_t sectors_to_grow = bytes_to_sectors(length) - bytes_to_sectors(inode_disk->length);

  while (sectors_to_grow > 0)
    {
      if (!inode_grow_one_sector(inode_disk))
        return false;
      sectors_to_grow--;
    }

  // left over from the last sector
  inode_disk->length = length;
  return true;
}

/* Free resource held by this indirect_block located on SECTOR */
static void
free_indirect_block (block_sector_t sector)
{
  if ((int)sector == -1)
    return;

  struct indirect_block *this_block = malloc (sizeof(struct indirect_block));
  if (this_block == NULL)
    PANIC ("Unable to malloc indirect_block in free_indirect_block\n");

  cache_read_write (READ, sector, sector+1, META_DATA, this_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
  int i;
  for (i = 0; i < BLOCK_ENTRY_NUM; i++)
    if ((int)this_block->blocks[i] != -1)
      free_map_release (this_block->blocks[i], 1);
  free_map_release (sector, 1);
  free (this_block);
  return;
}

/* Free resource held by this dlb_indirect_block located on SECTOR */
static void
free_dbl_indirect_block (block_sector_t sector)
{
  if ((int)sector == -1)
    return;

  struct indirect_block *this_block = malloc (sizeof(struct indirect_block));
  if (this_block == NULL)
    PANIC ("Unable to malloc indirect_block in free_indirect_block\n");

  cache_read_write (READ, sector, sector+1, META_DATA, this_block, 0, 0, 0, BLOCK_SECTOR_SIZE);
  int i;
  for (i = 0; i < BLOCK_ENTRY_NUM; i++)
    if ((int)this_block->blocks[i] != -1)
      free_indirect_block (this_block->blocks[i]);
  free_map_release (sector, 1);
  free (this_block);
  return;
}

/* Free up all the resources held by a inode */
static void
inode_free (struct inode *inode)
{
  block_sector_t inode_disk_sector = inode->sector;
  int i;

  struct inode_disk* inode_disk = malloc (sizeof(struct inode_disk));
  if (inode_disk == NULL)
    PANIC ("Unable to malloc inode_disk in inode_free\n");

  cache_read_write (READ, inode_disk_sector, inode_disk_sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);
  for (i = 0; i < NUM_DIRECT_BLOCKS; i++)
    if ((int)inode_disk->direct_blocks[i] != -1)
      free_map_release (inode_disk->direct_blocks[i], 1);

  if ((int)inode_disk->indirect_block != -1)
    free_indirect_block (inode_disk->indirect_block);

  if ((int)inode_disk->dbl_indirect_block != -1)
    free_dbl_indirect_block (inode_disk->dbl_indirect_block);

  free_map_release (inode->sector, 1);
  free (inode_disk);
  return;
}


/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

static void
inode_lock (struct inode *inode)
{
  lock_acquire (&inode->lock);
}

static void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->lock);
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t type, block_sector_t parent_sector)
{
  struct inode_disk *inode_disk = NULL;

  ASSERT (length >= 0);
  ASSERT (sizeof *inode_disk == BLOCK_SECTOR_SIZE);

  inode_disk = calloc (1, sizeof *inode_disk);
  if (inode_disk != NULL)
    {
      inode_disk->magic = INODE_MAGIC;
      inode_disk->length = 0;
      inode_disk->indirect_block = -1;
      inode_disk->dbl_indirect_block = -1;
      inode_disk->type = type;
      inode_disk->parent_sector_number = parent_sector;
      inode_disk->num_of_valid_entries = 0;

      int i;
      for (i = 0; i < NUM_DIRECT_BLOCKS; i++)
        {
          inode_disk->direct_blocks[i] = -1;
        }

      if ((length != 0) && !inode_grow(inode_disk, length))
        {
          free (inode_disk);
          return false;
        }

      cache_read_write (WRITE, sector, sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);
      free (inode_disk);
    }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  bool found = false;

  lock_acquire (&open_inodes_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          found = true;
          break;
        }
    }
  lock_release (&open_inodes_lock);
  if (found)
    return inode;

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->lock);
  lock_acquire (&open_inodes_lock);
  list_push_front (&open_inodes, &inode->elem);
  lock_release (&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL){
    inode_lock (inode);
    inode->open_cnt++;
    inode_unlock (inode);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  bool inode_freed = false;
  inode_lock (inode);
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          inode_free (inode);
        }

      inode_unlock (inode);
      free (inode);
      inode_freed = true;
    }
  if(!inode_freed)
    inode_unlock (inode);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset, bool meta)
{
  //uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      block_sector_t prefetch_sector_idx = byte_to_sector (inode, offset+BLOCK_SECTOR_SIZE);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read_write (READ, sector_idx, prefetch_sector_idx, meta? META_DATA: REAL_DATA, buffer_, bytes_read, 0, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset, bool meta)
{
  //const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  inode_lock (inode);
  int deny_write_cnt = inode->deny_write_cnt;
  inode_unlock (inode);
  if (deny_write_cnt)
    return 0;

  // read latest disk inode to memory
  struct inode_disk *inode_disk = NULL;
  inode_disk = calloc (1, sizeof *inode_disk);

  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);

  off_t new_length = size + offset;
  if (new_length > inode_length (inode))
    if (!inode_grow (inode_disk, new_length))
      {
        free (inode_disk);
        return 0;
      }

  // write to cache latest inode since it had grown
  cache_read_write (WRITE, inode->sector, inode->sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      cache_read_write (WRITE, sector_idx, 0, meta? META_DATA: REAL_DATA, (void*)buffer_, 0, bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  // write back modified disk inode to disk
  cache_read_write (WRITE, inode->sector, inode->sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);
  free (inode_disk);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode_lock (inode);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode_unlock (inode);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  inode_lock (inode);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  inode_unlock (inode);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk *inode_disk = NULL;
  inode_disk = calloc (1, sizeof *inode_disk);
  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, inode_disk, 0, 0, 0, BLOCK_SECTOR_SIZE);
  off_t length = 0;
  length = inode_disk->length;
  free (inode_disk);
  return length;
}

/* Returns the type either file or directory */
uint32_t
inode_type (const struct inode *inode)
{
  struct inode_disk *disk_inode = NULL;
  disk_inode = calloc (1, sizeof *disk_inode);
  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);
  uint32_t type = disk_inode->type;
  free (disk_inode);
  return type;
}

void
inode_increment_valid_entries (const struct inode *inode)
{

  struct inode_disk *disk_inode = NULL;
  disk_inode = calloc (1, sizeof *disk_inode);
  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);
  disk_inode->num_of_valid_entries++;
  cache_read_write (WRITE, inode->sector, 0, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);
  free (disk_inode);


}

void
inode_decrement_valid_entries (const struct inode *inode)
{

  struct inode_disk *disk_inode = NULL;
  disk_inode = calloc (1, sizeof *disk_inode);
  cache_read_write (READ, inode->sector, total_sectors, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);

  if(disk_inode->num_of_valid_entries<=0)
    PANIC("decrementing num_of_valid_entries which is 0");
  disk_inode->num_of_valid_entries--;
  cache_read_write (WRITE, inode->sector, 0, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);
  free (disk_inode);


}

uint32_t
inode_get_valid_entries (const struct inode *inode)
{

  struct inode_disk *disk_inode = NULL;
  disk_inode = calloc (1, sizeof *disk_inode);
  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);

  uint32_t valid_entries = disk_inode->num_of_valid_entries;
  free (disk_inode);

  return valid_entries;
}

block_sector_t
inode_parent_sector_number (const struct inode *inode)
{
  struct inode_disk *disk_inode = NULL;
  disk_inode = calloc (1, sizeof *disk_inode);
  cache_read_write (READ, inode->sector, inode->sector+1, META_DATA, disk_inode, 0, 0, 0, BLOCK_SECTOR_SIZE);
  block_sector_t sec_num;
  sec_num = disk_inode->parent_sector_number;
  free (disk_inode);
  return sec_num;
}

block_sector_t
inode_sector_number (const struct inode *inode)
{
 return  inode->sector;
}

int
inode_get_open_cnt (struct inode *inode)
{
  inode_lock (inode);
  int open_cnt = inode->open_cnt;
  inode_unlock (inode);
  return open_cnt;
}
