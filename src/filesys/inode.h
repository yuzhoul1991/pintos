#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include <list.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

#define NUM_DIRECT_BLOCKS 12
#define DIRECT_CAP (NUM_DIRECT_BLOCKS * BLOCK_SECTOR_SIZE)
#define INDIRECT_CAP (DIRECT_CAP + BLOCK_ENTRY_NUM * BLOCK_SECTOR_SIZE)
#define DBL_INDIRECT_CAP (INDIRECT_CAP + BLOCK_ENTRY_NUM * BLOCK_ENTRY_NUM * BLOCK_SECTOR_SIZE)

#define BLOCK_ENTRY_NUM (BLOCK_SECTOR_SIZE / 4)


struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                                     /* File size in bytes. */
    unsigned magic;                                   /* Magic number. */
    uint32_t unused[109];                             /* Not used. */
    block_sector_t indirect_block;                    /* Sector number of the indirect block */
    block_sector_t dbl_indirect_block;                /* Sector numberr of the double indirect block */
    block_sector_t direct_blocks[NUM_DIRECT_BLOCKS];  /* Array for storing the pointers in inode */
    uint32_t type;                                    /* Indicates FILE_TYPE or DIR_TYPE */
    block_sector_t parent_sector_number;              /* Represents parent directories sector number */
    uint32_t num_of_valid_entries;                    /* Includes files and subdirectories */
  };

struct indirect_block
  {
    block_sector_t blocks[BLOCK_ENTRY_NUM];
  };

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock;                   /* inode lock */
    struct lock dir_lock;               /* inode lock used only by directory inodes */
  };

void inode_init (void);
void inode_dir_lock (struct inode *);
void inode_dir_unlock (struct inode *);
bool inode_create (block_sector_t, off_t, uint32_t type, block_sector_t parent_sector);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset, bool meta);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset, bool meta);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
uint32_t inode_type (const struct inode *);
void inode_increment_valid_entries (const struct inode *inode);
void inode_decrement_valid_entries (const struct inode *inode);
uint32_t inode_get_valid_entries (const struct inode *inode);
block_sector_t inode_parent_sector_number (const struct inode *inode);
block_sector_t inode_sector_number (const struct inode *inode);
int inode_get_open_cnt (struct inode *inode);
#endif /* filesys/inode.h */
