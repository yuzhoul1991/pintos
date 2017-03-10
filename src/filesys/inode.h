#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;

void inode_init (void);
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
bool inode_readdir (struct inode *inode, char *name);
#endif /* filesys/inode.h */
