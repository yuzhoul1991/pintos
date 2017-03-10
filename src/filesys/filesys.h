#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "devices/block.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

#define FILESYS_HELPER_TICKS 100       /* Timer sleep ticks after which write-behind and read-ahead happens. */
#define FILE_TYPE 0x0
#define DIR_TYPE  0x1

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_lock (void);
void filesys_unlock (void);
void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

void filesys_lock_init (void);
bool filesysdir_create (const char *dirname);
bool filesysdir_chdir (const char *dirname);
bool filesys_parse_path(const char *name,char *filename, block_sector_t *final_dir_sector);
bool filesys_parse_DOT (char *name);
bool filesys_parse_SLASH (char *name);

#endif /* filesys/filesys.h */
