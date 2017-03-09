#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/synch.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

#define FILESYS_HELPER_TICKS 100       /* Timer sleep ticks after which write-behind and read-ahead happens. */

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_lock (void);
void filesys_unlock (void);
void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name,uint32_t *filetype);
bool filesys_remove (const char *name);

void filesys_lock_init (void);
bool filesysdir_create (const char *dirname);
bool filesysdir_chdir (const char *dirname);

#endif /* filesys/filesys.h */
