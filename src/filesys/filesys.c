#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"
#include "threads/palloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

/* Filesys lock */
static struct lock lock;

static void do_format (void);

/* filesys api for locking and unlocking */
void
filesys_lock (void)
{
  //lock_acquire (&lock);
}

void
filesys_unlock (void)
{
  //lock_release (&lock);
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  cache_init ();
  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* initializes filesys_lock */
void
filesys_lock_init (void)
{
  lock_init (&lock);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
  cache_empty ();
}

bool
filesysdir_create (const char *dirname)
{
  char filename[512];
  bool success;
  block_sector_t inode_sector = 0;
  block_sector_t sector = 0;
  if (!filesys_parse_path (dirname, filename, &sector))
    return false;

  if(filesys_parse_DOT (filename)
     || filesys_parse_DOT_DOT (filename)
     || filesys_parse_SLASH (filename))
    return false;

  struct dir *dir = dir_open_sector (sector);
  success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_add (dir, filename, inode_sector)
                  && dir_create (inode_sector, 1, sector));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;

}

bool
filesysdir_chdir (const char *dirname)
{
  char filename[512];
  bool success;
  block_sector_t sector = 0;
  if(!filesys_parse_path (dirname, filename, &sector))
    return false;

  struct dir *dir = dir_open_sector (sector);
  struct inode *inode = NULL;

  if (filesys_parse_DOT (filename)
      || filesys_parse_DOT_DOT (filename)
      || filesys_parse_SLASH (filename))
    {
      if(dir == NULL)
        success = false;
      else
        {
          inode = inode_open (inode_sector_number (dir_get_inode (dir)));
          success = (inode
                       && (inode_type (inode) == DIR_TYPE));
        }

    }
  else
    success = (dir != NULL
                    && dir_lookup (dir, filename, &inode)
                    && (inode_type (inode) == DIR_TYPE));

  if (!success)
    return false;


  thread_set_sector (inode_sector_number (inode));
  inode_close (inode);
  dir_close (dir);

  return success;

}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size)
{
  block_sector_t inode_sector = 0;
  char filename[512];
  bool success;

  block_sector_t sector = 0;
  if(!filesys_parse_path (name, filename, &sector))
    return false;

  if(filesys_parse_DOT (filename)
     || filesys_parse_DOT_DOT (filename)
     || filesys_parse_SLASH (filename))
    return false;

  struct dir *dir = dir_open_sector (sector);

  success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, FILE_TYPE, sector)
                  && dir_add (dir, filename, inode_sector));

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char filename[512];
  block_sector_t sector = 0;
  if(!filesys_parse_path (name, filename, &sector))
    return false;

  struct dir *dir = dir_open_sector (sector);
  struct inode *inode = NULL;

  if (filesys_parse_DOT (filename)
      || filesys_parse_DOT_DOT (filename)
      || filesys_parse_SLASH (filename))
    {
      if(dir != NULL)
          inode = inode_open (inode_sector_number (dir_get_inode (dir)));
    }
  else
    {
      if (dir != NULL)
        dir_lookup (dir, filename, &inode);
    }

  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  char filename[512];
  bool success;
  block_sector_t sector = 0;

  if(!filesys_parse_path (name, filename, &sector))
    return false;

  if(filesys_parse_DOT (filename)
     || filesys_parse_DOT_DOT (filename)
     || filesys_parse_SLASH (filename))
    return false;

  struct dir *dir = dir_open_sector (sector);
  success = (dir != NULL
              && dir_remove (dir, filename));
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

bool
filesys_parse_path(const char *name,char *filename, block_sector_t *final_dir_sector)
{
  char *argv[128];
  char *token, *save_ptr;
  uint32_t argc=0;
  bool success = false;
  *final_dir_sector = thread_get_sector ();

  if(name==NULL)
    return success;

  if(!strcmp(name, "."))
    {
      strlcpy (filename, name, strlen(name)+1);
      return true;
    }

  if(!strcmp(name, ".."))
    {
      strlcpy (filename, name, strlen(name)+1);
      struct dir *dir = dir_open_sector (*final_dir_sector);
      if(dir == NULL)
        return false;
      *final_dir_sector = inode_parent_sector_number (dir_get_inode (dir));
      dir_close (dir);
      return true;
    }

  if(!strcmp(name, "/"))
    {
      strlcpy (filename, name, strlen(name)+1);
      *final_dir_sector = ROOT_DIR_SECTOR;
      return true;
    }

  if (name[0] == '/')
    *final_dir_sector = ROOT_DIR_SECTOR;

  char *fullname;
  fullname = palloc_get_page (0);
  if (fullname == NULL)
    return success;
  strlcpy (fullname, name, strlen(name)+1);

  for (token = strtok_r (fullname, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr))
  {
    argv[argc] = token;
    argv[argc][strlen(argv[argc])] = '\0';
    argc++;
  }
  uint32_t i;
  for (i=argc; i<128; i++)
  {
    argv[i] = "\0";
  }

  if(argc==0)
  {
    strlcpy (filename, fullname, strlen(fullname)+1);
    success = true;
    goto done;
  }

  for(i=0; i<argc;i++)
    {
      if(i==argc-1)
        {
          strlcpy (filename, argv[i], strlen(argv[i])+1);
          success = true;
          goto done;
        }
      if(i!=0)
        {
          if(!strcmp(argv[i], "."))
            {
              success = false;
              goto done;
            }
        }
      if(!strcmp(argv[i], "."))
        {
          //*final_dir_sector = ROOT_DIR_SECTOR;
        }
      else if(!strcmp(argv[i], ".."))
        {
          struct dir *dir = dir_open_sector (*final_dir_sector);
          if(dir == NULL)
            {
              success = false;
              goto done;
            }
          *final_dir_sector = inode_parent_sector_number (dir_get_inode (dir));
          dir_close (dir);
        }
      else
        {
          struct dir *dir = dir_open_sector (*final_dir_sector);
          if(dir == NULL)
            {
              success = false;
              goto done;
            }
          struct inode *inode = NULL;
          if(dir_lookup(dir, argv[i], &inode)
             && (inode_type (inode) == DIR_TYPE))
            {
              *final_dir_sector = inode_sector_number (inode);
              inode_close (inode);
              dir_close (dir);
            }
          else
            {
              inode_close (inode);
              dir_close (dir);
              success = false;
              goto done;
            }
        }
    }

done:
  palloc_free_page (fullname);
  return success;

}

bool
filesys_parse_DOT (char *name)
{
  if(name==NULL)
    return false;

  if(!strcmp(name, "."))
    return true;
  else
    return false;
}

bool
filesys_parse_DOT_DOT (char *name)
{
  if(name==NULL)
    return false;

  if(!strcmp(name, ".."))
    return true;
  else
    return false;
}

bool
filesys_parse_SLASH (char *name)
{
  if(name==NULL)
    return false;

  if(!strcmp(name, "/"))
    return true;
  else
    return false;
}
