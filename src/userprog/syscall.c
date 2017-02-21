#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "lib/round.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/input.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Check if ptr is a valid user address which is also mapped */
static void
syscall_check_valid_user_pointer(void* ptr, bool is_write, bool check_spte)
{
  bool valid = ptr != NULL;

  valid &= is_user_vaddr (ptr);

  if(check_spte)
    {
      struct spage_table_entry *spte = page_get_spte(ptr);

      valid &= spte != NULL;

      if (spte && is_write)
        {
          valid &= spte->writable;
        }
    }

  if (!valid)
  {
    process_update_exit_status(-1);
    thread_exit ();
  }
}

/* Check if ptr to a buffer is a valid user address which is also mapped for all size bytes. */
static void
syscall_check_valid_user_buffer(void* ptr, size_t size, bool is_write, bool check_spte)
{
  syscall_check_valid_user_pointer(ptr, is_write, check_spte);
  uint32_t *up_limit = (uint32_t*)ptr + size / 4;
  uint32_t *check_ptr = (uint32_t*)ROUND_DOWN ((int)ptr, PGSIZE);

  while (check_ptr <= (uint32_t*)up_limit)
    {
      syscall_check_valid_user_pointer(check_ptr, is_write, check_spte);
      check_ptr += PGSIZE / 4;
    }
}

static bool
syscall_vaddr_between_addrs(void* vaddr, void* start_vaddr, void* end_vaddr)
{
  return (vaddr >= start_vaddr && vaddr < end_vaddr);
}

static bool
syscall_invalid_mmap_address(struct thread *t, void* vaddr_start, void* vaddr_end)
{
  if (vaddr_start == 0)
    return true;

  if ((uint32_t)vaddr_start % PGSIZE != 0)
    return true;

  if((t->code_seg_start != 0) && (t->code_seg_end != 0))
  {
    if(syscall_vaddr_between_addrs(vaddr_start, t->code_seg_start, t->code_seg_end)
       || syscall_vaddr_between_addrs(vaddr_end, t->code_seg_start, t->code_seg_end))
      return true;
  }

  if((t->data_seg_start != 0) && (t->data_seg_end != 0))
  {
    if(syscall_vaddr_between_addrs(vaddr_start, t->data_seg_start, t->data_seg_end)
       || syscall_vaddr_between_addrs(vaddr_end, t->data_seg_start, t->data_seg_end))
      return true;
  }

  if((t->stack_start != PHYS_BASE) && (t->stack_end == PHYS_BASE))
  {
    if(syscall_vaddr_between_addrs(vaddr_start, t->stack_start, t->stack_end)
       || syscall_vaddr_between_addrs(vaddr_end, t->stack_start, t->stack_end))
      return true;
  }

  if(!list_empty(&t->mmap_list))
  {
    struct list_elem *e;
    for (e = list_begin (&t->mmap_list); e != list_end (&t->mmap_list); e = list_next (e))
    {
      struct mmap_info *m_info = list_entry (e, struct mmap_info, mmap_elem);
      if (syscall_vaddr_between_addrs(vaddr_start, m_info->vaddr_start, m_info->vaddr_end)
          || syscall_vaddr_between_addrs(vaddr_end, m_info->vaddr_start, m_info->vaddr_end))
        return true;
    }
  }

  return false;
}

/* get the syscall number stored in stack pointer of intr_frame f */
static int
syscall_get_number(struct intr_frame *f)
{
  syscall_check_valid_user_pointer (f->esp, false, true);
  return *((uint32_t*)f->esp);
}

/* Get the arguments of syscall stored at an offset of "offset" from stack pointer */
static uint32_t
syscall_get_arg(struct intr_frame *f, uint32_t offset)
{
  syscall_check_valid_user_pointer(f->esp + offset, false, true);
  return *(uint32_t*)(f->esp + offset);
}

static void
syscall_halt (void)
{
 shutdown_power_off();
}

static void
syscall_exit(int status)
{
  process_update_exit_status(status);
  thread_exit();
}

static pid_t
syscall_exec (const char *cmd_line)
{
  pid_t pid = process_wait_for_load (process_execute (cmd_line));
  return pid;
}

static int
syscall_wait (pid_t child_pid)
{
  return process_wait((tid_t)child_pid);
}

static bool
syscall_create (const char *file, unsigned initial_size)
{
  bool success;
  filesys_lock ();
  success = filesys_create(file,initial_size);
  filesys_unlock ();
  return success;
}

static bool
syscall_remove (const char *file)
{
  bool success;
  filesys_lock ();
  success = filesys_remove(file);
  filesys_unlock ();
  return success;
}

static int
syscall_open (const char *file)
{
  struct file_info *f_info = malloc(sizeof(struct file_info));
  if(f_info == NULL)
    PANIC("file_info malloc failed");
  f_info->fd = 2;
  filesys_lock ();
  f_info->file_ptr = filesys_open(file);
  filesys_unlock ();
  if(f_info->file_ptr == NULL)
  {
    free(f_info);
    return -1;
  }
  else
  {
    /* When a file is opened, add it to current thread's opened files. Also assign a fd */
    struct thread *t = thread_current ();
    f_info->fd = t->total_fds+2;
    t->total_fds++;
    list_push_back (&t->fd_list, &f_info->file_elem);
  }

  return (f_info->fd);
}

static int
syscall_filesize (int fd)
{
  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    int length = file_length(f_info->file_ptr);
    filesys_unlock ();
    return length;
  }
  else
    return -1;
}

static int
syscall_read (int fd, void *buffer, unsigned size)
{
  if(fd == 0)
  {
    *(uint8_t *)buffer = input_getc();
    return (sizeof buffer);
  }

  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    int actual_read = file_read(f_info->file_ptr, buffer, size);
    filesys_unlock ();
    return actual_read;
  }
  else
    return -1;
}

static int
syscall_write (int fd, const void *buffer, unsigned size)
{
  if(fd == 1)
  {
    size_t buffer_size = size;
    putbuf(buffer, buffer_size);
    return buffer_size;
  }

  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    int actual_write = file_write(f_info->file_ptr, buffer, size);
    filesys_unlock ();
    return actual_write;
  }
  else
    return -1;
}

static void
syscall_seek (int fd, unsigned position)
{
  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    file_seek(f_info->file_ptr, position);
    filesys_unlock ();
  }
}

static unsigned
syscall_tell (int fd)
{
  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    unsigned position = file_tell(f_info->file_ptr);
    filesys_unlock ();
    return position;
  }
  else
    return 0;
}

static void
syscall_close (int fd)
{
  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);

  if(e != NULL)
  {
    /* Remove file from current thread's opened files */
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    list_remove(e);
    filesys_lock ();
    file_close(f_info->file_ptr);
    filesys_unlock ();
    free(f_info);
  }
}

static mapid_t
syscall_mmap (int fd, void *vaddr)
{
  if((fd == 0)
     || (fd == 1))
    return MAP_FAILED;

  struct thread *t = thread_current ();
  /* Find the struct file * corresponding to fd */
  struct list_elem *e = thread_find_fd(t, fd);
  struct file_info *f_info = NULL;
  uint32_t length = 0;

  if(e != NULL)
  {
    f_info = list_entry (e, struct file_info, file_elem);
    filesys_lock ();
    length = file_length(f_info->file_ptr);
    filesys_unlock ();
    if(length == 0)
      return MAP_FAILED;
  }
  else
    return MAP_FAILED;

  if(syscall_invalid_mmap_address(t, vaddr, (pg_round_up(vaddr+length))))
    return MAP_FAILED;

  struct mmap_info *m_info = malloc(sizeof(struct mmap_info));
  if(m_info == NULL)
    PANIC("mmap_info malloc failed");

    m_info->vaddr_start = vaddr;
    m_info->vaddr_end = (pg_round_up(vaddr+length));
    m_info->mmap_size = length;
    t->total_mmaps++;
    list_push_back (&t->mmap_list, &m_info->mmap_elem);

    uint8_t *upage = (uint8_t *) vaddr;
    uint32_t read_bytes = length;
    uint32_t zero_bytes = PGSIZE - (length % PGSIZE);
    off_t per_page_off = 0;
    while (read_bytes > 0 || zero_bytes > 0)
      {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Setup spte for this file page */
        if(!page_add_file (upage, f_info->file_ptr, per_page_off, page_read_bytes, page_zero_bytes, true, true))
          return MAP_FAILED;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        per_page_off += PGSIZE;
    }

  return (m_info->mapid);
}

static void
syscall_munmap (mapid_t mapid)
{
  struct thread *t = thread_current ();
  struct list_elem *e = thread_find_mmap(t, mapid);

  if(e == NULL)
    return;
  else
    {
      struct mmap_info *m_info = list_entry (e, struct mmap_info, mmap_elem);
      thread_munmap(m_info);
      list_remove(e);
      free(m_info);
    }
}

static void
syscall_handler (struct intr_frame *f)
{
  char *file_name, *command_line;
  int fd;
  void *buffer, *vaddr;
  unsigned file_size, position;
  pid_t pid;
  mapid_t map_id;

  int syscall_num = syscall_get_number(f);
  /* Call different system calls depending on syscall_num */
  switch(syscall_num)
  {
    case(SYS_HALT):
      syscall_halt();
      break;
    case(SYS_EXIT):
      syscall_exit (syscall_get_arg(f, 4));
      break;
    case(SYS_EXEC):
      command_line = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(command_line, false, true);
      f->eax = syscall_exec (command_line);
      break;
    case(SYS_WAIT):
      pid = (pid_t)syscall_get_arg(f, 4);
      f->eax = syscall_wait (pid);
      break;
    case(SYS_CREATE):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name, false, true);
      file_size = (unsigned)syscall_get_arg(f, 8);
      f->eax = syscall_create (file_name, file_size);
      break;
    case(SYS_REMOVE):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name, false, true);
      f->eax = syscall_remove (file_name);
      break;
    case(SYS_OPEN):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name, false, true);
      f->eax = syscall_open (file_name);
      break;
    case(SYS_FILESIZE):
      fd = (int)syscall_get_arg(f, 4);
      f->eax = syscall_filesize (fd);
      break;
    case(SYS_READ):
      fd = (int)syscall_get_arg(f, 4);
      buffer = (void*)syscall_get_arg(f, 8);
      file_size = (unsigned)syscall_get_arg(f, 12);
      syscall_check_valid_user_buffer(buffer, file_size, true, true);
      //FIXME: Pin buffer vaddr
      f->eax = syscall_read(fd, buffer, file_size);
      break;
    case(SYS_WRITE):
      fd = (int)syscall_get_arg(f, 4);
      buffer = (void*)syscall_get_arg(f, 8);
      file_size = (unsigned)syscall_get_arg(f, 12);
      syscall_check_valid_user_buffer(buffer, file_size, false, true);
      //FIXME: Pin buffer vaddr
      f->eax = syscall_write(fd, buffer, file_size);
      break;
    case(SYS_SEEK):
      fd = (int)syscall_get_arg(f, 4);
      position = (unsigned)syscall_get_arg(f, 8);
      syscall_seek (fd, position);
      break;
    case(SYS_TELL):
      fd = (int)syscall_get_arg(f, 4);
      f->eax = syscall_tell (fd);
      break;
    case(SYS_CLOSE):
      fd = (int)syscall_get_arg(f, 4);
      syscall_close (fd);
      break;
    case(SYS_MMAP):
      fd = (int)syscall_get_arg(f, 4);
      vaddr = (void*)syscall_get_arg(f, 8);
      //syscall_check_valid_user_buffer(vaddr, 0, true, false);
      f->eax = syscall_mmap (fd, vaddr);
      break;
    case(SYS_MUNMAP):
      map_id = (mapid_t)syscall_get_arg(f, 4);
      syscall_munmap (map_id);
      break;
    default:
      printf ("syscall not implemented\n");
      process_update_exit_status(-1);
      thread_exit ();
      break;
  }
}
