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
syscall_check_valid_user_pointer(void* ptr)
{
  struct thread *t_current = thread_current ();
  if (ptr == NULL
      || !is_user_vaddr (ptr)
      || pagedir_get_page (t_current->pagedir, ptr) == NULL)
    thread_exit ();
}

/* Check if ptr to a buffer is a valid user address which is also mapped for all size bytes. */
static void
syscall_check_valid_user_buffer(void* ptr, size_t size)
{
  syscall_check_valid_user_pointer(ptr);
  uint32_t *up_limit = (uint32_t*)ptr + size / 4;
  uint32_t *check_ptr = (uint32_t*)ROUND_DOWN ((int)ptr, PGSIZE);

  while (check_ptr <= (uint32_t*)up_limit)
    {
      syscall_check_valid_user_pointer(check_ptr);
      check_ptr += PGSIZE / 4;
    }
}

/* get the syscall number stored in stack pointer of intr_frame f */
static int
syscall_get_number(struct intr_frame *f)
{
  syscall_check_valid_user_pointer (f->esp);
  return *((uint32_t*)f->esp);
}

/* Get the arguments of syscall stored at an offset of "offset" from stack pointer */
static uint32_t
syscall_get_arg(struct intr_frame *f, uint32_t offset)
{
  syscall_check_valid_user_pointer(f->esp + offset);
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

static void
syscall_handler (struct intr_frame *f)
{
  char *file_name, *command_line;
  int fd;
  void *buffer;
  unsigned file_size, position;
  pid_t pid;

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
      syscall_check_valid_user_pointer(command_line);
      f->eax = syscall_exec (command_line);
      break;
    case(SYS_WAIT):
      pid = (pid_t)syscall_get_arg(f, 4);
      f->eax = syscall_wait (pid);
      break;
    case(SYS_CREATE):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name);
      file_size = (unsigned)syscall_get_arg(f, 8);
      f->eax = syscall_create (file_name, file_size);
      break;
    case(SYS_REMOVE):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name);
      f->eax = syscall_remove (file_name);
      break;
    case(SYS_OPEN):
      file_name = (char *)syscall_get_arg(f, 4);
      syscall_check_valid_user_pointer(file_name);
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
      syscall_check_valid_user_buffer(buffer, file_size);
      f->eax = syscall_read(fd, buffer, file_size);
      break;
    case(SYS_WRITE):
      fd = (int)syscall_get_arg(f, 4);
      buffer = (void*)syscall_get_arg(f, 8);
      file_size = (unsigned)syscall_get_arg(f, 12);
      syscall_check_valid_user_buffer(buffer, file_size);
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
    default:
      printf ("syscall not implemented\n");
      thread_exit ();
      break;
  }
}
