#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "lib/user/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, uint32_t argc, char **argv);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create new child info for the process you are trying to create */
  struct child_info *c_info = malloc(sizeof(struct child_info));
  if (c_info == NULL)
    thread_exit ();

  c_info->loaded = false;
  c_info->exit_status = -1;
  c_info->child_thread = NULL;
  sema_init(&c_info->sema_load,0);
  sema_init(&c_info->sema_exit,0);

  struct thread *cur = thread_current ();
  cur->recent_child = c_info;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    /* Free child_info if child not created */
    free(c_info);
    cur->recent_child = NULL;
  }
  else
  {
    /* Update child_info with child's tid and add it to parent's list */
    c_info->tid = tid;
    list_push_back (&cur->child_list, &c_info->child_elem);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name_arg = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current ();

  page_init (cur);
  uint32_t argc = 0;
  char *argv[128];

  /* Get characters separated by " " and pass it through argv.
     argv will eventually be pushed to stack
  */

  char *token, *save_ptr;
  char *file_name = strtok_r(file_name_arg, " ", &save_ptr);
  if(file_name != NULL)
  {
    argv[argc] = file_name;
    argv[argc][strlen(argv[argc])] = '\0';
    argc++;
    strlcpy (cur->process_name, file_name, sizeof cur->process_name);
  }
  for (token = strtok_r (NULL, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
  {
    argv[argc] = token;
    /* terminate argv with \0 */
    argv[argc][strlen(argv[argc])] = '\0';
    argc++;
  }

  int i;
  for(i=argc; i<128; i++)
  {
    argv[i] = "\0";
  }

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp, argc, argv);

  /* child process updates loaded value and releases semaphore sema_load.
     Thus enabling parent to read loading status without race condition
  */
  if(cur->parent_child_info != NULL)
  {
    cur->parent_child_info->loaded = success;
    struct semaphore *c_sema_load = &cur->parent_child_info->sema_load;
    sema_up(c_sema_load);
  }
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* When passed a tid child_id, iterate through parent's child_list and find child_info corresponding
   to the child. If no child_info is found, the function return's NULL.
   If no child_info is found, it could mean, Parent has no child with child_id or the parent had already
   waited for child_id*/
struct child_info *
process_get_child_info (tid_t child_id)
{
  struct thread* t_current = thread_current ();
  struct list_elem *e;
  struct list *child_list = &t_current->child_list;

  if (list_empty(&t_current->child_list))
    return NULL;

  for (e = list_begin (child_list); e != list_end (child_list); e = list_next (e))
  {
    struct child_info *child_s = list_entry (e, struct child_info, child_elem);
    if (child_s->tid == child_id)
    {
      return child_s;
    }
  }

  return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *cur = thread_current ();
  if(list_empty (&cur->child_list))
    return -1;

  /* Parent tries to find child_info corresponding to child_tid.
     If not found, then the function returns -1 */
  struct child_info *child_s = process_get_child_info (child_tid);
  if (child_s == NULL)
    return -1;

  /* Parent trie to acquire semaphore sema_exit to synchronize with child process's exit.
     Once it acuires it, Parent reads child's exit status and frees up child_info memory.
  */
  sema_down(&child_s->sema_exit);
  int exit_status = child_s->exit_status;
  list_remove(&child_s->child_elem);
  free (child_s);

  return exit_status;
}

/* Waits for thread TID to finish loading and return its pid. If the
   child didnot get created or loaded, returns a PID of -1*/
pid_t
process_wait_for_load(tid_t child_tid)
{
  if(child_tid == TID_ERROR)
    return PID_ERROR;

  struct thread *cur = thread_current ();
  struct semaphore *c_sema_load = &cur->recent_child->sema_load;

  /* Parent trie to acquire semaphore sema_load to synchronize with child process's loading.
     Once it acuires it, Parent reads child's loading status. If child is not loaded properly,
     then we free up memory corresponding to child_info and return -1.
  */
  sema_down(c_sema_load);
  if(cur->recent_child->loaded)
    return ((pid_t)child_tid);
  else
  {
    struct child_info *remove_child = cur->recent_child;
    list_remove(&remove_child->child_elem);
    free(remove_child);
    cur->recent_child = NULL;
    return PID_ERROR;
  }
}

/* This function updates exit status of current process and updates parent's child_info if any */
void
process_update_exit_status(int status)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  old_level = intr_disable ();
  if(cur->parent_child_info != NULL)
    cur->parent_child_info->exit_status = status;
  intr_set_level (old_level);
  cur->exit_status = status;
}

/* Close unclosed file's of this process */
static void
process_free_file_descriptors(void)
{
  struct thread *cur = thread_current ();
  /* Close all unclosed fd's by this thread*/
  while(!list_empty(&cur->fd_list))
  {
    struct list_elem *e = list_begin(&cur->fd_list);
    struct file_info *f_info = list_entry (e, struct file_info, file_elem);
    list_remove(e);
    filesys_lock ();
    file_close(f_info->file_ptr);
    filesys_unlock ();
    free(f_info);
    cur->total_fds--;
  }
}

/* Free up code segment user vaddr */
static void
process_free_code_segment(void)
{
  struct thread *cur = thread_current ();
  if(cur->code_seg_start == 0
     || cur->code_seg_end == 0)
    return;
  void* start_vaddr = cur->code_seg_start;
  void* end_vaddr   = cur->code_seg_end;
  void* vaddr;
  for(vaddr = start_vaddr; vaddr<end_vaddr; vaddr+=PGSIZE)
    page_free_vaddr(vaddr, FREE_UVADDR_WRITE_ZERO);
}

/* Free up data segment user vaddr */
static void
process_free_data_segment(void)
{
  struct thread *cur = thread_current ();
  if(cur->data_seg_start == 0
     || cur->data_seg_end == 0)
    return;
  void* start_vaddr = cur->data_seg_start;
  void* end_vaddr   = cur->data_seg_end;
  void* vaddr;
  for(vaddr = start_vaddr; vaddr<end_vaddr; vaddr+=PGSIZE)
    page_free_vaddr(vaddr, FREE_UVADDR_WRITE_ZERO);
}

/* Free up stack segment user vaddr */
static void
process_free_stack_segment(void)
{
  struct thread *cur = thread_current ();
  if(cur->stack_start == cur->stack_end)
    return;
  void* start_vaddr = cur->stack_start;
  void* end_vaddr   = cur->stack_end;
  void* vaddr;
  for(vaddr = start_vaddr; vaddr<end_vaddr; vaddr+=PGSIZE)
    page_free_vaddr(vaddr, FREE_UVADDR_WRITE_ZERO);
}

/* Free up unmapped mmap's of this process */
static void
process_free_mmaps(void)
{
  struct thread *cur = thread_current ();
  /* Munmap all unclosed mmap's by this thread*/
  while(!list_empty(&cur->mmap_list))
  {
    struct list_elem *e = list_begin(&cur->mmap_list);
    struct mmap_info *m_info = list_entry (e, struct mmap_info, mmap_elem);
    thread_munmap(m_info);
    list_remove(e);
    free(m_info);
    cur->total_mmaps--;
  }
}

static void
process_release_exit_semaphore(void)
{
  struct thread *cur = thread_current ();
  /* Child process obtains child_info created by parent. Releases the semaphore sema_exit
     so that a parent in process_wait can read the exit status of child
  */
  enum intr_level old_level;
  old_level = intr_disable ();
  if(cur->parent_child_info != NULL)
  {
    struct semaphore *c_sema_exit = &cur->parent_child_info->sema_exit;
    cur->parent_child_info->child_thread = NULL;
    sema_up(c_sema_exit);
  }
  intr_set_level (old_level);
}

/* Free up hash table corresponding to spte table */
static void
process_free_spage_table(void)
{
  struct thread *t_current = thread_current ();
  page_free (t_current);
}

static void
process_free_child_list(void)
{
  struct thread *cur = thread_current ();
  /* free up all child_info for children the current process did not wait */
  while(!list_empty(&cur->child_list))
  {
    struct list_elem *e = list_begin(&cur->child_list);
    struct child_info *c_info = list_entry (e, struct child_info, child_elem);
    list_remove(e);
    enum intr_level old_level;
    old_level = intr_disable ();
    if (c_info->child_thread != NULL)
      c_info->child_thread->parent_child_info = NULL;
    intr_set_level (old_level);
    free(c_info);
  }
}

static void
process_destroy_pagedir(void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

static void
process_close_executable_file(void)
{
  struct thread *cur = thread_current ();
  /* Close the executable file */
  if(cur->executable != NULL)
  {
    filesys_lock ();
    file_close (cur->executable);
    filesys_unlock ();
  }
}

static void
process_print_exit_msg(void)
{
  struct thread *cur = thread_current ();
  printf("%s: exit(%d)\n",cur->process_name,cur->exit_status);
}

void
process_exit (void)
{
  process_free_file_descriptors ();
  process_free_code_segment ();
  process_free_data_segment ();
  process_free_stack_segment ();
  process_free_mmaps ();
  process_free_spage_table ();
  process_destroy_pagedir ();
  process_close_executable_file ();
  process_free_child_list ();
  process_print_exit_msg ();
  process_release_exit_semaphore ();
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, uint32_t argc, char **argv);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, uint32_t argc, char **argv)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  filesys_lock ();
  file = filesys_open (file_name);
  filesys_unlock ();

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  filesys_lock ();
  off_t bytes_read = file_read (file, &ehdr, sizeof ehdr);
  filesys_unlock ();
  if (bytes_read != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Deny write to executable and keep track of executable file to close it at exit */
  filesys_lock ();
  file_deny_write (file);
  filesys_unlock ();
  t->executable = file;

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;
      off_t file_len;

      filesys_lock ();
      file_len = file_length (file);
      filesys_unlock ();

      if (file_ofs < 0 || file_ofs > file_len)
        goto done;
      filesys_lock ();
      file_seek (file, file_ofs);
      filesys_unlock ();

      filesys_lock ();
      bytes_read = file_read (file, &phdr, sizeof phdr);
      filesys_unlock ();
      if (bytes_read != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  filesys_lock ();
  off_t length = file_length (file);
  filesys_unlock ();
  if (phdr->p_offset > (Elf32_Off) length)
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread *t = thread_current ();

  /* Update data and code segment's start and end user vaddr */
  if(writable)
  {
    t->data_seg_start = (void *) upage;
    t->data_seg_end = t->data_seg_start + read_bytes + zero_bytes;
  }
  else
  {
    t->code_seg_start = (void *) upage;
    t->code_seg_end = t->code_seg_start + read_bytes + zero_bytes;
  }

  off_t per_page_off = ofs;
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Setup spte for this file page */
      if(!page_add_file (upage, file, per_page_off, page_read_bytes, page_zero_bytes, writable, false))
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      per_page_off += PGSIZE;
    }
  return true;
}

/* word align the stack pointer */
static void
word_align(void **esp)
{
  if(((uint32_t) * esp) % 4 != 0)
  {
    *esp-=((uint32_t)*esp)%4;
    uint8_t zero = 0;
    *(uint8_t*)*esp = zero;
  }
}

/* push dummy return value zero to stack */
static void
push_dummy_return_value(void **esp)
{
  uint32_t zero = 0;
  *esp = *esp - (sizeof zero);
  *(uint32_t*)*esp = zero;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, uint32_t argc, char **argv)
{
  /* eagerly allocate the first page under PHYS_BASE of user stack */
  bool success = grow_stack (((uint8_t*)PHYS_BASE) - PGSIZE);
  if (success)
  {
    int32_t i;
    uint32_t argv_address[argc];

    *esp = PHYS_BASE;

    // save off user argument address
    for(i=argc; i>=0; i--)
    {
      argv_address[i] = 0;
    }
    /* Copy value of arguments onto stack in descending order. Keep track of address where we store it */
    for(i=argc-1; i>=0; i--)
    {
      size_t argv_len = strlen(argv[i]) + 1; //Adding +1 to include \0
      *esp = *esp - argv_len;
      memcpy(*esp, argv[i], argv_len);
      argv_address[i] = (uint32_t)*esp;
    }

    /* Word align the stack */
    word_align(esp);

    /* push addresses where argument values are present onto stack */
    for(i=argc; i>=0; i--)
    {
      *esp = *esp - (sizeof argv_address[i]);
      *(uint32_t*)*esp = argv_address[i];
    }

    /* push address to argv[0], argc value and return address to stack */
    uint32_t old_address = (uint32_t)*esp;
    *esp = *esp - (sizeof old_address);
    *(uint32_t*)*esp = old_address;
    *esp = *esp - (sizeof argc);
    *(uint32_t*)*esp = argc;

    push_dummy_return_value(esp);
  }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
