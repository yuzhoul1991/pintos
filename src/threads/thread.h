#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <hash.h>
#include <stdint.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "devices/block.h"

/* Struct which stores relevant file info */
struct file_info
  {
    int fd;                      /* fd of the opened file */
    struct file *file_ptr;       /* pointer to the file opened */
    struct list_elem file_elem;  /* List element for fd_list list. */
    uint32_t type; //0:file , 1: directory

  };

typedef int mapid_t;
/* Struct which stores relevant mmap info */
struct mmap_info
  {
    mapid_t mapid;               /* mapid of the mmap */
    struct file *file_ptr;       /* pointer to the file mmaped */
    void* vaddr_start;           /* Start virtual address of mmap */
    void* vaddr_end;             /* End virtual address of mmap */
    size_t mmap_size;            /* size of file mmaped */
    struct list_elem mmap_elem;  /* List element for mmap_list list. */

  };

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Struct which stores child process's info*/
struct child_info
  {
   tid_t tid;                        /* tid of the child process */
   bool loaded;                      /* Indicates if the child process loaded succesfully*/
   int exit_status;                  /* Indicates if the child process exit status */
   struct thread *child_thread;      /* Reference to child thread struct */
   struct list_elem child_elem;      /* List element for child_list */
   struct semaphore sema_load;        /* Semaphore to wait for to get updated loaded value */
   struct semaphore sema_exit;        /* Semaphore to wait for to get updated exit_status value */
  };

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                    /* Page directory. */
    void* code_seg_start;                 /* Start vaddr of code_segment*/
    void* code_seg_end;                   /* End vaddr of code_segment*/
    void* data_seg_start;                 /* Start vaddr of data_segment*/
    void* data_seg_end;                   /* End vaddr of data_segment*/
    void* stack_start;                    /* Start vaddr of stack_segment*/
    void* stack_end;                      /* End vaddr of stack_segment*/
    int total_mmaps;                      /* Total mmaps opened by current process */
    struct list mmap_list;                /* List of opened mmaps */
    int total_fds;                        /* Total fds opened by current process */
    struct list fd_list;                  /* List of opened files */
    struct list child_list;               /* List of all child process */
    struct child_info* recent_child;      /* Pointer to thread's recent child process forked */
    struct child_info* parent_child_info; /* If this Process is a child, Pointer to child_info about itself stored in parent's child_list*/
    struct file *executable;              /* pointer to struct file of executable */
    char process_name[15];                /* Name of the process given passed in process_execute. */
    int exit_status;                      /* Exit status of the thread */
    struct hash spage_table;              /* Per process suplimental page table */
#endif

    struct list_elem *cond_waiter_elem;       /* When thread waits on a condition, this points to list_elem of thread's semaphore_elem */

    int64_t end_tick;                   /*Absolute tick value for threads which run timer_sleep to come out of sleep */

     /* for directories */
     block_sector_t cwd_sector_number; //  current working directory sector number can be used for figuringout inode

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

struct list_elem *thread_find_fd(struct thread *t, int fd);
struct list_elem *thread_find_mmap(struct thread *t, int fd);

void thread_munmap(struct mmap_info *m_info);
void thread_set_sector (block_sector_t sector);
block_sector_t thread_get_sector (void);
bool thread_find_current_dir (block_sector_t sector);
void thread_set_end_tick (int64_t ticks);
void thread_push_timer_sleep_waitlist (void);
void thread_check_timer_sleep_waitlist (void);

#endif /* threads/thread.h */
