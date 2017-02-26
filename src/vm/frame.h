#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/palloc.h"

struct list frame_table;       /* Frame table which is a list of frames in use */
struct list_elem *clock_hand;  /* Clock hand which points to an element in frame_table list */

struct frame_table_entry
  {
    struct spage_table_entry *spte; /* spte of user virtual address which the frame corresponds to currently */
    struct list_elem elem;          /* list element to add to frame_table list */
    struct thread *thread;          /* thread of user virtual address which the frame corresponds to currently */
    void* kvaddr;                   /* kernel virtual address of this frame */
  };

void frame_table_init(void);

// synchronization api
void frame_lock_acquire(void);
void frame_lock_release(void);

void* frame_get_page(enum palloc_flags flags, struct spage_table_entry *spte);
void frame_free_page(struct spage_table_entry *spte);
void * frame_get_kpage(struct spage_table_entry *spte);

#endif
