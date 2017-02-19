#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/palloc.h"

struct list frame_table;

struct frame_table_entry
  {
    struct spage_table_entry *spte;
    struct list_elem elem;
    struct thread *thread;
    bool touched_by_hand;
    void* kvaddr;
  };

void frame_table_init(void);

// synchronization api
void frame_lock_acquire(void);
void frame_lock_release(void);

void* frame_get_page(enum palloc_flags flags, struct spage_table_entry *spte);
void frame_free_page(struct spage_table_entry *spte);
void * frame_get_kpage(struct spage_table_entry *spte);

#endif
