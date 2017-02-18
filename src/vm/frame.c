#include <debug.h>
#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"

// lock for frame allocator
static struct lock lock;

void frame_lock_acquire()
{
  lock_acquire(&lock);
}

void frame_lock_release()
{
  lock_release(&lock);
}

void frame_table_init()
{
  lock_init(&lock);
  list_init(&frame_table);
}

void * frame_get_page(enum palloc_flags flags, struct spage_table_entry *spte)
{
  struct thread* t_current = thread_current ();
  struct frame_table_entry *new_fte = malloc(sizeof(struct frame_table_entry));
  if (new_fte == NULL)
    PANIC ("frame table entry malloc failed!");

  new_fte->spte = spte;
  new_fte->touched_by_hand = false;
  new_fte->thread = t_current;
  new_fte->kvaddr = palloc_get_page (flags);
  if (new_fte->kvaddr == NULL)
    {
      free (new_fte);
      // FIXME: implement eviction here
      PANIC ("No physical memory available, eviction not implemented yet!");
    }

  frame_lock_acquire ();
  list_push_back (&frame_table, &new_fte->elem);
  frame_lock_release ();
  return new_fte->kvaddr;
}

void frame_free_page(struct spage_table_entry *spte)
{
  struct list_elem *e;
  struct frame_table_entry *to_free = NULL;

  frame_lock_acquire ();
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_table_entry *fte = list_entry (e, struct frame_table_entry, elem);
    if (fte->spte == spte)
    {
      to_free = fte;
      break;
    }
  }
  list_remove (&to_free->elem);
  frame_lock_release ();
  palloc_free_page (to_free->kvaddr);
  free (to_free);
}
