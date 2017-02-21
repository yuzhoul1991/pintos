#include <debug.h>
#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"

// lock for frame allocator
static struct lock lock;

void
frame_lock_acquire()
{
  lock_acquire(&lock);
}

void
frame_lock_release()
{
  lock_release(&lock);
}

void
frame_table_init()
{
  lock_init(&lock);
  list_init(&frame_table);
  clock_hand = NULL;
}

static struct frame_table_entry *
frame_eviction(void)
{
  struct frame_table_entry *evicted_frame = NULL;
  while(clock_hand)
  {
    if(list_next(clock_hand) == list_tail(&frame_table))
      clock_hand = list_begin(&frame_table);
    else
      clock_hand = list_next(clock_hand);

    struct frame_table_entry *potential_frame = list_entry (clock_hand, struct frame_table_entry, elem);
    lock_acquire(&potential_frame->spte->entry_lock);
    enum intr_level old_level;
    old_level = intr_disable ();
    if(pagedir_is_accessed(potential_frame->thread->pagedir, potential_frame->spte->uvaddr))
      pagedir_set_accessed(potential_frame->thread->pagedir, potential_frame->spte->uvaddr, false);
    else
    {
      if(!potential_frame->spte->pinned)
      {
        evicted_frame = potential_frame;
        break;
      }
    }

    intr_set_level (old_level);
    lock_release(&potential_frame->spte->entry_lock);
  }

  if(evicted_frame)
  {
    lock_acquire(&evicted_frame->spte->entry_lock);
    enum intr_level old_level;
    old_level = intr_disable ();

    if(pagedir_is_dirty(evicted_frame->thread->pagedir, evicted_frame->spte->uvaddr))
    {
      if(evicted_frame->spte->type == SPTE_MMAP)
      {
          filesys_lock ();
          file_seek (evicted_frame->spte->file, evicted_frame->spte->offset);
          filesys_unlock ();
          /* Write mmaped file. */
          filesys_lock ();
          off_t bytes_write = file_write (evicted_frame->spte->file, evicted_frame->kvaddr, PGSIZE);
          filesys_unlock ();
          if (bytes_write != PGSIZE)
            PANIC ("page_free_vaddr: Not writing PGSIZE dirty bytes to file");
        }
      else
      {
        evicted_frame->spte->type = SPTE_SWAP;
        evicted_frame->spte->swap_idx = swap_get_idx();
        //FIXME
        swap_write_idx(evicted_frame->spte->swap_idx, evicted_frame->kvaddr);
      }
    }
    pagedir_clear_page(evicted_frame->thread->pagedir, evicted_frame->spte->uvaddr);

    intr_set_level (old_level);
    lock_release(&evicted_frame->spte->entry_lock);
  }
  
  return evicted_frame;
}

void *
frame_get_page(enum palloc_flags flags, struct spage_table_entry *spte)
{
  struct thread* t_current = thread_current ();
  void * kpage;

  frame_lock_acquire ();
  kpage = palloc_get_page (flags);
  if (kpage == NULL)
    {
      struct frame_table_entry *evicted_fte = frame_eviction();
      if(evicted_fte)
      {
        evicted_fte->spte = spte;
        evicted_fte->touched_by_hand = false;
        evicted_fte->thread = t_current;
      }
    }
  else
   {
     struct frame_table_entry *new_fte = malloc(sizeof(struct frame_table_entry));
     if (new_fte == NULL)
       PANIC ("frame table entry malloc failed!");

     new_fte->spte = spte;
     new_fte->touched_by_hand = false;
     new_fte->thread = t_current;
     new_fte->kvaddr = kpage;
     if(list_empty(&frame_table))
       list_push_back (&frame_table, &new_fte->elem);
     else
       list_insert(list_next(clock_hand), &new_fte->elem);
     clock_hand = &new_fte->elem;
   }


  frame_lock_release ();
  return kpage;
}

void
frame_free_page(struct spage_table_entry *spte)
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

  /* If clock_hand == the element to remove 
     [H]->[F0]->[F1]->[F2]->[T] , clock_hand = [F1] ---(point to next)---> clock_hand = [F2]
     [H]->[F0]->[F1]->[F2]->[T] , clock_hand = [F2] ---(wrap around)---> clock_hand = [F0]
  */
  if(clock_hand == &to_free->elem)
  {
    if(list_size(&frame_table) == 1)
      clock_hand = NULL;
    else
    {
      if(list_next(clock_hand) == list_tail(&frame_table))
        clock_hand = list_begin (&frame_table);
      else
        clock_hand = list_next (&to_free->elem);
    }
  }

  ASSERT (to_free != NULL);
  if (to_free != NULL)
  {
    list_remove (&to_free->elem);
    palloc_free_page (to_free->kvaddr);
    free (to_free);
  }
  frame_lock_release ();
}

void *
frame_get_kpage(struct spage_table_entry *spte)
{
  struct list_elem *e;
  struct frame_table_entry *fte = NULL;
  bool found = true;

  frame_lock_acquire ();
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    fte = list_entry (e, struct frame_table_entry, elem);
    if (fte->spte == spte)
    {
      found = true;
      break;
    }
  }
  frame_lock_release ();

  if(!found)
    PANIC ("frame table entry not found for a valid SPTE");

  return fte->kvaddr;
}
