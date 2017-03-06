#include <debug.h>
#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"

// lock for frame allocator
static struct lock lock;

/* Acquires frame lock */
void
frame_lock_acquire()
{
  lock_acquire(&lock);
}

/* Releases frame lock */
void
frame_lock_release()
{
  lock_release(&lock);
}

/* Initializes frame_table list, frame lock and clock_hand */
void
frame_table_init()
{
  lock_init(&lock);
  list_init(&frame_table);
  clock_hand = NULL;
}

/* Function which does the eviction process. Pick a suitable frame based on clock algorithm */
static struct frame_table_entry *
frame_eviction(void)
{
  struct frame_table_entry *evicted_frame = NULL;
  while(clock_hand)
  {
    /* Move clock_hand to next frame. Includes wrap around to frame int he head of frame_table */
    if(list_next(clock_hand) == list_tail(&frame_table))
      clock_hand = list_begin(&frame_table);
    else
      clock_hand = list_next(clock_hand);

    struct frame_table_entry *potential_frame = list_entry (clock_hand, struct frame_table_entry, elem);
    lock_acquire(&potential_frame->spte->entry_lock);
    enum intr_level old_level;
    old_level = intr_disable ();
    /* If the frame is accessed, then clear it so that we can atleast pick it in 2nd round */
    if(pagedir_is_accessed(potential_frame->thread->pagedir, potential_frame->spte->uvaddr))
      pagedir_set_accessed(potential_frame->thread->pagedir, potential_frame->spte->uvaddr, false);
    else
    {
      /* If the frame is not accessed and is not pinned then pick it for eviction. */
      if(!potential_frame->spte->pinned)
        evicted_frame = potential_frame;
    }

    intr_set_level (old_level);
    lock_release(&potential_frame->spte->entry_lock);

    if(evicted_frame != NULL)
      break;
  }

  if(evicted_frame)
  {
    lock_acquire(&evicted_frame->spte->entry_lock);
    enum intr_level old_level;
    old_level = intr_disable ();

    /* If picked frame is dirty then copy it to swap or file. */
    if(pagedir_is_dirty(evicted_frame->thread->pagedir, evicted_frame->spte->uvaddr))
    {
      /* Clear page table entry corresponding to picked frame's user vaddr */
      pagedir_clear_page(evicted_frame->thread->pagedir, evicted_frame->spte->uvaddr);
      intr_set_level (old_level);
      /* If frame to be evicted is a MMAP then copy to the file it corresponds to. */
      if(evicted_frame->spte->type == SPTE_MMAP)
      {
          filesys_lock ();
          file_seek (evicted_frame->spte->file, evicted_frame->spte->offset);
          filesys_unlock ();
          /* Write mmaped file. */
          filesys_lock ();
          off_t bytes_write = file_write (evicted_frame->spte->file, evicted_frame->kvaddr, PGSIZE, false);
          filesys_unlock ();
          if (bytes_write != PGSIZE)
            PANIC ("page_free_vaddr: Not writing PGSIZE dirty bytes to file");
        }
      else
      {
        /* If frame to be evicted is not MMAP then copy to swap file and store swap's sector */
        evicted_frame->spte->type = SPTE_SWAP;
        evicted_frame->spte->swap_idx = swap_get_idx();
        
        swap_write_idx(evicted_frame->spte->swap_idx, evicted_frame->kvaddr);
      }
    }
    else
    {
      /* Clear page table entry corresponding to picked frame's user vaddr */
      pagedir_clear_page(evicted_frame->thread->pagedir, evicted_frame->spte->uvaddr);
      intr_set_level (old_level);
    }

    lock_release(&evicted_frame->spte->entry_lock);
  }
  
  return evicted_frame;
}

/* Gets a frame for supplementry page table entry corresponding to user vaddr */
void *
frame_get_page(enum palloc_flags flags, struct spage_table_entry *spte)
{
  struct thread* t_current = thread_current ();
  void * kpage;

  frame_lock_acquire ();
  /* Try to get a frame from palloc */
  kpage = palloc_get_page (flags);
  if (kpage == NULL)
    {
      /* If palloc is unsucessfull then try eviction logic to get a frame.
         Update the picked frame's thread pointer and spte pointer. */
      struct frame_table_entry *evicted_fte = frame_eviction();
      if(evicted_fte)
      {
        evicted_fte->spte = spte;
        evicted_fte->thread = t_current;
        kpage = evicted_fte->kvaddr;
      }
    }
  else
   {
     /* If palloc is sucessfull then malloc a frame table entry.
         Update the new frame's thread pointer and spte pointer. */
     struct frame_table_entry *new_fte = malloc(sizeof(struct frame_table_entry));
     if (new_fte == NULL)
       PANIC ("frame table entry malloc failed!");

     new_fte->spte = spte;
     new_fte->thread = t_current;
     new_fte->kvaddr = kpage;
     /* Insert the new element next to clock_hand. Update clock_hand to point to new element.*/
     if(list_empty(&frame_table))
       list_push_back (&frame_table, &new_fte->elem);
     else
       list_insert(list_next(clock_hand), &new_fte->elem);
     clock_hand = &new_fte->elem;
   }


  frame_lock_release ();
  return kpage;
}

/* If a frame is assigned to spte(corresponding to user vaddr), then free the frame and add it to palloc user pool. */
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
     [H]->[F0]->[F1]->[F2]->[T] , clock_hand = [F1] ---(point to next)---> clock_hand = [F0]
     [H]->[F0]->[F1]->[F2]->[T] , clock_hand = [F0] ---(wrap around)---> clock_hand = [F2]
  */
  if(clock_hand == &to_free->elem)
  {
    if(list_size(&frame_table) == 1)
      clock_hand = NULL;
    else
    {
      if(clock_hand == list_begin(&frame_table))
        clock_hand = list_prev (list_end (&frame_table));
      else
        clock_hand = list_prev (&to_free->elem);
    }
  }

  if (to_free != NULL)
  {
    list_remove (&to_free->elem);
    palloc_free_page (to_free->kvaddr);
    free (to_free);
  }
  frame_lock_release ();
}

/* Get the frame corresponding to spte. */
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
