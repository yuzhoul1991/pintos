#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"

static unsigned
spage_hash_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry (e, struct spage_table_entry, elem);
  return hash_int((int)spte->uvaddr);
}

static bool
spage_hash_less_func (const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux UNUSED)
{
  struct spage_table_entry *spte_a = hash_entry (a, struct spage_table_entry, elem);
  struct spage_table_entry *spte_b = hash_entry (b, struct spage_table_entry, elem);
  if (spte_a->uvaddr < spte_b->uvaddr)
    return true;
  return false;
}

static void
spage_free_hash_action_func (struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry (e, struct spage_table_entry, elem);
  struct thread *t = thread_current ();
  hash_delete (&t->spage_table, &spte->elem);
  free (spte);
}

void
page_init(struct thread *t)
{
  hash_init (&t->spage_table, spage_hash_hash_func, spage_hash_less_func, NULL);
}

void
page_free(struct thread *t)
{
  hash_destroy(&t->spage_table, spage_free_hash_action_func);
}

/* Grow the stack to user vaddr */
bool
grow_stack(void* uvaddr)
{
  if ((uint32_t)(pg_round_down(uvaddr)) < STACK_LIMIT)
    {
      return false;
    }

  struct thread * t_current = thread_current ();
  void * this_page_start = pg_round_down (uvaddr);

  while (t_current->stack_start > this_page_start)
    {
      ASSERT (pg_ofs(t_current->stack_start) == 0);

      t_current->stack_start -= PGSIZE;
      struct spage_table_entry *new_spte = malloc (sizeof(struct spage_table_entry));
      if (new_spte == NULL)
        return false;

      new_spte->file = NULL;
      new_spte->read_bytes = 0;
      new_spte->zero_bytes = 0;
      new_spte->offset = 0;
      new_spte->type = SPTE_ZERO;
      new_spte->swap_idx = 0;
      new_spte->uvaddr = t_current->stack_start;
      new_spte->writable = true;
      new_spte->pinned = true;
      lock_init(&new_spte->entry_lock);

      // only allocate physical page for this page
      if (t_current->stack_start == this_page_start)
        {
          // Ask the frame allocator for a new physical page
          uint8_t *kpage = frame_get_page(PAL_USER | PAL_ZERO, new_spte);
          if (kpage == NULL)
            {
              free (new_spte);
              return false;
            }

          // Successfully got a physical page install the page
          if (!install_page(new_spte->uvaddr, kpage, true))
            {
              frame_free_page(new_spte);
              free (new_spte);
              return false;
            }

          memset (kpage, 0, PGSIZE);
        }
      hash_insert (&t_current->spage_table, &new_spte->elem);

      page_unpin(new_spte);
    }

  return true;
}

/* Get the spte corresponding to a user vaddr */
struct spage_table_entry*
page_get_spte(void* fault_addr)
{
  struct spage_table_entry probe;
  struct thread *t_current = thread_current ();
  probe.uvaddr = pg_round_down(fault_addr);
  struct hash_elem *e = hash_find (&t_current->spage_table, &probe.elem);
  if (e == NULL)
    return NULL;
  return hash_entry (e, struct spage_table_entry, elem);
}

/* Create spte entries corresponding to upage. Associate it with a file and store read_bytes, zero_bytes */
bool
page_add_file(uint8_t *upage, struct file *file, off_t ofs, uint32_t read_bytes,
                   uint32_t zero_bytes, bool writable, bool mmaped)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs(upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread* t_current = thread_current ();
  struct spage_table_entry *new_spte = malloc (sizeof(struct spage_table_entry));
  if (new_spte == NULL)
    return false;

  new_spte->file = file;
  new_spte->read_bytes = read_bytes;
  new_spte->zero_bytes = zero_bytes;
  new_spte->offset = ofs;
  new_spte->type = mmaped? SPTE_MMAP: SPTE_FILE;
  new_spte->swap_idx = 0;
  new_spte->uvaddr = upage;
  new_spte->writable = writable;
  new_spte->pinned = false;
  lock_init(&new_spte->entry_lock);

  hash_insert (&t_current->spage_table, &new_spte->elem);
  return true;
}

/* For a page faulting stack user vaddr: Get a frame, fill it with 0s and map it to page table */
bool
page_load_for_stack(struct spage_table_entry *spte)
{
  ASSERT (spte != NULL);

  struct thread* t_current = thread_current ();

  uint8_t *kpage = frame_get_page(PAL_USER | PAL_ZERO, spte);
  if (kpage == NULL)
    {
      hash_delete (&t_current->spage_table, &spte->elem);
      free (spte);
      return false;
    }

  if (!install_page(spte->uvaddr, kpage, true))
    {
      frame_free_page(spte);
      hash_delete (&t_current->spage_table, &spte->elem);
      free (spte);
      return false;
    }

  memset (kpage, 0, PGSIZE);

  page_unpin(spte);
  return true;
}

/* For a page faulting user vaddr with data in file: Get a frame, fill it with reads from file and map it to page table */
bool
page_load_from_file(struct spage_table_entry *spte)
{
  ASSERT (spte != NULL);

  /* Calculate how to fill this page.
     We will read PAGE_READ_BYTES bytes from FILE
     and zero the final PAGE_ZERO_BYTES bytes. */
  size_t page_read_bytes = spte->read_bytes;
  size_t page_zero_bytes = spte->zero_bytes;

  uint8_t *kpage = frame_get_page(PAL_USER, spte);
  if (kpage == NULL)
    PANIC ("No frames available even after implementing eviction");

  /* entire page is zero, no need to read from disk */
  if (page_zero_bytes == PGSIZE)
    {
      memset (kpage, 0, PGSIZE);
    }
  else
    {
      filesys_lock ();
      file_seek (spte->file, spte->offset);
      filesys_unlock ();
      /* Load this page. */
      filesys_lock ();
      off_t bytes_read = file_read (spte->file, kpage, page_read_bytes, false);
      filesys_unlock ();
      if (bytes_read != (int) page_read_bytes)
        {
          frame_free_page (spte);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
    }

  /* Add the page to the process's address space. */
  if (!install_page (spte->uvaddr, kpage, spte->writable))
    {
      frame_free_page (spte);
      return false;
    }

  return true;
}

/* For a page faulting user vaddr with data in swap: Get a frame, fill it with reads from swap, free swap slot and map it to page table */
bool
page_load_from_swap(struct spage_table_entry *spte)
{
  ASSERT (spte != NULL);

  struct thread *t = thread_current ();
  uint8_t *kpage = frame_get_page(PAL_USER, spte);
  if (kpage == NULL)
    PANIC ("No frames available even after implementing eviction");


  /* Add the page to the process's address space. */
  if (!install_page (spte->uvaddr, kpage, spte->writable))
    {
      frame_free_page (spte);
      return false;
    }
  pagedir_set_dirty(t->pagedir, spte->uvaddr, true);

  swap_read_idx(spte->swap_idx, kpage);
  swap_release_idx(spte->swap_idx);

  return true;
}

/* Pin a user vaddr */
void
page_pin(struct spage_table_entry *spte)
{
  lock_acquire(&spte->entry_lock);
  spte->pinned = true;
  lock_release(&spte->entry_lock);
}

/* UnPin a user vaddr */
void
page_unpin(struct spage_table_entry *spte)
{
  lock_acquire(&spte->entry_lock);
  spte->pinned = false;
  lock_release(&spte->entry_lock);
}

/* Get pinned of a user vaddr */
bool
page_get_pinned(struct spage_table_entry *spte)
{
  bool pin = false;
  lock_acquire(&spte->entry_lock);
  pin = spte->pinned;
  lock_release(&spte->entry_lock);
  return pin;
}

/* Free a user vaddr */
void
page_free_vaddr(void *vaddr, size_t write_bytes UNUSED)
{
  struct spage_table_entry *spte = page_get_spte(vaddr);
  if(spte)
  {
    struct thread *t = thread_current ();

    page_pin(spte);

    /* If user vaddr is in page_table and dirty. Store in file for mmaped vaddr. */
    if(pagedir_get_page (t->pagedir, vaddr) != NULL)
    {
      //When freeing vaddr, Only MMAP has to writeback to file
      if(spte->type == SPTE_MMAP)
      {

        if(pagedir_is_dirty(t->pagedir, vaddr))
        {
          filesys_lock ();
          file_seek (spte->file, spte->offset);
          filesys_unlock ();
          /* Write mmaped file. */
          uint8_t *kpage = frame_get_kpage(spte);
          filesys_lock ();
          file_write (spte->file, kpage, write_bytes, false);
          filesys_unlock ();
        }

      }
      frame_free_page(spte);
      pagedir_clear_page(t->pagedir, vaddr);
    }
    else
    {
      //When freeing vaddr, If vaddr has no frame, only SWAP needs to be reased.
      if(spte->type == SPTE_SWAP)
        swap_release_idx(spte->swap_idx);
    }

    page_unpin(spte);

    hash_delete (&t->spage_table, &spte->elem);
    free(spte);
  }
}
