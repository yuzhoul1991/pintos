#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"

static unsigned spage_hash_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry (e, struct spage_table_entry, elem);
  return hash_int((int)spte->uvaddr);
}

static bool spage_hash_less_func (const struct hash_elem *a,
                                  const struct hash_elem *b,
                                  void *aux UNUSED)
{
  struct spage_table_entry *spte_a = hash_entry (a, struct spage_table_entry, elem);
  struct spage_table_entry *spte_b = hash_entry (b, struct spage_table_entry, elem);
  if (spte_a->uvaddr < spte_b->uvaddr)
    return true;
  return false;
}

static void spage_free_hash_action_func (struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry (e, struct spage_table_entry, elem);
  free (spte);
}

void page_init(struct thread *t)
{
  hash_init (&t->spage_table, spage_hash_hash_func, spage_hash_less_func, NULL);
}

void page_free(struct thread *t)
{
  hash_destroy(&t->spage_table, spage_free_hash_action_func);
}

bool grow_stack(void* uvaddr)
{
  if ((uint32_t)(pg_round_down(uvaddr)) < STACK_LIMIT)
    {
      return false;
    }

  struct thread * t_current = thread_current ();
  struct spage_table_entry *new_spte = malloc (sizeof(struct spage_table_entry));
  if (new_spte == NULL)
    return false;

  new_spte->file = NULL;
  new_spte->read_bytes = 0;
  new_spte->zero_bytes = 0;
  new_spte->offset = 0;
  new_spte->type = SPTE_SWAP;
  new_spte->uvaddr = pg_round_down(uvaddr);
  new_spte->writable = true;

  // Ask the frame allocator for a new physical page
  uint32_t *kpage = (uint32_t*)frame_get_page(PAL_USER | PAL_ZERO, new_spte);
  if (kpage == NULL)
    {
      free (new_spte);
      return false;
    }

  // Successfully got a physical page install the page
  if (!install_page(new_spte->uvaddr, kpage, true))
    {
      free (new_spte);
      return false;
    }

  hash_insert (&t_current->spage_table, &new_spte->elem);
  return true;
}

struct spage_table_entry* page_get_spte(void* fault_addr)
{
  struct spage_table_entry probe;
  struct thread *t_current = thread_current ();
  probe.uvaddr = pg_round_down(fault_addr);
  struct hash_elem *e = hash_find (&t_current->spage_table, &probe.elem);
  if (e == NULL)
    return NULL;
  return hash_entry (e, struct spage_table_entry, elem);
}

bool page_add_file(uint8_t *upage, struct file *file, off_t ofs, uint32_t read_bytes,
                   uint32_t zero_bytes, bool writable)
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
  new_spte->type = SPTE_FILE;
  new_spte->uvaddr = upage;
  new_spte->writable = writable;

  hash_insert (&t_current->spage_table, &new_spte->elem);
  return true;
}

bool page_load_from_file(struct spage_table_entry *spte)
{
  ASSERT (spte != NULL);

  /* Calculate how to fill this page.
     We will read PAGE_READ_BYTES bytes from FILE
     and zero the final PAGE_ZERO_BYTES bytes. */
  size_t page_read_bytes = spte->read_bytes;
  size_t page_zero_bytes = spte->zero_bytes;

  uint32_t *kpage = (uint32_t*)frame_get_page(PAL_USER, spte);
  if (kpage == NULL)
    // FIXME: what to do with the spte? leave it alone and try again next time it faults?
    return false;

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
      off_t bytes_read = file_read (spte->file, kpage, page_read_bytes);
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
