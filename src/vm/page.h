#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "kernel/hash.h"
#include "filesys/off_t.h"

#define MAX_STACKSIZE 8 * 1024 * 1024
#define STACK_LIMIT (uint32_t)(PHYS_BASE - MAX_STACKSIZE)
#define STACK_REACH_LIMIT 32

#define SPTE_FILE 0x1
#define SPTE_SWAP 0x2
#define SPTE_MMAP 0x4
#define SPTE_ZERO 0x8

#define FREE_UVADDR_WRITE_ZERO 0

struct spage_table_entry
  {
    struct file *file;      /* File pointer to spte associated with a file */
    uint32_t read_bytes;    /* Number of actual bytes to read from file for spte associated with a file */
    uint32_t zero_bytes;    /* Number of zero bytes to fill page for spte associated with a file */
    off_t offset;           /* Offset from file for spte associated with a file */
    uint8_t type;           /* type can be modified by other threads during eviction. Read or write of this should have pinned=true */
    uint32_t swap_idx;      /* swap index which corresponds to swap sector for spte associated with swap */
    void* uvaddr;           /* user virtual address corresponding to this spte */
    bool writable;          /* Indicates if user page is writable or not */
    bool pinned;            /* Indicates if the user page is pinned or not */
    struct lock entry_lock; /* lock corresponding to this spte */
    struct hash_elem elem;  /* hash elem to add to spte hash */
  };

void page_init(struct thread* t);
void page_free(struct thread* t);

// grow the stack by one page in which the faulted uvaddr is located
bool grow_stack(void* uvaddr);

// find the corresponding spte from spage_table with faulted address
struct spage_table_entry* page_get_spte(void *fault_addr);

bool page_add_file(uint8_t *upage, struct file *file, off_t ofs, uint32_t read_bytes,
                   uint32_t zero_bytes, bool writable, bool mmaped);

bool page_load_from_file(struct spage_table_entry *spte);
bool page_load_from_swap(struct spage_table_entry *spte);
bool page_load_for_stack(struct spage_table_entry *spte);
void page_pin(struct spage_table_entry *spte);
void page_unpin(struct spage_table_entry *spte);
bool page_get_pinned(struct spage_table_entry *spte);
void page_free_vaddr(void *vaddr, size_t write_bytes);

#endif
