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

struct spage_table_entry
  {
    struct file *file;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    off_t offset;
    uint8_t type;           /* type can be modified by other threads during eviction. Read or write of this should have pinned=true */
    void* uvaddr;
    bool writable;
    bool pinned;
    struct lock entry_lock;
    struct hash_elem elem;
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
void page_pin(struct spage_table_entry *spte);
void page_unpin(struct spage_table_entry *spte);
bool page_get_pinned(struct spage_table_entry *spte);
void page_free_vaddr(void *vaddr);

#endif
