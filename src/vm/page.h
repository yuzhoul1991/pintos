#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/vaddr.h"
#include "threads/thread.h"
#include "kernel/hash.h"
#include "filesys/off_t.h"

#define MAX_STACKSIZE 8 * 1024 * 1024
#define STACK_LIMIT (uint32_t)(PHYS_BASE - MAX_STACKSIZE)
#define STACK_REACH_LIMIT 32

#define SPTE_FILE 0x1
#define SPTE_SWAP 0x2
#define SPTE_MMAP 0x4

struct spage_table_entry
  {
    struct file *file;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    off_t offset;
    uint8_t type;
    void* uvaddr;
    bool writable;
    struct hash_elem elem;
  };

void page_init(struct thread* t);
void page_free(struct thread* t);

// grow the stack by one page in which the faulted uvaddr is located
bool grow_stack(void* uvaddr);

// find the corresponding spte from spage_table with faulted address
struct spage_table_entry* page_get_spte(void *fault_addr);

bool page_add_file(uint8_t *upage, struct file *file, off_t ofs, uint32_t read_bytes,
                   uint32_t zero_bytes, bool writable);

bool page_load_from_file(struct spage_table_entry *spte);

#endif
