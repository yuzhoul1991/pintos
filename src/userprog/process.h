#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/user/syscall.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
pid_t process_wait_for_load (tid_t);
void process_update_exit_status(int status);
void process_exit (void);
void process_activate (void);
struct child_info* process_get_child_info(tid_t id);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
