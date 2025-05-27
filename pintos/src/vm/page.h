#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "devices/block.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "vm/swap.h"
#include "threads/interrupt.h"

enum page_status {
  ALL_ZERO,
  ON_FRAME,
  ON_SWAP,
  FROM_FILESYS
};

struct supplemental_page_table_entry {
  void *upage;
  void *kpage;
  struct hash_elem elem;
  enum page_status status;
  swap_index_t swap_index;
  bool dirty;
  struct file *file;
  off_t file_offset;
  uint32_t read_bytes, zero_bytes;
  bool writable;
};

// ✅ 선언 꼭 있어야 하는 함수들
bool vm_alloc_page(enum palloc_flags flags, void *upage, bool writable);
bool vm_claim_page(void *upage); // ✅ 이게 없으면 undefined 발생
bool vm_do_claim_page(struct supplemental_page_table_entry *s);
void vm_stack_growth(void *addr);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool write, bool user);

void spt_create(struct thread *t);
void spt_destroy(struct thread *t);
struct supplemental_page_table_entry *spt_lookup(struct thread *t, void *upage);

#endif
