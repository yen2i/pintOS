#include "vm/page.h"
#include <stdlib.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/interrupt.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include <string.h>
#include "threads/palloc.h" 

static unsigned spt_hash(const struct hash_elem *e, void *aux UNUSED);
static bool spt_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void spt_free_entry(struct hash_elem *e, void *aux UNUSED);

void spt_create(struct thread *t) {
  hash_init(&t->page_map, spt_hash, spt_less, NULL);
}

void spt_destroy(struct thread *t) {
  hash_destroy(&t->page_map, spt_free_entry);  // 🔧 메모리 해제 함수 연결!
}

struct supplemental_page_table_entry *spt_lookup(struct thread *t, void *upage) {
  struct supplemental_page_table_entry spt;
  spt.upage = pg_round_down(upage);

  struct hash_elem *e = hash_find(&t->page_map, &spt.elem);
  if (e != NULL)
    return hash_entry(e, struct supplemental_page_table_entry, elem);
  return NULL;
}

// 🔧 메모리 해제 함수
static void spt_free_entry(struct hash_elem *e, void *aux UNUSED) {
  struct supplemental_page_table_entry *spte = hash_entry(e, struct supplemental_page_table_entry, elem);
  free(spte);
}

// 해시 함수
static unsigned spt_hash(const struct hash_elem *e, void *aux UNUSED) {
  const struct supplemental_page_table_entry *spte = hash_entry(e, struct supplemental_page_table_entry, elem);
  return hash_bytes(&spte->upage, sizeof spte->upage);
}

// 비교 함수
static bool spt_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct supplemental_page_table_entry *spa = hash_entry(a, struct supplemental_page_table_entry, elem);
  const struct supplemental_page_table_entry *spb = hash_entry(b, struct supplemental_page_table_entry, elem);
  return spa->upage < spb->upage;
}

bool
vm_try_handle_fault(struct intr_frame *f, void *addr, bool write, bool user UNUSED) {
  struct thread *t = thread_current();
  void *upage = pg_round_down(addr);
  struct supplemental_page_table_entry *s = spt_lookup(t, upage);

  if (s == NULL) {
    // ✅ 스택 자동 성장 조건
    if ((uint8_t *)addr >= (uint8_t *)f->esp - 32 &&
        (uint8_t *)PHYS_BASE - (uint8_t *)upage <= (1 << 20)) {
      vm_stack_growth(addr);
      return true;
    }
    return false;
  }

  if (write && !s->writable)
    return false;

  return vm_do_claim_page(s);
}

bool
vm_do_claim_page(struct supplemental_page_table_entry *s) {
  void *kpage = frame_allocate(PAL_USER, s->upage);
  if (kpage == NULL)
    return false;

  s->kpage = kpage;
  s->status = ON_FRAME;

  switch (s->status) {
    case ALL_ZERO:
      memset(kpage, 0, PGSIZE);
      break;

    case ON_SWAP:
      vm_swap_in(s->swap_index, kpage);
      break;

    case FROM_FILESYS:
      if (file_read_at(s->file, kpage, s->read_bytes, s->file_offset) != (int)s->read_bytes) {
        frame_free(kpage);
        return false;
      }
      memset(kpage + s->read_bytes, 0, s->zero_bytes);
      break;

    default:
      PANIC("vm_do_claim_page: unknown page status");
  }

  if (!install_page(s->upage, kpage, s->writable)) {
    frame_free(kpage);
    return false;
  }

  return true;
}
  void
  vm_stack_growth(void *addr) {
    void *upage = pg_round_down(addr);
    if (vm_alloc_page(PAL_USER | PAL_ZERO, upage, true)) {
      vm_claim_page(upage);
    }
  }

bool
vm_alloc_page(enum palloc_flags flags, void *upage, bool writable) {
  upage = pg_round_down(upage);

  struct supplemental_page_table_entry *s = spt_lookup(thread_current(), upage);
  if (s != NULL)
    return false;

  s = malloc(sizeof(struct supplemental_page_table_entry));
  if (s == NULL)
    return false;

  s->upage = upage;
  s->kpage = NULL;
  s->status = ALL_ZERO;
  s->writable = writable;

  hash_insert(&thread_current()->page_map, &s->elem);
  return true;
}

bool
vm_claim_page(void *upage) {
  upage = pg_round_down(upage);
  struct supplemental_page_table_entry *s = spt_lookup(thread_current(), upage);
  if (s == NULL)
    return false;

  return vm_do_claim_page(s);
}
