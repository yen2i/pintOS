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
#include "vm/frame.h"        // 🔧 frame_allocate, frame_free


static unsigned spt_hash(const struct hash_elem *e, void *aux UNUSED);
static bool spt_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void spt_free_entry(struct hash_elem *e, void *aux UNUSED);

void spt_create(struct thread *t) {
  hash_init(&t->page_map, spt_hash, spt_less, NULL);
}

// 🔹 entry 하나씩 해제할 helper 함수
static void spt_destroy_helper(struct hash_elem *e, void *aux UNUSED) {
  struct supplemental_page_table_entry *spte = hash_entry(e, struct supplemental_page_table_entry, elem);

  // 페이지가 프레임에 올라와 있다면 해제
  if (spte->status == ON_FRAME && spte->kpage != NULL) {
    frame_free(spte->kpage);
  }

  // lazy loading용 aux가 있으면 해제
  if (spte->status == FROM_FILESYS && spte->aux != NULL) {
    free(spte->aux);
  }

  // 마지막으로 spte 자체 해제
  free(spte);
}

// 🔹 전체 spt 해제 함수
void spt_destroy(struct thread *t) {
  hash_destroy(&t->page_map, spt_destroy_helper);
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
      if (s->init != NULL) {
        if (!s->init(s, s->aux)) {
          frame_free(kpage);
          return false;
        }
      } else {
        PANIC("No initializer function for FROM_FILESYS page");
      }
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

    // 페이지 등록 (initializer는 NULL → all-zero page로)
    if (!vm_alloc_page_with_initializer(PAL_USER, upage, true, NULL, NULL)) {
      PANIC("Stack growth failed: could not allocate page.");
    }

    // 실제 페이지 할당
    if (!vm_claim_page(upage)) {
      PANIC("Stack growth failed: could not claim page.");
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

bool
install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  // 가상 주소가 이미 매핑되어 있으면 실패
  if (pagedir_get_page(t->pagedir, upage) != NULL)
    return false;

  // 새로 매핑 시도
  return pagedir_set_page(t->pagedir, upage, kpage, writable);
}

bool
vm_alloc_page_with_initializer(enum palloc_flags flags, void *upage,
                               bool writable, vm_initializer *init,
                               void *aux) {
  struct thread *t = thread_current();
  upage = pg_round_down(upage);

  if (spt_lookup(t, upage) != NULL)
    return false;

  struct supplemental_page_table_entry *spte = malloc(sizeof(struct supplemental_page_table_entry));
  if (spte == NULL)
    return false;

  spte->upage = upage;
  spte->kpage = NULL;
  spte->writable = writable;
  spte->status = (init == NULL) ? ALL_ZERO : FROM_FILESYS;
  spte->init = init;
  spte->aux = aux;

  return (hash_insert(&t->page_map, &spte->elem) == NULL);
}

void
vm_dealloc_page(void *upage) {
  struct thread *t = thread_current();
  struct supplemental_page_table_entry *spte = spt_lookup(t, upage);

  if (spte == NULL)
    return;

  if (spte->kpage != NULL)
    frame_free(spte->kpage);

  hash_delete(&t->page_map, &spte->elem);
  free(spte);
}
