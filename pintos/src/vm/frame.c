#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <debug.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct list frame_table;
static struct hash frame_map;     // 전체 프레임 해시 테이블
static struct list frame_list;    // FIFO or Clock 대기용 리스트
static struct lock frame_lock;    // 동기화를 위한 락
static struct list_elem *clock_ptr; // clock algorithm의 포인터
static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
static bool evict_frame(enum palloc_flags flags, void *upage, void **out_kpage);


void frame_init(void) {
    hash_init(&frame_map, frame_hash, frame_less, NULL);
    list_init(&frame_list);
    lock_init(&frame_lock);
    clock_ptr = NULL;
}

static unsigned
frame_hash(const struct hash_elem *e, void *aux UNUSED) {
    struct frame_table_entry *f = hash_entry(e, struct frame_table_entry, helem);
    return hash_bytes(&f->kpage, sizeof f->kpage);
}

static bool
frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct frame_table_entry *fa = hash_entry(a, struct frame_table_entry, helem);
    struct frame_table_entry *fb = hash_entry(b, struct frame_table_entry, helem);
    return fa->kpage < fb->kpage;
}


void frame_table_init(void) {
  list_init(&frame_table);
}

void *frame_allocate(enum palloc_flags flags, void *upage) {
    ASSERT((flags & PAL_USER) != 0);
    lock_acquire(&frame_lock);

    void *kpage = palloc_get_page(flags);
    if (!evict_frame(flags, upage, &kpage)) {
        lock_release(&frame_lock);
        return NULL;
    }

    // 새 프레임 등록
    struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
    if (fte == NULL) {
        palloc_free_page(kpage);
        lock_release(&frame_lock);
        return NULL;
    }

    fte->kpage = kpage;
    fte->upage = upage;
    fte->t = thread_current();
    fte->pinned = false;

    hash_insert(&frame_map, &fte->helem);
    list_push_back(&frame_list, &fte->lelem);

    lock_release(&frame_lock);
    return kpage;
}

void
frame_do_free(void *kpage, bool free_page) {
  lock_acquire(&frame_lock);

  struct frame_table_entry f;
  f.kpage = kpage;
  struct hash_elem *e = hash_find(&frame_map, &f.helem);
  if (e == NULL) {
    lock_release(&frame_lock);
    return;
  }

  struct frame_table_entry *entry = hash_entry(e, struct frame_table_entry, helem);
  hash_delete(&frame_map, &entry->helem);
  free(entry);

  if (free_page) {
    palloc_free_page(kpage);
  }

  lock_release(&frame_lock);
}

void
frame_set_pinned(void *kpage, bool pinned) {
  lock_acquire(&frame_lock);

  struct frame_table_entry f;
  f.kpage = kpage;
  struct hash_elem *e = hash_find(&frame_map, &f.helem);
  if (e != NULL) {
    struct frame_table_entry *entry = hash_entry(e, struct frame_table_entry, helem);
    entry->pinned = pinned;
  }

  lock_release(&frame_lock);
}

/* Eviction 대상 프레임 선택 (Clock Algorithm) */
static struct frame_table_entry *pick_frame_to_evict(void) {
  size_t n = list_size(&frame_list);
  size_t i;
  for (i = 0; i < n * 2; i++) {  // 두 바퀴 돌면서 찾는다
    if (clock_ptr == NULL || clock_ptr == list_end(&frame_list)) {
      clock_ptr = list_begin(&frame_list);
    }

    struct frame_table_entry *f = list_entry(clock_ptr, struct frame_table_entry, lelem);
    struct thread *t = f->t;

    if (!f->pinned) {
      if (pagedir_is_accessed(t->pagedir, f->upage)) {
        pagedir_set_accessed(t->pagedir, f->upage, false);  // accessed 비트 클리어
      } else {
        // accessed == false, pinned == false → evict 대상
        struct list_elem *old = clock_ptr;
        clock_ptr = list_next(clock_ptr);
        return f;
      }
    }

    clock_ptr = list_next(clock_ptr);
  }

  return NULL;  // 찾지 못하면 NULL
}
/* 프레임 교체 및 스왑 아웃 */
static bool evict_frame(enum palloc_flags flags, void *upage, void **out_kpage) {
  struct frame_table_entry *victim = pick_frame_to_evict();
  if (victim == NULL) {
    return false;  // evict 실패
  }

  struct thread *t = victim->t;
  void *old_kpage = victim->kpage;
  void *old_upage = victim->upage;

  struct supplemental_page_table_entry *spte = spt_lookup(t, old_upage);
  if (spte == NULL) {
    PANIC("evict_frame: can't find spte for evicted page");
  }

  // dirty 확인
  bool dirty = pagedir_is_dirty(t->pagedir, old_upage) || spte->dirty;

  // swap out 진행
  if (spte->status == ON_FRAME || spte->status == ALL_ZERO) {
    if (dirty) {
      spte->swap_index = vm_swap_out(old_kpage);  // 스왑 영역으로 내보냄
      spte->status = ON_SWAP;
    } else {
      spte->status = ALL_ZERO;
    }
  }

  spte->kpage = NULL;

  pagedir_clear_page(t->pagedir, old_upage);  // Page mapping 제거
  frame_do_free(old_kpage, true);             // frame 테이블 및 물리 메모리 해제

  // 새 페이지 확보
  *out_kpage = palloc_get_page(flags);
  if (*out_kpage == NULL) return false;

  return true;
}

void frame_free(void *kpage) {
  ASSERT(pg_round_down(kpage) == kpage);  // 페이지 정렬 확인

  lock_acquire(&frame_lock);  // 🔒 프레임 테이블 접근 시 락 필요

  struct frame_table_entry f;
  f.kpage = kpage;

  struct hash_elem *e = hash_find(&frame_map, &f.helem);
  if (e == NULL) {
    lock_release(&frame_lock);
    return;
  }

  struct frame_table_entry *entry = hash_entry(e, struct frame_table_entry, helem);
  hash_delete(&frame_map, &entry->helem);
  list_remove(&entry->lelem); // list에서도 제거
  free(entry);  // entry 자체도 해제

  palloc_free_page(kpage);  // 실제 물리 페이지 해제

  lock_release(&frame_lock);
}
