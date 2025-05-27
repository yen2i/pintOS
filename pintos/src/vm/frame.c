#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include <list.h>
#include <debug.h>

struct frame {
  void *kpage;                     // 커널 물리 주소
  struct thread *owner;           // 프레임을 소유한 스레드
  void *upage;                    // 대응되는 유저 가상 주소
  struct list_elem elem;         // 프레임 테이블 연결 리스트
};

static struct list frame_table;

void frame_table_init(void) {
  list_init(&frame_table);
}

void *frame_allocate(enum palloc_flags flags, void *upage) {
  ASSERT((flags & PAL_USER) != 0);  // 유저 영역 요청이어야 함

  void *kpage = palloc_get_page(flags);
  if (kpage == NULL) {
    // 추후: 교체 알고리즘으로 대체
    PANIC("frame_allocate: out of memory");
  }

  struct frame *f = malloc(sizeof(struct frame));
  if (f == NULL)
    return NULL;

  f->kpage = kpage;
  f->owner = thread_current();
  f->upage = upage;
  list_push_back(&frame_table, &f->elem);

  return kpage;
}

void frame_free(void *kpage) {
  struct list_elem *e;
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
    struct frame *f = list_entry(e, struct frame, elem);
    if (f->kpage == kpage) {
      list_remove(e);
      palloc_free_page(kpage);
      free(f);
      return;
    }
  }
  PANIC("frame_free: trying to free non-existent frame");
}
