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

struct supplemental_page_table_entry;  // 전방 선언
typedef bool (*vm_initializer)(struct supplemental_page_table_entry *spte, void *aux);

enum page_status {
  ALL_ZERO,
  ON_FRAME,
  ON_SWAP,
  FROM_FILESYS
};

struct supplemental_page_table_entry {
  void *upage;                         // 유저 가상 주소
  void *kpage;                         // 커널 물리 주소

  struct hash_elem elem;              // 해시 테이블 요소
  enum page_status status;            // 페이지 상태
  swap_index_t swap_index;            // 스왑 영역 인덱스
  bool dirty;                         // 더티 플래그
  struct file *file;                  // 파일 매핑 정보
  off_t file_offset;                  // 파일 내 오프셋
  uint32_t read_bytes, zero_bytes;   // 로드할 바이트 수
  bool writable;                      // 쓰기 가능 여부

  vm_initializer init;   // lazy loading용 초기화 함수 포인터
  void *aux;              // 초기화 함수에 넘길 추가 인자

};

// ✅ 인터페이스 함수 선언
bool install_page(void *upage, void *kpage, bool writable);
bool vm_alloc_page(enum palloc_flags flags, void *upage, bool writable);
bool vm_claim_page(void *upage);
bool vm_do_claim_page(struct supplemental_page_table_entry *s);
void vm_stack_growth(void *addr);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool write, bool user);
bool vm_alloc_page_with_initializer(enum palloc_flags flags, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux);

// ✅ SPT 관련
// page.h
void vm_dealloc_page(void *upage);
void spt_create(struct thread *t);
void spt_destroy(struct thread *t);
struct supplemental_page_table_entry *spt_lookup(struct thread *t, void *upage);

#endif // VM_PAGE_H
