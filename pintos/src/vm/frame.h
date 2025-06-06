#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <stdbool.h>
#include "threads/thread.h"
#include "threads/palloc.h"  // ✅ PAL_USER, palloc_flags 정의

/* 프레임 테이블 초기화 */
void frame_table_init(void);

/* 프레임 할당 (물리 프레임을 요청하여 등록) */
void *frame_allocate(enum palloc_flags flags, void *upage);

/* 프레임 해제 */
void frame_free(void *kpage);

/* 내부용: 프레임 강제 해제 (선택적 palloc_free_page 포함) */
void frame_do_free(void *kpage, bool free_page);

/* 내부용: 핀 여부 설정 (프레임이 스왑 불가능하도록 고정) */
void frame_set_pinned(void *kpage, bool pinned);

/* 프레임 테이블 엔트리 구조체 */
struct frame_table_entry {
    void *kpage;                 // 물리 메모리 주소 (Kernel page)
    struct hash_elem helem;     // 해시 테이블용 요소
    struct list_elem lelem;     // 리스트용 요소 (clock 등)
    void *upage;                // 가상 주소 (User page)
    struct thread *t;           // 이 프레임을 소유한 스레드
    bool pinned;                // 교체 방지 여부 (true면 evict 불가)
};

#endif /* VM_FRAME_H */
