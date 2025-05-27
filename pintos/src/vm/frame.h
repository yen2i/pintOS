#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include "threads/thread.h"
#include "threads/palloc.h"  // ✅ PAL_USER, palloc_flags 정의

void frame_table_init(void);
void *frame_allocate(enum palloc_flags flags, void *upage);
void frame_free(void *kpage);

#endif
