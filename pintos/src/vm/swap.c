#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/thread.h"
#include <stdbool.h>
#include <debug.h>

static struct block *swap_block;
static struct bitmap *swap_available;
static size_t swap_size;

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void vm_swap_init(void) {
  ASSERT(SECTORS_PER_PAGE > 0);
  swap_block = block_get_role(BLOCK_SWAP);

  if (swap_block == NULL) {
    PANIC("Error: Can't initialize swap block");
    NOT_REACHED();
  }

  swap_size = block_size(swap_block);
  swap_available = bitmap_create(swap_size);
  bitmap_set_all(swap_available, true);  // true = 비어있음
}

void vm_swap_in(swap_index_t swap_index, void *kpage) {
  ASSERT(swap_block != NULL);
  ASSERT(bitmap_test(swap_available, swap_index) == false); // false = 사용중
  ASSERT(kpage != NULL);

  size_t i;
  for (i = 0; i < SECTORS_PER_PAGE; i++) {
    block_read(swap_block,
               swap_index * SECTORS_PER_PAGE + i,
               (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }

  bitmap_set(swap_available, swap_index, true);  // 다시 비어있는 상태로
}

swap_index_t vm_swap_out(void *kpage) {
  ASSERT(swap_block != NULL);
  ASSERT(kpage != NULL);
  size_t i;

  size_t swap_index = bitmap_scan(swap_available, 0, 1, true);
  if (swap_index == BITMAP_ERROR) {
    PANIC("Error: No free swap slot available");
  }

  for (i = 0; i < SECTORS_PER_PAGE; i++) {
    block_write(swap_block,
                swap_index * SECTORS_PER_PAGE + i,
                (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }

  bitmap_set(swap_available, swap_index, false);  // 사용중
  return swap_index;
}

void vm_swap_free(swap_index_t swap_index) {
  ASSERT(swap_block != NULL);
  ASSERT(swap_index < bitmap_size(swap_available));
  bitmap_set(swap_available, swap_index, true);  // 비어있는 상태로 전환
}
