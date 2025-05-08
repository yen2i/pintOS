#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"     // shutdown_power_off()
#include "userprog/process.h" // process_wait()
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/pte.h"
#include "threads/synch.h"    // for lock_* functions
#include "filesys/file.h"     // if file_write etc. is used later
#include "lib/kernel/console.h" // for putbuf()
#include "devices/shutdown.h"
#include "userprog/pagedir.h"

/* syscall handler 함수 선언 */
static void syscall_handler(struct intr_frame *f);
struct lock filesys_lock;

/* 시스템 콜 초기화 */
void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

/* syscall handler 기본 구조 */
static void syscall_handler(struct intr_frame *f) {
  uint32_t syscall_num;

  // 유저 스택에서 syscall 번호 가져오기
  if (!is_user_vaddr(f->esp)) {
    exit(-1);
  }

  syscall_num = *(uint32_t *)(f->esp);  // 첫 번째 인자: syscall 번호

  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      if (!is_user_vaddr(f->esp + 4)) exit(-1);
      exit(*(int *)(f->esp + 4));
      break;

    case SYS_WAIT:
      if (!is_user_vaddr(f->esp + 4)) exit(-1);
      f->eax = wait(*(int *)(f->esp + 4));
      break;

    case SYS_WRITE: {
      int fd = *(int *)(f->esp + 4);
      void *buffer = *(void **)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);
      
      f->eax = write(fd, buffer, size);
  break;
}
    default:
      printf("Unknown syscall number: %d\n", syscall_num);
      thread_exit();
  }
}

/* 실제 시스템 콜 함수들 - 반드시 handler 함수 밖에 정의할 것! */
void halt(void) {
  shutdown_power_off();  // QEMU 종료
}

void exit(int status) {
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit();
}

int wait(int pid) {
  return process_wait(pid);
}

int write(int fd, const void *buffer, unsigned size) {

  if (buffer == NULL || !is_user_vaddr(buffer)) {
    exit(-1);
  }
  lock_acquire(&filesys_lock);

  int bytes_written = 0;
  
  if (fd == 1) {
    putbuf((char *)buffer, size);  // 반드시 캐스팅
    bytes_written = size;
  }else {
    bytes_written = 0;
  }

  lock_release(&filesys_lock);
  return bytes_written;
}

bool is_valid_ptr(const void *usr_ptr) {
  return usr_ptr != NULL
      && is_user_vaddr(usr_ptr)
      && pagedir_get_page(thread_current()->pagedir, usr_ptr) != NULL;
}


