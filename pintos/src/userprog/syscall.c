#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/pte.h"     // pagedir_get_page
#include "threads/palloc.h"  // optional, for robustness

// 함수 프로토타입 선언
static void syscall_handler(struct intr_frame *f);
static bool is_valid_ptr(const void *usr_ptr);
void halt(void);
void exit(int status);
int wait(int pid);

// 시스템 콜 초기화
void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// 포인터 유효성 확인 함수
static bool is_valid_ptr(const void *usr_ptr) {
  struct thread *cur = thread_current();

  // 1. NULL인지 확인
  if (usr_ptr == NULL) return false;

  // 2. 사용자 주소 공간인지 확인
  if (!is_user_vaddr(usr_ptr)) return false;

  // 3. 실제 매핑된 페이지인지 확인
  if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL) return false;

  return true;
}

// 시스템 콜 핸들러
static void syscall_handler(struct intr_frame *f) {
  if (!is_valid_ptr(f->esp)) {
    exit(-1);
  }

  // 시스템 콜 번호 추출
  int syscall_num = *(int *)(f->esp);

  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT: {
      if (!is_valid_ptr(f->esp + 4)) {
        exit(-1);
      }
      int status = *(int *)(f->esp + 4);
      exit(status);
      break;
    }

    case SYS_WAIT: {
      if (!is_valid_ptr(f->esp + 4)) {
        exit(-1);
      }
      int pid = *(int *)(f->esp + 4);  // pid_t 대신 int
      f->eax = wait(pid);  // 결과를 eax 레지스터에 저장
      break;
    }

    default:
      printf("Unknown system call: %d\n", syscall_num);
      exit(-1);
  }
}

// 시스템 콜: halt()
// PintOS를 종료함
void halt(void) {
  shutdown_power_off();
}

// 시스템 콜: exit(status)
// 현재 프로세스를 상태와 함께 종료
void exit(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;

  // 포맷 출력 (테스트 요구사항)
  printf("%s: exit(%d)\n", cur->name, status);

  thread_exit();
}

// 시스템 콜: wait(pid)
// 자식 프로세스 종료 대기
int wait(int pid) {
  return process_wait(pid);  // ch3에서 구현됨
}
