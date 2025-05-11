#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
/* for shutdown_power_off */
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"

//User Programs: File Manipulation-1 
struct file_descriptor
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

/* a list of open files, represents all the files open by the user process
   through syscalls. */
struct list open_files; 

/* the lock used by syscalls involving file system to ensure only one thread
   at a time is accessing file system */
struct lock fs_lock;

static void syscall_handler (struct intr_frame *);

/* System call functions */
static void halt (void);
static void exit (int);
static int wait (tid_t);
static bool create(const char *file_name, unsigned initial_size);
static bool remove(const char *file_name);
static int open(const char *file_name);
static int allocate_fd(void);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write (int, const void *, unsigned);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static void close_open_file(int fd);



/* End of system call functions */

static struct file_descriptor *get_open_file (int);

bool is_valid_ptr (const void *);
//static int allocate_fd (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init (&open_files);
  lock_init (&fs_lock);
}

//User Programs: System Calls-1
static void
syscall_handler (struct intr_frame *f)
{
  int * esp = f->esp;

  if (!is_valid_ptr(esp) || pagedir_get_page(thread_current()->pagedir, esp) == NULL)
    exit(-1);

  int syscall_number = * esp;

  switch (syscall_number)
        {
        case SYS_HALT:
          halt ();
          break;
          
        case SYS_EXIT:
          if(!is_valid_ptr(esp+1))
            exit(-1);
          exit (*(esp + 1));
          break;

        case SYS_WAIT:
        if(!is_valid_ptr(esp+1))
            exit(-1);
          f->eax = wait (*(esp + 1));
          break;

        case SYS_CREATE:
          if (!is_valid_ptr(esp + 5) || !is_valid_ptr(*(esp + 4)))
            exit(-1);
          f->eax = create(*(esp + 4), *(esp + 5));
          break;

        case SYS_REMOVE:
          if (!is_valid_ptr(esp + 1) || !is_valid_ptr((void *) *(esp + 1)))
            exit(-1);
          f->eax = remove((char *) *(esp + 1));
          break;

        case SYS_OPEN:
          if (!is_valid_ptr(esp + 1) || !is_valid_ptr((void *) *(esp + 1)))
            exit(-1);
          f->eax = open((char *) *(esp + 1));
          break;

        case SYS_FILESIZE:
          if (!is_valid_ptr(esp + 1))
            exit(-1);
          f->eax = filesize(*(esp + 1));
          break;

        case SYS_READ:
          if (!is_valid_ptr(esp + 7) || !is_valid_ptr((void *) *(esp + 6)))
            exit(-1);
          f->eax = read(*(esp + 5), (void *) *(esp + 6), *(esp + 7));
          break;

        case SYS_WRITE:
          {
            if(!is_valid_ptr(esp+7)){
              exit(-1);
            } else if (!is_valid_ptr(*(esp+6)))
            {
              exit(-1);
            }
            
            int fd = *(esp+5);
            const void *buffer = *(esp+6);
            unsigned size = *(esp+7);
          
            f->eax = write(fd, buffer, size);
          }
          break;

        case SYS_SEEK:
          if (!is_valid_ptr(esp + 2))
            exit(-1);
          seek(*(esp + 1), *(esp + 2));
          break;

        case SYS_TELL:
          if (!is_valid_ptr(esp + 1))
            exit(-1);
          f->eax = tell(*(esp + 1));
          break;

        case SYS_CLOSE:
          if (!is_valid_ptr(esp + 1))
            exit(-1);
          close(*(esp + 1));
          break;

        default:
          break;
        }

    }

    //User Programs: System Calls-3
    int 
    wait (tid_t pid)
    { 
      return process_wait(pid);
    }

    //User Programs: System Calls-4
    void
    exit(int status) {
      struct thread *cur = thread_current();               // 4-1. 현재 스레드
      printf("%s: exit(%d)\n", cur->name, status);         // 4-2. 종료 메시지 출력
      //thread_exit_with_status(status);                     // 4-3. 종료 (상태 전달)
      // 임시 대안 (기본 PintOS 구조 기준)
      cur->exit_status = status;
      thread_exit();
      }

      //User Programs: System Calls-5
      void
      halt (void)
      {
        shutdown_power_off ();
      }


/* 🛠️ 3-49 bool create 구현완료 */
static bool
create(const char *file_name, unsigned initial_size)
{
  if (!is_valid_ptr(file_name))
    exit(-1);

  lock_acquire(&fs_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&fs_lock);
  return success;
}
/* 🛠️ 3-50 bool remove 구현완료 */
static bool
remove(const char *file_name)
{
  if (!is_valid_ptr(file_name))
    exit(-1);

  lock_acquire(&fs_lock);
  bool success = filesys_remove(file_name);
  lock_release(&fs_lock);
  return success;
}

/* 🛠️ 3-51~52 int open 구현완료 */
static int
open(const char *file_name)
{
  if (!is_valid_ptr(file_name))
    exit(-1);

  lock_acquire(&fs_lock);
  struct file *f = filesys_open(file_name);
  if (f == NULL)
  {
    lock_release(&fs_lock);
    return -1;
  }
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  if (fd == NULL)
  {
    file_close(f);
    lock_release(&fs_lock);
    return -1;
  }

  fd->fd_num = allocate_fd();                
  fd->file_struct = f;                         
  fd->owner = thread_current()->tid;           
  list_push_back(&open_files, &fd->elem);     

  lock_release(&fs_lock);
  return fd->fd_num;
}
/* 🛠️ 3-52 int allocate_fd 구현완료 */
static int
allocate_fd(void)
{
  static int next_fd = 2;
  return next_fd++;
}

/* 🛠️ 3-53 int filesize 구현완료 */
static int
filesize(int fd)
{
  lock_acquire(&fs_lock);
  struct file_descriptor *fd_struct = get_open_file(fd);

  if (fd_struct == NULL)
  {
    lock_release(&fs_lock);
    return -1;
  }
  int size = file_length(fd_struct->file_struct);

  lock_release(&fs_lock);
  return size;
}

/* 🛠️ 3-54~55 int read 구현완료 */
static int
read(int fd, void *buffer, unsigned size)
{
  if (!is_valid_ptr(buffer))
    exit(-1);

  lock_acquire(&fs_lock);

  if (fd == STDOUT_FILENO)
  {
    lock_release(&fs_lock);
    return -1;
  }

  int status = -1;

  if (fd == STDIN_FILENO)
  {
    unsigned i;
    uint8_t *buf = buffer;
    for (i = 0; i < size; i++)
      buf[i] = input_getc();
    status = size;
  }
  else
  {
    struct file_descriptor *fd_struct = get_open_file(fd);
    if (fd_struct != NULL)
      status = file_read(fd_struct->file_struct, buffer, size);
  }

  lock_release(&fs_lock);
  return status;
}

//User Programs: File Manipulation-4
int
write (int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;  
  int status = 0;

  // 버퍼 포인터의 유효성 검사 (유저 영역에 존재하는지 등)
  if (!is_valid_ptr (buffer))
    exit (-1);

  // 파일 시스템 보호를 위한 락 획득
  lock_acquire (&fs_lock); 

  // 표준 입력에는 쓰기가 불가능하므로 -1 반환
  if (fd == STDIN_FILENO)
    {
      lock_release(&fs_lock);
      return -1;
    }

  // 표준 출력일 경우 putbuf()로 화면에 출력하고 종료
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      lock_release(&fs_lock);
      return size;
    }

  // 열린 파일 목록에서 해당 fd를 찾아 파일에 쓰기 수행
  fd_struct = get_open_file (fd);
  if (fd_struct != NULL)
    status = file_write (fd_struct->file_struct, buffer, size);

  // 락 해제 후 결과 반환
  lock_release (&fs_lock);
  return status;
}

/* 🛠️ 3-56 void seek 구현완료 */
static void
seek(int fd, unsigned position)
{
  lock_acquire(&fs_lock);
  struct file_descriptor *fd_struct = get_open_file(fd);

  if (fd_struct != NULL)
    file_seek(fd_struct->file_struct, position);

  lock_release(&fs_lock);
}

/* 🛠️ 3-57 unsigned tell 구현완료 */
static unsigned
tell(int fd)
{
  lock_acquire(&fs_lock);
  struct file_descriptor *fd_struct = get_open_file(fd);
  unsigned result = 0;
  if (fd_struct != NULL)
    result = file_tell(fd_struct->file_struct);

  lock_release(&fs_lock);
  return result;
}

/* 🛠️ 3-58 void close 구현완료 */
static void
close(int fd)
{
  lock_acquire(&fs_lock);
  struct file_descriptor *fd_struct = get_open_file(fd);

  if (fd_struct != NULL && fd_struct->owner == thread_current()->tid)
    close_open_file(fd);

  lock_release(&fs_lock);
}

/* 🛠️ 3-59 void close_open_file 구현완료 */
static void
close_open_file(int fd)
{
  struct list_elem *e = list_begin(&open_files);

  while (e != list_end(&open_files))
  {
    struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);

    if (fd_struct->fd_num == fd)
    {
      e = list_remove(e);
      file_close(fd_struct->file_struct);
      free(fd_struct);
      return;
    }
    else
    {
      e = list_next(e);
    }
  }
}

//User Programs: File Manipulation-3
struct file_descriptor *
get_open_file (int fd)
{
  struct list_elem *e;
  struct file_descriptor *fd_struct; 
  
  /* open_files 리스트의 마지막 요소부터 순회 시작 */
  e = list_tail(&open_files);

  /* 리스트의 시작(head)에 도달할 때까지 순회 */
  while (e != list_head(&open_files)) {
    fd_struct = list_entry(e, struct file_descriptor, elem); /* 리스트 요소를 file_descriptor 구조체로 변환 */
    
    /* fd 번호가 일치하면 해당 구조체를 반환 */
    if (fd_struct->fd_num == fd)
        return fd_struct;
    e = list_prev(e);    /* 이전 요소로 이동 */
  }
  
  /* 일치하는 파일 디스크립터를 찾지 못한 경우 NULL 반환 */
  return NULL;
}

/* The kernel must be very careful about doing so, because the user can
 * pass a null pointer, a pointer to unmapped virtual memory, or a pointer
 * to kernel virtual address space (above PHYS_BASE). All of these types of
 * invalid pointers must be rejected without harm to the kernel or other
 * running processes, by terminating the offending process and freeing
 * its resources.
 */

//User Programs: System Calls-2
bool is_valid_ptr(const void *ptr) {
  return ptr != NULL &&
         is_user_vaddr(ptr) &&
         pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}