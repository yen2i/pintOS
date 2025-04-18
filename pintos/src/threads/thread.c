#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

#include "threads/fixed-point.h"
int load_avg; // static 제거!

// thread.c 맨 위에 추가해줘
void update_all_priorities(void);
void update_thread_priority(struct thread *t);


/* Random value for struct thread's magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

//Threads:AlarmClock-2
static struct list sleep_queue; //sleep 상태의 thread 저장하는 list

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */


//Threads:BSD -12
int int_to_fp(int n) {
  return n * F;
}

int fp_to_int(int x) {
  return x / F;
}

int fp_to_int_round(int x) {
  return x >= 0 ? (x + F / 2) / F : (x - F / 2) / F;
}

int add_fp(int x, int y) {
  return x + y;
}

int sub_fp(int x, int y) {
  return x - y;
}

int add_mixed(int x, int n) {
  return x + n * F;
}

int sub_mixed(int x, int n) {
  return x - n * F;
}

int mult_fp(int x, int y) {
  return ((int64_t) x) * y / F;
}

int mult_mixed(int x, int n) {
  return x * n;
}

int div_fp(int x, int y) {
  return ((int64_t) x) * F / y;
}

int div_mixed(int x, int n) {
  return x / n;
}

bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */

//Threads:BSD -4.1
void
update_load_avg_and_recent_cpu(void)
{
  size_t ready_threads = list_size(&ready_list);
  if (thread_current() != idle_thread)
    ready_threads++;  // running thread 포함

  // load_avg = (59/60) * load_avg + (1/60) * ready_threads
  load_avg = add_fp(
               mult_fp(div_mixed(int_to_fp(59), 60), load_avg),
               mult_mixed(div_mixed(int_to_fp(1), 60), ready_threads)
             );

  // 모든 스레드 순회하며 recent_cpu 갱신
  struct list_elem *e;
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, allelem);
    if (t == idle_thread)
      continue;

    // Compute coefficient: (2 * load_avg) / (2 * load_avg + 1)
    int coef = div_fp(mult_mixed(load_avg, 2), add_mixed(mult_mixed(load_avg, 2), 1));
    // Apply formula: recent_cpu = coef * recent_cpu + nice
    t->recent_cpu = add_mixed(mult_fp(coef, t->recent_cpu), t->nice);
  }
}

//Threads:BSD -4.2
void
update_all_priorities(void)
{
  struct list_elem *e;

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, allelem);

    if (t == idle_thread) continue;  // idle thread는 계산 안 함

    int new_priority = int_to_fp(PRI_MAX);
    int recent_cpu_div4 = div_mixed(t->recent_cpu, 4);       // recent_cpu / 4
    int nice_times2 = int_to_fp(t->nice * 2);                 // nice * 2

    new_priority = sub_fp(new_priority, recent_cpu_div4);    // - recent_cpu / 4
    new_priority = sub_fp(new_priority, nice_times2);        // - nice * 2

    t->priority = fp_to_int_round(new_priority);             // 고정소수점 → 정수 (반올림)

    // 범위 제한 (PRI_MIN ~ PRI_MAX)
    if (t->priority > PRI_MAX)
      t->priority = PRI_MAX;
    else if (t->priority < PRI_MIN)
      t->priority = PRI_MIN;
  }
}

/* Threads:BSD -11.1
 * Recalculates the priority of the given thread based on its recent_cpu and nice values.
 * Uses the formula:
 *     priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
 * This is part of the 4.4BSD scheduler and called periodically or when nice changes.
 */

void
update_thread_priority(struct thread *t)
{
  if (t == idle_thread) return;

  int priority = int_to_fp(PRI_MAX);
  int term1 = div_mixed(t->recent_cpu, 4);   //(fixed-point division)
  int term2 = int_to_fp(t->nice * 2);  //(converted to fixed-point)

  priority = sub_fp(priority, term1);
  priority = sub_fp(priority, term2);

  // Convert fixed-point priority to integer with roundinng
  t->priority = fp_to_int_round(priority);

  // Clamp priority within [PRI_MIN, PRI_MAX] range
  if (t->priority > PRI_MAX)
    t->priority = PRI_MAX;
  else if (t->priority < PRI_MIN)
    t->priority = PRI_MIN;
}

//Threads:AlarmClock-3
void
thread_sleep (int64_t ticks)
{
  struct thread *cur;
  enum intr_level old_level;

  old_level = intr_disable ();   // interrupt off
  cur = thread_current ();
  
  ASSERT (cur != idle_thread);

  cur->wake_up_tick = ticks;         // block state에서 thread가 일어날 시간 정보 저장
  list_push_back (&sleep_queue, &cur->elem);   // sleep_queue 에 추가
  thread_block ();            // block state로 변경

  intr_set_level (old_level);   // interrupt on
}

//Threads:AlarmClock-4
void
thread_wakeup (int64_t ticks)
{
  struct list_elem *e = list_begin (&sleep_queue);

  while (e != list_end (&sleep_queue)){      // sleep_queue를 끝까지 돌면서 확인
    struct thread *t = list_entry (e, struct thread, elem);
    if (t->wake_up_tick <= ticks){   // thread가 wakeup할 시간인지 check
      e = list_remove (e);   // sleep queue 에서 제거
      thread_unblock (t);   // thread unblock
    }
    else 
      e = list_next (e);     // wakeup할 시간 아니면 다음 요소 확인
  }
}

void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_queue); //초기화

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();


}

/* Starts preemptive thread scheduling by enabling interrupts.

   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */

//Threads:PriorityScheduling-3
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;



  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  

  thread_unblock (t);
  preempt_check ();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */

//Threads:PriorityDonation-추가
bool 
compared_priority (const struct list_elem *f, const struct list_elem *s, void *aux UNUSED)
{
    return list_entry (f, struct thread, elem)->priority
         > list_entry (s, struct thread, elem)->priority;
}


void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  //Threads:PriorityScheduling-5
  list_insert_ordered (&ready_list, &t->elem, compared_priority, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}



/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();

  //Threads:PriorityScheduling-6
  if (cur != idle_thread) 
    //list_push_back (&ready_list, &cur->elem);
    list_insert_ordered (&ready_list, &cur->elem, compared_priority, 0);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

//Threads:PriorityScheduling-2
void 
preempt_check (void)
{
    if (!list_empty (&ready_list) && 
    thread_current ()->priority < 
    list_entry (list_front (&ready_list), struct thread, elem)->priority)
        thread_yield ();
}

//Threads:PriorityScheduling-1
bool
compared_donate_priority (const struct list_elem *l, 
            const struct list_elem *s, void *aux UNUSED)
{
   return list_entry (l, struct thread, donation_elem)->priority
       > list_entry (s, struct thread, donation_elem)->priority;
}

//Threads:PriorityDonation-3
void
donate_priority (void)
{
  int depth;
  struct thread *cur = thread_current ();

  for (depth = 0; depth < 8; depth++){
    if (!cur->waiting_for_lock) break;   //없으면 종료
      struct thread *holder = cur->waiting_for_lock->holder;   //lock의 소유자
      holder->priority = cur->priority;   //소유자우선순위->현재스레드 우선순위로 바꿈
      cur = holder;
  }
}

//Threads:PriorityDonation-추가
void
removed_lock (struct lock *lock)
{
  struct list_elem *e;
  struct thread *cur = thread_current ();

  for (e = list_begin (&cur->donation); e != list_end (&cur->donation); e = list_next (e)){
    struct thread *t = list_entry (e, struct thread, donation_elem);
    if (t->waiting_for_lock == lock)
      list_remove (&t->donation_elem);
  }
}

//Threads:PriorityDonation-2
void
restore_priority (void)
{
  struct thread *cur = thread_current ();

  cur->priority = cur->original_priority;
  
  if (!list_empty (&cur->donation)) {
    list_sort (&cur->donation, compared_donate_priority, 0);

    struct thread *front = list_entry (list_front (&cur->donation), struct thread, donation_elem);
    if (front->priority > cur->priority)
      cur->priority = front->priority;
  }
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  //Threads:BSD -3
  // If using MLFQS (BSD Scheduler), ignore manual priority changes
   if (thread_mlfqs)
    return; 

  //Threads:PriorityDonation-5
  thread_current ()->original_priority = new_priority;

  restore_priority (); //donation 포함한 최종 priority 반영
  //Threads:PriorityScheduling-4
  preempt_check (); // 더 높은 priority 스레드 있으면 yield
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  //Threads:BSD -11
  struct thread *t = thread_current();
  t->nice = nice;

  update_thread_priority(t);  // priority 재계산 함수
  preempt_check();            // 높은 우선순위 스레드 있으면 양보
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  //Threads:BSD -10
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  //Threads:BSD -7
  return fp_to_int_round(mult_mixed(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  //Threads:BSD -8
  return fp_to_int_round(mult_mixed(thread_current()->recent_cpu, 100));
}
/*여기까지*/

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into esp', and then round that
     down to the start of a page.  Because struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);

//Threads:PriorityDonation-4
  t->original_priority = priority;
  t->waiting_for_lock = NULL;
  list_init (&t->donation);

  //Threads:BSD -2
  t->nice = 0;
  t->recent_cpu = 0;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of stack' member within struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);