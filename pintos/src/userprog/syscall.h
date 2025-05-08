#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdint.h>

void syscall_init(void);
void halt(void);
void exit(int status);
int wait(int pid);
int write(int fd, const void *buffer, unsigned size);
bool is_valid_ptr(const void *usr_ptr);

#endif /* userprog/syscall.h */