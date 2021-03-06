#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "devices/shutdown.h"



void syscall_init (void);

void halt (void);

void exit (int status);

tid_t exec(const char* cmd_line);

int wait(tid_t pid);

int wait(tid_t pid);

bool create (const char *file, unsigned initial_size);

bool remove (const char *file);

int open(const char *file);

int filesize(int fd);

int read(int fd, void *buffer, unsigned size);

int write(int fd, const void *buffer,  unsigned size);

void seek(int fd, unsigned position);

unsigned tell(int fd);

void close(int fd);


#endif /* userprog/syscall.h */
