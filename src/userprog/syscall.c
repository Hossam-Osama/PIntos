#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>
#include <stdlib.h>
#include "syscall.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
int wait(int pid);
static struct lock lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock);
}
// function to validate that the address provided by the user is not null and inside my user space
// and it's mapped in the page table (have a physical address)


static void
syscall_handler (struct intr_frame *f ) 
{
  void *esp = f->esp;
  int pid;


  switch (*(int *)esp)
  {
  case SYS_WAIT:
    pid = (*((int *)esp + 1));
    f->eax = wait(pid);
    break;
   case SYS_EXIT:
    int status = *((int *)esp + 1);
    exit(status);
    break;
   case SYS_EXEC:
    char *cmd_line = (char *)(*((int *)esp + 1));
    if (cmd_line == NULL)
      exit(-1);
    lock_acquire(&lock);
    f->eax = exec(cmd_line);
    lock_release(&lock);
    break;
  default:
    break;
  }

  
}
int wait(int pid)
{
  return process_wait(pid);
}





// system call for exiting myself and if i happened to have a parent then
// i'll set my parent's childStatus field to the status that i've terminated on
void exit(int status)
{
  struct thread *cur = thread_current()->parent;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if (cur)
    cur->childState = status;
  thread_exit();
}

