#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <list.h>
#include <threads/synch.h>

void syscall_init (void);
typedef int pid_t;
static struct lock lock;

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1) /* Error value for tid_t. */

struct file_descriptor
{
  struct file *fp; //pointer to the file
  int fd;          //number for file descriptor
  struct list_elem elem; //index of file in the list of file hold by the thread
};
//Alana drove here

struct child_process
{
  tid_t tid;                  /* Tid of the child*/
  int exit_status;           /* The exit status of the child */
  bool exited;               /* Check if the child has exited */
  bool wait_on;              /* check if a child can only be waited once */
  struct list_elem child_elem; /* Index of the process in the children list */
  struct semaphore wait_sema;/* Semaphore to block the parent while waiting for the child to exit */
};
//Naomi drove

#endif /* userprog/syscall.h */
