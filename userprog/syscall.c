#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include <stdlib.h>
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void kill();
bool check_valid(void *ptr);
struct file *file_from_fd (int fd);
struct child_process* find_child_process(int child_tid);
void close_all_files();
void remove_all_children();

void kill () 
{
  exit(-1);
}


void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock);
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  /* Stack pointer 
  when you cast (int *)f->esp, it turns into an int pointer that uses 4 bytes
  so whenever you do ((int *)f->esp) + 1, the 1 adds 4 bytes already.

  Think about it like this:
  return address at 0xbff0 or system call handler number
  argument 1 at 0xbff4      ((int*)f->esp) + 1 = (int*)(f->esp + 4)
  argument 2 ar 0xbff8      ((int*)f->esp) + 2 = (int*)(f->esp + 8)
  argument 3 at 0xbffC      ((int*)f->esp) + 3 = (int*)(f->esp + 12)

  If the callee has a return value, it stores it into register EAX
  */
  /*Everyone drove here*/
  if(f == NULL)
  {
    kill();
  }
  //check validity of the pointer
  int *ptr = f->esp;
  if(!check_valid(ptr)||!check_valid(ptr+1)||!check_valid(ptr+2)||
  !check_valid(ptr+3))
  {
    // terminate the process
    kill();
  }
  int syscall_nr = *((int *)(f->esp)); //cast from int pointer and dereference
  int* arg1 = ptr + 1;
  int* arg2 = ptr + 2;
  int* arg3 = ptr + 3;
  
  switch (syscall_nr) 
  {
    case SYS_HALT:
      //0 argument
      halt();
      break;
      
    case SYS_EXIT:
      //1 argument int status
      exit(*arg1); //dereference, void
      break;

    case SYS_EXEC:
      //1 argument const char*cmd_line
      f->eax = exec(*arg1); //dereference, have a return value
      break;

    case SYS_WAIT:
      //1 argument pid_t pid
      f->eax = wait(*arg1); //dereference
      break;

    case SYS_CREATE:
      //2 arguments const char *file, unsigned size

      //check for the dereferences of the file name
      if(!check_valid(*arg1))
      {
        kill();
      }
      f->eax = create(*arg1, *arg2);
      break;

    case SYS_REMOVE:
      //1 argument const char *file

      //check for the dereferences of the file name
      if(!check_valid(*arg1))
      {
        kill();
      }
      f->eax = remove(*arg1);
      break;

    case SYS_OPEN:
      //1 argument const char *file

      //check for the dereferences of the file name
      if(!check_valid(*arg1))
      {
        kill();
      }
      f->eax = open(*arg1);
      break;

    case SYS_FILESIZE:
      //1 argument int fd
      f->eax = filesize(*arg1);
      break;

    case SYS_READ:
      //3 arguments int fd, void *buffer, unsigned size

      //check for the dereferences of the buffer
      if(!check_valid(*arg2))
      {
        kill();
      }
      f->eax = read(*arg1, *arg2, *arg3);
      break;

    case SYS_WRITE:
      //3 arguments int fd, const void *buffer, unsigned size
      //check for the dereferences of the buffer
      if(!check_valid(*arg2))
      {
        kill();
      }
      f->eax = write(*arg1, *arg2, *arg3);
      break;

    case SYS_SEEK:
      //2 arguments int fd, unsigned position
      seek(*arg1, *arg2); //void
      break;

    case SYS_TELL:
      //1 argument int fd
      f->eax = tell(*arg1);
      break;

    case SYS_CLOSE:
      //1 argument int fd
      close(*arg1); //void
      break;

    default:
      kill();
  }
}

// Terminates Pintos by calling shutdown_power_off() 
// (declared in devices/shutdown.h). This should be seldom used,
// because you lose some information about possible deadlock situations, etc.
void halt (void)
{
  /*Alana started driving*/
  shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel.
// If the process's parent waits for it (see below), this is the status
// that will be returned. Conventionally, a status of 0 indicates success
// and nonzero values indicate errors.
void exit (int status)
{
  hash_destroy(&thread_current()->suppl_pt, destroy_page);
  struct thread *cur = thread_current();
  struct child_process *child = cur->child;
  child->exit_status = status;
  
  if(cur->file_used)
  {
    file_allow_write(cur->file_used);
  }
  printf("%s: exit(%d)\n", cur->name, status);

  //close all files and remove all files
  close_all_files();
  //remove all child and exit
  sema_up(&child->wait_sema);
  child->exited = true;
  if(child->exited && child->wait_on)
  {
    palloc_free_page(child);
  }
  remove_all_children();
  thread_exit(); // terminate thread
  /*Alana stopped driving*/
}

// Runs the executable whose name is given in cmd_line, passing any given
// arguments, and returns the new process's program id (pid). Must return
// pid -1, which otherwise should not be a valid pid, if the program cannot
// load or run for any reason. Thus, the parent process cannot return from
// the exec until it knows whether the child process successfully loaded its
// executable. You must use appropriate synchronization to ensure this.
pid_t exec (const char *cmd_line)
{
  /*Camille started driving*/
  tid_t child_tid = process_execute(cmd_line);
  return (pid_t) child_tid;
}


// If pid is still alive, waits until it terminates. Then,
// returns the status that pid passed to exit. If pid did not
// call exit(), but was terminated by the kernel (e.g. killed due to an
// exception), wait(pid) must return -1. It is perfectly legal for a parent
// process to wait for child processes that have already terminated by the time
// the parent calls wait, but the kernel must still allow the parent to
// retrieve its child's exit status or learn that the child was terminated
// by the kernel.
int wait (pid_t pid)
{
  return process_wait((tid_t)pid);
}

// Creates a new file called file initially initial_size bytes in size.
// Returns true if successful, false otherwise. Creating a new file does
// not open it: opening the new file is a separate operation which would
// require a open system call.
bool create (const char *file, unsigned initial_size)
{
  if(file == NULL)
  {
    kill();
  }
  lock_acquire(&lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&lock);
  return success;
}

// Deletes the file called file. Returns true if successful, false otherwise.
// A file may be removed regardless of whether it is open or closed, and 
// removing an open file does not close it. See Removing an Open File, for
// details.
bool remove (const char *file)
{
  lock_acquire(&lock);
  bool success = filesys_remove(file);
  lock_release(&lock);
  return success;
  /*Camille stopped driving*/
}

// Opens the file called file. Returns a nonnegative integer
// handle called a "file descriptor" (fd) or -1 if the file
// could not be opened.
// File descriptors numbered 0 and 1 are reserved for the console:
// fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO)
// is standard output. The open system call will never return either
// of these file descriptors, which are valid as system call arguments
// only as explicitly described below.
//
// Each process has an independent set of file descriptors. File descriptors
// are not inherited by child processes.
//
// When a single file is opened more than once, whether by a single process
// or different processes, each open returns a new file descriptor. Different
// file descriptors for a single file are closed independently in separate
// calls to close and they do not share a file position.
int open (const char *file)
{
  //when a file is open, assign a file descriptor
  //the user the passes this file descriptors into read/write to identify
  //which one it wants to write to
  //file descriptor starts at 2 and ends at 128
  /*Naomi started driving*/

  lock_acquire(&lock);
  if(file == NULL)
  {
    lock_release(&lock);
    return -1;
  }
  struct file *open_file = filesys_open(file); //open file
  // check if can open file
  if(open_file == NULL)
  {
    lock_release(&lock);
    return -1;
  }

  struct file_descriptor *new_fd = palloc_get_page(0);
  struct thread *t = thread_current(); //get the current thread

  //Assign file descriptor number and pointer to the file 
  new_fd->fp = open_file;
  new_fd->fd = t->next_descriptor;
  //increment next descriptor
  t->next_descriptor++;
  //Add the new fd to the end of the thread's file_list
  list_push_back(&t->file_list, &new_fd->elem);
  lock_release(&lock);
  //returns the file descriptor 
  return new_fd->fd;
  /*Naomi stopped driving*/
}


// Returns the size, in bytes, of the file open as fd.
int filesize (int fd)
{
  /*Alana started driving*/
  //Get the file based on fd
  struct file *ptr = file_from_fd(fd);
  if(ptr == NULL)
  {
    return 0;
  }
  lock_acquire(&lock);
  int fileSize = file_length(ptr);
  lock_release(&lock);
  return fileSize;
}

// Reads size bytes from the file open as fd into buffer. 
// Returns the number of bytes actually read (0 at end of file),
// or -1 if the file could not be read (due to a condition other than end
// of file). fd 0 reads from the keyboard using input_getc().
int read (int fd, void *buffer, unsigned size)
{
  //check buffer if it's valid. if false, kill
  if(!check_valid(buffer))
  {
    kill();
  }
  //If the buffer is empty, waits for a key to be pressed. 
  if(fd == 0)
  {
    input_getc();
  }
  //get the file base on fd
  struct file *dest_file = file_from_fd(fd);
  //check if the dest_file has no match
  if (dest_file == NULL)
  {
    return -1;
  }
  //Read the file
  lock_acquire(&lock);
  int bytes_read = file_read(dest_file, buffer, size);
  lock_release(&lock);
  return bytes_read;
  /*Alana stopped driving*/
}

/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes
actually written, which may be less than size if some bytes could not be
written. Writing past end-of-file would normally extend the file, but file 
growth is not implemented by the basic file system. The expected behavior is 
to write as many bytes as possible up to end-of-file and return the actual
number written, or 0 if no bytes could be written at all.

fd 1 writes to the console. Your code to write to the console should write all 
of buffer in one call to putbuf(), at least as long as size is not bigger than
a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise,
lines of text output by different processes may end up interleaved on the
console, confusing both human readers and our grading scripts.
*/
int write (int fd, const void *buffer, unsigned size)
{
  /*Camille started driving*/
  //check for invliad size
  if(!check_valid(buffer))
  {
    kill();
  }
  if(fd < 1)
  {
    kill();
  }
  if(size <= 0)
  {
    return size;
  }
  if(fd == 1)
  {
    //write to console
    putbuf(buffer, size);
    return size;
  } 
  else
  {
    //find the file and write to that file
    //iterate through the list of files to fin d the file
    struct file *dest_file = file_from_fd(fd);
    if(dest_file == NULL)
    {
      return -1;
    }
    lock_acquire(&lock);
    int bytes_written = file_write(dest_file, buffer, size);
    lock_release(&lock);
    return bytes_written;
  }
}
/*
Changes the next byte to be read or written in open file fd to position,
expressed in bytes from the beginning of the file. 
(Thus, a position of 0 is the file's start.)

A seek past the current end of a file is not an error.
A later read obtains 0 bytes, indicating end of file.
A later write extends the file, filling any unwritten gap with zeros.
(However, in Pintos, files will have a fixed length until project 4 
is complete, so writes past end of file will return an error.) 
These semantics are implemented in the file system and do not require
any special effort in system call implementation.
*/
void seek (int fd, unsigned position)
{
  struct file *dest_file = file_from_fd(fd);
  if (dest_file != NULL)
  {
    lock_acquire(&lock);
    file_seek(dest_file, position);
    lock_release(&lock);
  }
}

/*
Returns the position of the next byte to be read or written in open file fd,
expressed in bytes from the beginning of the file.
*/
unsigned tell (int fd)
{
  struct file *dest_file = file_from_fd(fd);
  if (dest_file != NULL) 
  {
    lock_acquire(&lock);
    off_t cur_pos = file_tell(fd);
    lock_release(&lock);
    return cur_pos;
  }
  return 0;
  /*Camille stopped driving*/
}

/*
Closes file descriptor fd. Exiting or terminating a process implicitly closes 
all its open file descriptors, as if by calling this function for each one.
*/
void close (int fd)
{
  /*Naomi started driving*/
  struct list_elem *e;
  struct thread *t = thread_current();
  for(e = list_begin(&t->file_list); e != list_end(&t->file_list);
  e = list_next(e))
  {
    struct file_descriptor *fd_elem = list_entry(e, struct file_descriptor, 
    elem);
    if(fd_elem->fd == fd)
    {
      lock_acquire(&lock);
      file_close(fd_elem->fp);
      lock_release(&lock);
      list_remove(e);
      palloc_free_page(fd_elem);
      return;
    }
  }
  kill();
  /*Naomi stopped driving*/
}

//check if the pointer is valid or not
bool check_valid(void *ptr){
  //check not NULL (ptr!= NULL)
  //check a pointer to unmapped virtual memory (is_user_vaddr(ptr))
  //check pointer to kernel virtual address space (is_user_vaddr(ptr))
  //checks if there is a page pagedir_get_page(thread_current()->pagedir, ptr)
  /*Alana started driving*/
  return (ptr != NULL && is_user_vaddr(ptr) 
          && pagedir_get_page(thread_current()->pagedir, ptr) != NULL);
}

// //Helper method to get the file based on fd
struct file *file_from_fd (int fd)
{
  struct list_elem *e;
  struct thread *t = thread_current();
  //iterate over the file list to find the matching fd
  //file_list - keeps track of list of files
  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
  {
    //get the file descrptor structre
    struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, 
    elem);
    //checks if the current fd matches the requested fd
    if(file_desc->fd == fd)
    {
      //return the file pointer
      return file_desc -> fp;
    }
  }
  return NULL;//returns null if fd has no match
  /*Alana stopped driving*/
}

/* Helper method to find the child giving a tid*/
struct child_process* find_child_process(int child_tid)
{
  /*Camille started driving*/
  struct list *children = &thread_current()->children;
  struct list_elem *e;
  struct child_process *child = NULL; //to return

  //no children, return immediately
  if(list_empty(children))
  {
    return NULL;
  }

  //look up the child process with the given TID
  for (e = list_begin(children); e != list_end(children); e = list_next(e))
  {
    struct child_process *temp = list_entry(e, struct child_process,
     child_elem);
    if (temp->tid == child_tid)
    {
      //found the children process
      child = temp;
      break;
    }
  }
  return child;
  /*Camille stopped driving*/
}


//A helper method to remove and close all files
void close_all_files()
{
  /*Naomi started driving*/
  struct thread *current = thread_current();
  struct list_elem *e;
  while(!list_empty(&current->file_list))
  {
    e = list_pop_front(&current->file_list);
    struct file_descriptor *f = list_entry(e, struct file_descriptor, elem);
    lock_acquire(&lock);
    file_close(file_from_fd(f->fd));
    lock_release(&lock);
    palloc_free_page(f);
  }
}

// A helper method to remove all children processes
void remove_all_children()
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  for (e = list_begin (&cur->children); 
    e != list_end (&cur->children); e = list_next (e))
  {
    list_remove(e);     
    struct child_process *c = list_entry(e, struct child_process, child_elem);
    c->wait_on = true;
    //free children      
    if (c->exited && c->wait_on) 
    {
      palloc_free_page(c);
    }
  }
  /*Naomi stopped driving*/
}