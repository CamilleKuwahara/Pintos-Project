#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void remove_cur_child(int tid);

#define MAX_STACK_SIZE (8 * 1024 * 1024) // 8 MB
bool check_overflow(void *esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name)
{
  /*Naomi started driving*/
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *token = palloc_get_page (0);
  if (token == NULL)
  {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  strlcpy (token, file_name, strlen(file_name) + 1);
  char *save_ptr;
  //gets the first argument
  token = strtok_r(token, " ", &save_ptr); 
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (token, PRI_DEFAULT, start_process, fn_copy);

  //create new child
  struct thread *cur = thread_current();
  sema_init(&cur->wait_load, 0);
  sema_down(&cur->wait_load);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
    return -1;
  }

  //child was unable to be loaded, remove the current child from the list
  if(cur->load_child == false)
  {
    remove_cur_child(tid);
    return -1;
  }
  return tid;
  /*Naomi stopped driving*/
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *file_name_)
{
  /*Alana started driving*/
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  //initialize the page table
  hash_init(&thread_current()->suppl_pt, hash_func, less_func, NULL);
  //initialize stack_pages to 0
  thread_current()->stack_pages = 0;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp); // calls setup_stack

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
    struct thread *cur = thread_current();
    cur->parent->load_child = false;
    cur->child->exit_status = -1;
    sema_up(&thread_current()->parent->wait_load);
    exit(-1);
  }
  thread_current()->parent->load_child = true;
  sema_up(&thread_current()->parent->wait_load);
  /*Alana stopped driving*/


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid UNUSED) 
{ 
  /*Camille started driving*/
  //find the child
  struct child_process *child = find_child_process(child_tid);

  if(child == NULL)
  {
    return -1;
  }
  
  //wait until the child has exit
  sema_down(&child->wait_sema); 
  child->wait_on = true; //mark the child 
  list_remove(&child->child_elem); //remove the child off the list
  int status = child->exit_status; //save the staus before freeing the child
  if (child->wait_on && child->exited) {
    palloc_free_page(child);
  }
  return status;
  /*Camille stopped driving*/
}

/* Free the current process's resources. */
void process_exit (void)
{
  /* Naomi started driving*/
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
    /* Naomi stopped driving*/
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
//  static bool setup_stack (void **esp, char ** argv, int argc);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  //Naomi started driving
  char* fn_copy = palloc_get_page(0);
   if(fn_copy == NULL){
    return -1;
  }
  char* save_ptr;
  strlcpy (fn_copy, file_name, PGSIZE); //make copy of file name
  char *token = strtok_r(fn_copy, " ", &save_ptr);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (token);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if(success)
  {
    file_deny_write(file);
    thread_current()->file_used = file;
  }
  else
  {
    file_close (file);
  }
  palloc_free_page(fn_copy);
  return success;
  //Naomi stopped driving
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      //VM Project 3 - setting up the page
      struct page *vm_page = malloc(sizeof(struct page));
      if (vm_page == NULL) return false;

      //initialize page metadata
      vm_page->virtual_address = upage;
      vm_page->owner = thread_current();
      vm_page->frame = NULL;
      vm_page->file = file;
      vm_page->file_offset = ofs;
      vm_page->file_bytes = page_read_bytes;
      vm_page->block_sector = -1;
      vm_page->reference_bit = false;
      vm_page->writable = writable;
      vm_page->dirty = false;
      vm_page->location = FILE_SYS;

      //insert page to page table
      hash_insert(&thread_current()->suppl_pt, &vm_page->hash_elem);
     
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      //update offset
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp, const char *file_name)   
{
  //everyone drove and update code here
  //Get a free frame from the frame table
  struct frame *vm_frame = get_free_frame();
  //create a new page for the stack
  struct page *vm_page = new_page(((uint8_t *) PHYS_BASE) - PGSIZE);

  vm_frame->page = vm_page;     
  vm_page->frame = vm_frame;     
  vm_page->owner = thread_current();

  //insert the page into the current thread's supplemental page table
  hash_insert(&thread_current()->suppl_pt, &vm_page->hash_elem);

  uint8_t *kpage;
  kpage = vm_frame->page;
  
  bool success = false;
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
    {
      *esp = (char *)PHYS_BASE;
      thread_current()->stack_pages++;
    }
    else
    {
      palloc_free_page (kpage);
    }
  }

  char *save_ptr, *token;
  //allocate memory for filename copy
  char *fn_copy = palloc_get_page(PAL_USER | PAL_ZERO); 
  strlcpy (fn_copy, file_name, PGSIZE); //make copy of file name
  //allocate memory for parse arg array
  char **argv = palloc_get_page(PAL_USER | PAL_ZERO); 
  int argc = 0; //counter
  token = strtok_r(fn_copy, " ", &save_ptr);
  //parse command line
  while(token != NULL)
  {
    argv[argc] = token;
    argc++;
    token = strtok_r(NULL, " ", &save_ptr);
  }
  argv[argc] = NULL;
  char *arg_address[argc]; //initialize address array
  //Align the stack pointer before first push
  if((uintptr_t)*esp % 4 != 0) 
  {
    *esp = (void *)((uintptr_t)*esp - ((uintptr_t)*esp % 4));
    if(!check_overflow(*esp)){
      return false;
    }
  }

  //Push each string on stack in right->left order
  //memcpy(destination, source, size)
  for(int i = argc - 1; i >= 0; i--)
  {
    int length = strlen(argv[i]) + 1; //size of arg + 1 for null terminator
    *esp = (char *)*esp - length; //moves sp down to allocate space for arg
    if(!check_overflow(*esp)){
      return false;
    }
    memcpy(*esp, argv[i], length); //copy arg from argv[i] to esp
    arg_address[i] = *esp; //store the address sp onto an array
  }
  arg_address[argc] = NULL; //add null pointer sentinel

  //Add word alignment
  //round the stack pointer down to multiple of 4
  size_t alignment = (size_t)*esp % 4;
  if(alignment != 0) //if is more than 0, then it goes through
  {
    *esp = (char *)*esp - alignment;
    if(!check_overflow(*esp)){
      return false;
    }
    memset(*esp, 0, alignment); //fills a block of memory with a value of 0
  }

  //Push address of each string to stack
  for(int i = argc; i >= 0; i--)
  {
   *esp = (char* )*esp - sizeof(char *);
    if(!check_overflow(*esp)){
      return false;
    }
    memcpy(*esp, &arg_address[i], sizeof(char *));
  }

  //Push argv(address of argv[0]) to stack
  void * tmp = *esp;
  *esp = (char *)*esp - sizeof(char **);
  if(!check_overflow(*esp)){
    return false;
  }
  memcpy(*esp, &tmp, sizeof(char**));

  //Push argc to stack
  *esp = (char *)*esp - sizeof(int);
  if(!check_overflow(*esp)){
    return false;
  }
  memcpy(*esp, &argc, sizeof(int));
  
  //Push fake return address
  *esp = (char *)*esp - sizeof(void*);
  if(!check_overflow(*esp)){
    return false;
  }
  memset(*esp, 0, sizeof(void*));

  //free the pages after
  palloc_free_page(fn_copy);
  palloc_free_page(argv);

  return success;
  //everyone drove and update the code here
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}

//A helper method to remove the current children if load fails
void remove_cur_child(int tid){
  struct thread *cur = thread_current();
  struct list_elem *e;
    for (e = list_begin (&cur->children); 
    e != list_end (&cur->children); e = list_next (e))
      {
        struct child_process *c =
         list_entry (e, struct child_process, child_elem);
        if (c->tid == tid) {
          list_remove(e);
          palloc_free_page(c);          
          break;
        }        
      }
}
bool check_overflow(void *esp){
  void *stack_bound = (char*) PHYS_BASE - MAX_STACK_SIZE;
  if(esp < stack_bound || esp >= PHYS_BASE){
    return false;
  }
  return true;
}
//Naomi droved