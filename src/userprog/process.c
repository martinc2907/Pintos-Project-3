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
#include "threads/malloc.h"

#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Helper functions */
static struct child * add_child(struct thread * parent, pid_t pid);
static struct child * search_child(pid_t pid);

/* Lock for file system. */
extern struct lock file_lock;


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create info bundle to pass onto child */
  struct info_bundle * bundle  = malloc(sizeof(struct info_bundle));
  bundle->parent = thread_current();
  bundle->file_name = fn_copy;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, bundle);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  

  /* Block until we know load is done */
  sema_down(&thread_current()->load_sema);
  if(thread_current()->load_success == false){
    return -1;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct info_bundle * bundle; 
  char *file_name = bundle->file_name;
  struct intr_frame if_;
  bool success;


  /* ----------------Parsing args declarations ----------------- */
  int i = 0;
  /* For parsing arguments */
  char *token, *save_ptr;

  /* For pushing to stack */
  int token_length;
  uint8_t * filler; /* One byte filler */
  uint32_t * filler_four;  /* Four byte filler */
  filler = malloc(sizeof(uint8_t));
  *filler = 0;
  filler_four = malloc(sizeof(uint32_t));
  *filler_four = 0;
  int token_count = 0;

  /* For storing addresses of parsed tokens */
  char ** parsed_tokens;  /* array of pointers pointing to each token */
  char ** parsed_tokens_copy;//iterator

  /* For storing addresses of tokens that have been stored on stack */
  char ** tokens_on_stack; 
  char ** tokens_on_stack_copy;//iterator

  /* ----------------------------------------------- */

  /* done using bundle. free it. */
  bundle = (struct info_bundle *)aux;
  free(bundle);

  /* Initialise the arrays of pointers. */
  parsed_tokens = palloc_get_page(0);
  parsed_tokens_copy = parsed_tokens;
  tokens_on_stack = palloc_get_page(0);
  tokens_on_stack_copy = tokens_on_stack;

  /* Parse the arguments and store token location in parsed_tokens. */
  for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)){
    *parsed_tokens_copy++ = token;
    token_count++;
  }

  /* Store file name for printing later*/
  thread_current()->file_name = palloc_get_page(0); //palloc here instead of init_thread because of error in init_thread.
  strlcpy( thread_current()->file_name, file_name, strlen(file_name)+1);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);  //file_name points to the same location, but it only refers to the first argument since null termianted. 

  /* Add child(this thread) to parent's children_list */
  struct child * c = add_child(thread_current()->parent,thread_tid());
  if(!success)
    c->exit_status = -1;


  /* Notify parent thread of load status */
  struct thread * parent = thread_current()->parent;
  parent->load_success = success;
  sema_up(&parent->load_sema);  //unblock parent.


  /* If load success, prepare stack. */
  if(success){

    /* Push arguments 
        grep foo bar
        ____
        bar
        ____
        foo
        ____
        grep
        ____
    */
    for(i = token_count-1; i>=0; i--){
      token = *(parsed_tokens+i);
      token_length = strlen(token)+1;

      if_.esp -= token_length;
      memcpy(if_.esp, token, token_length);

      *tokens_on_stack_copy++ = if_.esp; //store the stack addresses of tokens for later.
    }


    /* Word-align stack */
    while((int)if_.esp%4){
      if_.esp -= 1;
      memcpy(if_.esp, filler, 1);
    }

    /* Last argument- Null */
    if_.esp -= 4;
    memcpy(if_.esp, filler_four,4);



    /* Push addresses of arguments in right-to-left order
        grep foo bar
        ____
        bar
        ____
        foo
        ____
        grep
        ____ 
        filler
        ____
        bar address
        ____
        foo address
        ____
        grep address
        ____
    */
    for(i = 0; i<token_count; i++){
      if_.esp -=4;
      memcpy(if_.esp, tokens_on_stack+i,4); //tricky part.
    }

    /* Push address of the latest stack entry. */
    void * temp;
    temp = if_.esp;
    if_.esp -= 4;
    memcpy(if_.esp, &temp ,4);  //tricky part.

    /* Push number of tokens */
    if_.esp -= 4;
    memcpy(if_.esp, &token_count, 4);

    /* Push fake return address */
    if_.esp -= 4;
    memcpy(if_.esp, filler_four, 4);


    free(filler);
    free(filler_four);
    palloc_free_page(parsed_tokens);
    palloc_free_page(tokens_on_stack);
    palloc_free_page(file_name);
  }
  /* If load failed, quit. */
  else{
    free(filler);
    free(filler_four);
    palloc_free_page(parsed_tokens);
    palloc_free_page(tokens_on_stack);
    palloc_free_page(file_name);
    thread_exit();
  }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
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
int
process_wait (tid_t child_tid UNUSED) 
{
  /* Initial thoughts:
    - Create a wait-semaphore(initialised to 1) and pid var in each thread struct.
    - Down semaphore here, and update pid here. 
    - When a thread dies, up semaphore, but semaphore in which thread to up? thread_foreach.
    - Don't know if it will work.
   */

  /* second method:
    - create a global list for each process/thread.
    - Search for tid/pid in the children_list.
    - Always returns -1 regardless of situation.
  */


  /* Return value:
    - terminated by exit-> return status 
    - terminated by kernel (due to error)-> return -1
    - invalid pid ->return -1
      -invalid when wrong pid, or called wait already.
  */

  struct child * c;
  pid_t pid = child_tid;

  c = search_child(pid);
  /* pid invalid */
  if(c == NULL){
    return -1;
  }

  /* If been waited on already */
  if(c->wait_status == true){
    return -1;
  }

  /* Wait for child process to die: blocked if not dead yet. */
  c->wait_status = true;
  sema_down(&c->sema);

  return c->exit_status;  // If kernel shut down process, status will be -1.
}

/* Free the current process's resources. */
void
process_exit (void)
{
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
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
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
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Allocate supplemental page table. */
  t->sup_table = sup_table_create();

  /* Open executable file. */
  lock_acquire(&file_lock);
  file = filesys_open (file_name);
  lock_release(&file_lock);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

    thread_current()->file = file;
    file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
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
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
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
  if (!setup_stack (esp))
    goto done;


  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
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
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
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

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL){
        frame_table_evict_frame();
        kpage = palloc_get_page(PAL_USER);
        ASSERT(kpage != NULL);
      }
      //return false if mem allocation fails. 

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;
  struct thread * cur = thread_current();

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if(kpage == NULL){
    frame_table_evict_frame();
    kpage = palloc_get_page(PAL_USER);
    ASSERT(kpage != NULL);
  }

  success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
  cur->stack_boundary = ((uint8_t *) PHYS_BASE) - PGSIZE;
  cur->stack_size = 0;
  if (success)
    *esp = PHYS_BASE;
  else
    palloc_free_page (kpage);
  

  return success;
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
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();
  //printf("install : %d\n", upage);

  /* Verify that there's not already a page at that virtual address */
  if(pagedir_get_page(t->pagedir, upage) != NULL){
    return false;
  }

  if(pagedir_set_page(t->pagedir, upage,kpage,writable)){
    frame_table_set_frame(upage, t->tid);
    sup_table_set_page(upage, writable);
    return true;
  }
  return false;

  // /* Verify that there's not already a page at that virtual
  //    address, then map our page there. */
  // return (pagedir_get_page (t->pagedir, upage) == NULL
  //         && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/* Helper functions */

static struct child * add_child(struct thread * parent, pid_t pid){

  struct child * c;

  /* Initialise child struct */
  c = malloc(sizeof(struct child));
  c->pid = pid;
  c->wait_status = false;
  sema_init(&c->sema,0);

  /* Insert child struct to children_list */
  list_push_front(&parent->children_list, &c->child_list_elem);//don't forget

  return c;
}

static struct child * search_child(pid_t pid){
  struct list_elem *e;
  struct child * c;
  struct list * children_list;

  children_list = &thread_current()->children_list;
  for(e = list_begin(children_list); e!= list_end(children_list); e=  list_next(e)){
    c = list_entry(e, struct child, child_list_elem);
    if(c->pid == pid){
      return c;
    } 
  }
  return NULL;
}
