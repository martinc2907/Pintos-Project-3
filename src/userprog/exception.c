#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/frame.h" 
#include "vm/page.h"

#define STACK_LIMIT 1048576

/* Number of page faults processed. */
static long long page_fault_cnt;

/* Page fault lock */
extern struct lock page_fault_lock;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);
static void stack_grow(void);
static bool
install_page (void *upage, void *kpage, bool writable);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* Initialise page fault lock. */
  lock_init(&page_fault_lock);

  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Lock on */
  lock_acquire(&page_fault_lock);

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  struct thread * cur = thread_current();
  void * upage = (void *) pg_round_down(fault_addr);
  void * kpage;
  struct sup_table_entry * ste = sup_table_lookup(upage,cur);


  /* Stack growth if necessary */
  //first check if within stack boundaries. 
  if( fault_addr < PHYS_BASE && fault_addr >= PHYS_BASE - STACK_LIMIT){
    if(user){
      if(fault_addr >= f->esp || f->esp-4== fault_addr || f->esp-32 == fault_addr){
        if(ste == NULL){
          stack_grow();
          lock_release(&page_fault_lock);
          return;
        }
      }
    }else{
      void * esp = thread_current()->user_esp;
      void * stack_boundary = thread_current()->stack_boundary;
      if(fault_addr < stack_boundary){
        stack_grow();
        lock_release(&page_fault_lock);
        return;
      }
    }
  }

  // Page faults can be caused by user/kernel threads. We are trying to handle user threads.
  if(user){
    /* Before dealing with page fault, make sure no other process is dealing with page fault. */
    //have a page fault lock or disable interrupts?

    /* Check if invalid access- kernel or writing r/o */
    if( fault_addr == NULL ||is_kernel_vaddr(fault_addr) || 
          (write && !not_present) || ste == NULL){
      lock_release(&page_fault_lock);
      terminate_thread();
    }
    
    enum page_location location = ste->location;
    switch(location){

      case ALL_ZERO:
        //terminate thread and free all resources
        lock_release(&page_fault_lock);
        terminate_thread();
        break;

      case IN_RAM:
        //page fault shouldn't have occurred, wtf?
        //it could occur before implementing synchronisation. 
        ASSERT(false);
        break;

      case IN_SWAP:
        /* Obtain a frame- factor this? */
        kpage = palloc_get_page(PAL_USER);
        if(kpage == NULL){
          frame_table_evict_frame();
          kpage = palloc_get_page(PAL_USER);
          ASSERT(kpage != NULL);
        }

        /* Copy data into frame */
        swap_in(kpage, ste->index);

        /* Update tables */
        pagedir_set_page(cur->pagedir, upage, kpage, ste->writeable);
        sup_table_location_to_RAM(upage,cur); //this must be called after swap in like so, since index gets altered.
        frame_table_set_frame(upage, cur->tid);
        break;

      case IN_FILESYS:
        //same thing as IN_SWAP.
        //not implemented yet, so 
        ASSERT(false);
        break;
    }
    lock_release(&page_fault_lock);
    return;
  }

  //How to handle kernel page faults?
  else{
    lock_release(&page_fault_lock);

    printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
    kill (f);

  }



  // /* To implement virtual memory, delete the rest of the function
  //    body, and replace it with code that brings in the page to
  //    which fault_addr refers. */
  // printf ("Page fault at %p: %s error %s page in %s context.\n",
  //         fault_addr,
  //         not_present ? "not present" : "rights violation",
  //         write ? "writing" : "reading",
  //         user ? "user" : "kernel");
  // kill (f);
}

static void stack_grow(void){
  struct thread * cur = thread_current();
  uint8_t * stack_boundary = cur->stack_boundary;

  /* Stack limit- 8MB */
  if(cur->stack_size >= STACK_LIMIT){
    printf("term pf error\n");
    lock_release(&page_fault_lock);
    terminate_thread();
  }

  void * kpage = palloc_get_page (PAL_USER|PAL_ZERO);
  if(kpage == NULL){
    frame_table_evict_frame();
    kpage = palloc_get_page(PAL_USER);
    ASSERT(kpage!=NULL);
  }

  uint8_t * new_stack_boundary = stack_boundary - PGSIZE;
  //do i need to check success?
  install_page(new_stack_boundary,kpage,true);
  cur->stack_boundary = new_stack_boundary;
  cur->stack_size += PGSIZE;
}

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

