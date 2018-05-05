#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

#include "userprog/exception.h"
static void syscall_handler (struct intr_frame *);

/* Handler declarations */
static void halt_handler(struct intr_frame *f);
static void exit_handler(struct intr_frame *f);
static void exec_handler(struct intr_frame *f);
static void wait_handler(struct intr_frame *f);
static void create_handler(struct intr_frame *f);
static void remove_handler(struct intr_frame *f);
static void open_handler(struct intr_frame *f);
static void filesize_handler(struct intr_frame *f);
static void read_handler(struct intr_frame *f);
static void write_handler(struct intr_frame *f);
static void seek_handler(struct intr_frame *f);
static void tell_handler(struct intr_frame *f);
static void close_handler(struct intr_frame *f);

/* General helper functions */
static struct child * search_child(struct thread * t, pid_t pid);
static struct file_info * search_file_info(int fd);
static int add_file_info(struct file * f);

/* Helper functions for checking user pointer validity */
static void check_user_pointer(struct intr_frame *f, void * user_ptr);
static void check_ustack_boundaries(struct intr_frame *f, int no_of_args);

//
static void pin_frame(void * uddr);
static void unpin_frame(void * uaddr);


/* Global variable accessed by accessible by all threads. */
struct lock file_lock;

extern struct lock page_fault_lock;

void
syscall_init (void) 
{
	/* We are in kernel code obviously */
	/* Registers handler for interrupt 0x30= just means system call */
	/* second argument is DPL- descriptor privilege level. */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void * user_esp = f->esp;
	check_user_pointer(f,user_esp);	//check if esp is valid.
	int sys_call_no = *((int *)user_esp);
	thread_current()->user_esp = f->esp;	//for page fault handling.

	switch(sys_call_no){
		case SYS_HALT:
			halt_handler(f);
			break;

		case SYS_EXIT:
			exit_handler(f);
			break;

		case SYS_EXEC:
			exec_handler(f);
			break;

		case SYS_WAIT:
			wait_handler(f);
			break;

		case SYS_CREATE:
			create_handler(f);
			break;

		case SYS_REMOVE:
			remove_handler(f);
			break;

		case SYS_OPEN:
			open_handler(f);
			break;

		case SYS_FILESIZE:
			filesize_handler(f);
			break;

		case SYS_READ:
			read_handler(f);
			break;

		case SYS_WRITE:
			write_handler(f);
			break;

		case SYS_SEEK:
			seek_handler(f);
			break;

		case SYS_TELL:
			tell_handler(f);
			break;

		case SYS_CLOSE:
			close_handler(f);
			break;

		default:
			thread_exit();
	}
}



static void halt_handler(struct intr_frame *f){
	shutdown_power_off();
}

static void exit_handler(struct intr_frame *f){
	int exit_status;
	pid_t pid;
	struct thread * cur;
	struct child * c;

	/* Get arguments from user stack */
	exit_status = *((int * )(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg


	cur = thread_current();
	pid = cur->tid;
	c = search_child(cur->parent, pid);

	/* Need to give exit status to child struct owned by parent. */
	if(c != NULL){//c will be null if parent exited already. 
		c->exit_status = exit_status;
		/* Up mutex- unblocks parent if waiting on child */
		sema_up(&c->sema);	
	}

	printf ("%s: exit(%d)\n", thread_current()->file_name,exit_status);
	thread_exit();
}

static void exec_handler(struct intr_frame *f){
	pid_t pid;
	char * cmd_line;

	cmd_line = *((char **)(f->esp+4));
	check_ustack_boundaries(f, 1); //1 arg
	check_user_pointer(f,cmd_line);

	pin_frame(cmd_line);

	pid = process_execute(cmd_line);	//blocking until load is done inside process_execute.

	f->eax = pid;

	unpin_frame(cmd_line);
}


static void wait_handler(struct intr_frame *f){
	pid_t pid;
	int exit_status;

	/* Get arguments from user stack */
	pid = *((int *)(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg

	exit_status = process_wait(pid);

	/* Return child's exit status */
	f->eax = exit_status;
}

static void create_handler(struct intr_frame *f){
	bool success; 
	char * file;
	unsigned initial_size; 

	/* Get arguments from user stack */
	file = *((char **)(f->esp + 4));
	initial_size = *((unsigned *)(f->esp + 8));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 2); //2 arg
	check_user_pointer(f,file);

	pin_frame(file);

	lock_acquire(&file_lock);
	success = filesys_create(file,initial_size);
	lock_release(&file_lock);

	f->eax = success;

	unpin_frame(file);
}

static void remove_handler(struct intr_frame *f){
	bool success;
	char * file;

	/* Get arguments from user stack */
	file = *((char **)(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg
	check_user_pointer(f,file);

	pin_frame(file);

	lock_acquire(&file_lock);
	success = filesys_remove(file);
	lock_release(&file_lock);

	f->eax = success;

	unpin_frame(file);
}


static void open_handler(struct intr_frame *f){
	struct file * file;
	char * name;

	/* Get arguments from user stack */
	name = *((char **)(f->esp+4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg
	check_user_pointer(f,name);

	pin_frame(name);

	lock_acquire(&file_lock);
	file = filesys_open(name);
	/* If open fail, return -1. */
	if(file == NULL){
		lock_release(&file_lock);
		f->eax = -1;
		unpin_frame(name);
		return;
	}
	/* Assign fd, insert to list. */
	f->eax = add_file_info(file);
	lock_release(&file_lock);

	unpin_frame(name);
}

static void filesize_handler(struct intr_frame *f){
	int size;
	int fd;

	/* Get arguments from user stack */
	fd = *((int*)(f->esp+4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg

	struct file_info * fi = search_file_info(fd);

	lock_acquire(&file_lock);
	size = file_length(fi->file);
	lock_release(&file_lock);

	f->eax = size;
}

static void read_handler(struct intr_frame *f){
	int fd;
	void * buffer;
	char * buffer_copy;
	unsigned size;
	struct file_info * fi;
	unsigned bytes_read = 0;

	/* Get arguments from user stack */
	fd = *((int *)(f->esp + 4));
	buffer = *((void **)(f->esp+8));
	size = *((unsigned *)(f->esp+12));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 3); //3 arg
	check_user_pointer(f,buffer);

	pin_frame(buffer);

	/* Make sure buffer is a valid address. */
	//IMPORTANT: not pg_no, it's pg_round_down.
	void * upage = pg_round_down(buffer);
	if(sup_table_lookup(upage, thread_current())->writeable != true){
		terminate_thread();
	}

	fi  = search_file_info(fd);
	if(fi == NULL){
		f->eax = 0;
		unpin_frame(buffer);
		return;
	}

	/* Read from keyboard */
	if(fd == 0){
		buffer_copy = buffer;
		while(bytes_read != size){
			*(buffer_copy) = input_getc();
			bytes_read++;
			buffer_copy++;
		}
		f->eax = bytes_read;
		unpin_frame(buffer);
		return;
	}


	lock_acquire(&file_lock);
	bytes_read = file_read(fi->file, buffer, size);
	lock_release(&file_lock);

	f->eax = bytes_read;

	unpin_frame(buffer);
}

static void write_handler(struct intr_frame * f){
	int bytes_written = 0;
	struct file_info * fi;

	int fd;
	void * buffer;
	unsigned size;

	// printf("write called\n");

	/* Get arguments from user stack */
	fd = *((int *)(f->esp + 4));
	buffer = *((void **)(f->esp + 8));
	size = *((unsigned *)(f->esp + 12));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 3); //3 arg
	check_user_pointer(f,buffer);

	pin_frame(buffer);

	// /* Check if buffer is in writeable section. (pt-write-code-2.c)*/
	// void * upage = pg_no(buffer);//get upage first.
	// //check if upage is writable by checking sup table. 
	// printf("handling write\n");
	// if(sup_table_lookup(upage) == NULL){
	// 	printf("FUCK\n");
	// }
	// if(sup_table_lookup(upage)->writeable != true){
	// 		printf("here1\n");

	// 	terminate_thread();
	// }
	// printf("here2\n");

	/* Write to console */
	if(fd == 1){
		putbuf(buffer, size);
		bytes_written = size;
	}

	else{
		fi = search_file_info(fd);
		if(fi == NULL){
			f->eax = 0;
			unpin_frame(buffer);
			return;
		}

		lock_acquire(&file_lock);
		bytes_written = file_write(fi->file, buffer, size);
		lock_release(&file_lock);
	}

	f->eax = bytes_written;
	unpin_frame(buffer);
}


static void seek_handler(struct intr_frame *f){
	int fd;
	unsigned position;
	struct file_info * fi;

	/* Get arguments from user stack */
	fd = *((int *)(f->esp + 4));
	position = *((unsigned *)(f->esp+8));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 2); //2 arg

	fi = search_file_info(fd);

	lock_acquire(&file_lock);
	file_seek(fi->file,position);
	lock_release(&file_lock);
}

static void tell_handler(struct intr_frame *f){
	int fd;
	int position;
	struct file_info * fi;

	/* Get arguments from user stack */
	fd = *((int *)(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg

	fi = search_file_info(fd);

	lock_acquire(&file_lock);
	position = file_tell(fi->file);
	lock_release(&file_lock);

	f->eax = position;
}

static void close_handler(struct intr_frame *f){
	int fd;
	struct file_info * fi;

	/* Get arguments from user stack */
	fd = *((int *)(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg

	fi = search_file_info(fd);

	if(fi!=NULL){
		lock_acquire(&file_lock);

		file_close(fi->file);
		list_remove(&fi->file_info_elem);
		free(fi);	//free since we don't need the fd anymore once we close. 

		lock_release(&file_lock);
	}
}



/* -------------- Helper function definitions -------------- */

/* Returns child with pid amongst children owned by thread. */
static struct child * search_child(struct thread * t, pid_t pid){
  struct list_elem *e;
  struct child * c;
  struct list * children_list;

  children_list = &t->children_list;
  for(e = list_begin(children_list); e!= list_end(children_list); e=  list_next(e)){
    c = list_entry(e, struct child, child_list_elem);
    if(c->pid == pid){
      return c;
    } 
  }
  return NULL;
}

/* Return file_info struct with specified file descriptor amongst list owned by thread*/
static struct file_info * search_file_info(int fd){
	struct list_elem * e;
	struct list * file_info_list;
	struct file_info * fi;

	file_info_list = &thread_current()->file_info_list;
	for(e = list_begin(file_info_list); e!= list_end(file_info_list); e = list_next(e)){
		fi = list_entry(e, struct file_info, file_info_elem);
		if(fi->fd == fd){
			return fi;
		}
	}
	return NULL;
}


/* Checks if the arguments of the system call crosses the user stack boundary into kernel region. */
static void check_ustack_boundaries(struct intr_frame *f, int no_of_args){
	/* If threads args are not in user region, terminate. */
	if(!is_user_vaddr(f->esp + no_of_args* 4)){
		terminate_thread();
	}
}

/* Checks the validity of pointers handed by user thread. */
static void check_user_pointer(struct intr_frame *f, void * user_ptr){
	void * kernel_address;
	struct thread * cur = thread_current();

	/* Check if NULL */
	if(user_ptr == NULL){
		//Call exit with status -1.
		terminate_thread();
		return;
	}

	/* Check if it doesn't point to user address space */
	if(!is_user_vaddr (user_ptr)){
		//Call exit with status -1.
		terminate_thread();
		return;
	}

	// /* Check if it's mapped */
	// kernel_address = pagedir_get_page(thread_current()->pagedir, user_ptr);
	// if(kernel_address == NULL){
	// 	//Call exit with status -1.
	// 	terminate_thread();
	// 	return;
	// }

	lock_acquire(&page_fault_lock);

	/* Check if mapped somewhere */
	void * upage = pg_round_down(user_ptr);
	struct sup_table_entry * ste = sup_table_lookup(upage,cur);
	if(ste == NULL){
		terminate_thread();
		return;
	}
	if(ste->location != IN_RAM){
		/* Must bring into RAM through eviction */
		void * kpage = palloc_get_page(PAL_USER);
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
	}
	lock_release(&page_fault_lock);

	/* User-ptr is valid if reached here. */	

}

static void pin_frame(void * uaddr){
	void * upage = pg_round_down(uaddr);
	struct thread * cur = thread_current();

	lock_acquire(&page_fault_lock);

	/* Do pinning frame */
	struct frame_table_entry * fte;
	fte = frame_table_lookup(upage, cur->tid);
	ASSERT(fte!= NULL);
	fte->pinned = true;

	lock_release(&page_fault_lock);

}

static void unpin_frame(void * uaddr){
	void * upage = pg_round_down(uaddr);
	struct thread * cur = thread_current();

	lock_acquire(&page_fault_lock);

	/* Do pinning frame */
	struct frame_table_entry * fte;
	fte = frame_table_lookup(upage, cur->tid);
	ASSERT(fte!= NULL);
	fte->pinned = false;

	lock_release(&page_fault_lock);
}

/* Function similar to exit_handler. Newly defined with -1 exit status because esp might be invalid. */
void terminate_thread(){
	struct thread * cur;
	int pid;
	struct child * c;

	int exit_status = -1;

	cur = thread_current();
	pid = cur->tid;

	c = search_child(cur->parent, pid);

	/* Need to give exit status to child struct owned by parent. */
	if(c != NULL){//c will be null if parent exited already. 
		c->exit_status = exit_status;
		/* Up mutex */
		sema_up(&c->sema);	
	}

	printf ("%s: exit(%d)\n", thread_current()->file_name,exit_status);
	thread_exit(); //CHECK IF I NEED TO FREE EVERYTHING.
}

/* Add file info */
static int add_file_info(struct file * f){
	struct thread * cur = thread_current();
	struct file_info * fi = malloc(sizeof(struct file_info));

	fi->file = f;
	fi->fd = cur->max_fd;
	cur->max_fd = cur->max_fd +1;

	/* Insert into thread's list of file_infos */
  	list_push_front(&cur->file_info_list, &fi->file_info_elem);

  	return (fi->fd);
}


