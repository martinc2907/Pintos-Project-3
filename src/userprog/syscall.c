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
static void init_file_lock(void);

/* Helper functions for checking user pointer validity */
static void check_user_pointer(struct intr_frame *f, void * user_ptr);
static void check_ustack_boundaries(struct intr_frame *f, int no_of_args);

/* Global variable accessed by accessible by all threads. */
struct lock file_lock;

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
			printf("system call!\n");
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

	pid = process_execute(cmd_line);	//blocking until load is done inside process_execute.

	f->eax = pid;
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

	lock_acquire(&file_lock);
	success = filesys_create(file,initial_size);
	lock_release(&file_lock);

	f->eax = success;
}

static void remove_handler(struct intr_frame *f){
	bool success;
	char * file;

	/* Get arguments from user stack */
	file = *((char **)(f->esp + 4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg
	check_user_pointer(f,file);

	lock_acquire(&file_lock);
	success = filesys_remove(file);
	lock_release(&file_lock);

	f->eax = success;
}


static void open_handler(struct intr_frame *f){
	struct file * file;
	char * name;

	/* Get arguments from user stack */
	name = *((char **)(f->esp+4));

	/* Check validity of arguments */
	check_ustack_boundaries(f, 1); //1 arg
	check_user_pointer(f,name);


	lock_acquire(&file_lock);
	file = filesys_open(name);
	/* If open fail, return -1. */
	if(file == NULL){
		lock_release(&file_lock);
		f->eax = -1;
		return;
	}
	/* Assign fd, insert to list. */
	f->eax = add_file_info(file);
	lock_release(&file_lock);

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

	/* Make sure buffer is a valid address. */
	//IMPORTANT: not pg_no, it's pg_round_down.
	void * upage = pg_round_down(buffer);
	if(sup_table_lookup(upage)->writeable != true){
		terminate_thread();
	}

	fi  = search_file_info(fd);
	if(fi == NULL){
		f->eax = 0;
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
		return;
	}


	lock_acquire(&file_lock);
	bytes_read = file_read(fi->file, buffer, size);
	lock_release(&file_lock);

	f->eax = bytes_read;
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
			return;
		}

		lock_acquire(&file_lock);
		bytes_written = file_write(fi->file, buffer, size);
		lock_release(&file_lock);
	}

	f->eax = bytes_written;
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

	/* Check if it's mapped */
	kernel_address = pagedir_get_page(thread_current()->pagedir, user_ptr);
	if(kernel_address == NULL){
		//Call exit with status -1.
		terminate_thread();
		return;
	}

	/* User-ptr is valid if reached here. */	
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


