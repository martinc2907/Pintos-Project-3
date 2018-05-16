#include "frame.h"

#include <stdio.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/swap.h"
#include "vm/page.h"

extern struct frame_table * ft;
struct list evict_list;
extern struct lock frame_table_lock;
extern struct lock file_lock;
struct list_elem * clock;	//algo checks from the next el where clock points. 

static unsigned frame_hash(const struct hash_elem *f_, void * aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,void * aux UNUSED);
static void free_each_entry(struct hash_elem * e, void * aux);


/* Creates frame table for all the processes. This should be initalised
	in init.c */
void frame_table_create(int max_size_){
	// printf("CREATING FRAME TABLE\n");
	ft = malloc(sizeof (struct frame_table));
	ft->max_size = max_size_;	//replace with the number of avaialble physical frames.
	hash_init(&ft->frames, frame_hash,frame_less,NULL);
	list_init(&evict_list);
	lock_init(&frame_table_lock);
}


/* Makes a frame table entry that points to upage. 
	This is only called when RAM has space for more pages.
	Used like this:  if(palloc != null), ~. if(palloc == null),~.
*/
void frame_table_set_frame(void * upage, int tid){
	// printf("setting frame\n");
	ASSERT(hash_size(&ft->frames) < ft->max_size);
	ASSERT(frame_table_lookup(upage, tid)== NULL);

	lock_acquire(&frame_table_lock);

	struct frame_table_entry * f = malloc(sizeof(struct frame_table_entry));
	f->upage = upage; 
	f->tid = tid;
	f->pinned = false;
	f->owner_thread = thread_current();
	hash_insert(&ft->frames, &f->hash_elem);
	list_push_front(&evict_list,&f->list_elem);

	/* Make clock point to the only element. */
	if(list_size(&evict_list)==1){
		clock = list_front(&evict_list);
	}
	ASSERT(clock!=NULL);

	lock_release(&frame_table_lock);

	ASSERT(frame_table_lookup(upage,tid)!= NULL);
}



/* Evict a frame- second chance algorithm w/ clock.  */
void frame_table_evict_frame(){

	uint32_t * pagedir = thread_current()->pagedir;
	void * kpage;
	void * upage;
	struct frame_table_entry * fte;
	struct hash_elem * e;
	struct list_elem * le;

	lock_acquire(&frame_table_lock);

	//examine from clock element.
	le = clock;
	while(true){
		fte = list_entry(le, struct frame_table_entry, list_elem);
		upage = fte->upage;
		if(!pagedir_is_accessed(pagedir, upage)){
			if(fte->pinned == false){
				clock = list_next(le);
				if(clock == list_end(&evict_list)){
					clock = list_front(&evict_list);
				}
				break;
			}
		}else{
			pagedir_set_accessed(pagedir, upage, false);
		}
		le = list_next(le);
		if(le == list_end(&evict_list)){
			le = list_front(&evict_list);
		}
	}

	/* Delete from hash table and list. */
	e = hash_delete(&ft->frames,&fte->hash_elem);
	ASSERT(e != NULL);
	list_remove(&fte->list_elem);
	ASSERT(hash_size(&ft->frames) == list_size(&evict_list));


	/* Frame table entry points to upage. Get kpage. */
	struct thread * owner_thread = thread_current();
	fte = hash_entry(e, struct frame_table_entry, hash_elem);
	upage = fte->upage;
	//what if evicted page is owned by different pid?
	owner_thread = fte->owner_thread;
	pagedir = owner_thread->pagedir;
	kpage = pagedir_get_page(owner_thread->pagedir, upage);

	// kpage = pagedir_get_page(pagedir, upage);
	// if(kpage == NULL){
	// 	//evicted page owned by different thread.
	// 	owner_thread = fte->owner_thread;
	// 	pagedir = owner_thread->pagedir;
	// 	kpage = pagedir_get_page(pagedir, upage);
	// }

	/* Free the entry */
	free(fte);
	
	struct sup_table_entry * ste = sup_table_lookup(upage,owner_thread);

	// A frame has been allocated to the page, so it was tarnsferrd to RAM at one point.
	/* File system. */
	if(ste->from_file){
		ASSERT(pagedir_get_page(owner_thread->pagedir, upage)!= NULL);
		/* Write out to swap if dirtied. */
		if(pagedir_is_dirty(owner_thread->pagedir, upage)){
			int swap_location = swap_out(kpage);
			palloc_free_page(kpage);

			sup_table_location_to_SWAP(upage, swap_location, owner_thread);
			pagedir_clear_page(owner_thread->pagedir, upage);
			lock_release(&frame_table_lock);
		}

		/* Page only accessed, not dirtied. */
		else{
			palloc_free_page(kpage);
			sup_table_location_to_FILE(upage, ste->file, ste->offset, ste->read, ste->zero, owner_thread);
			pagedir_clear_page(owner_thread->pagedir, upage);
			lock_release(&frame_table_lock);
		}
	}

	/* Swap slots. */
	else{
		//printf("swap:%u\n", (int) upage);
		/* Swap out this page to swap slot, then free the physical frame. */
		int swap_location = swap_out(kpage);
		palloc_free_page(kpage);

		/* Update sup table and page table. */
		sup_table_location_to_SWAP(upage, swap_location, owner_thread);
		pagedir_clear_page(owner_thread->pagedir, upage);

		ASSERT(hash_size(&ft->frames)!=1);
		lock_release(&frame_table_lock);
	}

}


/* Look up the frame that points to upage. */
struct frame_table_entry * frame_table_lookup(void * upage, int tid){
	struct frame_table_entry fte;
	struct hash_elem * e;

	lock_acquire(&frame_table_lock);
	fte.upage = upage;
	fte.tid = tid;
	e = hash_find(&ft->frames,&fte.hash_elem);
	lock_release(&frame_table_lock);

	return e == NULL ? NULL : hash_entry(e, struct frame_table_entry, hash_elem);
}

/* Delete and free entry */
void frame_table_delete_entry(void * upage, int tid){
	lock_acquire(&frame_table_lock);
	struct hash_elem * e;
	struct frame_table_entry * p;

	struct frame_table_entry fte; 
	fte.upage = upage;
	fte.tid = tid;

	e = hash_delete(&ft->frames,&fte.hash_elem);
	ASSERT(e!=NULL);
	p = hash_entry(e, struct frame_table_entry, hash_elem);
	//ASSERT(clock != &p->list_elem); 	//if caught here, make sure to update clock.
	if(clock == &p->list_elem){
		clock = list_next(&p->list_elem);
	}
	list_remove(&p->list_elem);
	free(p);
	lock_release(&frame_table_lock);
}

void frame_table_destroy(void){
	hash_destroy(&ft->frames, free_each_entry);
}

static void free_each_entry(struct hash_elem * e, void * aux){
	struct frame_table_entry * fte = hash_entry(e, struct frame_table_entry, hash_elem);
	free(fte);
}


/* ------------------- Essential hash table functions ------------------------ */

/* Hash function
	- Hash using the virtual address of user page as the key.
	- Since sharing is not implemented, it should be unique. 
 */
static unsigned frame_hash(const struct hash_elem *f_, void * aux UNUSED){
	const struct frame_table_entry *f = hash_entry(f_, struct frame_table_entry, hash_elem);
	int hash_this = hash_bytes(&f->upage, sizeof(f->upage)) ^ hash_bytes(&f->tid, sizeof(f->tid));
	return hash_this;
}


/* Comparison function for finding frame inside a bucket.
	- Returns true if frame a precedes frame b
	- Compares the upage address.
 */
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
					void * aux UNUSED){
	// const struct frame_table_entry * a = hash_entry(a_, struct frame_table_entry, hash_elem);
	// const struct frame_table_entry * b = hash_entry(b_, struct frame_table_entry, hash_elem);

	/* Modified this function a little. */
	unsigned a_hash = frame_hash(a_, NULL);
	unsigned b_hash = frame_hash(b_,NULL);
	/* Rmb, this function just checks whether the elements inside the same bucket are equal. */
	//return (a->upage < b->upage) && (a->tid < b->tid);
	return a_hash > b_hash;
}

