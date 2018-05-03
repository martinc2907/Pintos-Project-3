#include "frame.h"

#include <stdio.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/page.h"

extern struct frame_table * ft;

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
  	// printf("FINISHING FRAME TABLE\n");
}


/* Makes a frame table entry that points to upage. 
	This is only called when RAM has space for more pages.
	Used like this:  if(palloc != null), ~. if(palloc == null),~.
*/
void frame_table_set_frame(void * upage, int tid){
	ASSERT(hash_size(&ft->frames) < ft->max_size);
	ASSERT(frame_table_lookup(upage, tid)== NULL);

	struct frame_table_entry * f = malloc(sizeof(struct frame_table_entry));
	f->upage = upage; 
	f->tid = tid;
	hash_insert(&ft->frames, &f->hash_elem);

	ASSERT(frame_table_lookup(upage,tid)!= NULL);
}



/* Evict a frame.  */
void frame_table_evict_frame(){
	// printf("EVICTION CALLED!!\n");
	/* Evict one randomly for now */
	uint32_t * pagedir = thread_current()->pagedir;
	void * kpage;
	void * upage;

	/* Delete from frame table */
	struct hash_iterator i;
	hash_first(&i,&ft->frames);
	hash_next(&i);
	struct hash_elem * e = hash_delete(&ft->frames,hash_cur(&i));
	ASSERT(e != NULL);

	/* Frame table entry points to upage. Get kpage. */
	struct frame_table_entry * fte = hash_entry(e, struct frame_table_entry, hash_elem);
	upage = fte->upage;
	kpage = pagedir_get_page(pagedir, upage);
	ASSERT(e != NULL);

	/* Free the entry */
	free(fte);
	
	/* Swap out this page to swap slot, then free the physical frame. */
	int swap_location = swap_out(kpage);
	palloc_free_page(kpage);

	/* Update sup table and page table. */
	sup_table_location_to_SWAP(upage, swap_location);
	pagedir_clear_page(pagedir, upage);
}


/* Look up the frame that points to upage. */
struct frame_table_entry * frame_table_lookup(void * upage, int tid){
	struct frame_table_entry fte;
	struct hash_elem * e;

	fte.upage = upage;
	fte.tid = tid;
	e = hash_find(&ft->frames,&fte.hash_elem);

	return e == NULL ? NULL : hash_entry(e, struct frame_table_entry, hash_elem);
}

/* Delete and free entry */
void frame_table_delete_entry(void * upage, int tid){
	struct hash_elem * e;

	struct frame_table_entry fte; 
	fte.upage = upage;
	fte.tid = tid;

	e = hash_delete(&ft->frames,&fte.hash_elem);
	ASSERT(e!=NULL);
	free(hash_entry(e,struct frame_table_entry, hash_elem));
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

