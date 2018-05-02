#include "page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <stdio.h>


/* 
Locate the page that faulted in the supplemental page table. If the memory reference
is valid, use the supplemental page table entry to locate the data that goes in the page,
which might be in the file system, or in a swap slot, or it might simply be an all-zero
page. If you implement sharing, the page’s data might even already be in a page frame,
but not in the page table.


Supplemental page table and page fault handler
Change ‘process.c’ to record the necessary information
in the supplemental page table when loading an executable and 
setting up its stack. Implement loading of code and data segments 
in the page fault handler. For now, consider only valid accesses.
After this step, your kernel should pass all of the project 2 
functionality test cases, but only some of the robustness tests.
*/

static unsigned sup_table_hash(const struct hash_elem *p_, void * aux UNUSED);
static bool sup_table_less(const struct hash_elem *a_, const struct hash_elem *b_,
					void * aux UNUSED);
static void free_each_entry(struct hash_elem * e, void * aux);

/* Creates a supplemental page table. 
	Should be called in thread_create or something. */
struct sup_table * sup_table_create(void){
	// printf("CREATING SUP TABLE\n");
	struct sup_table * st;

	st = malloc(sizeof(struct sup_table));
	hash_init(&st->supplementals, sup_table_hash,sup_table_less,NULL);
	return st;
}

/* Makes a supplemental page table entry that contains information about a 
	virtual page(upage). Since the page will be placed in RAM when this is called,
	initialise the page's location as RAM. */
void sup_table_set_page(void * upage, bool writeable){
	struct sup_table_entry * ste;
	struct thread * cur = thread_current();
	struct sup_table * s_t = cur->sup_table;

	//make sure the sup table entry doesn't already exist. 
	ASSERT(sup_table_lookup(upage) == NULL);

	/* Make entry in sup table */
	ste = malloc(sizeof(struct sup_table_entry));
	ste->location = IN_RAM;
	ste->writeable = writeable; 
	ste->upage = upage;
	ste->index = -1;

	//inserts element. 
	hash_insert(&s_t->supplementals, &ste->hash_elem);
}


/* Modifies the location of the page. (IN_RAM? IN_FILESYS? IN_SWAP?) */
/* Remember, upage has to be valid all the time for hashing. cannot be null */
void sup_table_location_to_RAM(void * upage){
	/* Make sure entry exists in the table already. */
	ASSERT(sup_table_lookup(upage)!= NULL);

	struct sup_table_entry * ste = sup_table_lookup(upage);
	ste->location = IN_RAM;
	ste->index = -1;	/* invalidate the index */
						/* invalidate file descriptor. */
}

void sup_table_location_to_SWAP(void * upage, int index){
	ASSERT(sup_table_lookup(upage)!= NULL);

	struct sup_table_entry * ste = sup_table_lookup(upage);
	ste->location = IN_SWAP;
	ste->index = index;	
						/* invalidate the file descriptor. */
}

void sup_table_location_to_FILE(void * upage, int fd){
 	ASSERT(sup_table_lookup(upage)!= NULL);

 	struct sup_table_entry * ste = sup_table_lookup(upage);
 	ste->location = IN_FILESYS;

 	//Do stuff. 
}

//Look up the frame.
struct sup_table_entry * sup_table_lookup(void * upage){
	struct thread * cur = thread_current();
	struct sup_table * st = cur->sup_table;
	struct sup_table_entry ste;
	struct hash_elem * e;

	ste.upage = upage;
	e = hash_find(&st->supplementals,&ste.hash_elem);

	return e == NULL ? NULL : hash_entry(e, struct sup_table_entry, hash_elem);
}


void sup_table_destroy(struct sup_table * st){
	hash_destroy(&st->supplementals, free_each_entry);
}

static void free_each_entry(struct hash_elem * e, void * aux){
	struct sup_table_entry * ste = hash_entry(e, struct sup_table_entry, hash_elem);
	free(ste);
}
/* ------------------- Essential hash table functions ------------------------ */

/* Hash function: hash using the virtual address of page(upage) as the key. */
static unsigned sup_table_hash(const struct hash_elem *ste_, void * aux UNUSED){
	const struct sup_table_entry *ste = hash_entry(ste_, struct sup_table_entry, hash_elem);
	return hash_bytes(&ste->upage, sizeof(ste->upage));
}

/* Comparison function for finding frame inside a bucket.
	- Returns true if page a precedes page b
	- Compares the upage. */
static bool sup_table_less(const struct hash_elem *a_, const struct hash_elem *b_,
					void * aux UNUSED){
	const struct sup_table_entry * a = hash_entry(a_, struct sup_table_entry, hash_elem);
	const struct sup_table_entry * b = hash_entry(b_, struct sup_table_entry, hash_elem);

	return a->upage < b->upage;
}
