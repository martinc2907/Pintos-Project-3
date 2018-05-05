#ifndef VM_FRAME_H
#define VM_FRAME_H


#include "lib/kernel/hash.h"
#include <hash.h>

struct frame_table * ft;
struct lock frame_table_lock;

struct frame_table{
	struct hash frames;	/* Actual hash table */
	size_t max_size;		/* Max number of frames */
};

struct frame_table_entry{
	struct hash_elem hash_elem;
	struct list_elem list_elem;
	void * upage;	/* Pointer to user page. */
	int tid; 		/* Need to store tid since upage can overlap, since we're dealing with all threads. */
	bool pinned; 	/* Pin frames so they cannot be evicted. */
	struct thread * owner_thread;
};


void frame_table_create(int max_size_);
void frame_table_set_frame(void * upage, int tid);
void frame_table_evict_frame(void);
struct frame_table_entry * frame_table_lookup(void * upage, int tid);
void frame_table_delete_entry(void * upage, int tid);
void frame_table_destroy(void);

#endif
