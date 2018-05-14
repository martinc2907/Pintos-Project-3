/* Supplementary page table
	Per process, not global- since virtual addresses could overlap
	 between different processes.*/
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include <hash.h>


/* Constants that define where the page is located. */
enum page_location {ALL_ZERO, IN_RAM, IN_SWAP, IN_FILESYS};

struct sup_table{
	struct hash supplementals;
};

struct sup_table_entry{
	struct hash_elem hash_elem;
	enum page_location location;
	void * upage;	/* Page In RAM- don't really need to store this. */
	int index; 		/* Page in Swap slot-bitmap index */
					/* Page in filesys */
	bool writeable; 
};


struct sup_table * sup_table_create(void);
void sup_table_set_page(void * upage, bool writeable);
void sup_table_location_to_RAM(void * upage, struct thread * t);
void sup_table_location_to_SWAP(void * upage, int index, struct thread * t);
void sup_table_location_to_FILE(void * upage, int fd, struct thread * t);	//change this later.
struct sup_table_entry * sup_table_lookup(void * upage, struct thread * t);
void sup_table_destroy(struct sup_table * st);
void sup_table_delete_entry(void * upage);


#endif
