#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include <bitmap.h>

struct swap_table * swap_table_ptr;

struct swap_table{
	struct block * swap_block;
	struct bitmap * swap_bitmap;
};


void swap_create(void);
int swap_out(void * kpage);
bool swap_in(void * kpage, int bitmap_index);
void swap_free(int index);
void swap_destroy(void);
int swap_count(void);


#endif
