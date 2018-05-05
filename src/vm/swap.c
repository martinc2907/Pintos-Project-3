#include "swap.h"
#include "threads/malloc.h"
#include <stdio.h>



/* Bitmap represents whether the pages are free. Bit at index represents whether
	page at index is free.
	Each bit represents a page, which is 8 sectors.  */

extern struct swap_table * swap_table_ptr;


/* Create swap table */
//bitmap is initally all set to false. false = block available. true=in use.
void swap_create(void){
	int no_of_pages;

	swap_table_ptr = malloc(sizeof(struct swap_table));
	swap_table_ptr->swap_block = block_get_role(BLOCK_SWAP);
	no_of_pages = block_size(swap_table_ptr->swap_block)/8;
	swap_table_ptr->swap_bitmap = bitmap_create(no_of_pages);
}

/* Write page in RAM to page in Block. */
//return page location in swap block. 
int swap_out(void * kpage){
	int i;
	int index = bitmap_scan_and_flip(swap_table_ptr->swap_bitmap,0,1,false);
	if(index == BITMAP_ERROR){
		printf("FUCKK QUIT\n");
		//no space in swap block.
		//do something.( see manual)
	}

	int sector_index = index * 8;

	for(i = 0; i < 8; i ++){
		block_write(swap_table_ptr->swap_block, sector_index + i , kpage);
		kpage += BLOCK_SECTOR_SIZE;
	}

	return index;
}

/* Write data in swap block to kpage. */
bool swap_in(void * kpage, int bitmap_index){
	int i;
	int sector_index = bitmap_index * 8;
	for(i =0; i < 8; i++){
		block_read(swap_table_ptr->swap_block, sector_index + i,kpage);
		kpage += BLOCK_SECTOR_SIZE;
	}

	bitmap_set(swap_table_ptr->swap_bitmap, bitmap_index ,false);

	return true;
}	

int swap_count(void){
	return bitmap_count(swap_table_ptr->swap_bitmap, 0, bitmap_size(swap_table_ptr->swap_bitmap), true);
}

/* Marks swap slot at index as available. */
void swap_free(int index){
	bitmap_set(swap_table_ptr->swap_bitmap, index, false);
}

void swap_destroy(void){
	//free the global pointer too!!!!!!!!!!!!!
	bitmap_destroy(swap_table_ptr->swap_bitmap);
}