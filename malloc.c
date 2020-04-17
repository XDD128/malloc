#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ALIGN_SIZE 16
#define CHUNK_SIZE 65536

void *first_header = NULL;
char *last_block = NULL;
void *current_ceiling;
void *current_alloc_break;

char DEBUG_MODE = 0;


/*
TODO: make sbrk automator at the end, modulo the size and add it so we can 
allocate more memory
*/
struct header{

    size_t alloc_size;
    size_t this_chunk_size;
    struct header *prev;
    struct header *next;
    int free_flag;

};

/*only works if subsequent and aligned, so make it aligned*/
struct header *merge_with_next(struct header *current){
    size_t total_chunk_size = sizeof(struct header) + 
    current -> next -> alloc_size;
    current -> alloc_size += total_chunk_size;
    current -> this_chunk_size += total_chunk_size;
    current -> next = (current -> next -> next);

    return current;
}

/*assume that this current header has its free flag as 1*/
/*this also only works with free, a different one must be used with realloc 
cause the flag*/
struct header *merge(struct header *current){
    while (current->next && current->free_flag == 1){
        merge_with_next(current);
    }

    while (current->prev && current->prev->free_flag == 1){
        current = merge_with_next(current->prev);
    }

    return current;
}

/*assume 16 byte aligned memory*/
char *get_first_byte(char *ptr){
    size_t location = (size_t)ptr;
    return (char*)(location - (location % ALIGN_SIZE));

}
size_t align(size_t size){
    return size + (ALIGN_SIZE - (size % ALIGN_SIZE));
}

/*return a pointer to the header of the given block pointer*/
struct header *get_header(void *block){
    return (block - 1);
}

int ask_for_more_memory(size_t size){
    /*it divides the chunk*/ 
    size_t ask_size = size + (CHUNK_SIZE - (size % CHUNK_SIZE));
    void *current_end = sbrk(0);
    void *next_sbrk = sbrk(ask_size);
    /*sbrk failed*/
    if (next_sbrk == 1){
        return 0;
    }
    else{
        return 1;
    }
}
/*if needed, initially align the pointer to sbrk to something divisible by 16*/
void align_sbrk(){
    void *current_sbrk = sbrk(0);
    sbrk(ALIGN_SIZE - ((size_t)current_sbrk % ALIGN_SIZE));
}

int distance_from_ceiling(void *ptr){
    char *current_ceiling = sbrk(0);
    return (int)(current_ceiling - (char*)ptr);
}

/*distance from block to next header*/
size_t size_of_total_chunk(struct header *current){
    /*return the distance between the end of current header and beginning of 
    next*/
    return (size_t)((char*)(current->next)-(char*)(current+1));
}


void *malloc(size_t size){
    struct header *this_header;
    /*base case, return NULL for a size of 0 or less*/
    if (size <= 0){
        return NULL;
    }

    size_t total_chunk_size = (sizeof(struct header) + align(size));

    /*initialize globals if first call to malloc*/
    if (!first_header){
        DEBUG_MODE = getenv("DEBUG_MALLOC");
        /*This is where the first chunk of memory will start*/
        this_header = sbrk(0);
        /*If this sbrk succeeds, we will have 64k bytes to work with*/
        /*void *new_chunk_start = sbrk(CHUNK_SIZE);
        /*both pointers should be equal, if returned -1, then failed
        if (new_chunk_start == -1){
            /*if we cannot allocate memory, return NULL
            return NULL;
        }
        */
        if (!ask_for_more_memory(size)){
            return NULL;
        }
        /*if (this_header == new_chunk_start)*/
        else{
        /*at this point, we have allocated a chunk, now we can setup the first 
        block*/
        /*TODO, fix this section with accounting for bigger than 64k chunk*/
        this_header -> alloc_size = align(size);
        this_header -> prev = NULL;
        this_header -> next = NULL;
        this_header -> free_flag = 0;
        first_header = this_header;
        }
        

    }

    /*General Case: Find an existing free block or allocate a new one*/
    else{
        struct header *prev_header;
        this_header = first_header;
        
        /*check if the current header isnt null, then check if the block isn't
         free or bigger than the available chunk */
        while (this_header && ((this_header -> free_flag == 0) | 
        (this_header -> alloc_size < align(size)))){
            prev_header = this_header;
            this_header = this_header->next;
        }

        /*if its NULL, this is the last block, so if we have space, allocate 
        using this*/
        if (this_header == NULL)
        {
            void *current_ceiling = sbrk(0);
            struct header *possible_header = ((char*)(prev_header + 1) + 
            prev_header -> alloc_size);
            
            /*if the next place we can put the pointer to the next block is 
            sizeable enough*/
            if (distance_from_ceiling(possible_header) >= total_chunk_size){
                this_header = possible_header;
                this_header -> prev = prev_header;
                this_header -> next = NULL;
                this_header -> free_flag = 0;
                this_header -> alloc_size = align(size);
                
            }
            /*unti we get enough memory, loop sbrk*/
            else{

                if (!ask_for_more_memory(total_chunk_size)){
                    return NULL;
                }
                this_header = possible_header;
                this_header -> prev = prev_header;
                this_header -> next = NULL;
                this_header -> free_flag = 0;
                this_header -> alloc_size = align(size);

            }
            
        }
        
        /*if we found a suitable existing block, just repurpose it*/
        /*merging memory takes care*/
        else if (this_header -> free_flag == 1 && 
        (align(size) <= (this_header->alloc_size))){
            /*mark it as not free anymore, resize it, return the pointer 
            to the block*/
            this_header -> free_flag = 0;
            this_header -> alloc_size = align(size);
            /*TODO, if it doesn't work, add support for the new variable 
            this_chunk size*/


            size_t total_chunk_size = size_of_total_chunk(this_header);
            if (total_chunk_size - this_header->alloc_size
             >= (sizeof(struct header))){
                struct header *next_free_header = 
                (struct header *)
                ((char*)(this_header + 1)+this_header->alloc_size);
                next_free_header -> free_flag = 0;
                next_free_header -> alloc_size = 
                total_chunk_size - 
                (this_header->alloc_size + sizeof(struct header)); 
                /*put this new header between the two existing ones
                in the linked list*/
            
                next_free_header -> next = this_header -> next;
                next_free_header -> next -> prev = next_free_header;
                this_free_header -> next = next_free_header;

            }
            return (this_header + 1);
        }


        /*CASE 1: find a header+memory block suitable for
         this call, size of block <= requested size*/
    }
    
    return (this_header + 1);
}

void *calloc(size_t nmemb, size_t size){
    size_t total_size = size*nmemb;
    void *this_block = malloc(total_size);
    if (this_block != NULL){
        memset(this_block, 0, total_size);
    }
    return this_block;
}

void free(void *ptr){
    if (ptr == NULL){
        return NULL;
    }
    struct header *this_header = get_header(ptr);
    this_header -> free_flag = 1;

    size_t total_chunk_size = size_of_total_chunk(this_header);
    if (total_chunk_size > (this_header -> alloc_size)){
        this_header -> alloc_size = total_chunk_size;
    }
    /*merge prev and next blocks if they are also freed*/
    merge(this_header);
}

void *realloc(void *ptr, size_t size){
    /*merge(ptr);*/
    if (!ptr){
        return NULL;
    }
    /*behaves as free*/
    if (size = 0){
        free(ptr);
        return;
    }

    if (NULL){

    }

}