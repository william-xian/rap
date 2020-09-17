#include <stdlib.h>
#include<stdio.h>

typedef struct {
	void *p;
	int status;
} rp_heap_item;

typedef struct {
	unsigned int capacity;
	unsigned int size;
	rp_heap_item* data;
} rp_heap;

void rp_heap_init(rp_heap *p,unsigned int capacity) {
	p->capacity=capacity;
	p->size=0;
	p->data = malloc(sizeof(rp_heap_item)*capacity);
}

void rp_heap_destroy(rp_heap *p) {
	free(p->data);
}

void* rp_heap_ref(void* obj) {
	
	return obj;
}


int main(int argc,char* argv[]){
	rp_heap rp;
	rp_heap_init(&rp,1024);
	printf("size=%d,capacity=%d\n",rp.size,rp.capacity);
	rp_heap_destroy(&rp);
	return 0;
}
