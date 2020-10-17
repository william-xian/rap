/*
 * rapc.h
 *
 * Author: Liar
 */

#ifndef _RAPC_H
#define _RAPC_H
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<assert.h>
#include<pcre.h>

#define rp_a_(T) \
typedef struct { \
	int capacity; \
	int size; \
	T *pAddr; \
} rp_a_##T;\
\
rp_a_##T * rp_a_new_##T\
(int capcaity) { \
	rp_a_##T *arr = malloc(sizeof(rp_a_int));\
	arr->size = 0;\
	arr->capacity = capcaity;\
	arr->pAddr = (void*)malloc(sizeof(T)*arr->capacity); \
	return arr;\
}\
void rp_a_init_##T\
(rp_a_##T arr,int capcaity) { \
	arr.size = 0;\
	arr.capacity = capcaity;\
	arr.pAddr = (void*)malloc(sizeof(T)*arr.capacity); \
}\
void rp_a_push_##T\
(rp_a_##T *arr, T value) { \
	if(arr == NULL){\
		return;\
	}\
	if(arr->size  == arr->capacity){\
		T *newSpace = malloc(sizeof(T) * arr->capacity*2);\
		memcpy(newSpace, arr->pAddr, arr->capacity  * sizeof(T));\
		free(arr->pAddr);\
		arr->capacity = arr->capacity * 2;\
		arr->pAddr = newSpace;\
	}\
	arr->pAddr[arr->size] = value;\
	arr->size++;\
}\
void rp_a_push_n_##T\
(rp_a_##T *arr,int n, T* value) { \
	if(arr == NULL){\
		return;\
	}\
	if(arr->size+n  >= arr->capacity){\
		T *newSpace = malloc(sizeof(T) * arr->capacity*2);\
		memcpy(newSpace, arr->pAddr, arr->capacity  * sizeof(T));\
		free(arr->pAddr);\
		arr->capacity = arr->capacity * 2;\
		arr->pAddr = newSpace;\
	}\
	for(int i =0;i < n; i++) arr->pAddr[arr->size++] = *(value++);\
}\
\
void rp_a_free_##T(rp_a_##T *arr) {\
	if(arr == NULL){\
		return;\
	}\
	if(arr->pAddr != NULL){\
		free(arr->pAddr);\
	}\
	free(arr);\
}


rp_a_(int)
rp_a_(char)

typedef rp_a_char string;

string* string_new(const char* src) {
	int len = strlen(src);
	string *p = rp_a_new_char(len+1);
	p->size = len;
	p->capacity = len+1;
	strcpy(p->pAddr,src);
	return p;
}

#define log_d(...) printf("%s:%d D ",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\n");
#define log_i(...) printf("%s:%d",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\n");
#define log_w(fmt, args...) printf(fmt,##arg);
#define log_e(fmt, args...) printf(fmt,##arg);
 
#endif /* _RPC_H */

