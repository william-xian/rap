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

#define rap_a_(T) \
typedef struct { \
	int capacity; \
	int size; \
	T *pAddr; \
} rap_a_##T;\
\
rap_a_##T * rap_a_new_##T\
(int capcaity) { \
	rap_a_##T *arr = malloc(sizeof(rap_a_int));\
	arr->size = 0;\
	arr->capacity = capcaity;\
	arr->pAddr = (void*)malloc(sizeof(T)*arr->capacity); \
	return arr;\
}\
void rap_a_init_##T\
(rap_a_##T arr,int capcaity) { \
	arr.size = 0;\
	arr.capacity = capcaity;\
	arr.pAddr = (void*)malloc(sizeof(T)*arr.capacity); \
}\
void rap_a_push_##T\
(rap_a_##T *arr, T value) { \
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
void rap_a_push_n_##T\
(rap_a_##T *arr,int n, T* value) { \
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
void rap_a_free_##T(rap_a_##T *arr) {\
	if(arr == NULL){\
		return;\
	}\
	if(arr->pAddr != NULL){\
		free(arr->pAddr);\
	}\
	free(arr);\
}


rap_a_(int)
rap_a_(char)

typedef rap_a_char string;

string* string_new(const char* src) {
	int len = strlen(src);
	string *p = rap_a_new_char(len+1);
	p->size = len;
	p->capacity = len+1;
	strcpy(p->pAddr,src);
	return p;
}

#define log_d(...) printf("%s:%-4d D ",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\n");
#define log_i(...) printf("%s:%-4d I ",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\n");
#define log_w(...) printf("%s:%-4d W ",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\n");
#define log_e(...) printf("\033[31m%s:%-4d E ",__FILE__,__LINE__);printf(__VA_ARGS__);printf("\033[0m\n");
 
#endif /* _RPC_H */

