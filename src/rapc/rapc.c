#include "rapc.h"

enum type_t {
	NONE,
	CLASS,
	DEED,
	FIELD,
	FUNCTION,
	INT,
	INT2,
	INT4,
	INT8,
};

typedef struct {
	int type;
	int start;
	int end;
} token_t;

typedef struct 
{
	/* data */
} function_t;

typedef struct {
	char filename[256];
	int filesize;
	char *file;
	token_t package;
	token_t imports[100];
	token_t comments[1000];
	token_t strings[1000];
	token_t type;
	token_t fields[128];
	token_t functions[128];
	function_t function_tokens[128];
} class_t;


	
void class_init(class_t *clazz, char *srcFile) {
	const char *error;
	int errno;
	pcre *p = pcre_compile("\\((([^()]*|(?R))*)\\)",0,&error,&errno,NULL);
	if(p == NULL) {
		printf("ERROR");
	}
}


int main(int argc,char* argv[]){
	class_t clazz;
	class_init(&clazz, argv[1]);
	return 0;
}


