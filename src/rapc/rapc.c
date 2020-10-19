#include "rapc.h"

#define VECTOR_SIZE 3*100

enum token_type_t {
	NONE,
	STRING,
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
	ushort type;
	ushort start;
	ushort end;
} token_t;

#define token_t_null {NONE, 0, 0}
typedef struct 
{
	short class_no;
	token_t content;
	token_t name;
} field_t;

typedef struct 
{
	short class_no;
	token_t content;
	token_t name;
	token_t args[16];
	token_t returns[16];
	token_t expresses[1024];
	/* data */
} function_t;

typedef struct 
{
	token_t content;
	token_t name;
	token_t defGenericType;
	token_t supers[16];
} class_t;


typedef struct {
	char filename[256];
	ushort filesize;
	char *content;
	ushort import_cnt;
	ushort comment_cnt;
	ushort string_cnt;
	ushort class_cnt;
	token_t package;
	token_t imports[128];
	token_t comments[1024];
	token_t strings[1024];
	class_t classes[32];
	field_t fields[128];
	function_t functions[512];
} source_t;

pcre *rBacket;
pcre *pComma;
int errno;
const char *error;

void printRange(char *str,ushort start, ushort end) {
	char buf[8196];
	strncpy(buf,&str[start],end - start);
	buf[end-start+1] = '\0';
	printf("%s\n", buf);
}


int source_parse(source_t *src) {
	log_d("启动")
	int rc;
	int ovector[VECTOR_SIZE];
	pcre_extra *rsBacket = pcre_study(rBacket,PCRE_MULTILINE|PCRE_EXTRA, &error);
	int start = 0;
	
	while(start < src->filesize) {
		rc = pcre_exec(rBacket, NULL, src->content, src->filesize, start, 0, ovector, VECTOR_SIZE);
		if(rc >= 0) {
			printRange(src->content, ovector[0], ovector[1]);
			start = ovector[1];
		}else {
			break;
		}
	}

	return 0;
}


int source_load(source_t *src) {
	FILE *fp = fopen(src->filename, "r");
	assert(fp != NULL);
	errno = fseek(fp,0,SEEK_END);
	assert(errno == 0);
	int filesize = ftell(fp);
	errno = fseek(fp,0,SEEK_SET);
	assert(errno == 0);
	src->filesize = filesize;
	src->content = malloc(filesize+1);
	fread(src->content,filesize,filesize,fp);
	src->content[filesize] = '\0';
	errno = fclose(fp);
	assert(errno == 0);
	return 0;
}


int source_init(source_t *src, char *filename) {
	log_d("启动")
	rBacket = pcre_compile("\\{(([^{}]*|(?R))*)\\}", 0, &error,&errno,NULL);
	pComma = pcre_compile("\\((([^()]*|(?R))*)\\)", 0, &error,&errno,NULL);
	assert(rBacket != NULL);
	assert(pComma != NULL);


	strcpy(src->filename,filename);
	src->filename[strlen(filename)] = '\0';
	src->package.type = NONE;
	source_load(src);
	
	source_parse(src);
	
	pcre_free(rBacket);
	pcre_free(pComma);

	printf(">>>>>>>>>>> %s >>>>>>>>>>>\n%s\n<<<<<<<<<<< %s <<<<<<<<<<<\n", src->filename, src->content, src->filename);
}

int main(int argc,char* argv[]){
	log_d("启动")
	source_t src;
	source_init(&src, argv[1]);
	return 0;
}