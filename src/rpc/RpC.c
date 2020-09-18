#include<stdlib.h>
#include<stdio.h>
#include "RpC.h"

typedef struct {
	string name;
} import_item_t;


rp_a_(import_item_t)

typedef struct {
	string name;
} func_item_t;

rp_a_(func_item_t)

typedef struct {
	string name;
} fields_item_t;

rp_a_(fields_item_t)

typedef struct {
	string name;
	rp_a_import_item_t imports;
	string class_comment;
	string class_name;

} class_meta_t;

rp_a_(class_meta_t)



	
void rpc(char *srcFile,char*srcDir,char*outDir) {
	rp_a_class_meta_t *metas = rp_a_new_class_meta_t(1024);

	FILE *fp = fopen(srcFile, "r");
	char line[1024];
	int n = 0;
	while(fgets(line,1024,fp) != NULL) {
		printf("%s\n",line);
	}

    rp_a_free_class_meta_t(metas);
}


int main(int argc,char* argv[]){
	rpc(argv[1],"","");
	return 0;
}


