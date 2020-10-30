#include "rapc.h"

#define VECTOR_SIZE 3 * 100

enum range_type_t
{
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

typedef struct
{
	ushort start;
	ushort end;
} range_t;


rap_a_(range_t)


typedef struct
{
	int type;
	ushort start;
	ushort end;
} express_t;

rap_a_(express_t)

typedef struct
{
	short class_no;
	int access;
	range_t name;
	range_t type;
	range_t val;
} field_t;

typedef struct
{
	short class_no;
	int access;
	range_t content;
	range_t name;
	rap_a_range_t args;
	rap_a_range_t returns;
	rap_a_express_t expresses;
	/* data */
} function_t;



typedef struct
{
	range_t modifier;
	range_t content;
	range_t defGenericType;
	range_t supers[16];
} class_t;

typedef struct
{
	char filename[256];
	ushort filesize;
	char *data;
	char *content;
	range_t package;
	rap_a_range_t imports;
	rap_a_range_t comments;
	rap_a_range_t strings;
	rap_a_range_t classes;
	field_t fields[128];
	function_t functions[512];
} source_t;

#define PATTERN_SIZE 20

enum pattern_name
{
	COMMENT,
	CONST_STRING,
	CONST_CHAR,
	PACKAGE,
	IMPORT,
	BACKET,
	COMMA
};

static char *patterns[PATTERN_SIZE] = {
	"/\\*(.|\n)*?\\*/",
	"\".*?\"",
	"'.*?'",
	"package .*;",
	"import .*;",
	"\\{(([^{}]*|(?R))*)\\}",
	"\\((([^()]*|(?R))*)\\)",
	NULL};

static pcre *pcres[PATTERN_SIZE];

int errno;
const char *error;
#define MSG_MAX_LEN 1024
char msg[MSG_MAX_LEN];

void printRange(char *str, ushort start, ushort end)
{
	char buf[8196];
	strncpy(buf, &str[start], end - start);
	buf[end - start] = '\0';
	printf("%s\n", buf);
}

void source_replace_string(char *str, int len)
{
	char before = ' ', open = ' ', cur;
	for (int i = 0; i < len; i++)
	{
		cur = str[i];
		if (open != ' ')
		{
			if (str[i] == open)
			{
				if (before != '\\')
				{
					open = ' ';
				}
				else
				{
					str[i] = '-';
				}
			}
			else
			{
				str[i] = '-';
			}
		}
		else
		{
			if (str[i] == '"' || str[i] == '\'')
			{
				open = str[i];
			}
		}
		before = cur;
	}
}

void source_set_range(char *str, int start, int end, char c)
{
	for (int i = start; i < end; i++)
	{
		str[i] = c;
	}
}

int source_parse(source_t *src)
{
	log_d("启动") int rc;
	int ovector[3];
	int start = 0;

	while (start < src->filesize)
	{
		rc = pcre_exec(pcres[COMMENT], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			/* 删除注释 */
			range_t val = {ovector[0], ovector[1]};
			rap_a_push_range_t(&src->comments, val);
			for (int i = ovector[0]; i < ovector[1]; i++)
			{
				src->content[i] = ' ';
			}
			start = ovector[1];
		}
		else
		{
			break;
		}
	}

	source_replace_string(src->content, src->filesize);
	start = 0;
	while (start < src->filesize)
	{
		rc = pcre_exec(pcres[CONST_STRING], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			range_t val = {ovector[0], ovector[1]};
			rap_a_push_range_t(&src->strings, val);
			start = ovector[1];
		}
		else
		{
			break;
		}
	}
	
	start = 0;
	while (start < src->filesize)
	{
		rc = pcre_exec(pcres[CONST_CHAR], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			range_t val = {ovector[0], ovector[1]};
			rap_a_push_range_t(&src->strings, val);
			start = ovector[1];
		}
		else
		{
			break;
		}
	}
	/** TODO check colsed */

	start = 0;
	rc = pcre_exec(pcres[PACKAGE], NULL, src->content, src->filesize, start, 0, ovector, 3);
	if (rc >= 0)
	{

		src->package.start = ovector[0];
		src->package.end = ovector[1];
		start = ovector[1];
		source_set_range(src->content, ovector[0], ovector[1], ' ');
		rc = pcre_exec(pcres[PACKAGE], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			snprintf(msg, MSG_MAX_LEN, "包名最多一个,%d,%d\n", ovector[0], ovector[1]);
			perror(msg);
			return 1;
		}
	}
	while (start < src->filesize)
	{
		rc = pcre_exec(pcres[IMPORT], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			range_t val = {ovector[0], ovector[1]};
			rap_a_push_range_t(&src->imports, val);
			source_set_range(src->content, ovector[0], ovector[1], ' ');
			start = ovector[1];
		}
		else
		{
			break;
		}
	}

	while (start < src->filesize)
	{
		rc = pcre_exec(pcres[BACKET], NULL, src->content, src->filesize, start, 0, ovector, 3);
		if (rc >= 0)
		{
			range_t val = {start, ovector[1]};
			rap_a_push_range_t(&src->classes, val);
			source_set_range(src->content, start, ovector[1], ' ');
			start = ovector[1];
		}
		else
		{
			break;
		}
	}
	return 0;
}

int source_load(source_t *src)
{
	FILE *fp = fopen(src->filename, "r");
	assert(fp != NULL);
	errno = fseek(fp, 0, SEEK_END);
	assert(errno == 0);
	int filesize = ftell(fp);
	errno = fseek(fp, 0, SEEK_SET);
	assert(errno == 0);
	src->filesize = filesize;
	src->data = malloc(filesize + 1);
	src->content = malloc(filesize + 1);
	fread(src->data, filesize, filesize, fp);
	src->data[filesize] = '\0';
	strncpy(src->content, src->data, filesize + 1);
	errno = fclose(fp);
	assert(errno == 0);
	return 0;
}

int source_init(source_t *src, char *filename)
{

	log_d("启动") for (int i = 0; patterns[i] != NULL; i++)
	{
		pcres[i] = pcre_compile(patterns[i], 0, &error, &errno, NULL);
		if (errno != 0)
		{
			log_e("pattern:%s, errno: %d, error: %s", patterns[i], errno, error);
		}
	}

	strcpy(src->filename, filename);
	src->filename[strlen(filename)] = '\0';
	source_load(src);

	source_parse(src);

	for (int i = 0; patterns[i] != NULL; i++)
	{
		pcre_free(pcres[i]);
	}

	for (int i = 0; i < src->comments.size; i++)
	{
		//printRange(src->data, src->comments.data[i].start, src->comments.data[i].end);
	}
	for (int i = 0; i < src->strings.size; i++)
	{
		//printRange(src->data, src->strings.data[i].start, src->strings.data[i].end);
	}

	printRange(src->data, src->package.start, src->package.end);

	for (int i = 0; i < src->imports.size; i++)
	{
		printRange(src->data, src->imports.data[i].start, src->imports.data[i].end);
	}

	for (int i = 0; i < src->classes.size; i++)
	{
		printRange(src->data, src->classes.data[i].start, src->classes.data[i].end);
	}
}

int main(int argc, char *argv[])
{
	log_d("启动");
	source_t src;
	source_init(&src, argv[1]);
	return 0;
}