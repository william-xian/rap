

C_ARGS=-lpcre
headers=rapc.h
sources=rapc.c

build: $(headers) $(sources)
	gcc -o rapc $(C_ARGS) $^

run: build
	./rapc
