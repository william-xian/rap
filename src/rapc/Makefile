

C_ARGS=-lpcre -DDebug
INC=rapc.h
SRC=rapc.c

build: $(INC) $(SRC)
	gcc -o rapc $(C_ARGS) $^

run: build
	./rapc ../../demo/Main.rap
