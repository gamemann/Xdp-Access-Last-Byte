SRC_DIR=./src
BUILD_DIR=./build

CC_FLAGS=-O2 -g -target bpf

all: last_one last_two last_three
last_one:
	clang ${CC_FLAGS} -o ${BUILD_DIR}/last_one.o -c ${SRC_DIR}/last_one.c
last_two:
	clang ${CC_FLAGS} -o ${BUILD_DIR}/last_two.o -c ${SRC_DIR}/last_two.c
last_three:
	clang ${CC_FLAGS} -o ${BUILD_DIR}/last_three.o -c ${SRC_DIR}/last_three.c