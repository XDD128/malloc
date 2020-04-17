

CC = gcc

CFLAGS = -Wall -g -fpic

ARCH := $(shell getconf LONG_BIT)

LIB_32 := ~/CPE453/A1/lib
LIB_64 := ~/CPE453/A1/lib64

LIB := $(LIB_$(ARCH))

intel-all: lib/libmalloc.so lib64/libmalloc.so

lib/libmalloc.so: lib malloc32.o
	$(CC) $(CFLAGS) -m32 -shared -o $@ malloc32.o

lib64/libmalloc.so: lib64 malloc64.o
	$(CC) $(CFLAGS) -share -o $@ malloc64.o

lib:
	mkdir lib

lib64:
	mkdir lib64

malloc32.o: malloc.c
	$(CC) $(CFLAGS) -m32 -c -o malloc32.o malloc.c

malloc64.o: malloc.c
	$(CC) $(CFLAGS) -m64-c -o malloc64.o malloc.c
