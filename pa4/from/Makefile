# File: Makefile
# By: Andy Sayler <www.andysayler.com>
# Adopted from work by: Chris Wailes <chris.wailes@gmail.com>
# Project: CSCI 3753 Programming Assignment 5
# Creation Date: 2010/04/06
# Modififed Date: 2012/04/12
# Description:
#	This is the Makefile for PA5.


CC           = gcc

CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

FUSE_EXAMPLES = fusehello fusexmp fusec
XATTR_EXAMPLES = xattr-util
OPENSSL_EXAMPLES = aes-crypt-util
FUSEC = fusec

.PHONY: all fusec clean

all: fusec


fusec: fusec.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)


fusec.o: fusec.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<


aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f *.o
	rm -f *~
	rm -f handout/*~
	rm -f handout/*.log
	rm -f handout/*.aux
	rm -f handout/*.out



