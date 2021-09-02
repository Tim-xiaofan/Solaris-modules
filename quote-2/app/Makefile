# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = user

# all source are stored in SRCS-y
SRCS-y = user.c

ifeq ($(OS),Windows_NT)
		PLATFORM="Windows"
		SHELL=powershell.exe
else 
ifeq ($(shell uname),Darwin)
		PLATFORM="MacOS"
else 
ifeq ($(shell uname),Linux)
		PLATFORM="Unix-Like"
endif
endif
endif

# Add flag 
CFLAGS += -g -Wall -I./
CC = gcc

$(APP): $(SRCS-y) Makefile 
	$(CC) $(CFLAGS) $(SRCS-y) -o $@


ifeq ($(shell uname),Linux)
.PHONY: clean
clean:
	echo "Linux rm"
	rm -f *.o
	rm -f *.exe
	rm -f $(APP)
else 
ifeq ($(OS),Windows_NT)
SHELL=powershell.exe
.PHONY: clean
clean:
	echo "Windows rm"
	rm -Force *.o
	rm -Force *.exe
	rm -Force $(APP)
endif
endif
