# SPDX-License-Identifier: Apache-2.0
# ******************************************************************************
#
# @file			Makefile
#
# @brief        Makefile for CXL State library
#
# @copyright    Copyright (C) 2024 Jackrabbit Founders LLC. All rights reserved.
#
# @date         Mar 2024
# @author       Barrett Edwards <code@jrlabs.io>
#
# ******************************************************************************

CC=gcc
CFLAGS= -g3 -O0 -Wall -Wextra
MACROS=
INCLUDE_DIR=/usr/local/include
LIB_DIR=/usr/local/lib
INCLUDE_PATH=-I $(INCLUDE_DIR)
LIB_PATH=-L $(LIB_DIR)
LIBS=-l fmapi -l arrayutils -l pciutils
TARGET=cxlstate

all: testbench lib$(TARGET).a

testbench: testbench.c main.o 
	$(CC) $^ $(CFLAGS) $(MACROS) $(INCLUDE_PATH) $(LIB_PATH) $(LIBS) -o $@ 

lib$(TARGET).a: main.o
	ar rcs $@ $^

main.o: main.c main.h
	$(CC) -c $< $(CFLAGS) $(MACROS) $(INCLUDE_PATH) -o $@ 

clean:
	rm -rf ./*.o ./*.a testbench

doc: 
	doxygen

install: lib$(TARGET).a
	sudo cp lib$(TARGET).a $(LIB_DIR)/
	sudo cp main.h $(INCLUDE_DIR)/$(TARGET).h

.PHONY: all clean doc install

# Variables 
# $^ 	Will expand to be all the sensitivity list
# $< 	Will expand to be the frist file in sensitivity list
# $@	Will expand to be the target name (the left side of the ":" )
# -c 	gcc will compile but not try and link 
