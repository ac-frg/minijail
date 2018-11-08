# Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

#CXX := clang++
#CC := clang

BASE_VER=0
include common.mk

CXXFLAGS += $(shell llvm-config-4.0 --cxxflags) -Wno-format-nonliteral -std=gnu++17
LDFLAGS += $(shell llvm-config-4.0 --ldflags)
LDLIBS += $(shell llvm-config-4.0 --libs)

ifeq ($(USE_ASAN),yes)
CPPFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
USE_EXIT_ON_DIE = yes
endif


all: syscall_analyzer


syscall_analyzer: CXX_BINARY(syscall_analyzer)


CXX_BINARY(syscall_analyzer): main.o logging.o syscall_analyzer.o
clean: CLEAN(syscall_analyzer)
