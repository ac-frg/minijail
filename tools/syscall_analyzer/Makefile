# Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

BASE_VER=0
include common.mk

LLVM_CONFIG ?= llvm-config-7

CPPFLAGS += $(shell $(LLVM_CONFIG) --cppflags)
CXXFLAGS += $(shell $(LLVM_CONFIG) --cxxflags)
LDFLAGS += $(shell $(LLVM_CONFIG) --ldflags)
LDLIBS += $(shell $(LLVM_CONFIG) --libs)

CXXFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-format-nonliteral -std=gnu++17 -Werror

ifeq ($(USE_ASAN),yes)
CPPFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
USE_EXIT_ON_DIE = yes
endif

USE_SYSTEM_GTEST ?= no
ifeq ($(USE_SYSTEM_GTEST),no)
GTEST_DIR = ../../googletest-release-1.8.0/googletest
CPPFLAGS += -isystem $(GTEST_DIR)/include

GTEST_CXXFLAGS := -std=gnu++17
GTEST_LIBS := ../../gtest.a -lpthread
else
GTEST_CXXFLAGS := $(shell gtest-config --cxxflags)
GTEST_LIBS := $(shell gtest-config --libs)
endif

CORE_OBJECT_FILES := syscall_analyzer.o disassembler.o logging.o


all: syscall_analyzer


syscall_analyzer: CXX_BINARY(syscall_analyzer)


tests: TEST(CXX_BINARY(syscall_analyzer_unittest))


CXX_BINARY(syscall_analyzer): main.o $(CORE_OBJECT_FILES)
clean: CLEAN(syscall_analyzer)


CXX_BINARY(syscall_analyzer_unittest): CXXFLAGS += $(GTEST_CXXFLAGS)
CXX_BINARY(syscall_analyzer_unittest): LDLIBS += $(GTEST_LIBS)
ifeq ($(USE_SYSTEM_GTEST),no)
CXX_BINARY(syscall_analyzer_unittest): $(GTEST_LIBS)
endif
CXX_BINARY(syscall_analyzer_unittest): syscall_analyzer_unittest.o \
	$(CORE_OBJECT_FILES) testrunner.o
clean: CLEAN(syscall_analyzer_unittest)
