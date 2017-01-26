# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

LIBDIR ?= lib
PRELOADNAME = libminijailpreload.so
PRELOADPATH = \"/$(LIBDIR)/$(PRELOADNAME)\"
CPPFLAGS += -DPRELOADPATH="$(PRELOADPATH)"

ifneq ($(HAVE_SECUREBITS_H),no)
CPPFLAGS += -DHAVE_SECUREBITS_H
endif
ifneq ($(USE_seccomp),yes)
CPPFLAGS += -DUSE_SECCOMP_SOFTFAIL
endif

all: CC_BINARY(minijail0) CC_LIBRARY(libminijail.so) \
		CC_LIBRARY(libminijailpreload.so)

parse_seccomp_policy: CXX_BINARY(parse_seccomp_policy)

# TODO(jorgelo): convert to TEST().
tests: CC_BINARY(libminijail_unittest) CXX_BINARY(libminijail_unittest_gtest) \
	CC_BINARY(syscall_filter_unittest) \
	CXX_BINARY(syscall_filter_unittest_gtest)

CC_BINARY(minijail0): LDLIBS += -lcap -ldl
CC_BINARY(minijail0): libconstants.gen.o libsyscalls.gen.o libminijail.o \
		syscall_filter.o signal_handler.o bpf.o util.o elfparse.o \
		syscall_wrapper.o minijail0.o
clean: CLEAN(minijail0)

CC_LIBRARY(libminijail.so): LDLIBS += -lcap
CC_LIBRARY(libminijail.so): libminijail.o syscall_filter.o signal_handler.o \
		bpf.o util.o syscall_wrapper.o libconstants.gen.o \
		libsyscalls.gen.o
clean: CLEAN(libminijail.so)

CC_BINARY(libminijail_unittest): LDLIBS += -lcap
CC_BINARY(libminijail_unittest): libminijail_unittest.o libminijail.o \
		syscall_filter.o signal_handler.o bpf.o util.o \
		syscall_wrapper.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(libminijail_unittest)

CXX_BINARY(libminijail_unittest_gtest): CXXFLAGS += -Wno-write-strings
CXX_BINARY(libminijail_unittest_gtest): LDLIBS += -lcap
CXX_BINARY(libminijail_unittest_gtest): libminijail_unittest_gtest.o libminijail.o \
		syscall_filter.o signal_handler.o bpf.o util.o \
		syscall_wrapper.o libconstants.gen.o libsyscalls.gen.o gtest_main.a
clean: CLEAN(libminijail_unittest_gtest)

CC_LIBRARY(libminijailpreload.so): LDLIBS += -lcap -ldl
CC_LIBRARY(libminijailpreload.so): libminijailpreload.o libminijail.o \
		libconstants.gen.o libsyscalls.gen.o syscall_filter.o \
		signal_handler.o bpf.o util.o syscall_wrapper.o
clean: CLEAN(libminijailpreload.so)

CC_BINARY(syscall_filter_unittest): syscall_filter_unittest.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(syscall_filter_unittest)

CXX_BINARY(syscall_filter_unittest_gtest): syscall_filter_unittest_gtest.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o gtest_main.a
clean: CLEAN(syscall_filter_unittest_gtest)

CXX_BINARY(parse_seccomp_policy): parse_seccomp_policy.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(parse_policy)

libsyscalls.gen.o: CPPFLAGS += -I$(SRC)

libsyscalls.gen.o.depends: libsyscalls.gen.c

# Only regenerate libsyscalls.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libsyscalls.gen.c: $(SRC)/Makefile $(SRC)/libsyscalls.h
	@printf "Generating target-arch specific $@...\n"
	$(QUIET)$(SRC)/gen_syscalls.sh "$(CC)" "$@"
	@printf "$@ done.\n"
clean: CLEAN(libsyscalls.gen.c)

$(eval $(call add_object_rules,libsyscalls.gen.o,CC,c,CFLAGS))

libconstants.gen.o: CPPFLAGS += -I$(SRC)

libconstants.gen.o.depends: libconstants.gen.c

# Only regenerate libconstants.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libconstants.gen.c: $(SRC)/Makefile $(SRC)/libconstants.h
	@printf "Generating target-arch specific $@...\n"
	$(QUIET)$(SRC)/gen_constants.sh "$(CC)" "$@"
	@printf "$@ done.\n"
clean: CLEAN(libconstants.gen.c)

$(eval $(call add_object_rules,libconstants.gen.o,CC,c,CFLAGS))

################################################################################
# Google Test

# Points to the root of Google Test, relative to where this file is.
# Remember to tweak this if you move this file.
GTEST_DIR = googletest

# Flags passed to the preprocessor.
# Set Google Test's header directory as a system directory, such that
# the compiler doesn't generate warnings in Google Test headers.
CPPFLAGS += -isystem $(GTEST_DIR)/include

# Flags passed to the C++ compiler.
CXXFLAGS += -g -Wall -Wextra -pthread

# All Google Test headers.  Usually you shouldn't change this
# definition.
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h

# House-keeping build targets.
clean: clean_gtest

clean_gtest:
	rm -f gtest.a gtest_main.a *.o

# Builds gtest.a and gtest_main.a.

# Usually you shouldn't tweak such internal variables, indicated by a
# trailing _.
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

# For simplicity and to avoid depending on Google Test's
# implementation details, the dependencies specified below are
# conservative and not optimized.  This is fine as Google Test
# compiles fast and for ordinary users its source rarely changes.
gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

################################################################################
