# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

# Common variables
# ========================================================
minijailCommonCFlags := -Wall -Werror
minijailCommonSharedLibraries := libcap

# Generated code
# ========================================================
define generate-syscalls
$(intermediates)/libsyscalls.c: PRIVATE_CUSTOM_TOOL = $$< "$(lastword $(CLANG)) -isystem bionic/libc/kernel/uapi/asm-$(TARGET_ARCH)" $$@
$(intermediates)/libsyscalls.c: $(LOCAL_PATH)/gen_syscalls.sh
	$$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(intermediates)/libsyscalls.c
endef

define generate-constants
$(intermediates)/libconstants.c: PRIVATE_CUSTOM_TOOL = $$< "$(lastword $(CLANG)) -isystem bionic/libc/kernel/uapi/asm-$(TARGET_ARCH)" $$@
$(intermediates)/libconstants.c: $(LOCAL_PATH)/gen_constants.sh
	$$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(intermediates)/libconstants.c
endef

# libminijail shared library for target
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail

# LOCAL_MODULE_CLASS must be defined before calling $(local-generated-sources-dir)
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
intermediates := $(local-generated-sources-dir)

$(eval $(generate-syscalls))
$(eval $(generate-constants))

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	libminijail.c \
	signal_handler.c \
	syscall_filter.c \
	util.c \

LOCAL_SHARED_LIBRARIES := $(minijailCommonSharedLibraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
include $(BUILD_SHARED_LIBRARY)

# Native unit tests. Run with:
# adb shell /data/nativetest/libminijail_unittest/libminijail_unittest
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_unittest
ifdef BRILLO
  LOCAL_MODULE_TAGS := debug
endif

# LOCAL_MODULE_CLASS must be defined before calling $(local-generated-sources-dir)
LOCAL_MODULE_CLASS := EXECUTABLES
intermediates := $(local-generated-sources-dir)

$(eval $(generate-syscalls))
$(eval $(generate-constants))

LOCAL_SRC_FILES := \
	bpf.c \
	libminijail_unittest.c \
	libminijail.c \
	signal_handler.c \
	syscall_filter.c \
	util.c \

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SHARED_LIBRARIES := $(minijailCommonSharedLibraries)
include $(BUILD_NATIVE_TEST)
