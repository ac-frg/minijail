/* syscall_filter.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Syscall filter functions.
 */

#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdbool.h>

#include "bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct filter_block {
	struct sock_filter *instrs;
	size_t len;

	struct filter_block *next;
	struct filter_block *last;
	size_t total_len;
};

enum syscall_policy_action {
	SYSCALL_POLICY_ACTION_ALLOW,
	SYSCALL_POLICY_ACTION_DENY,
	SYSCALL_POLICY_ACTION_ERRNO,
	SYSCALL_POLICY_ACTION_FILTER
};

struct syscall_policy_entry {
	int nr;
	enum syscall_policy_action action;
	int errno_val;
	int lbl_id;

	struct filter_block *filter_block;

	struct syscall_policy_entry *next;
	struct syscall_policy_entry *last;
};

struct parser_state {
	const char *filename;
	size_t line_number;
};

struct bpf_labels;

struct syscall_policy_entry *
compile_policy_line(struct parser_state *state, int nr, const char *policy_line,
		    struct bpf_labels *labels, int do_ret_trap);
int compile_file(const char *filename, FILE *policy_file,
		 struct syscall_policy_entry **policy_list,
		 struct bpf_labels *labels, int use_ret_trap, int allow_logging,
		 unsigned int include_level);
int compile_filter(const char *filename, FILE *policy_file,
		   struct sock_fprog *prog, int do_ret_trap,
		   int add_logging_syscalls);

void free_policy_list(struct syscall_policy_entry *policy_list);

int seccomp_can_softfail(void);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* SYSCALL_FILTER_H */
