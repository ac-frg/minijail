/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * Landlock functions and constants definitions.
 */

#ifndef _LANDLOCK_UTIL_H
#define _LANDLOCK_UTIL_H

#include "landlock.h"
#include "util.h"

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
		const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr, const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
			rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
		const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ACCESS_FS_ROUGHLY_READONLY ( \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_READ_EXECUTE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM)

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE)

/* Populates the landlock ruleset for a path and any needed paths beneath. */
static bool populate_ruleset_internal(const char *const path,
		const int ruleset_fd, const uint64_t allowed_access)
{
	struct landlock_path_beneath_attr path_beneath = {
		.parent_fd = -1,
	};
	struct stat statbuf;
	path_beneath.parent_fd = open(path, O_PATH | O_CLOEXEC);
	if (path_beneath.parent_fd < 0) {
		pwarn("Failed to open \"%s\": %s\n", path, strerror(errno));
		return false;
	}
	if (fstat(path_beneath.parent_fd, &statbuf)) {
		close(path_beneath.parent_fd);
		return false;
	}
	path_beneath.allowed_access = allowed_access;
	if (!S_ISDIR(statbuf.st_mode)) {
		path_beneath.allowed_access &= ACCESS_FILE;
	}
	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
			&path_beneath, 0)) {
		pwarn("Failed to update ruleset \"%s\": %s\n", path, strerror(errno));
		close(path_beneath.parent_fd);
		return false;
	}
	close(path_beneath.parent_fd);
	return true;
}

#endif
