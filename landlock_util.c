/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>

#include "util.h"
#include "landlock_util.h"

bool populate_ruleset_internal(const char *const path,
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
