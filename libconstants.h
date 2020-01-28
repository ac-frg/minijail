/* Copyright 2015 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef MINIJAIL_LIBCONSTANTS_H_
#define MINIJAIL_LIBCONSTANTS_H_

/*
 * If any aspect of this struct is changed then parse_constants.cc will likely
 * need to be updated to reflect how to parse the data type.
 */
struct constant_entry {
	const char *name;
	unsigned long value;
};

extern const struct constant_entry constant_table[];

#endif  /* MINIJAIL_LIBCONSTANTS_H_ */
