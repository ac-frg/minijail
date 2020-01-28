/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef PARSE_CONSTANTS_H_
#define PARSE_CONSTANTS_H_

#include <string>
#include <vector>

namespace parse_constants {

struct constant_entry {
  std::string name;
  unsigned long long int value;
};

typedef std::vector<constant_entry> constant_vector;

bool run_command(const std::string &command, std::string &output);

bool parse_table_readelf(const std::string &file_name,
			 const std::string &table_name,
			 constant_vector &vector);

bool parse_table_gdb(const std::string &file_name,
		     const std::string &table_name,
		     bool query_length, constant_vector &vector);

bool parse_table_gdb_mi(const std::string &file_name,
			const std::string &table_name,
			bool query_length, constant_vector &vector);

}  // namespace parse_constants

#endif // PARSE_CONSTANTS_H_
