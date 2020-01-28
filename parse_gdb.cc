/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by using gdb to parse an unstripped dump_constants
// instead of executing it.

#include "parse_constants.h"

#include <climits>
#include <cstring>
#include <iostream>

namespace parse_constants {

using std::cerr;
using std::cout;
using std::endl;
using std::string;

namespace {

// parse files of the form:
//
// $1 = 160
// $2 = {{name = "exit", nr = 1}, {name = "fork", nr = 2}, {name = , nr = -1}}
//
// or
//
// $1 = {{name = "exit", nr = 1}, {name = "fork", nr = 2}, {name = , nr = -1}}
//
// or
//
// $1 = {{name = "x86_64", value = 64}}
//
// The first form is when gdb doesn't know the length of the array and
// we must ask it to 'print' the length variable.  The latter is when
// the length variable has been optimized away but gdb knows the array length.
// The third form is used to handle a single-element array that reports
// the arch information.  The second struct member may be called |nr| (used
// by libsyscalls.h) or |value| (used by libsyscalls.h).

// The first part of the array line
constexpr char kFilePrefix[] = " = {";
constexpr size_t kFilePrefixLen = (sizeof(kFilePrefix) - 1);

// The first part of each element
constexpr char kNamePrefix[] = "{name = ";
constexpr size_t kNamePrefixLen = (sizeof(kNamePrefix) - 1);

// The second part of each element
constexpr char kNameSuffix[] = ", value = ";
constexpr size_t kNameSuffixLen = (sizeof(kNameSuffix) - 1);
constexpr char kNameSuffix2[] = ", nr = ";
constexpr size_t kNameSuffix2Len = (sizeof(kNameSuffix2) - 1);

// Default app to launch, and evironment variable to override.
constexpr char kGdb[] = "gdb";
constexpr char kGdbEnvVar[] = "GDB";

}  // namespace

// parse_table_gdb() tries to use gdb (gdb to use is optionally specified by the
// "GDB" environment variable) to query and parse an array called
// |table_name| from an executable file called |file_name|. If |query_length|
// is true then function will also attempt to use a variable with name
// |table_name| (plus a "_len" suffix) that indicates the number of elements
// in the array.  The contents of the array is added to |vector|.
bool parse_table_gdb(const string &file_name, const string &table_name,
		     bool query_length, constant_vector &vector)
{
  char *gdb = getenv(kGdbEnvVar);
  string command = gdb ? gdb : kGdb;
  command += " \"";
  command += file_name;
  command += "\" --nx --nw --silent --batch ";
  command += "\"--eval-command=set pagination off\" ";
  if (query_length) {
    command += "\"--eval-command=print ";
    command += table_name;
    command += "_len\" ";
  }
  command += "\"--eval-command=set print elements unlimited\" ";
  command += "\"--eval-command=set print address off\" ";
  command += "\"--eval-command=print ";
  if (query_length)
    command += "*";
  command += table_name;
  if (query_length)
    command += "@\\$1";
  command += "\" \"--eval-command=quit\" 2> /dev/null";

  string output;
  if (!run_command(command, output)) {
    return false;
  }

  const char *curr = output.c_str();

  if (query_length)
    // We don't care about the reported length (it's merely passed as $1 to
    // the next command) so skip over the first line.
    while (*curr && *(curr++) != '\n');

  // Line should start with $1 or $2
  if (curr[0] != '$' || (curr[1] != '1' && curr[1] != '2')) {
    cerr << "Array line has unexpected start: " << curr << endl;
    return false;
  }
  curr += 2;

  if (strncmp(curr, kFilePrefix, kFilePrefixLen)) {
    // If |query_length| is false then we'll try again with it set to
    // true.  So, don't complain unless it's true, and if it's false
    // then cleanup the file.
    if (query_length)
      cerr << "Variable value has unexpected start" << endl;
    return false;
  }
  curr += kFilePrefixLen;

  while (curr[0]) {
    if (strncmp(curr, kNamePrefix, kNamePrefixLen)) {
      cerr << "Element has unexpected start" << endl;
      return false;
    }
    curr += kNamePrefixLen;

    if (curr[0] == ',')
      // no name specified, so stop parsing
      break;
    else if (curr[0] != '\"') {
      cerr << "Character after 'name' wasn't comma or quote" << endl;
      return false;
    }
    ++curr;

    const char *name_end = strchr(curr, '\"');
    if (!name_end) {
      cerr << "Failed to find end of name" << endl;
      return false;
    }
    string name(curr, name_end-curr);
    curr = name_end + 1;

    if (strncmp(curr, kNameSuffix, kNameSuffixLen) == 0)
      curr += kNameSuffixLen;
    else if (strncmp(curr, kNameSuffix2, kNameSuffix2Len) == 0)
      curr += kNameSuffix2Len;
    else {
      cerr << "Name has unexpected suffix" << endl;
      return false;
    }

    char *value_end = nullptr;
    errno = 0;
    unsigned long long int value = strtoull(curr, &value_end, 0);
    if ((value == 0 && errno == EINVAL) ||
	(value == ULLONG_MAX && errno == ERANGE)) {
      cerr << "Failed to parse value" << endl;
      return false;
    }
    if (!value_end || value_end[0] != '}') {
      cerr << "Value has unexpected suffix" << endl;
      return false;
    }
    curr = value_end + 1;

    constant_entry entry = {name, value};
    vector.push_back(entry);

    if (curr[0] == ',' && curr[1] == ' ')
      curr += 2;
    else if (curr[0] == '}')
      // saw final closure
      break;
    else {
      cerr << "Unexpected start to next element" << endl;
      return false;
    }
  }

  return true;
}

}  // namespace parse_constants
